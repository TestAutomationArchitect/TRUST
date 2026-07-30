#!/usr/bin/env node
/**
 * TRUST — publish preflight. Runs from prepublishOnly, so a broken or placeholder
 * package cannot reach a registry that partner organisations install from.
 *
 * A security tool is itself a supply-chain target: the checks below are the minimum
 * bar for shipping one to third parties.
 */

import { readFile } from "node:fs/promises";
import { execFileSync, execSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];
const notes = [];

const pkg = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));

// 1. The placeholder scope must be replaced before a first publish.
if (/your-org|example|placeholder/.test(pkg.name)) {
  failures.push(
    `package.json name is still the placeholder "${pkg.name}". Set your real scope ` +
      `(and the repository/homepage URLs), then re-run. Partners will type this name.`,
  );
}

// 2. No dependencies. This is a design guarantee, not an accident.
for (const field of ["dependencies", "peerDependencies", "optionalDependencies"]) {
  const deps = Object.keys(pkg[field] ?? {});
  if (deps.length) failures.push(`${field} must stay empty (found: ${deps.join(", ")}). TRUST ships stdlib-only.`);
}

// 3. No install-time scripts — partners must be able to `npm ci --ignore-scripts`.
for (const hook of ["preinstall", "install", "postinstall"]) {
  if (pkg.scripts?.[hook]) failures.push(`scripts.${hook} is not permitted — consumers must be able to install with --ignore-scripts.`);
}

// 4. Provenance and public access must be declared.
if (pkg.publishConfig?.provenance !== true) failures.push("publishConfig.provenance must be true so partners can verify the build.");

// 5. Tests must pass.
try {
  execFileSync(process.execPath, ["--test", "test/*.test.mjs"], { cwd: root, stdio: "pipe" });
  notes.push("unit tests pass");
} catch (error) {
  failures.push(`unit tests failed:\n${(error.stdout ?? Buffer.alloc(0)).toString().split("\n").slice(-25).join("\n")}`);
}

// 6. The tarball must not contain secrets or local artefacts.
try {
  // A single command string, not args + shell:true — the latter triggers DEP0190 because
  // arguments would be concatenated rather than escaped. npm needs a shell on Windows.
  const packed = JSON.parse(execSync("npm pack --dry-run --json", { cwd: root, stdio: ["ignore", "pipe", "pipe"] }).toString());
  // npm has changed this payload's shape between majors, and the CI runner does not
  // necessarily run the same npm as a developer's machine. Accept either an array of
  // results or a single object, and treat "could not enumerate" as missing information —
  // never as evidence of a bad tarball. Turning silence into a blocker previously failed
  // a release for a file that was present all along.
  const result = Array.isArray(packed) ? packed[0] : packed;
  const entries = (result?.files ?? []).map((f) => (typeof f === "string" ? f : f.path)).filter(Boolean);

  if (entries.length === 0) {
    notes.push(
      `npm pack --json reported no file list (npm ${execSync("npm --version").toString().trim()}) — ` +
        "skipping tarball content assertions; verify with `npm pack --dry-run` if this persists",
    );
  } else {
    const forbidden = entries.filter((f) => /^\.env$|^reports\/|^\.git\/|\.pem$|\.key$|^test\//.test(f));
    if (forbidden.length) failures.push(`tarball would include files that must never ship: ${forbidden.join(", ")}`);
    if (!entries.includes("src/cli.mjs")) failures.push("tarball is missing src/cli.mjs — check the files allowlist.");
    const size = Number(result?.unpackedSize);
    notes.push(`tarball contains ${entries.length} files${Number.isFinite(size) ? `, ${(size / 1024).toFixed(0)} kB unpacked` : ""}`);
  }
} catch (error) {
  notes.push(`could not inspect the tarball (${error.message.split("\n")[0]}) — verify with \`npm pack --dry-run\` manually`);
}

// 7. Every catalog ID must be documented, since IDs are the public contract.
const { CATALOG, getDomain } = await import(pathToFileURL(path.join(root, "src", "catalog.mjs")).href);
const undocumented = Object.entries(CATALOG).filter(([, meta]) => !meta.purpose || meta.purpose.length < 20);
if (undocumented.length) failures.push(`catalog entries without a usable purpose: ${undocumented.map(([id]) => id).join(", ")}`);
const orphanDomains = [...new Set(Object.values(CATALOG).map((m) => m.category))].filter((c) => getDomain(c) === "Platform" && c !== "Other");
if (orphanDomains.length) notes.push(`categories falling back to the Platform domain: ${orphanDomains.join(", ")}`);

for (const note of notes) console.error(`  · ${note}`);
if (failures.length) {
  console.error(`\n✖ preflight failed — ${failures.length} blocker(s):\n`);
  for (const failure of failures) console.error(`  - ${failure}\n`);
  process.exit(1);
}
console.error(`\n✔ preflight passed — ${pkg.name}@${pkg.version} is ready to publish`);
