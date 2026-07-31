import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { readFileSync } from "node:fs";

import * as api from "../src/index.mjs";
import { parseArgs } from "../src/cli.mjs";
import { defineProbe, resolveProbes, runProfile, loadCustomProbes, PROFILES } from "../src/runner.mjs";
import { scaffold, configTemplate } from "../src/init.mjs";
import { registerCatalogEntries, registerDomains, registerRootCauses, getTestMeta, domainForId, canonicalId, DEPRECATED_IDS, listCatalog } from "../src/catalog.mjs";
import { finding, skipped } from "../src/finding.mjs";
import { TOOL } from "../src/report.mjs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

// ── the package contract partners depend on ────────────────────────
test("package is publishable and stdlib-only", () => {
  assert.equal(pkg.private, undefined, "private must be removed to publish");
  assert.equal(pkg.type, "module");
  assert.ok(pkg.engines.node.startsWith(">=22"));
  assert.deepEqual(Object.keys(pkg.dependencies ?? {}), [], "TRUST must stay dependency-free");
  assert.deepEqual(Object.keys(pkg.peerDependencies ?? {}), []);
  // Provenance belongs to the CI publish command, not to publishConfig: setting it there
  // makes every local publish fail with "provider: null", since no CI provider is present.
  assert.equal(pkg.publishConfig, undefined, "provenance must not be demanded of every publish");
  const workflow = readFileSync(new URL("../.github/workflows/publish.yml", import.meta.url), "utf8");
  assert.match(workflow, /npm publish[^\n]*--provenance/, "CI must still publish with provenance");
  for (const hook of ["preinstall", "install", "postinstall"]) {
    assert.equal(pkg.scripts[hook], undefined, `${hook} would break npm ci --ignore-scripts`);
  }
});

test("package exposes a CLI and a library entry point", () => {
  assert.equal(pkg.bin.trust, "./src/cli.mjs");
  assert.equal(pkg.exports["."], "./src/index.mjs");
  assert.ok(pkg.files.includes("src/"));
  assert.ok(!pkg.files.some((f) => f.startsWith("test")), "tests must not ship");
});

test("the public API exports everything a partner needs to embed or extend TRUST", () => {
  for (const name of [
    "runProfile", "defineProbe",
    "loadConfig", "validateConfig", "SafeHttpClient",
    "finding", "skipped", "inconclusive", "canary", "redact",
    "registerCatalogEntries", "registerDomains", "listCatalog", "getTestMeta",
    "buildCombinedReport", "writeCombinedReport", "writeRunReport", "buildRunReport",
    "scaffold",
  ]) {
    assert.equal(typeof api[name], "function", `${name} must be exported from the package root`);
  }
  assert.equal(typeof api.PROFILES, "object");
  assert.equal(typeof api.TOOL.version, "string");
  assert.deepEqual(Object.keys(api.PROFILES).sort(), ["agent", "all", "authenticated", "mobile", "passive"]);
});

// ── extension points ───────────────────────────────────────────────
test("defineProbe validates shape and defaults to every profile", () => {
  const probe = defineProbe({ name: "acme", run: async () => [] });
  assert.deepEqual(probe.profiles, ["all"]);
  assert.equal(probe.label, "acme");
  assert.throws(() => defineProbe({ run: async () => [] }), /requires a name/);
  assert.throws(() => defineProbe({ name: "x" }), /requires an async run/);
});

test("resolveProbes selects built-ins by profile and custom probes by declaration", () => {
  const custom = defineProbe({ name: "acme", profiles: ["passive"], run: async () => [] });
  const passive = resolveProbes("passive", [custom]).map((p) => p.name);
  assert.deepEqual(passive, ["web", "idp", "injection", "acme"]);
  assert.deepEqual(resolveProbes("agent", [custom]).map((p) => p.name), ["token", "agent"], "a passive-only probe must not run in the agent profile");
  assert.ok(resolveProbes("all", [custom]).map((p) => p.name).includes("acme"));
});

test("registerCatalogEntries makes a partner test score and group like a built-in", () => {
  registerCatalogEntries({ "ACME-SSO-CLOCK-SKEW": { category: "ACME Identity", purpose: "Verify the SAML assertion window rejects a skewed clock." } });
  registerDomains({ "ACME Identity": "Identity Binding" });
  assert.equal(getTestMeta("ACME-SSO-CLOCK-SKEW").category, "ACME Identity");
  assert.equal(domainForId("ACME-SSO-CLOCK-SKEW"), "Identity Binding");
  assert.ok(listCatalog().some((e) => e.id === "ACME-SSO-CLOCK-SKEW"));
  assert.throws(() => registerCatalogEntries({ BAD: { category: "x" } }), /needs a purpose/);
  assert.throws(() => registerCatalogEntries({ BAD: { purpose: "y" } }), /needs a category/);
});

test("registerDomains inserts a new domain before Platform in the narrative order", () => {
  registerDomains({ "ACME Supply Chain": "Supply Chain" });
  registerRootCauses({ "Supply Chain": "Third-party integrations are insufficiently constrained" });
  assert.ok(api.DOMAIN_ORDER.includes("Supply Chain"));
  assert.equal(api.DOMAIN_ORDER.at(-1), "Platform", "Platform stays the catch-all at the end");
  assert.equal(api.ROOT_CAUSE_MAP["Supply Chain"], "Third-party integrations are insufficiently constrained");
});

test("renamed IDs resolve through the alias map so partner dashboards keep working", () => {
  DEPRECATED_IDS["GQL-USERID-SPOOF"] = "API-USERID-SPOOF";
  try {
    assert.equal(canonicalId("GQL-USERID-SPOOF"), "API-USERID-SPOOF");
    assert.equal(getTestMeta("GQL-USERID-SPOOF").category, "Identity Spoofing");
    assert.equal(domainForId("GQL-USERID-SPOOF"), "Identity Binding");
  } finally {
    delete DEPRECATED_IDS["GQL-USERID-SPOOF"];
  }
});

test("canonicalId does not loop on a circular alias", () => {
  DEPRECATED_IDS.A = "B";
  DEPRECATED_IDS.B = "A";
  try {
    assert.ok(["A", "B"].includes(canonicalId("A")));
  } finally {
    delete DEPRECATED_IDS.A;
    delete DEPRECATED_IDS.B;
  }
});

// ── runProfile as a library call ────────────────────────────────────
const embedConfig = {
  name: "embed",
  environment: "dev",
  targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com"] },
  safety: { maxRequests: 10, minimumDelayMs: 50, requestTimeoutMs: 5000, allowWrites: false, allowAgentInvocations: false, productionOverride: false },
};

test("runProfile runs a custom probe, emits events and returns an exit code without writing", async () => {
  const events = [];
  const probe = defineProbe({
    name: "acme",
    label: "ACME controls",
    profiles: ["passive"],
    catalog: { "ACME-EMBED": { category: "Web Hardening", purpose: "Verify the embedded probe path returns a real finding." } },
    async run() {
      return [
        finding({ id: "ACME-EMBED", title: "Embedded probe reports", status: "fail", severity: "high", evidence: "observed", remediation: "fix" }),
        skipped("ACME-EMBED-SKIP", "Embedded probe skip path", "no token"),
      ];
    },
  });

  const result = await runProfile({
    config: embedConfig,
    profile: "mobile", // no mobile config → the built-in module skips, keeping this offline
    probes: [{ ...probe, profiles: ["mobile"] }],
    onEvent: (e) => events.push(e.type),
  });

  assert.equal(result.exitCode, 2, "a high-severity failure must gate CI");
  assert.equal(result.paths, null, "omitting out must not write to disk");
  assert.ok(result.findings.some((f) => f.id === "ACME-EMBED"));
  assert.equal(result.report.findings.find((f) => f.id === "ACME-EMBED").domain, "Infrastructure");
  assert.ok(events.includes("module") && events.includes("finding") && events.includes("done"));
});

test("runProfile rejects an unknown profile and refuses a production target", async () => {
  await assert.rejects(() => runProfile({ config: embedConfig, profile: "nonsense" }), /Unknown profile/);
  await assert.rejects(
    () => runProfile({ config: { ...embedConfig, environment: "prod" }, profile: "passive" }),
    /Production target refused/,
  );
});

test("loadCustomProbes resolves paths relative to the config directory", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "trust-probe-"));
  try {
    await mkdir(path.join(dir, "probes"), { recursive: true });
    const probeUrl = new URL("../src/runner.mjs", import.meta.url).href;
    await writeFile(
      path.join(dir, "probes", "acme.mjs"),
      `import { defineProbe } from ${JSON.stringify(probeUrl)};
       export default defineProbe({ name: "acme-file", profiles: ["passive"], async run() { return []; } });`,
    );
    const loaded = await loadCustomProbes({ probes: ["./probes/acme.mjs"] }, dir);
    assert.equal(loaded.length, 1);
    assert.equal(loaded[0].name, "acme-file");
    await assert.rejects(() => loadCustomProbes({ probes: ["./nope.mjs"] }, dir), /Cannot load probe module/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ── init scaffolding ───────────────────────────────────────────────
test("scaffold writes a valid config, env template and probe, and never clobbers", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "trust-init-"));
  try {
    const first = await scaffold({ dir, target: "https://dev.acme.example.com", environment: "dev", name: "acme-dev" });
    assert.ok(first.written.some((f) => f.endsWith(path.join("config", "dev.json"))));
    assert.ok(first.written.some((f) => f.endsWith(".env.example")));
    assert.ok(first.written.some((f) => f.endsWith(path.join("trust-probes", "example.mjs"))));
    assert.ok(first.written.some((f) => f.endsWith(".gitignore")));

    // The generated config must load and validate through the real code path.
    const config = await api.loadConfig(first.configPath);
    assert.deepEqual(api.validateConfig(config), []);
    assert.equal(config.name, "acme-dev");
    assert.ok(config.targets.allowedHosts.includes("dev.acme.example.com"));

    const gitignore = await readFile(path.join(dir, ".gitignore"), "utf8");
    assert.match(gitignore, /^\.env$/m, "the scaffold must gitignore .env");

    // Second run leaves everything alone.
    const second = await scaffold({ dir, target: "https://dev.acme.example.com", environment: "dev" });
    assert.equal(second.written.length, 0);
    assert.ok(second.skipped.length >= 3);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("configTemplate produces parseable jsonc for an arbitrary target", () => {
  const text = configTemplate({ name: "x", target: "https://uat.bank.example.co.uk", environment: "uat" });
  const parsed = JSON.parse(api.stripJsonComments ? api.stripJsonComments(text) : text.replace(/\/\/.*$/gm, ""));
  assert.equal(parsed.environment, "uat");
  assert.ok(parsed.targets.allowedHosts.includes("uat.bank.example.co.uk"));
});

// ── CLI argument surface ───────────────────────────────────────────
test("CLI parses subcommands, defaults and rejects bad input", () => {
  assert.equal(parseArgs(["run", "--config", "c.json", "--profile", "agent"]).command, "run");
  assert.equal(parseArgs(["--config", "c.json"]).command, "run", "no subcommand means run");
  assert.equal(parseArgs(["--config", "c.json"]).profile, "passive");
  assert.equal(parseArgs(["report"]).dir, "reports");
  assert.equal(parseArgs(["init", "--target", "https://x.example.com"]).env, "dev");
  assert.equal(parseArgs(["catalog", "--json"]).json, true);
  assert.equal(parseArgs(["--version"]).version, true);

  assert.throws(() => parseArgs(["run"]), /--config is required/);
  assert.throws(() => parseArgs(["run", "--config", "c.json", "--profile", "nope"]), /Unknown profile/);
  assert.throws(() => parseArgs(["init"]), /--target is required/);
  assert.throws(() => parseArgs(["deploy"]), /Unknown command/);
  assert.throws(() => parseArgs(["run", "--config"]), /requires a value/);
  assert.throws(() => parseArgs(["--wat"]), /Unknown argument/);
});

test("every profile names at least one built-in module", () => {
  for (const [name, profile] of Object.entries(PROFILES)) {
    assert.ok(profile.modules.length > 0, `${name} has no modules`);
    assert.ok(profile.description.length > 10);
  }
});

test("the version the reports state is the version that was published", () => {
  // TOOL.version is a constant rather than a runtime read of the manifest, so this is what
  // stops a report claiming a version that was never released.
  assert.equal(TOOL.version, pkg.version);
});

test("every file the package promises to ship exists", async () => {
  const { stat } = await import("node:fs/promises");
  for (const entry of pkg.files) {
    // A stale entry is silent: npm omits what it cannot find, and the gap only shows up in a
    // partner's install.
    await stat(new URL(`../${entry}`, import.meta.url));
  }
});
