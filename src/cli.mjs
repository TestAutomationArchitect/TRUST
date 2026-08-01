#!/usr/bin/env node
/**
 * TRUST — command line interface.
 *
 *   trust init   --target https://dev.example.com [--name app] [--env dev] [--dir .]
 *   trust run    --config config/dev.json --profile passive [--out reports] [--dry-run] [--quiet]
 *   trust report --dir reports [--out file.html] [--title "…"]
 *   trust tokens --config config/dev.json [--out .trust-credentials.env]
 *   trust baseline --dir reports [--out .trust-baseline.json]
 *   trust catalog [--json] [--domain Authorization]
 *
 * `trust --config … --profile …` with no subcommand is equivalent to `trust run`.
 *
 * Exit codes:
 *   0  no blocking failures (all clear, or only low/info issues)
 *   1  configuration or safety error — nothing was tested
 *   2  a critical, high or medium severity control failed
 */

import path from "node:path";
import { realpathSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { loadConfig, validateConfig, SafetyError, ConfigError } from "./safety.mjs";
import { runProfile, PROFILES } from "./runner.mjs";
import { resolveBudget, resolvedSections } from "./config.mjs";
import { writeCombinedReport, loadReports } from "./assessment/index.mjs";
import { scaffold } from "./init.mjs";
import { runPreflight } from "./preflight.mjs";
import { toSarif } from "./export/sarif.mjs";
import { toJUnit } from "./export/junit.mjs";
import { buildBaseline, loadBaseline, writeBaseline, diffAgainstBaseline, exitCodeForDiff } from "./baseline.mjs";
import { resolveAuth, exportNameFor } from "./auth/index.mjs";
import { SafeHttpClient } from "./safety.mjs";
import { listCatalog } from "./catalog.mjs";
import { TOOL } from "./report.mjs";
import { loadEnv } from "./env.mjs";

const COMMANDS = ["init", "run", "report", "catalog", "preflight", "validate", "tokens", "baseline", "help", "version"];

const USAGE = `${TOOL.name} ${TOOL.version} — ${TOOL.tagline}

  trust init    --target <url> [--name <slug>] [--env dev] [--dir .] [--force] [--no-probe]
                scaffold config/<env>.json, .env.example and an example probe

  trust run     --config <path> --profile <${Object.keys(PROFILES).join("|")}>
                [--out reports] [--dry-run] [--quiet] [--only <ID>] [--verbose]
                [--baseline <file>] [--sarif <file>] [--junit <file>]
                run a profile, write JSON + HTML, exit 2 on a blocking failure
                (with --baseline, only on a blocking failure that is *new*).
                --only <ID> narrows to the module that can produce that control
                and reports only it; --verbose traces every guarded request

  trust report  [--dir reports] [--out <file.html>] [--title <text>]
                [--trends-dir .trends] [--no-trends] [--score-by control|execution]
                [--baseline <file>] [--sarif <file>] [--junit <file>]
                merge the latest run per profile into one Trust Assessment.
                --score-by control counts each control once however many profiles
                executed it; the 1.x default counts every execution

  Secrets: .env in the working directory is loaded automatically (real environment
  variables always win). Override with --dotenv <path>, disable with --no-env.
  Do not use --env-file through an installed binary: Node intercepts that flag.

  trust preflight --config <path> [--profile all] [--offline]
                check the run will work before it spends the request budget:
                config, allowlist coverage, tokens, budget, host reachability

  trust validate --config <path>
                config and allowlist checks only — no network, no tokens needed

  trust tokens  --config <path> [--out .trust-credentials.env] [--json]
                acquire every declared auth strategy once and write the tokens to a
                file (mode 600), so a CI job authenticates once and every later step
                reuses it. Tokens are never printed.

  trust baseline --dir reports [--out .trust-baseline.json] [--note "…"]
                record today's findings as accepted, so the gate means "nothing got
                worse" rather than "nothing is wrong"

  trust catalog [--json] [--domain <trust domain>]
                list every known test with its category, domain and purpose

  trust --version | --help
`;

export function parseArgs(argv) {
  const opts = {
    command: "run",
    config: "",
    profile: "passive",
    out: "",
    dir: "reports", // `report` reads from here; `init` writes into "." unless --dir is given
    dirSet: false,
    title: "",
    target: "",
    name: "",
    env: "dev",
    force: false,
    withProbe: true,
    json: false,
    domain: "",
    envFile: ".env",
    baseline: "",
    sarif: "",
    junit: "",
    note: "",
    scoreBy: process.env.TRUST_SCORE_BY || "execution",
    only: "",
    verbose: false,
    noEnv: false,
    noTrends: false,
    offline: false,
    trendsDir: process.env.TRUST_TRENDS_DIR || ".trends",
    dryRun: false,
    quiet: false,
    help: false,
    version: false,
  };

  let rest = argv;
  if (argv.length && !argv[0].startsWith("-")) {
    if (!COMMANDS.includes(argv[0])) throw new ConfigError(`Unknown command "${argv[0]}". Expected one of: ${COMMANDS.join(", ")}`);
    opts.command = argv[0];
    rest = argv.slice(1);
  }

  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    const next = () => {
      const value = rest[++i];
      if (value === undefined) throw new ConfigError(`${arg} requires a value`);
      return value;
    };
    switch (arg) {
      case "--config": opts.config = next(); break;
      case "--profile": opts.profile = next(); break;
      case "--out": opts.out = next(); break;
      case "--dir": opts.dir = next(); opts.dirSet = true; break;
      case "--title": opts.title = next(); break;
      case "--target": opts.target = next(); break;
      case "--name": opts.name = next(); break;
      case "--env": case "--environment": opts.env = next(); break;
      case "--domain": opts.domain = next(); break;
      case "--baseline": opts.baseline = next(); break;
      case "--sarif": opts.sarif = next(); break;
      case "--junit": opts.junit = next(); break;
      case "--note": opts.note = next(); break;
      case "--only": case "--probe": opts.only = next(); break;
      case "--verbose": case "-v-": opts.verbose = true; break;
      case "--score-by": {
        opts.scoreBy = next();
        if (!["control", "execution"].includes(opts.scoreBy)) throw new ConfigError(`--score-by must be "control" or "execution", got "${opts.scoreBy}"`);
        break;
      }
      case "--force": opts.force = true; break;
      case "--no-probe": opts.withProbe = false; break;
      case "--json": opts.json = true; break;
      // Node claims --env-file for itself when the CLI runs through an npm bin shim, so that
      // flag never reaches this parser and the user sees "node: .env: not found". --dotenv is
      // ours alone. (--env is taken: it is the environment name for `trust init`.) --env-file
      // still works for a direct `node src/cli.mjs` invocation, where Node has already parsed.
      case "--dotenv": case "--env-file": opts.envFile = next(); break;
      case "--no-env": opts.noEnv = true; break;
      case "--no-trends": opts.noTrends = true; break;
      case "--offline": opts.offline = true; break;
      case "--trends-dir": opts.trendsDir = next(); break;
      case "--dry-run": opts.dryRun = true; break;
      case "--quiet": opts.quiet = true; break;
      case "--help": case "-h": opts.help = true; break;
      case "--version": case "-v": opts.version = true; break;
      default: throw new ConfigError(`Unknown argument: ${arg}`);
    }
  }

  if (opts.command === "help") opts.help = true;
  if (opts.command === "version") opts.version = true;
  if (!opts.help && !opts.version) {
    if (opts.command === "run") {
      if (!opts.config) throw new ConfigError("--config is required (or run `trust init` first)");
      if (!PROFILES[opts.profile]) {
        throw new ConfigError(`Unknown profile "${opts.profile}". Choose one of: ${Object.keys(PROFILES).join(", ")}`);
      }
    }
    if (opts.command === "init" && !opts.target) throw new ConfigError("--target is required, e.g. --target https://dev.example.com");
    if (opts.command === "tokens" && !opts.config) throw new ConfigError("--config is required");
    if ((opts.command === "preflight" || opts.command === "validate") && !opts.config) {
      throw new ConfigError("--config is required");
    }
  }
  return opts;
}

// ─── console presentation ───────────────────────────────────────────
const COLOR = process.stderr.isTTY && !process.env.NO_COLOR;
const paint = (code, text) => (COLOR ? `[${code}m${text}[0m` : text);
const STATUS_STYLE = { pass: (t) => paint(32, t), fail: (t) => paint(31, t), warn: (t) => paint(33, t), skip: (t) => paint(90, t) };
const log = (...args) => console.error(...args);

// ─── commands ───────────────────────────────────────────────────────
async function commandInit(opts) {
  const result = await scaffold({
    dir: opts.dirSet ? opts.dir : ".",
    name: opts.name,
    target: opts.target,
    environment: opts.env,
    force: opts.force,
    withProbe: opts.withProbe,
  });
  log(paint(1, `${TOOL.name} ${TOOL.version}`), `— scaffolded ${result.name}`);
  for (const file of result.written) log(paint(32, `  + ${file}`));
  for (const file of result.skipped) log(paint(90, `  · ${file} (exists, left alone)`));
  log("");
  log("  Next:");
  log(`    1. cp .env.example .env   and fill in tokens for two test identities`);
  log(`    2. review ${result.configPath} — allowedHosts is the safety boundary`);
  log(`    3. trust run --config ${result.configPath} --profile passive`);
  console.log(result.configPath);
  return 0;
}

async function commandRun(opts) {
  const config = await loadConfig(opts.config);
  const profile = PROFILES[opts.profile];
  const advisories = validateConfig(config);
  const budget = resolveBudget(config, opts.profile);
  const aliases = resolvedSections(config);

  log(paint(1, `${TOOL.name} ${TOOL.version}`), `— ${config.name} (${config.environment})`);
  log(`  target   ${config.targets.web}`);
  log(`  profile  ${opts.profile} — ${profile.description}`);
  log(
    `  safety   max ${budget.total} requests${budget.suites ? ` (per-suite: ${Object.entries(budget.suites).map(([k, v]) => k + " " + v).join(", ")})` : ""} · ${config.safety.minimumDelayMs}ms floor · ` +
      `writes ${config.safety.allowWrites ? "ON" : "off"} · agent invocations ${config.safety.allowAgentInvocations ? "ON" : "off"}`,
  );
  if (Object.keys(aliases).length) {
    log(paint(90, `  config   ${Object.entries(aliases).map(([canonical, key]) => canonical + " → " + key).join(", ")}`));
  }
  if (config.extendsChain) log(paint(90, `  extends  ${config.extendsChain.length} file(s) merged`));
  for (const advisory of advisories) log(paint(33, `  ! ${advisory}`));

  if (opts.dryRun) {
    log(paint(90, "\n  dry run — no requests issued"));
    return 0;
  }

  if (opts.only) log(paint(90, `  only     ${opts.only} — modules that cannot produce this ID are skipped`));

  const result = await runProfile({
    config,
    profile: opts.profile,
    out: opts.out || "reports",
    baseDir: path.dirname(path.resolve(opts.config)),
    only: opts.only,
    validate: false, // already validated, so advisories are not printed twice
    onEvent: (event) => {
      if (event.type === "request" && opts.verbose) {
        // Header names, never values: a trace is the last place a token should surface.
        log(paint(90, `    → ${event.method.padEnd(6)} ${String(event.status).padStart(3)}  ${event.ms}ms  ${event.url}  [${event.headerNames.join(", ")}]`));
      }
      if (event.type === "module") log(paint(90, `\n▸ ${event.label}`));
      else if (event.type === "module-aborted") log(paint(31, `  safety guard stopped ${event.name}: ${event.message}`));
      else if (event.type === "finding" && !opts.quiet) {
        const f = event.finding;
        const style = STATUS_STYLE[f.status] ?? ((t) => t);
        log(`  ${style(f.status.toUpperCase().padEnd(4))} ${paint(90, f.severity.padEnd(8))} ${f.id} — ${f.title}`);
      }
    },
  });

  await writeExports(opts, [result.report], opts.config);

  // A baseline turns the gate into "nothing got worse". Everything is still reported; what
  // changes is only which findings can block the build.
  let exitCode = result.exitCode;
  if (opts.baseline) {
    const diff = diffAgainstBaseline([result.report], await loadBaseline(opts.baseline));
    exitCode = exitCodeForDiff(diff);
    logDiff(diff);
  }

  const { summary, paths } = result;
  const failDomains = [...new Set(result.report.findings.filter((f) => f.status === "fail").map((f) => f.domain))];
  log("");
  log(
    `  ${STATUS_STYLE.pass(`${summary.pass} pass`)} · ${STATUS_STYLE.fail(`${summary.fail} fail`)} · ` +
      `${STATUS_STYLE.warn(`${summary.warn} warn`)} · ${STATUS_STYLE.skip(`${summary.skip} skip`)} · ${result.requestCount} requests`,
  );
  if (failDomains.length) log(paint(31, `  failing domains: ${failDomains.join(", ")}`));
  log(`  ${paths.jsonPath}`);
  log(`  ${paths.htmlPath}`);
  console.log(paths.jsonPath);
  return exitCode;
}

/** Write SARIF and JUnit alongside the run's own JSON, when asked for. */
async function writeExports(opts, reports, configPath) {
  if (opts.sarif) {
    const sarif = toSarif(reports, { configPath: configPath || "trust.config.json", toolVersion: TOOL.version });
    await writeFile(opts.sarif, `${JSON.stringify(sarif, null, 2)}
`);
    log(paint(90, `  sarif    ${opts.sarif} — ${sarif.runs[0].results.length} result(s)`));
  }
  if (opts.junit) {
    await writeFile(opts.junit, toJUnit(reports));
    log(paint(90, `  junit    ${opts.junit}`));
  }
}

/** What changed against the baseline. Fixed findings are reported as loudly as new ones. */
function logDiff(diff) {
  log("");
  log(
    `  baseline: ${diff.fresh.length ? paint(31, `${diff.fresh.length} new`) : paint(32, "0 new")} · ` +
      `${diff.worsened.length ? paint(31, `${diff.worsened.length} worsened`) : `${diff.worsened.length} worsened`} · ` +
      `${paint(90, `${diff.known.length} known`)} · ${diff.fixed.length ? paint(32, `${diff.fixed.length} fixed`) : "0 fixed"}`,
  );
  for (const f of diff.fresh) log(paint(31, `    new      ${f.severity.padEnd(8)} ${f.id} — ${f.title}`));
  for (const f of diff.worsened) log(paint(31, `    worsened ${f.severity.padEnd(8)} ${f.id} — was ${f.was}, now ${f.status}`));
  for (const f of diff.fixed) log(paint(32, `    fixed    ${(f.severity ?? "").padEnd(8)} ${f.id} — ${f.title}`));
  if (diff.notRun?.length) {
    // Not fixed — not looked for. Saying so is the difference between a gate a team trusts and
    // one that congratulates them for skipping a profile.
    log(paint(90, `    ${diff.notRun.length} baselined finding(s) belong to profiles this run did not execute`));
  }
}

async function commandPreflight(opts, { reach }) {
  const config = await loadConfig(opts.config);
  const { checks, ok } = await runPreflight(config, { profile: opts.profile, reach });

  log(paint(1, `${TOOL.name} ${TOOL.version}`), `— preflight for ${config.name} (${config.environment})`);
  const mark = { ok: paint(32, "✓"), warn: paint(33, "!"), fail: paint(31, "✗") };
  for (const c of checks) log(`  ${mark[c.status]} ${paint(90, c.name.padEnd(22))} ${c.detail}`);

  const fails = checks.filter((c) => c.status === "fail").length;
  const warns = checks.filter((c) => c.status === "warn").length;
  log("");
  log(ok ? paint(32, `  ready — ${warns} advisory item(s)`) : paint(31, `  not ready — ${fails} blocking issue(s), ${warns} advisory`));
  return ok ? 0 : 1;
}

/**
 * Acquire every declared strategy once and persist the result.
 *
 * The problem this solves is unattended CI: a token pasted into .env expires, and a job that
 * authenticates in every step multiplies sign-ins until the IdP rate-limits the assessment.
 * The written file is read back by a later `trust run` through the same env var the strategy
 * would export, so acquisition happens once per pipeline.
 *
 * A token is never printed. What reaches the console is the strategy name, kind and expiry.
 */
async function commandTokens(opts) {
  const config = await loadConfig(opts.config);
  validateConfig(config);
  const declared = Object.keys(config.auth?.strategies ?? {});
  if (declared.length === 0) throw new ConfigError("config.auth.strategies is empty — nothing to acquire");

  const client = new SafeHttpClient(config, { budget: resolveBudget(config, opts.profile) });
  client.beginSuite("auth");
  log(paint(1, `${TOOL.name} ${TOOL.version}`), `— acquiring ${declared.length} credential(s) for ${config.name} (${config.environment})`);
  const resolved = await resolveAuth(config, client, {});

  const lines = [];
  let failures = 0;
  for (const [name, credential] of resolved) {
    if (credential.error) {
      failures += 1;
      log(`  ${paint(31, "✗")} ${paint(90, name.padEnd(18))} ${credential.error}`);
      continue;
    }
    const expiry = credential.expiresAt ? `expires ${credential.expiresAt}` : "no expiry claim";
    if (credential.kind === "bearer") {
      const envName = exportNameFor(name, config.auth.strategies[name]);
      lines.push(`${envName}=${credential.token}`);
      log(`  ${paint(32, "✓")} ${paint(90, name.padEnd(18))} ${credential.type} → ${envName} (${expiry})`);
    } else {
      // Signing credentials are short-lived and bound to the run that acquired them; writing
      // them to a file would outlive their usefulness and widen what a leaked file exposes.
      log(`  ${paint(32, "✓")} ${paint(90, name.padEnd(18))} ${credential.type} → signing credentials, acquired per run (${expiry})`);
    }
  }

  if (opts.json) {
    console.log(JSON.stringify(
      [...resolved.values()].map((c) => ({ name: c.name, strategy: c.type, kind: c.kind ?? null, ok: !c.error, expiresAt: c.expiresAt ?? null, error: c.error ?? null })),
      null, 2,
    ));
    return failures ? 1 : 0;
  }

  const outPath = opts.out || ".trust-credentials.env";
  if (lines.length) {
    // 0600, and appended to .gitignore by `trust init` — this file is a live credential.
    await writeFile(outPath, lines.map((line) => `${line}\n`).join(""), { mode: 0o600 });
    log("");
    log(`  ${outPath} — ${lines.length} credential(s), mode 600`);
    log(paint(90, `  load it before the run:  trust run --dotenv ${outPath} --config ${opts.config} --profile authenticated`));
    console.log(outPath);
  }
  return failures ? 1 : 0;
}

async function commandReport(opts) {
  const { outPath, profiles, trendsDir, unitCounts } = await writeCombinedReport({ dir: opts.dir, out: opts.out, title: opts.title, noTrends: opts.noTrends, trendsDir: opts.trendsDir, scoreBy: opts.scoreBy });
  log(`Merged ${profiles.length} profile(s): ${profiles.join(", ")}`);
  if (unitCounts) {
    log(
      opts.scoreBy === "control"
        ? paint(90, `  scoring  by control — ${unitCounts.controls} controls, ${unitCounts.executions} executions`)
        : paint(90, `  scoring  by execution — ${unitCounts.executions} executions across ${unitCounts.controls} controls. ` +
            `A control run in several profiles is weighted once per run; --score-by control counts it once`),
    );
  }
  if (!opts.noTrends) log(paint(90, `  history  ${trendsDir}/trends.json — restore and persist this in CI, or every run looks like the first`));

  // Exporting from `report` covers every profile at once, which is what a CI job wants to
  // upload — one SARIF file for the whole assessment rather than one per profile.
  let exitCode = 0;
  if (opts.sarif || opts.junit || opts.baseline) {
    const reports = [...(await loadReports(opts.dir)).values()];
    await writeExports(opts, reports, opts.config);
    if (opts.baseline) {
      const diff = diffAgainstBaseline(reports, await loadBaseline(opts.baseline));
      exitCode = exitCodeForDiff(diff);
      logDiff(diff);
    }
  }
  console.log(outPath);
  return exitCode;
}

/**
 * Record today's findings as accepted. A team adopting TRUST mid-life inherits findings it did
 * not cause; without this the choice is to fail every build until the backlog clears, or to stop
 * gating on the tool at all.
 */
async function commandBaseline(opts) {
  const reports = [...(await loadReports(opts.dir)).values()];
  if (reports.length === 0) throw new ConfigError(`No TRUST reports found in ${opts.dir} — run a profile first`);
  const baseline = buildBaseline(reports, { note: opts.note });
  const outPath = await writeBaseline(baseline, opts.out || ".trust-baseline.json");

  log(paint(1, `${TOOL.name} ${TOOL.version}`), `— baseline for ${baseline.target || baseline.environment}`);
  log(`  ${baseline.findings.length} accepted finding(s) from ${baseline.profiles.join(", ")}`);
  for (const entry of baseline.findings.slice(0, 10)) log(paint(90, `    ${entry.status.padEnd(4)} ${entry.severity.padEnd(8)} ${entry.id}`));
  if (baseline.findings.length > 10) log(paint(90, `    … and ${baseline.findings.length - 10} more`));
  log("");
  log(paint(90, `  gate on it:  trust run --baseline ${outPath} --config <config> --profile <profile>`));
  log(paint(90, "  a baseline hides nothing from the report — it only decides what may block a build"));
  console.log(outPath);
  return 0;
}

function commandCatalog(opts) {
  let entries = listCatalog();
  if (opts.domain) entries = entries.filter((e) => e.domain.toLowerCase() === opts.domain.toLowerCase());
  if (opts.json) {
    console.log(JSON.stringify(entries, null, 2));
    return 0;
  }
  let currentDomain = "";
  for (const entry of entries) {
    if (entry.domain !== currentDomain) {
      currentDomain = entry.domain;
      console.log(`\n${paint(1, currentDomain)}`);
    }
    console.log(`  ${entry.id.padEnd(38)} ${paint(90, entry.category)}`);
  }
  console.log(`\n${entries.length} tests${opts.domain ? ` in ${opts.domain}` : ""}`);
  return 0;
}

// ─── main ───────────────────────────────────────────────────────────
const MIN_NODE_MAJOR = 22;

async function main() {
  // Fail with a sentence, not a stack trace, on an older runtime.
  const major = Number(process.versions.node.split(".")[0]);
  if (major < MIN_NODE_MAJOR) {
    throw new ConfigError(`${TOOL.name} needs Node ${MIN_NODE_MAJOR} or newer (running ${process.versions.node}). It relies on built-in fetch and modern crypto.`);
  }

  const opts = parseArgs(process.argv.slice(2));
  if (opts.version) {
    console.log(TOOL.version);
    return 0;
  }
  if (opts.help) {
    console.log(USAGE);
    return 0;
  }
  if (!opts.noEnv && ["run", "report", "tokens", "preflight"].includes(opts.command)) {
    const env = await loadEnv(opts.envFile);
    if (env.present) {
      log(paint(90, `  env      ${env.loaded.length} variable(s) from ${env.envFile ?? opts.envFile}` +
        (env.skipped.length ? ` · ${env.skipped.length} already set in the environment and left alone` : "")));
    }
  }

  switch (opts.command) {
    case "init": return commandInit(opts);
    case "run": return commandRun(opts);
    case "report": return commandReport(opts);
    case "preflight": return commandPreflight(opts, { reach: !opts.offline });
    case "validate": return commandPreflight(opts, { reach: false });
    case "tokens": return commandTokens(opts);
    case "baseline": return commandBaseline(opts);
    case "catalog": return commandCatalog(opts);
    default: throw new ConfigError(`Unknown command "${opts.command}"`);
  }
}

// Only drive the CLI when this file *is* the entry point. realpath matters because an
// installed bin is a symlink into node_modules/.bin.
const entry = process.argv[1] ? pathToFileURL(realpathSync(process.argv[1])).href : "";
if (import.meta.url === entry) {
  main()
  .then((code) => process.exit(code))
  .catch((error) => {
    if (error instanceof ConfigError || error instanceof SafetyError) {
      log(paint(31, `${error.name}: ${error.message}`));
      process.exit(1);
    }
    log(paint(31, error.stack ?? String(error)));
    process.exit(1);
  });
}
