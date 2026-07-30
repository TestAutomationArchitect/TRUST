#!/usr/bin/env node
/**
 * TRUST — command line interface.
 *
 *   trust init   --target https://dev.example.com [--name app] [--env dev] [--dir .]
 *   trust run    --config config/dev.json --profile passive [--out reports] [--dry-run] [--quiet]
 *   trust report --dir reports [--out file.html] [--title "…"]
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
import { pathToFileURL } from "node:url";
import { loadConfig, validateConfig, SafetyError, ConfigError } from "./safety.mjs";
import { runProfile, PROFILES } from "./runner.mjs";
import { writeCombinedReport } from "./assessment/index.mjs";
import { scaffold } from "./init.mjs";
import { listCatalog } from "./catalog.mjs";
import { TOOL } from "./report.mjs";
import { loadEnv } from "./env.mjs";

const COMMANDS = ["init", "run", "report", "catalog", "help", "version"];

const USAGE = `${TOOL.name} ${TOOL.version} — ${TOOL.tagline}

  trust init    --target <url> [--name <slug>] [--env dev] [--dir .] [--force] [--no-probe]
                scaffold config/<env>.json, .env.example and an example probe

  trust run     --config <path> --profile <${Object.keys(PROFILES).join("|")}>
                [--out reports] [--dry-run] [--quiet]
                run a profile, write JSON + HTML, exit 2 on a blocking failure

  trust report  [--dir reports] [--out <file.html>] [--title <text>]
                merge the latest run per profile into one Trust Assessment

  Secrets: .env in the working directory is loaded automatically (real environment
  variables always win). Override with --env-file <path>, disable with --no-env.

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
    noEnv: false,
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
      case "--force": opts.force = true; break;
      case "--no-probe": opts.withProbe = false; break;
      case "--json": opts.json = true; break;
      case "--env-file": opts.envFile = next(); break;
      case "--no-env": opts.noEnv = true; break;
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

  log(paint(1, `${TOOL.name} ${TOOL.version}`), `— ${config.name} (${config.environment})`);
  log(`  target   ${config.targets.web}`);
  log(`  profile  ${opts.profile} — ${profile.description}`);
  log(
    `  safety   max ${config.safety.maxRequests} requests · ${config.safety.minimumDelayMs}ms floor · ` +
      `writes ${config.safety.allowWrites ? "ON" : "off"} · agent invocations ${config.safety.allowAgentInvocations ? "ON" : "off"}`,
  );
  for (const advisory of advisories) log(paint(33, `  ! ${advisory}`));

  if (opts.dryRun) {
    log(paint(90, "\n  dry run — no requests issued"));
    return 0;
  }

  const result = await runProfile({
    config,
    profile: opts.profile,
    out: opts.out || "reports",
    baseDir: path.dirname(path.resolve(opts.config)),
    validate: false, // already validated, so advisories are not printed twice
    onEvent: (event) => {
      if (event.type === "module") log(paint(90, `\n▸ ${event.label}`));
      else if (event.type === "module-aborted") log(paint(31, `  safety guard stopped ${event.name}: ${event.message}`));
      else if (event.type === "finding" && !opts.quiet) {
        const f = event.finding;
        const style = STATUS_STYLE[f.status] ?? ((t) => t);
        log(`  ${style(f.status.toUpperCase().padEnd(4))} ${paint(90, f.severity.padEnd(8))} ${f.id} — ${f.title}`);
      }
    },
  });

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
  return result.exitCode;
}

async function commandReport(opts) {
  const { outPath, profiles } = await writeCombinedReport({ dir: opts.dir, out: opts.out, title: opts.title });
  log(`Merged ${profiles.length} profile(s): ${profiles.join(", ")}`);
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
  if (!opts.noEnv && (opts.command === "run" || opts.command === "report")) {
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
