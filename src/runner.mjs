/**
 * TRUST — profile runner.
 *
 * The orchestration shared by the CLI and the programmatic API. It never writes to
 * the console and never calls process.exit; progress is reported through the onEvent
 * callback so an embedder can render it however it likes.
 */

import path from "node:path";
import { pathToFileURL } from "node:url";
import { SafeHttpClient, SafetyError, validateConfig } from "./safety.mjs";
import { resolveBudget, resolvedSections } from "./config.mjs";
import { resolveAuth } from "./auth/index.mjs";
import { exitCodeFor, summarize } from "./finding.mjs";
import { buildRunReport, writeRunReport } from "./report.mjs";
import { registerCatalogEntries, registerDomains, registerRootCauses, registerSummaryRules } from "./catalog.mjs";
import { runWebProbes } from "./probes/web.mjs";
import { runInjectionProbes } from "./probes/injection.mjs";
import { runTokenProbes } from "./probes/token.mjs";
import { runApiProbes } from "./probes/api.mjs";
import { runStorageProbes } from "./probes/storage.mjs";
import { runAgentProbes } from "./probes/agent.mjs";
import { runMobileProbes } from "./probes/mobile.mjs";

export const PROFILES = {
  passive: { modules: ["web", "injection"], auth: "none", description: "Unauthenticated probes against the public surface" },
  authenticated: { modules: ["token", "api", "storage"], auth: "identity tokens", description: "API and storage authorisation with two identities" },
  agent: { modules: ["token", "agent"], auth: "bearer tokens", description: "AI agent runtime, hierarchy and LLM safety" },
  mobile: { modules: ["mobile"], auth: "optional", description: "Mobile platform surface (server-observable controls)" },
  all: { modules: ["token", "web", "injection", "api", "storage", "agent", "mobile"], auth: "all tokens", description: "Every module" },
};

/** Built-in probe modules, in execution order. */
export const BUILTIN_PROBES = [
  { name: "token", label: "token hygiene (no requests)", run: runTokenProbes },
  { name: "web", label: "web / infrastructure", run: runWebProbes },
  { name: "injection", label: "input handling", run: runInjectionProbes },
  { name: "api", label: "API / authorisation", run: runApiProbes },
  { name: "storage", label: "storage isolation", run: runStorageProbes },
  { name: "agent", label: "AI agent runtime", run: runAgentProbes },
  { name: "mobile", label: "mobile platform", run: runMobileProbes },
];

/**
 * Declare a probe module that lives outside this package.
 *
 *   export default defineProbe({
 *     name: "acme-sso",
 *     label: "ACME SSO controls",
 *     profiles: ["authenticated"],           // or ["all"], or a custom profile name
 *     catalog: { "ACME-SSO-CLOCK-SKEW": { category: "Authentication", purpose: "…" } },
 *     async run(config, client) { return [ finding({ … }) ]; },
 *   });
 *
 * The catalog / domains / rootCauses / summaryRules fields are registered when the
 * module is loaded, so partner findings score and group like built-in ones.
 */
export function defineProbe(probe) {
  if (!probe?.name) throw new TypeError("defineProbe requires a name");
  if (typeof probe.run !== "function") throw new TypeError(`Probe ${probe.name} requires an async run(config, client)`);
  return {
    label: probe.name,
    profiles: ["all"],
    ...probe,
  };
}

function applyProbeRegistrations(probe) {
  if (probe.catalog) registerCatalogEntries(probe.catalog);
  if (probe.domains) registerDomains(probe.domains);
  if (probe.rootCauses) registerRootCauses(probe.rootCauses);
  if (probe.summaryRules) registerSummaryRules(probe.summaryRules);
}

/**
 * Load probe modules named in config.probes. Paths resolve relative to baseDir
 * (the directory holding the config file), so a config is portable within a repo.
 * A module may default-export one probe, an array of probes, or export `probes`.
 */
export async function loadCustomProbes(config, baseDir = process.cwd()) {
  const specs = config.probes ?? [];
  const loaded = [];
  for (const spec of specs) {
    let mod;
    // A bare specifier ("@acme/trust-probes") is left to Node's resolver. A path is
    // resolved against the config's directory first, then the working directory —
    // both are natural mental models, so accept either and name both when neither hits.
    const isBareSpecifier = /^[a-z@][\w@/.-]*$/i.test(spec) && !spec.startsWith(".");
    const candidates = isBareSpecifier
      ? [spec]
      : [...new Set([path.resolve(baseDir, spec), path.resolve(process.cwd(), spec)])].map((p) => pathToFileURL(p).href);
    const errors = [];
    for (const candidate of candidates) {
      try {
        mod = await import(candidate);
        break;
      } catch (error) {
        errors.push(`${candidate.replace("file:///", "")}: ${error.message.split("\n")[0]}`);
      }
    }
    if (!mod) throw new Error(`Cannot load probe module "${spec}". Tried:\n  - ${errors.join("\n  - ")}`);
    const exported = [mod.default, ...(Array.isArray(mod.probes) ? mod.probes : [])].flat().filter(Boolean);
    if (exported.length === 0) throw new Error(`Probe module "${spec}" exports neither a default probe nor a probes array`);
    for (const candidate of exported) {
      const probe = defineProbe(candidate);
      applyProbeRegistrations(probe);
      loaded.push(probe);
    }
  }
  return loaded;
}

/** Which probes run for a profile: built-ins by profile definition, custom by declaration. */
export function resolveProbes(profileName, customProbes = []) {
  const profile = PROFILES[profileName];
  const builtins = profile ? BUILTIN_PROBES.filter((p) => profile.modules.includes(p.name)) : [];
  const custom = customProbes.filter((p) => p.profiles.includes(profileName) || p.profiles.includes("all") || profileName === "all");
  return [...builtins, ...custom];
}

/**
 * Run one profile. Returns { report, findings, exitCode, paths, blocked }.
 *
 *   const { report, exitCode } = await runProfile({ config, profile: "passive", out: "reports" });
 *
 * Options:
 *   config      a validated-or-not config object (validate() runs unless validate:false)
 *   profile     profile name
 *   out         directory to write JSON + HTML into; omit to skip writing
 *   baseDir     base for resolving config.probes paths (default: cwd)
 *   probes      extra probes to run, in addition to config.probes
 *   onEvent     ({type, ...}) => void — "advisory" | "module" | "finding" | "module-aborted"
 */
export async function runProfile({ config, profile, out = "", baseDir = process.cwd(), probes = [], onEvent = () => {}, validate = true } = {}) {
  if (!PROFILES[profile] && probes.length === 0 && !(config?.probes ?? []).length) {
    throw new Error(`Unknown profile "${profile}". Choose one of: ${Object.keys(PROFILES).join(", ")}`);
  }
  if (validate) {
    for (const advisory of validateConfig(config)) onEvent({ type: "advisory", message: advisory });
  }

  const custom = await loadCustomProbes(config, baseDir);
  for (const extra of probes) applyProbeRegistrations(extra);
  const selected = resolveProbes(profile, [...custom, ...probes.map(defineProbe)]);
  if (selected.length === 0) throw new Error(`Profile "${profile}" selected no probe modules`);

  // The budget depends on the profile: a per-profile cap stops a long web sweep exhausting
  // the run before storage and agent probes execute.
  const budget = resolveBudget(config, profile);
  const client = new SafeHttpClient(config, { budget });
  const startedAt = new Date().toISOString();
  const findings = [];

  // Credentials are acquired before any probe runs, through the same guarded client — an IdP
  // is a host like any other and must be allowlisted. A strategy that cannot resolve is not
  // fatal: probes referencing it skip with the reason, and the rest of the run proceeds.
  client.beginSuite("auth");
  client.credentials = await resolveAuth(config, client, { onEvent });

  for (const probe of selected) {
    client.beginSuite(probe.name);
    onEvent({ type: "module", name: probe.name, label: probe.label });
    let produced;
    try {
      produced = await probe.run(config, client);
    } catch (error) {
      if (!(error instanceof SafetyError)) throw error;
      // A guard tripping is a result, not a crash: record it and keep going.
      onEvent({ type: "module-aborted", name: probe.name, message: error.message });
      produced = [
        {
          id: `${probe.name.toUpperCase()}-ABORTED`,
          title: `${probe.label} probe suite completed`,
          status: "warn",
          severity: "low",
          evidence: `Module aborted by a safety guard: ${error.message}`,
          remediation: "Raise safety.maxRequests or narrow the probe set, then re-run this module.",
        },
      ];
    }
    for (const f of produced) onEvent({ type: "finding", finding: f });
    findings.push(...produced);
  }

  const report = buildRunReport({
    config,
    profile,
    findings,
    requestCount: client.requestCount,
    blocked: client.blocked,
    budget: { ...budget, spentBySuite: client.suiteSpend },
    sectionAliases: resolvedSections(config),
    credentials: [...client.credentials.values()].map((c) => ({ name: c.name, strategy: c.type, kind: c.kind ?? null, ok: !c.error, expiresAt: c.expiresAt ?? null, error: c.error ?? null })),
    startedAt,
    finishedAt: new Date().toISOString(),
  });

  const paths = out ? await writeRunReport(report, out) : null;
  const result = { report, findings, summary: summarize(findings), exitCode: exitCodeFor(findings), requestCount: client.requestCount, blocked: client.blocked, paths };
  onEvent({ type: "done", ...result });
  return result;
}
