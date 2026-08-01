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
import { runIsolationProbes } from "./probes/isolation.mjs";
import { runIdpProbes } from "./probes/idp.mjs";
import { runJwtProbes } from "./probes/jwt.mjs";

export const PROFILES = {
  passive: { modules: ["web", "injection", "idp"], auth: "none", description: "Unauthenticated probes against the public surface and the identity provider" },
  authenticated: { modules: ["token", "jwt", "api", "storage", "isolation"], auth: "identity tokens", description: "API, storage and declared isolation boundaries with two identities" },
  agent: { modules: ["token", "agent"], auth: "bearer tokens", description: "AI agent runtime, hierarchy and LLM safety" },
  mobile: { modules: ["mobile"], auth: "optional", description: "Mobile platform surface (server-observable controls)" },
  all: { modules: ["token", "jwt", "web", "injection", "idp", "api", "storage", "isolation", "agent", "mobile"], auth: "all tokens", description: "Every module" },
};

/** Built-in probe modules, in execution order. */
export const BUILTIN_PROBES = [
  { name: "token", label: "token hygiene (no requests)", run: runTokenProbes },
  { name: "jwt", label: "server-side token validation", run: runJwtProbes },
  { name: "web", label: "web / infrastructure", run: runWebProbes },
  { name: "idp", label: "identity provider configuration", run: runIdpProbes },
  { name: "injection", label: "input handling", run: runInjectionProbes },
  { name: "api", label: "API / authorisation", run: runApiProbes },
  { name: "storage", label: "storage isolation", run: runStorageProbes },
  // After api and storage, so a declared boundary may depend on a built-in finding.
  { name: "isolation", label: "declared isolation boundaries", run: runIsolationProbes },
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
/**
 * Which built-in module owns an ID prefix — enough to run one control without running a
 * profile. A probe suite is the smallest executable unit, so `--only` narrows to the module
 * that can produce the ID and filters its output; it cannot run half a probe.
 */
const MODULE_FOR_PREFIX = [
  [/^WEB-/, "web"],
  [/^INJECT-/, "injection"],
  [/^TOKEN-/, "token"],
  [/^(API-|SESSION-|AUTH-)/, "api"],
  [/^JWT-/, "jwt"],
  [/^STORAGE-/, "storage"],
  [/^AGENT-/, "agent"],
  [/^MOBILE-/, "mobile"],
  [/^IDP-/, "idp"],
  [/^ISOLATION-/, "isolation"],
];

/** Modules that could produce an ID matching this pattern. Unknown prefixes run everything. */
export function modulesFor(pattern) {
  const matches = MODULE_FOR_PREFIX.filter(([prefix]) => prefix.test(pattern)).map(([, name]) => name);
  return matches.length ? matches : null;
}

export async function runProfile({ config, profile, out = "", baseDir = process.cwd(), probes = [], onEvent = () => {}, validate = true, only = "" } = {}) {
  if (!PROFILES[profile] && probes.length === 0 && !(config?.probes ?? []).length) {
    throw new Error(`Unknown profile "${profile}". Choose one of: ${Object.keys(PROFILES).join(", ")}`);
  }
  if (validate) {
    for (const advisory of validateConfig(config)) onEvent({ type: "advisory", message: advisory });
  }

  const custom = await loadCustomProbes(config, baseDir);
  for (const extra of probes) applyProbeRegistrations(extra);
  let selected = resolveProbes(profile, [...custom, ...probes.map(defineProbe)]);
  if (only) {
    // Narrow to the modules that could produce the ID. Custom probes always run, because their
    // IDs are their own and no prefix map can know them.
    const wanted = modulesFor(only);
    if (wanted) selected = selected.filter((p) => wanted.includes(p.name) || !BUILTIN_PROBES.some((b) => b.name === p.name));
  }
  if (selected.length === 0) throw new Error(`Profile "${profile}" selected no probe modules`);

  // The budget depends on the profile: a per-profile cap stops a long web sweep exhausting
  // the run before storage and agent probes execute.
  const budget = resolveBudget(config, profile);
  const client = new SafeHttpClient(config, { budget, onRequest: (trace) => onEvent({ type: "request", ...trace }) });
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
      // Probes receive what the run has produced so far, so a chained test can gate on an
      // upstream result from another module. A probe that ignores the third argument is
      // unaffected — every built-in did until conditional execution existed.
      produced = await probe.run(config, client, { findings: [...findings] });
    } catch (error) {
      // Two different failures, both survivable, neither allowed to cost the run.
      //
      // A guard tripping is a result: the harness refused to do something, and that belongs in
      // the report. A probe throwing anything else is a defect in the probe — and since the
      // extension point invites third-party code, one partner's bug must not destroy an
      // assessment that has already produced findings. The module is recorded as failed and
      // the run continues; the error text is the evidence.
      const guard = error instanceof SafetyError;
      onEvent({ type: "module-aborted", name: probe.name, message: error.message, guard });
      produced = [
        {
          id: `${probe.name.toUpperCase()}-ABORTED`,
          title: `${probe.label} probe suite completed`,
          status: "warn",
          severity: "low",
          evidence: guard
            ? `Module aborted by a safety guard: ${error.message}`
            : [`Module crashed: ${error.name}: ${error.message}`, ...String(error.stack ?? "").split("\n").slice(1, 4)].join("\n"),
          remediation: guard
            ? "Raise safety.maxRequests or narrow the probe set, then re-run this module."
            : `The probe module "${probe.name}" threw rather than returning findings. Every control it owns is unverified — treat this as no coverage for that module, not as a pass. Fix the probe and re-run.`,
        },
      ];
    }
    for (const f of produced) onEvent({ type: "finding", finding: f });
    findings.push(...produced);
  }

  // Filtering happens after execution: a probe suite is the executable unit, so the honest
  // description is "these are the findings you asked to see", not "this is all that ran".
  const reported = only ? findings.filter((f) => f.id === only || f.id.startsWith(only)) : findings;

  const report = buildRunReport({
    config,
    profile,
    findings: reported,
    requestCount: client.requestCount,
    blocked: client.blocked,
    budget: { ...budget, spentBySuite: client.suiteSpend },
    sectionAliases: resolvedSections(config),
    credentials: [...client.credentials.values()].map((c) => ({ name: c.name, strategy: c.type, kind: c.kind ?? null, ok: !c.error, expiresAt: c.expiresAt ?? null, error: c.error ?? null })),
    startedAt,
    finishedAt: new Date().toISOString(),
  });

  const paths = out ? await writeRunReport(report, out) : null;
  const result = { report, findings: reported, summary: summarize(reported), exitCode: exitCodeFor(reported), requestCount: client.requestCount, blocked: client.blocked, paths };
  onEvent({ type: "done", ...result });
  return result;
}
