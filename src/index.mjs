/**
 * TRUST — public API.
 *
 * Everything importable from the package root is here. Anything not exported from this
 * file is internal and may change in a minor release.
 *
 *   import { runProfile, loadConfig, defineProbe, finding } from "trust-verify";
 *
 *   const config = await loadConfig("config/dev.json");
 *   const { report, exitCode } = await runProfile({ config, profile: "passive", out: "reports" });
 *   await writeCombinedReport({ dir: "reports" });
 *   process.exit(exitCode);
 */

// ── Running probes ──────────────────────────────────────────────────
export { runProfile, defineProbe, loadCustomProbes, resolveProbes, PROFILES, BUILTIN_PROBES } from "./runner.mjs";

// ── Safety ──────────────────────────────────────────────────────────
export { SafeHttpClient, SafetyError, ConfigError, loadConfig, validateConfig, stripJsonComments, DEFAULT_SAFETY } from "./safety.mjs";

// ── Authoring findings ──────────────────────────────────────────────
export { finding, skipped, inconclusive, canary, redact, summarize, exitCodeFor, STATUSES, SEVERITIES, SEV_WEIGHT } from "./finding.mjs";

// ── Test metadata ───────────────────────────────────────────────────
export {
  CATALOG,
  TRUST_DOMAINS,
  DOMAIN_ORDER,
  ROOT_CAUSE_MAP,
  SUMMARY_RULES,
  DEPRECATED_IDS,
  getTestMeta,
  getDomain,
  domainForId,
  canonicalId,
  listCatalog,
  registerCatalogEntries,
  registerDomains,
  registerRootCauses,
  registerSummaryRules,
} from "./catalog.mjs";

// ── Reporting ───────────────────────────────────────────────────────
export { buildRunReport, buildRunHtml, writeRunReport, TOOL } from "./report.mjs";
export { buildReport as buildCombinedReport, writeCombinedReport, loadReports, buildModel, SECTIONS as ASSESSMENT_SECTIONS } from "./assessment/index.mjs";

// ── Scaffolding ─────────────────────────────────────────────────────
export { scaffold, configTemplate } from "./init.mjs";
export { runPreflight } from "./preflight.mjs";
export { section, resolveExtends, resolveBudget, resolvedSections, SECTION_ALIASES } from "./config.mjs";

// ── Built-in probe modules, for embedding one at a time ─────────────
export { runWebProbes } from "./probes/web.mjs";
export { runApiProbes } from "./probes/api.mjs";
export { runStorageProbes } from "./probes/storage.mjs";
export { runAgentProbes } from "./probes/agent.mjs";
export { runMobileProbes } from "./probes/mobile.mjs";
