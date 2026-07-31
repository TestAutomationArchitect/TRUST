/**
 * TRUST — config resolution.
 *
 * Two problems this solves, both reported from field use:
 *
 * 1. **Built-in probes hardcoded `config.api` and `config.agent`.** Real applications name
 *    their sections after their own architecture — `graphql`, `appSync`, `agentCore`,
 *    `bedrock` — so teams had to duplicate the same endpoint under a second key just to
 *    satisfy the built-ins, then keep both in step. Probes now ask for a *canonical* section
 *    and any conventional spelling resolves to it. The report records which key was used, so
 *    resolution is never a silent guess.
 *
 * 2. **Every environment needed its own complete config.** dev, staging and uat differ by a
 *    handful of values but had to repeat everything, and drifted. A config may now `extend`
 *    another and override only what differs.
 *
 * Deliberately not implemented: `$ref` indirection or a per-probe config-key map. Both add a
 * schema concept a reader has to learn. A fallback list is obvious on sight.
 */

import { readFile } from "node:fs/promises";
import path from "node:path";
import { ConfigError, stripJsonComments } from "./safety.mjs";

/**
 * Conventional spellings for each canonical section, in priority order.
 * First match wins, so an explicit `api` always beats an inferred `graphql`.
 */
export const SECTION_ALIASES = {
  api: ["api", "graphql", "appSync", "appsync", "rest", "backend"],
  agent: ["agent", "agentCore", "agentcore", "bedrock", "llm", "aiAgent"],
  storage: ["storage", "s3", "objectStore", "blob", "bucket"],
  mobile: ["mobile", "app", "device"],
  web: ["web", "frontend", "spa"],
  injection: ["injection", "inputHandling"],
  tokens: ["tokens", "token"],
};

/**
 * Resolve a canonical section. Returns the section and the key it came from, so a probe can
 * report `config.graphql` in its evidence rather than claiming the user configured `api`.
 */
export function section(config, canonical) {
  for (const key of SECTION_ALIASES[canonical] ?? [canonical]) {
    const value = config?.[key];
    if (value && typeof value === "object") return { value, key };
  }
  return { value: undefined, key: null };
}

/** Which alias each canonical section resolved to — recorded in the run for traceability. */
export function resolvedSections(config) {
  const out = {};
  for (const canonical of Object.keys(SECTION_ALIASES)) {
    const { key } = section(config, canonical);
    if (key && key !== canonical) out[canonical] = key;
  }
  return out;
}

/** Objects merge, everything else replaces — an array in a child is a deliberate override. */
function deepMerge(base, override) {
  if (Array.isArray(override) || override === null || typeof override !== "object") return override;
  const out = { ...base };
  for (const [key, value] of Object.entries(override)) {
    const current = out[key];
    out[key] = current && typeof current === "object" && !Array.isArray(current) ? deepMerge(current, value) : value;
  }
  return out;
}

/**
 * Resolve `extends` chains. Paths are relative to the file that declares them, so a config
 * can be moved with its base. A cycle is a configuration error, not a hang.
 */
export async function resolveExtends(configPath, seen = new Set()) {
  const absolute = path.resolve(configPath);
  if (seen.has(absolute)) {
    throw new ConfigError(`Config extends itself in a cycle: ${[...seen, absolute].join(" → ")}`);
  }
  seen.add(absolute);

  let raw;
  try {
    raw = await readFile(absolute, "utf8");
  } catch (error) {
    throw new ConfigError(`Cannot read config ${absolute}: ${error.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(stripJsonComments(raw));
  } catch (error) {
    throw new ConfigError(`Config ${absolute} is not valid JSON: ${error.message}`);
  }

  if (!parsed.extends) return parsed;

  const parentPath = path.resolve(path.dirname(absolute), parsed.extends);
  const parent = await resolveExtends(parentPath, seen);
  const { extends: _dropped, ...child } = parsed;
  const merged = deepMerge(parent, child);
  merged.extendsChain = [...(parent.extendsChain ?? [parentPath]), absolute];
  return merged;
}

/**
 * The request budget for a run.
 *
 * `safety.maxRequests` accepts a number (one cap for everything) or a map keyed by profile.
 * `safety.budgets` optionally caps individual probe suites, which is what stops a long web
 * sweep exhausting the run before the storage and agent probes get to execute — the failure
 * mode reported from the field, where those suites silently skipped with "cap reached".
 */
export function resolveBudget(config, profile) {
  const configured = config?.safety?.maxRequests;
  const total = typeof configured === "object" && configured !== null ? (configured[profile] ?? configured.default ?? 100) : (configured ?? 100);
  return { total, suites: config?.safety?.budgets ?? null };
}
