/**
 * TRUST — baselines.
 *
 * A team adopting TRUST mid-life inherits findings they did not cause and cannot fix this week.
 * Without a baseline the choice is to fail every build until the backlog clears — which nobody
 * does — or to stop gating on the tool, which is the same as removing it. A baseline makes the
 * gate mean "nothing got worse", which is a promise a team can actually keep.
 *
 * The rules are deliberately narrow:
 *
 *   - A baseline suppresses *known* findings. It never suppresses a new one, and never turns a
 *     fail into a pass. The report still shows everything.
 *   - Fixed findings are reported as loudly as new ones. A baseline that only accumulates is a
 *     ratchet in the wrong direction; a team should see its own progress.
 *   - Identity is test-plus-target and nothing else, so a changed response body does not make a
 *     known finding look new. See export/identity.mjs.
 */

import { readFile, writeFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { findingKey } from "./export/identity.mjs";
import { SEV_WEIGHT } from "./finding.mjs";
import { ConfigError } from "./safety.mjs";

export const BASELINE_VERSION = 1;
const ADVERSE = new Set(["fail", "warn"]);

/** Build a baseline document from one or more run reports. */
export function buildBaseline(reports, { note = "" } = {}) {
  const runs = [reports].flat().filter(Boolean);
  const entries = new Map();
  for (const report of runs) {
    for (const finding of report.findings ?? []) {
      if (!ADVERSE.has(finding.status)) continue;
      // Only adverse findings are recorded: a baseline is a list of accepted problems, not a
      // snapshot of everything, so a control that starts passing never has to be un-baselined.
      const key = findingKey(finding, { target: report.target });
      const existing = entries.get(key);
      // The same test can appear in two profiles. Keep the worse status, or accepting it as a
      // warning in one profile would quietly accept it as a failure in the other.
      if (existing && (existing.status === "fail" || finding.status !== "fail")) continue;
      entries.set(key, {
        key,
        id: finding.id,
        status: finding.status,
        severity: finding.severity,
        title: finding.title,
        profile: report.profile,
      });
    }
  }
  return {
    tool: "TRUST",
    baselineVersion: BASELINE_VERSION,
    createdAt: new Date().toISOString(),
    target: runs[0]?.target ?? "",
    environment: runs[0]?.environment ?? "",
    profiles: [...new Set(runs.map((r) => r.profile).filter(Boolean))],
    note,
    findings: [...entries.values()].sort((a, b) => a.key.localeCompare(b.key)),
  };
}

/**
 * Load a baseline. Accepts a baseline document, a run report, or a directory of run reports —
 * a team's first baseline is whatever they already have on disk, and requiring a conversion
 * step first is how a feature goes unused.
 */
export async function loadBaseline(target) {
  const resolved = path.resolve(target);
  let info;
  try {
    info = await stat(resolved);
  } catch (error) {
    throw new ConfigError(`Cannot read baseline ${resolved}: ${error.message}`);
  }

  if (info.isDirectory()) {
    const files = (await readdir(resolved)).filter((f) => f.endsWith(".json"));
    const reports = [];
    for (const file of files) {
      const parsed = await readJson(path.join(resolved, file));
      if (parsed?.profile && Array.isArray(parsed.findings)) reports.push(parsed);
    }
    if (reports.length === 0) throw new ConfigError(`No TRUST reports found in ${resolved} to use as a baseline`);
    return buildBaseline(reports);
  }

  const parsed = await readJson(resolved);
  if (!parsed) throw new ConfigError(`Baseline ${resolved} is not valid JSON`);
  if (parsed.baselineVersion) {
    if (parsed.baselineVersion > BASELINE_VERSION) {
      throw new ConfigError(`Baseline ${resolved} was written by a newer TRUST (baselineVersion ${parsed.baselineVersion})`);
    }
    return parsed;
  }
  if (Array.isArray(parsed.findings)) return buildBaseline(parsed);
  throw new ConfigError(`Baseline ${resolved} is neither a baseline nor a TRUST run report`);
}

async function readJson(file) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch {
    return null;
  }
}

export async function writeBaseline(baseline, out) {
  await writeFile(path.resolve(out), `${JSON.stringify(baseline, null, 2)}\n`);
  return path.resolve(out);
}

/**
 * Compare a run against a baseline.
 *
 * Returns { fresh, known, fixed, worsened, notRun }:
 *   fresh     adverse now, not adverse in the baseline — what a gate should act on
 *   known     adverse in both, at the same status
 *   fixed     adverse in the baseline, no longer adverse — reported, because progress counts
 *   worsened  known, but a warning has become a failure. Not new, but not accepted either.
 *   notRun    baselined under a profile this run did not execute — absent, not fixed
 *
 * The last one matters more than it looks. A baseline is usually recorded from a full
 * assessment, while CI gates a single profile; without scoping, `trust run --profile passive`
 * would report every authenticated finding as fixed and quietly congratulate a team on work it
 * had not done.
 */
export function diffAgainstBaseline(reports, baseline) {
  const runs = [reports].flat().filter(Boolean);
  const known = new Map((baseline?.findings ?? []).map((entry) => [entry.key, entry]));
  const ranProfiles = new Set(runs.map((r) => r.profile).filter(Boolean));
  const seen = new Set();
  const fresh = [];
  const unchanged = [];
  const worsened = [];

  for (const report of runs) {
    for (const finding of report.findings ?? []) {
      const key = findingKey(finding, { target: report.target });
      if (!ADVERSE.has(finding.status)) continue;
      seen.add(key);
      const previous = known.get(key);
      if (!previous) fresh.push({ ...finding, key });
      else if (previous.status === "warn" && finding.status === "fail") worsened.push({ ...finding, key, was: previous.status });
      else unchanged.push({ ...finding, key, was: previous.status });
    }
  }

  const absent = [...known.values()].filter((entry) => !seen.has(entry.key));
  // A baselined finding whose profile did not run this time was not fixed — it was not looked
  // for. "all" covers everything, and an entry with no recorded profile predates this rule, so
  // both are treated as in scope.
  const inScope = (entry) => !entry.profile || ranProfiles.has(entry.profile) || ranProfiles.has("all");
  return { fresh, known: unchanged, fixed: absent.filter(inScope), notRun: absent.filter((entry) => !inScope(entry)), worsened };
}

/**
 * The exit code for a baselined run: 2 when something *new* blocks, 0 otherwise.
 *
 * The severity threshold matches the unbaselined gate, so adding a baseline changes which
 * findings are considered, never what counts as blocking.
 */
export function exitCodeForDiff(diff, { blockOn = "medium" } = {}) {
  const threshold = SEV_WEIGHT[blockOn] ?? SEV_WEIGHT.medium;
  const blocking = [...diff.fresh, ...diff.worsened].filter((f) => f.status === "fail" && (SEV_WEIGHT[f.severity] ?? 0) >= threshold);
  return blocking.length ? 2 : 0;
}
