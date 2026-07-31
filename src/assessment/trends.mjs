/**
 * TRUST — trends.
 *
 * A single assessment says where you stand; a series says whether you are improving. This
 * maintains `trends.json` next to the reports and derives the run-over-run view from it.
 *
 * Design rules that keep the history honest:
 *
 *   - **Append, never rewrite.** A historical entry is evidence. Re-running against an older
 *     commit adds a point; it does not edit the past.
 *   - **Comparisons are only offered between comparable runs.** A changed config or catalogue
 *     moves controls between domains and changes the denominator, so entries record
 *     `configHash` and `catalogHash`, and a delta computed across a change says so.
 *   - **Store identity and counts, not evidence.** Trend history must stay small and must not
 *     become a second, unredacted copy of every finding. Only IDs are kept, so
 *     "newly introduced" and "fixed" can be named.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";

const MAX_ENTRIES = 100;

/** One point in the series — deliberately small. */
export function trendEntry(model, reports) {
  const first = reports.values().next().value ?? {};
  const failingIds = model.fails.map((f) => f.id).sort();
  return {
    runId: first.runId ?? null,
    at: first.generatedAt ?? new Date().toISOString(),
    timezone: first.timezone ?? null,
    commit: first.commit ?? null,
    branch: first.branch ?? null,
    toolVersion: first.toolVersion ?? null,
    configHash: first.configHash ?? null,
    catalogHash: first.catalogHash ?? null,
    profiles: [...reports.keys()].sort(),
    score: model.overallScore,
    readiness: model.readiness,
    coverage: { percent: model.coverage.percent, assessed: model.coverage.assessed, applicable: model.coverage.applicable },
    counts: {
      pass: model.passes.length,
      fail: model.fails.length,
      warn: model.warns.length,
      skip: model.skips.length,
      blockers: model.fails.filter((f) => f.severity === "critical" || f.severity === "high").length,
    },
    domains: Object.fromEntries([...model.domainScores.entries()].map(([name, d]) => [name, d.score])),
    failingIds,
    chains: model.attackPaths.map((p) => p.id),
  };
}

/** Read the history, tolerating absence and corruption — neither should stop a run. */
export async function loadTrends(dir) {
  try {
    const parsed = JSON.parse(await readFile(path.join(dir, "trends.json"), "utf8"));
    return Array.isArray(parsed?.runs) ? parsed : { version: 1, runs: [] };
  } catch {
    return { version: 1, runs: [] };
  }
}

/** Append this run and persist. Returns the history including the new entry. */
export async function appendTrend(dir, entry) {
  const history = await loadTrends(dir);
  // Re-writing the same run (a regenerated report) must not create a duplicate point.
  const runs = history.runs.filter((r) => r.runId !== entry.runId);
  runs.push(entry);
  runs.sort((a, b) => new Date(a.at) - new Date(b.at));
  const trimmed = runs.slice(-MAX_ENTRIES);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "trends.json"), JSON.stringify({ version: 1, runs: trimmed }, null, 2), { mode: 0o600 });
  return { version: 1, runs: trimmed };
}

/**
 * Compare the current entry with the previous comparable one.
 * Returns null when there is no history yet — a first run has no trend, and inventing one
 * would be worse than showing nothing.
 */
export function deltaAgainstPrevious(history, current) {
  const earlier = history.runs.filter((r) => r.runId !== current.runId);
  if (earlier.length === 0) return null;
  const previous = earlier[earlier.length - 1];

  const nowFailing = new Set(current.failingIds);
  const wasFailing = new Set(previous.failingIds ?? []);
  const introduced = [...nowFailing].filter((id) => !wasFailing.has(id));
  const fixed = [...wasFailing].filter((id) => !nowFailing.has(id));
  const persisting = [...nowFailing].filter((id) => wasFailing.has(id));

  // A changed config or catalogue makes the two runs measure different things.
  const comparable = previous.configHash === current.configHash && previous.catalogHash === current.catalogHash;
  const caveats = [];
  if (previous.configHash !== current.configHash) caveats.push("the configuration changed between runs");
  if (previous.catalogHash !== current.catalogHash) caveats.push("the control catalogue changed between runs");
  if (String(previous.profiles) !== String(current.profiles)) caveats.push(`different profiles ran (${previous.profiles.join(", ")} → ${current.profiles.join(", ")})`);

  const nowChains = new Set(current.chains ?? []);
  const wasChains = new Set(previous.chains ?? []);

  // Per-domain movement, including domains that appeared or stopped being assessed.
  const domainNames = [...new Set([...Object.keys(current.domains ?? {}), ...Object.keys(previous.domains ?? {})])].sort();
  const domains = domainNames.map((name) => {
    const now = current.domains?.[name] ?? null;
    const before = previous.domains?.[name] ?? null;
    return {
      name,
      now,
      before,
      delta: now !== null && before !== null ? now - before : null,
      state: now === null ? "no longer assessed" : before === null ? "newly assessed" : "",
    };
  });

  return {
    previous,
    comparable,
    caveats,
    scoreDelta: current.score - previous.score,
    coverageDelta: current.coverage.percent - previous.coverage.percent,
    blockerDelta: current.counts.blockers - previous.counts.blockers,
    passDelta: current.counts.pass - previous.counts.pass,
    skipDelta: current.counts.skip - previous.counts.skip,
    introduced,
    fixed,
    persisting,
    chainsIntroduced: [...nowChains].filter((c) => !wasChains.has(c)),
    chainsResolved: [...wasChains].filter((c) => !nowChains.has(c)),
    domains,
    readinessChanged: previous.readiness !== current.readiness,
    runsRecorded: history.runs.length,
    firstSeen: history.runs[0]?.at ?? null,
  };
}

/** Per-domain score series, for a sparkline in each domain row. */
export function domainSeries(history, name, limit = 20) {
  return history.runs.slice(-limit).map((r) => r.domains?.[name] ?? null);
}

/** Sparkline points for the score and coverage series, oldest first. */
export function series(history, limit = 20) {
  return history.runs.slice(-limit).map((r) => ({
    at: r.at,
    score: r.score,
    coverage: r.coverage?.percent ?? null,
    blockers: r.counts?.blockers ?? 0,
    readiness: r.readiness,
  }));
}
