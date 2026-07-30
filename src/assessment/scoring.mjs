/**
 * TRUST — severity-weighted scoring.
 *
 * Pass earns 100% of a test's severity weight, warn 50%, fail 0%. Skips are excluded from
 * both numerator and denominator, so an unvalidated control can never inflate a score.
 * Domains come back worst-first, because a strong composite hides a weak area.
 */

import { SEV_WEIGHT } from "../finding.mjs";
import { domainForId } from "../catalog.mjs";

export function computeScores(allFindings) {
  const domains = new Map();
  for (const f of allFindings) {
    const domain = domainForId(f.id);
    if (!domains.has(domain)) domains.set(domain, { pass: 0, fail: 0, warn: 0, skip: 0, totalWeight: 0, passWeight: 0, blockingFail: false });
    const d = domains.get(domain);
    d[f.status] += 1;
    if (f.status === "skip") continue;
    const w = SEV_WEIGHT[f.severity] ?? 1;
    d.totalWeight += w;
    if (f.status === "pass") d.passWeight += w;
    else if (f.status === "warn") d.passWeight += w * 0.5;
    else if (f.status === "fail" && (f.severity === "critical" || f.severity === "high")) d.blockingFail = true;
  }
  const scores = new Map();
  let totalW = 0;
  let totalPW = 0;
  for (const [domain, d] of domains) {
    const score = d.totalWeight > 0 ? Math.round((d.passWeight / d.totalWeight) * 100) : null;
    const status = d.blockingFail ? "fail" : d.fail > 0 || d.warn > 0 ? "warn" : d.totalWeight > 0 ? "pass" : "skip";
    scores.set(domain, { score, status, ...d });
    totalW += d.totalWeight;
    totalPW += d.passWeight;
  }
  // Worst domain first — a strong composite must not hide one weak area.
  const sorted = new Map([...scores.entries()].sort((a, b) => (a[1].score ?? 101) - (b[1].score ?? 101)));
  return { domains: sorted, overall: totalW > 0 ? Math.round((totalPW / totalW) * 100) : 0 };
}
