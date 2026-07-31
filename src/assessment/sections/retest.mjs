/**
 * Retest requirements — every control left unvalidated, and what has to be true to validate it.
 */

import { sectionCard, filterBar } from "../html.mjs";

export function renderRetest(model) {
  const { retestRows, skips, fails, warns } = model;
  return sectionCard({
    id: "section-retest",
    title: `Retest Requirements`,
    badge: `${fails.length ? `<span class="sc-chip sc-chip-bad">${fails.length} to fix</span>` : ""}${skips.length ? `<span class="sc-chip">${skips.length} unvalidated</span>` : ""}${!fails.length && !skips.length ? '<span class="sc-chip sc-chip-ready">nothing outstanding</span>' : ""}`,
    open: false,
    body: `${filterBar({ scope: "retest", placeholder: "Filter by control or condition…", count: fails.length + warns.length + skips.length, noun: "controls" })}
<div class="table-card"><div class="table-wrap">
<table>
  <thead><tr><th>Control</th><th>Closes when this holds</th><th>Re-run with</th></tr></thead>
  <tbody>
${retestRows}
  </tbody>
</table>
</div></div>`,
  });
}
