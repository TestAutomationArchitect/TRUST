/**
 * Retest requirements — every control left unvalidated, and what has to be true to validate it.
 */

import { sectionCard } from "../html.mjs";

export function renderRetest(model) {
  const { retestRows, skips, fails } = model;
  return sectionCard({
    id: "section-retest",
    title: `Retest Requirements`,
    badge: `<span class="sc-chip">${skips.length + fails.length} item${skips.length + fails.length === 1 ? '' : 's'}</span>`,
    open: false,
    body: `<div class="table-card"><div class="table-wrap">
<table>
  <thead><tr><th>Control</th><th>Closes when this holds</th><th>Re-run with</th></tr></thead>
  <tbody>
${retestRows}
  </tbody>
</table>
</div></div>`,
  });
}
