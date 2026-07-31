/**
 * Detailed findings, grouped by category with the worst categories first. Every card is collapsed until asked for.
 */

import { sectionCard, filterBar } from "../html.mjs";

export function renderFindings(model) {
  const { findingCards, fails, warns, allFindings } = model;
  return sectionCard({
    id: "section-findings",
    title: `Detailed Findings`,
    badge: `${fails.length ? `<span class="sc-chip sc-chip-bad">${fails.length} failed</span>` : ''}${warns.length ? `<span class="sc-chip sc-chip-warn">${warns.length} warn</span>` : ''}<span class="sc-chip">${allFindings.length} tests</span>`,
    open: false,
    body: `<div class="panel-toolbar">
  <span class="panel-hint">Cards are collapsed — open one for purpose, evidence and remediation.</span>
  <button class="inv-toggle" onclick="toggleAllFindings(this)">Expand all</button>
</div>
${filterBar({ scope: "findings", placeholder: "Filter by ID, control or category…", count: allFindings.length, noun: "controls" })}
${findingCards}`,
  });
}
