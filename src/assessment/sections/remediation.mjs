/**
 * Remediation plan, ordered by severity, with an owning area derived from the finding ID.
 */

import { sectionCard, filterBar } from "../html.mjs";

export function renderRemediation(model) {
  const { fails, warns, remediationRows, workstreamRows, workstreams } = model;
  return sectionCard({
    id: "section-remediation",
    title: `Remediation Plan`,
    badge: `<span class="sc-chip ${fails.length + warns.length ? 'sc-chip-warn' : ''}">${fails.length + warns.length} action${fails.length + warns.length === 1 ? '' : 's'}</span>`,
    open: false,
    body: `${workstreamRows ? `<div class="cat-header"><h4>Workstreams</h4><span class="cat-badge">${workstreams.length} unit(s) of work covering ${fails.length + warns.length} finding(s)</span></div>
<p class="scope-note">Findings that share a cause share a fix. A workstream closes only when every control in its criteria column holds on a re-run.</p>
<div class="table-card"><div class="table-wrap">
<table class="ws-table">
  <thead><tr><th class="ws-col-priority">Priority</th><th class="ws-col-workstream">Workstream</th><th class="ws-col-findings">Findings</th><th class="ws-col-criteria">Closure criteria</th></tr></thead>
  <tbody>
${workstreamRows}
  </tbody>
</table>
</div></div>

<div class="cat-header"><h4>Individual Findings</h4></div>
${filterBar({ scope: "remediation", placeholder: "Filter by finding, action or owner…", statuses: false, count: fails.length + warns.length, noun: "actions" })}` : ""}${
  fails.length === 0 && warns.length === 0
    ? '<div class="callout">No findings require remediation at this time.</div>'
    : `<div class="table-card"><div class="table-wrap">
<table>
  <thead><tr><th>Priority</th><th>Finding</th><th>Action Required</th><th>Owner</th></tr></thead>
  <tbody>
${remediationRows}
  </tbody>
</table>
</div></div>`
}`,
  });
}
