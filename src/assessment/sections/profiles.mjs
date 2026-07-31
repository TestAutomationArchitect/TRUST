/**
 * Per-profile run summary — when each profile ran, how many requests it spent, and its tally.
 */

import { sectionCard } from "../html.mjs";

export function renderProfiles(model) {
  const { profileRows, totalRequests } = model;
  return sectionCard({
    id: "section-profiles",
    title: `Profile Run Summary`,
    badge: `<span class="sc-chip">${profileRows.split("<tr>").length - 1} profiles</span><span class="sc-chip">${totalRequests} requests</span>`,
    open: false,
    body: `<div class="table-card"><div class="table-wrap">
<table>
  <thead><tr><th>Profile</th><th>Generated</th><th>Requests</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Skip</th></tr></thead>
  <tbody>
${profileRows}
  </tbody>
</table>
</div></div>`,
  });
}
