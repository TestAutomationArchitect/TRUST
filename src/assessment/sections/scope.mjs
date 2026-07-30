/**
 * Scope and approach — what was tested, under which safety limits, and what stayed out of reach.
 *
 * Everything here is derived from the runs themselves: the surfaces come from the config the
 * runs actually used, and each is cross-referenced with the findings it produced. Nothing in
 * this section is hand-written prose about an architecture, so the report cannot claim to have
 * tested a component that was never configured — a surface that was configured but only ever
 * skipped is reported as "not exercised", never as tested.
 */

import { esc, sectionCard } from "../html.mjs";
import { TOOL } from "../../report.mjs";

export function renderScope(model) {
  const { first, environment, safety, limitations, scopeRows, allowedHosts, profileScopeRows, totalRequests } = model;
  return sectionCard({
    id: "section-scope",
    title: `Scope &amp; Approach`,
    badge: `<span class="sc-chip">${esc(environment)}</span>`,
    open: false,
    body: `<p class="scope-lede">Testing was performed with the <strong>${esc(TOOL.name)}</strong> harness against the <strong>${esc(environment)}</strong> environment, spending ${totalRequests} request${totalRequests === 1 ? "" : "s"}. Requests were restricted to allowlisted HTTPS hosts, capped at ${safety.maxRequests ?? "n/a"}, spaced by a ${safety.minimumDelayMs ?? "n/a"}ms floor and timed out at ${safety.requestTimeoutMs ?? "n/a"}ms; production targets were blocked, redirects were never followed, and writes${safety.allowWrites ? " were <strong>enabled for this run</strong>" : " stayed disabled"} while agent invocations${safety.allowAgentInvocations ? " were <strong>enabled for this run</strong>" : " stayed disabled"}. Every verdict is a deterministic pattern match — no model judged a result.</p>

<div class="cat-header"><h4>Surfaces in Scope</h4><span class="cat-badge">derived from the executed runs</span></div>
<div class="table-card"><div class="table-wrap">
<table>
  <thead><tr><th>Surface</th><th>Target</th><th>Tests</th><th>Outcome</th></tr></thead>
  <tbody>
${scopeRows}
  </tbody>
</table>
</div></div>

<div class="cat-header"><h4>Profiles Executed</h4></div>
<div class="table-card"><div class="table-wrap">
<table>
  <thead><tr><th>Profile</th><th>Categories Covered</th><th>Tests</th><th>Status</th></tr></thead>
  <tbody>
${profileScopeRows}
  </tbody>
</table>
</div></div>

<div class="cat-header"><h4>Authorised Boundary</h4></div>
<p class="scope-note">The harness was permitted to contact these hosts and no others; any request outside this list was refused before it left the process. This allowlist is the technical expression of the engagement scope.</p>
<div class="host-list">${allowedHosts.map((h) => `<code>${esc(h)}</code>`).join("") || '<span style="color:var(--muted)">none recorded</span>'}</div>
${
  first.architecture
    ? `
<div class="cat-header"><h4>Architecture Under Test</h4><span class="cat-badge">supplied by config</span></div>
<div class="arch-box">${esc(first.architecture)}</div>`
    : ""
}

<div class="callout callout-warn" style="margin-top:18px;">
<strong>Limitations:</strong>
<ul style="margin:6px 0 0 18px;font-size:13px;line-height:1.7;">
${limitations.map((l) => `  <li>${esc(l)}</li>`).join("\n")}
</ul>
</div>`,
  });
}
