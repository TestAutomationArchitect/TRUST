/**
 * TRUST — HTML primitives shared by every section.
 *
 * esc() is the only thing standing between probe evidence and script injection in a
 * report that a security team opens in a browser. Every interpolation of
 * target-controlled text goes through it.
 */

export const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

export const SEV_CLASS = { critical: "sev-critical", high: "sev-high", medium: "sev-med", low: "sev-low", info: "sev-info" };

/**
 * The impact badge.
 *
 * Severity describes the impact **if the control fails** — it belongs to the control, not to
 * the observed result. So a red CRITICAL beside a green PASS was actively misleading: it read
 * as "something critical is wrong" when it meant "a critical control held". Realised impact
 * (fail) keeps the alarm colour; hypothetical impact (pass/skip) is rendered neutrally and
 * says so on hover.
 */
export const severityBadge = (sev, status = "fail") => {
  const level = esc(String(sev).toUpperCase());
  if (status === "pass" || status === "skip") {
    const tip = status === "pass" ? `Impact if this control had failed: ${sev}` : `Impact if this control fails: ${sev} — not assessed in this run`;
    return `<span class="badge sev-latent" title="${esc(tip)}">${level}<span class="badge-qualifier"> control</span></span>`;
  }
  return `<span class="badge ${SEV_CLASS[sev] ?? "sev-info"}" title="Realised impact: ${esc(sev)}">${level}</span>`;
};
export const statusCls = (s) => (s === "pass" ? "ok" : s === "fail" ? "bad" : s === "warn" ? "warn" : "skip");

export const OWNER_MAP = [
  [/^WEB-/, "Web / CDN"],
  [/^API-/, "API layer"],
  [/^AUTH-/, "Identity provider"],
  [/^STORAGE-/, "Storage"],
  [/^AGENT-/, "AI runtime"],
  [/^MOBILE-/, "Mobile platform"],
];
/**
 * The team that owns a finding. Built-in IDs map by prefix; a partner ID will not match any
 * of them, so fall back to the finding's own trust domain rather than dumping every custom
 * finding into "Platform".
 */
export const ownerFor = (idOrFinding, domain = "") => {
  const id = typeof idOrFinding === "string" ? idOrFinding : idOrFinding?.id ?? "";
  const resolved = typeof idOrFinding === "string" ? domain : (idOrFinding?.domain ?? domain);
  return OWNER_MAP.find(([pattern]) => pattern.test(id))?.[1] ?? resolved ?? "Platform";
};

const CHEVRON =
  '<svg class="panel-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>';

/**
 * A collapsible section card.
 *
 * Every section is collapsed by default so the report opens as a readable index rather
 * than a wall of tables; the nav pills expand one section at a time. The header stays
 * informative when closed, which is what `badge` is for — a reader should be able to see
 * "10 failed" without opening anything.
 *
 * Uses a real button-like header with aria-expanded rather than <details>, so the nav
 * pills, the print handler and the deep-link handler all drive one mechanism.
 */
export function sectionCard({ id, title, badge = "", body, open = false }) {
  return `<section class="section panel-card" id="${id}" data-collapsible>
  <div class="panel-toggle${open ? " open" : ""}" role="button" tabindex="0" aria-expanded="${open}" aria-controls="${id}-body"
       onclick="togglePanel(this)" onkeydown="panelKey(event, this)">
    <h3 class="panel-title">${title}</h3>
    <div class="panel-meta">${badge}${CHEVRON}</div>
  </div>
  <div class="panel-body${open ? " show" : ""}" id="${id}-body" role="region" aria-labelledby="${id}">
${body}
  </div>
</section>`;
}
