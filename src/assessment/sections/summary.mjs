/**
 * Trust summary — posture score, impact tiers, executive reading, root causes, verified controls.
 * This is the section an executive reads; everything below it is evidence for these claims.
 */

import { esc, sectionCard } from "../html.mjs";

export function renderSummary(model) {
  const { fails, warns, passes, overallScore, hasCriticalFail, hasHighFail, hasMediumFail, readiness, readinessLabel, execBullets, rootCauseRows, trustVerifiedItems, domainScores, coverage, postureLabel, attackPathRows } = model;
  return sectionCard({
    id: "section-summary",
    title: `Security Trust Assessment`,
    badge: `<span class="sc-chip sc-chip-score">${overallScore}</span><span class="sc-chip sc-chip-${readiness}">${readinessLabel}</span>`,
    open: true,
    body: `
<div class="posture-hero">
  <div class="posture-score">
    <div class="score-num" data-tip="Weighted score: pass=100%, warn=50%, fail=0%, by severity" style="color:${overallScore >= 90 ? "var(--ok)" : overallScore >= 60 ? "var(--warn)" : "var(--bad)"}">${overallScore}</div>
    <div class="score-label">${esc(postureLabel)}</div>
    <div class="readiness-badge ${readiness}" data-tip="${hasCriticalFail ? "Critical vulnerabilities must be resolved" : hasHighFail ? "High-severity issues block deployment" : hasMediumFail ? "Medium issues — deploy with a remediation plan" : warns.length ? "Advisory items outstanding" : "All critical controls pass"}">${readinessLabel}</div>
  </div>
  <div class="posture-domains">
${[...domainScores.entries()]
  .map(
    ([domain, d]) => `    <div class="domain-card" data-tip="${d.pass} passed, ${d.fail} failed${d.warn ? `, ${d.warn} warn` : ""}${d.skip ? `, ${d.skip} skipped` : ""}">
      <div class="domain-status s-${d.status}"></div>
      <div class="domain-name">${esc(domain)}</div>
      <div class="domain-score ${d.score >= 90 ? "ok" : d.score >= 50 ? "warn" : d.score !== null ? "bad" : "na"}">${d.score !== null ? d.score : "—"}</div>
    </div>`,
  )
  .join("\n")}
  </div>
</div>

<div class="impact-summary">
  <div class="impact-tile" data-tip="Critical or High severity failures — must fix before production"><div class="impact-count" style="color:var(--bad)">${fails.filter((f) => f.severity === "critical" || f.severity === "high").length}</div><div class="impact-label">Production Blockers</div></div>
  <div class="impact-tile" data-tip="Medium severity failures and warnings — next sprint"><div class="impact-count" style="color:var(--warn)">${fails.filter((f) => f.severity === "medium").length + warns.length}</div><div class="impact-label">High Priority</div></div>
  <div class="impact-tile" data-tip="Low/info severity — best-practice hardening"><div class="impact-count" style="color:var(--muted)">${fails.filter((f) => f.severity === "low" || f.severity === "info").length}</div><div class="impact-label">Configuration Improvements</div></div>
  <div class="impact-tile" data-tip="Security controls confirmed working"><div class="impact-count" style="color:var(--ok)">${passes.length}</div><div class="impact-label">Controls Validated</div></div>
  <div class="impact-tile" data-tip="Assessed / applicable controls. Skipped and never-run controls are excluded from the score, so coverage must be read alongside it."><div class="impact-count" style="color:${coverage.percent >= 80 ? "var(--ok)" : coverage.percent >= 50 ? "var(--warn)" : "var(--bad)"}">${coverage.percent}%</div><div class="impact-label">Coverage — ${coverage.assessed} of ${coverage.applicable}</div></div>
</div>

${coverage.partial ? `<div class="callout callout-warn coverage-note"><strong>Read the score with its coverage.</strong> ${coverage.assessed} of ${coverage.applicable} applicable controls reached a verdict (${coverage.percent}%): ${coverage.unvalidated} skipped for missing credentials or unmet preconditions, and ${coverage.notRun} not exercised by the profiles that ran. ${coverage.domainsAssessed} of ${coverage.domainsKnown} trust domains were assessed. The score describes the controls that ran — it is not a statement about the untested remainder.</div>` : ""}

<div class="exec-panel">
  <div class="exec-interp-title">Executive Interpretation</div>
  <ul class="exec-bullets">
${execBullets.join("\n")}
  </ul>
</div>

${attackPathRows ? `<div class="rc-tb-section">
  <div class="rc-tb-title" style="color:var(--bad);">Corroborated Attack Paths</div>
  <p class="scope-note">Each path below fires only when every control it depends on is failing in this run. These are combinations of findings already evidenced in this report, not predictions.</p>
  <table class="rc-tb-table">
${attackPathRows}
  </table>
</div>` : ""}

<div class="rc-tb-section">
  <div class="rc-tb-title" style="color:var(--bad);">Likely Root Causes</div>
  <table class="rc-tb-table">
${rootCauseRows}
  </table>
</div>

<div class="rc-tb-section">
  <div class="rc-tb-title" style="color:var(--ok);">Verified Trust Controls</div>
  <div class="tb-grid">
${trustVerifiedItems}
  </div>
</div>`,
  });
}
