/**
 * The executive dashboard — posture score, domain scores, readiness, coverage, executive
 * reading, correlated chains, root causes and verified controls.
 *
 * Deliberately NOT a collapsible card. Everything below it is evidence and collapses; this
 * is the part a reader must see on open, without a click. The Posture nav pill still scrolls
 * here, and collapses the evidence sections on the way.
 */

import { esc } from "../html.mjs";

export function renderSummary(model) {
  const { fails, warns, passes, overallScore, hasCriticalFail, hasHighFail, hasMediumFail, readiness, readinessLabel, execSynopsis, rootCauseRows, trustVerifiedItems, domainScores, coverage, postureLabel, attackPathRows } = model;
  return `<section class="section dashboard" id="section-summary">
  <div class="dashboard-head">
    <h2 class="dashboard-title">Security Trust Assessment</h2>
    <div class="dashboard-meta">
      <span class="sc-chip sc-chip-score">${overallScore}</span>
      <span class="sc-chip sc-chip-${readiness}">${readinessLabel}</span>
      <span class="sc-chip">${coverage.percent}% coverage</span>
      ${model.unitCounts ? `<span class="sc-chip" data-tip="A control executed in several profiles is one control. The score is computed per ${model.unitCounts.unit}.">${model.unitCounts.controls} controls · ${model.unitCounts.executions} executions</span>` : ""}
    </div>
  </div>
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

${coverage.partial ? `<div class="callout callout-warn coverage-note"><strong>Read the score with its coverage.</strong> ${coverage.assessed} of ${coverage.applicable} applicable controls reached a verdict (${coverage.percent}%): ${coverage.unvalidated} skipped, and ${coverage.notRun} not exercised by the profiles that ran. ${coverage.domainsAssessed} of ${coverage.domainsKnown} trust domains were assessed. The score describes the controls that ran — it is not a statement about the untested remainder.${
    coverage.skipsByKind?.unconfigured
      ? ` <strong>${coverage.skipsByKind.unconfigured} of the skips were never configured</strong> — nobody looked, so the target may well have those problems. ${coverage.skipsByKind["not-applicable"]} cannot apply here, and ${coverage.skipsByKind.precondition} could not proceed (an upstream control held, or an identity was missing).`
      : ""
  }</div>` : ""}

<div class="exec-panel">
  <div class="exec-interp-title">Executive Summary</div>
  <p class="exec-synopsis">${execSynopsis}</p>
</div>

${attackPathRows ? `<div class="rc-tb-section">
  <div class="rc-tb-title" style="color:var(--bad);">Correlated Control-Failure Chains</div>
  <p class="scope-note">Each chain fires only when every control it depends on failed in this run. Each component weakness was independently confirmed; the complete chain was <strong>not executed end-to-end</strong>. These are combinations of findings already evidenced in this report, not predictions.</p>
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
</div>
</section>`;
}
