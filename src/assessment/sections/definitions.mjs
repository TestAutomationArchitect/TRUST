/**
 * Definitions and methodology — how to read the score, the domains, the status scale.
 *
 * Presented as a COMPASS/AVANI glossary: a three-column grid of definition lists rather
 * than nested collapsible tables, so a reader scans it instead of unfolding it. The
 * content is unchanged from the tabular version; only the presentation differs.
 */

import { esc, sectionCard } from "../html.mjs";

/** One glossary column: a heading over a definition list. */
function group(heading, entries) {
  return `  <div class="glossary-section">
    <h4>${heading}</h4>
    <dl>
${entries.map(([term, body]) => `      <dt>${term}</dt>\n      <dd>${body}</dd>`).join("\n")}
    </dl>
  </div>`;
}

export function renderDefinitions(model) {
  const { safety } = model;

  const trustDomains = group("Trust Domains", [
    ["Identity Binding", "The acting identity is derived from verified token claims, never from a client-supplied field."],
    ["Authentication", "The authentication flow itself: SSO enforcement, and the absence of a weaker parallel path such as a password grant."],
    ["Authorization", "Record- and object-level access control: owner scoping, RBAC on writes, cross-user and cross-tenant isolation in APIs and storage."],
    ["AI Runtime", "The agent orchestration boundary — sub-agents reject direct invocation, sessions are owner-bound, memory is user-scoped, and guardrails apply at every level."],
    ["LLM Safety", "Prompt-injection resistance (direct and indirect), information-disclosure boundaries, and output sanitisation."],
    ["Infrastructure", "Transport security, browser hardening headers, CORS, rate limiting, clickjacking protection, token storage, error handling and artefact exposure."],
    ["Input Handling", "Validation, encoding and interpreter boundaries for untrusted input: injection, traversal, template evaluation, and header or host handling."],
    ["Assessment Integrity", "Whether the test setup itself supports the conclusions — distinct identities, distinct tenants, live credentials, least-privilege scope. A failure here weakens every other result in the report."],
  ]);

  const scoring = group("Posture Score", [
    [
      "Composite (0–100)",
      "Weighted pass rate across all domains: <code>score = Σ(weight × outcome) ÷ Σ(weight) × 100</code>, where outcome is 1 for pass, 0.5 for warn and 0 for fail. Skipped tests are excluded from both numerator and denominator, so an unvalidated control can never inflate the score." +
        '<div class="score-scale"><span class="sev-critical">Critical 10</span><span class="sev-high">High 5</span><span class="sev-med">Medium 3</span><span class="sev-low">Low 1</span><span class="sev-info">Info 0.5</span></div>',
    ],
    ["Domain Score", "The same formula applied per domain. Domains are ordered worst-first, because a strong composite hides a weak area."],
    [
      "Reading the bands",
      "Bands describe assessed-control performance only." +
        '<div class="score-scale"><span class="sev-low">90–100 strong</span><span class="sev-med">60–89 moderate</span><span class="sev-high">below 60 weak</span></div>',
    ],
    [
      "Bands do not decide readiness",
      "Deployment readiness is calculated independently: any critical or high-severity failure yields <strong>Not Ready</strong> regardless of the score. A report can score in the moderate band and still be blocked.",
    ],
    [
      "Scoring unit",
      (model.unitCounts?.unit === "control"
        ? "This report scores <strong>by control</strong>: a control executed in several profiles counts once, at its worst outcome."
        : "This report scores <strong>by execution</strong>: a control executed in several profiles counts once per execution, so a control that runs in more profiles carries more weight. " +
          "Run <code>trust report --score-by control</code> for the control-weighted figure, which is the unit this assessment is moving to.") +
        (model.unitCounts ? ` This run covered <strong>${model.unitCounts.controls}</strong> control(s) across <strong>${model.unitCounts.executions}</strong> execution(s).` : ""),
    ],
  ]);

  const readinessGroup = group("Deployment Readiness", [
    ["Ready", "No critical or high-severity failures and no outstanding advisories. Trust boundaries validated."],
    ["Caution", "Medium-severity failures or advisory warnings present. Deployment acceptable with a documented remediation plan and timeline."],
    ["Not Ready", "Critical or high-severity vulnerabilities confirmed. Remediate before production."],
  ]);

  const impact = group("Impact Tiers", [
    ["Production Blockers", "Critical or High failures: exploitable weaknesses with direct business impact — data exposure, impersonation, privilege escalation."],
    ["High Priority", "Medium failures and warnings: increased attack surface, or weakened defence in depth."],
    ["Configuration Improvements", "Low and Info items: best-practice hardening, not directly exploitable today."],
    ["Controls Validated", "Tests that confirmed a control works. These are engineering wins, and they are evidence in an audit."],
  ]);

  const reading = group("Reading a Finding", [
    [
      "Impact",
      "The consequence <em>if that control fails</em> — a property of the control, not of the result. A passing control can legitimately be critical: it means a critical boundary held. Realised impact carries the alarm colour; a held control shows the level in a neutral outline.",
    ],
    [
      "Headline vs Expected control",
      "A failing finding is headlined by what was <em>observed</em>; its positive assertion is shown beneath as the Expected control, which is also the condition under which it closes. A passing finding is headlined by the assertion itself.",
    ],
    [
      "Coverage",
      "Assessed controls as a share of applicable controls in the catalogue: <code>coverage = assessed ÷ (assessed + unvalidated + not&nbsp;run)</code>, where <em>unvalidated</em> is a control that ran but could not reach a verdict — missing credentials, unmet precondition — and <em>not run</em> is one no executed profile covers. The score is computed only over controls that reached a verdict, so coverage tells you how much of the target that score speaks for. Below 100% the score is labelled <em>Assessed</em> Security Posture.",
    ],
    [
      "Corroborated attack path",
      "A named combination that fires only when every control it depends on failed in this run. It is set intersection over findings already evidenced here — not a prediction, and not a model's opinion.",
    ],
    [
      "Confirmed vs probable",
      "Where a single signal could be misread, the verdict is a warning and the evidence says why. A failure is claimed only when independent sources agree — for example a password grant is reported as enabled only when both the token response and the provider's discovery document say so.",
    ],
  ]);

  const statusScale = group("Status Scale", [
    ['<span class="tag ok">PASS</span>', "Control validated — the boundary held under the test."],
    ['<span class="tag bad">FAIL</span>', "Control violated — a weakness was confirmed, with evidence attached to the finding."],
    ['<span class="tag warn">WARN</span>', "Inconclusive or partial — the control could not be fully validated. Manual review recommended."],
    [
      '<span class="tag skip">SKIP</span>',
      "Not executed: missing credentials, an unmet precondition, or a safety guard. The control remains <em>unvalidated</em> — a skip is never a pass.",
    ],
  ]);

  const methodology = group("Methodology", [
    ["Approach", "Authorised, non-destructive verification. Deterministic, repeatable and machine-parseable; no model judges a verdict."],
    [
      "Safety Controls",
      `HTTPS-only, host allowlist, ${esc(safety.maxRequests ?? "n/a")}-request cap, ${esc(safety.minimumDelayMs ?? "n/a")}ms delay floor, ${esc(safety.requestTimeoutMs ?? "n/a")}ms timeout, manual redirect handling, production block, and writes and agent invocations off by default.`,
    ],
    ["Evidence Standard", "Every finding carries Purpose (why it matters), Evidence (what was observed) and Remediation (how to fix it). No finding without proof."],
    ["Canary Technique", "Injection and leak tests plant a unique marker and assert on its absence in the response, so no interpretation is required."],
    ["Redaction", "JWTs, bearer tokens, cloud keys, connection strings, signed-URL signatures and key/value secrets are stripped from evidence before it reaches disk."],
    ["Scope Boundary", "Client-perspective trust-boundary testing. Server-side code review, infrastructure scanning and dependency auditing are out of scope."],
  ]);

  return sectionCard({
    id: "section-definitions",
    title: `Definitions &amp; Methodology`,
    badge: `<span class="sc-chip">how to read this report</span>`,
    open: false,
    body: `<div class="glossary-grid">
${[trustDomains, scoring, readinessGroup, impact, reading, statusScale, methodology].join("\n")}
</div>`,
  });
}
