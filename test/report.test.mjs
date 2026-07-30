import test from "node:test";
import assert from "node:assert/strict";
import { finding, skipped } from "../src/finding.mjs";
import { buildRunReport, buildRunHtml } from "../src/report.mjs";
import { buildReport, buildModel } from "../src/assessment/index.mjs";
import { getTestMeta, domainForId, CATALOG } from "../src/catalog.mjs";

const config = {
  name: "unit-app",
  environment: "dev",
  targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com"] },
  safety: { maxRequests: 50, minimumDelayMs: 150, requestTimeoutMs: 30000, allowWrites: false, allowAgentInvocations: false, productionOverride: false },
  architecture: "Browser → API",
};

const findings = [
  finding({ id: "API-USERID-SPOOF", title: "Server derives identity from the token", status: "fail", severity: "critical", evidence: "spoof accepted", remediation: "Use token claims" }),
  finding({ id: "WEB-HEADER-CONTENT-SECURITY-POLICY", title: "Security header CSP is deployed", status: "fail", severity: "medium", evidence: "absent", remediation: "Deploy a CSP" }),
  finding({ id: "WEB-TLS-VERSION", title: "Transport negotiates TLS 1.2 or higher", status: "pass", severity: "high", evidence: "TLSv1.3" }),
  finding({ id: "WEB-EXPOSED-ENV", title: "Sensitive resource is not exposed: /.env", status: "pass", severity: "high", evidence: "404" }),
  finding({ id: "WEB-EXPOSED-GIT-CONFIG", title: "Sensitive resource is not exposed: /.git/config", status: "pass", severity: "high", evidence: "404" }),
  skipped("AGENT-CONFIG", "AI agent probe suite", "allowAgentInvocations is false"),
];

function makeRun(profile, subset) {
  return buildRunReport({
    config,
    profile,
    findings: subset,
    requestCount: 12,
    startedAt: "2026-07-29T10:00:00.000Z",
    finishedAt: "2026-07-29T10:01:00.000Z",
  });
}

test("buildRunReport captures provenance, safety and summary", () => {
  const run = makeRun("passive", findings);
  assert.equal(run.tool, "TRUST");
  assert.equal(run.profile, "passive");
  assert.equal(run.environment, "dev");
  assert.equal(run.requestCount, 12);
  assert.equal(run.durationMs, 60000);
  assert.equal(run.safety.allowWrites, false);
  assert.deepEqual(run.summary, { pass: 3, fail: 2, warn: 0, skip: 1, total: 6 });
});

test("buildRunReport annotates each finding with category and domain", () => {
  const run = makeRun("passive", findings);
  const spoof = run.findings.find((f) => f.id === "API-USERID-SPOOF");
  assert.equal(spoof.category, "Identity Spoofing");
  assert.equal(spoof.domain, "Identity Binding");
});

test("buildRunHtml escapes evidence rather than injecting it", () => {
  const run = makeRun("passive", [finding({ id: "WEB-X", title: "t", status: "fail", severity: "low", evidence: "<img src=x onerror=alert(1)>" })]);
  const html = buildRunHtml(run);
  assert.ok(!html.includes("<img src=x"));
  assert.ok(html.includes("&lt;img src=x"));
});

test("combined report scores, ranks domains worst-first and blocks deployment", () => {
  const reports = new Map([
    ["passive", makeRun("passive", findings.filter((f) => f.id.startsWith("WEB-")))],
    ["authenticated", makeRun("authenticated", findings.filter((f) => !f.id.startsWith("WEB-")))],
  ]);
  const html = buildReport(reports);

  assert.match(html, /Not Ready/, "a critical failure must block deployment");
  assert.match(html, /Identity Binding/);
  assert.match(html, /Client-controlled identity is trusted/, "root cause for the failing domain");
  assert.match(html, /Sensitive deployment artefacts are not publicly exposed/, "passing families are summarised");
  assert.match(html, /Production Blockers/);
  assert.match(html, /Browser → API/, "architecture is carried through from config");

  // Worst domain first: Identity Binding (0) must precede Infrastructure.
  const idIdx = html.indexOf('class="domain-name">Identity Binding');
  const infraIdx = html.indexOf('class="domain-name">Infrastructure');
  assert.ok(idIdx > -1 && infraIdx > -1 && idIdx < infraIdx, "domain cards must be ordered worst-first");
});

test("combined report reports Ready only when nothing is outstanding", () => {
  const clean = [finding({ id: "WEB-TLS-VERSION", title: "TLS ok", status: "pass", severity: "high", evidence: "TLSv1.3" })];
  const html = buildReport(new Map([["passive", makeRun("passive", clean)]]));
  assert.match(html, /readiness-badge ready/);
  // The clean-run wording must not overclaim: it says what did not fail, not that nothing is wrong.
  assert.match(html, /No control failed in this run/);
  assert.doesNotMatch(html, /No vulnerabilities/);
});

test("combined report never emits raw secrets from evidence", () => {
  const leaky = [
    finding({ id: "API-CROSS-USER", title: "leak", status: "fail", severity: "high", evidence: "authorization: Bearer topsecrettoken99", remediation: "fix" }),
  ];
  const html = buildReport(new Map([["authenticated", makeRun("authenticated", leaky)]]));
  assert.ok(!html.includes("topsecrettoken99"));
});

test("every catalog entry has a category and a purpose", () => {
  for (const [id, meta] of Object.entries(CATALOG)) {
    assert.ok(meta.category, `${id} has no category`);
    assert.ok(meta.purpose && meta.purpose.length > 20, `${id} has no usable purpose`);
    assert.notEqual(domainForId(id), undefined);
  }
});

test("dynamic IDs resolve through prefix rules", () => {
  assert.equal(getTestMeta("WEB-EXPOSED-AWS-EXPORTS-JS").category, "Sensitive File Exposure");
  assert.equal(getTestMeta("AGENT-HIERARCHY-L3-SQL").category, "Agent Hierarchy");
  assert.equal(domainForId("AGENT-HIERARCHY-L3-SQL"), "AI Runtime");
  assert.equal(getTestMeta("TOTALLY-UNKNOWN").category, "Other");
  assert.equal(domainForId("TOTALLY-UNKNOWN"), "Platform");
});

test("impact badge is neutral on a pass and alarming only on a fail", () => {
  const run = makeRun("passive", [
    finding({ id: "WEB-TLS-VERSION", title: "TLS ok", status: "pass", severity: "critical", evidence: "TLSv1.3" }),
    finding({ id: "API-CROSS-USER", title: "Isolation holds", status: "fail", severity: "critical", evidence: "leaked", remediation: "fix", observed: "Cross-user read is permitted" }),
  ]);
  const html = buildReport(new Map([["passive", run]]));
  // A critical control that held must not be painted as a critical failure.
  assert.match(html, /sev-latent[^>]*title="Impact if this control had failed: critical"/);
  assert.match(html, /sev-critical[^>]*title="Realised impact: critical"/);
  assert.match(html, /Cross-user read is permitted/, "the failing card headlines what was observed");
  assert.match(html, /Expected control/, "and keeps the assertion visible");
});

// ── Coverage transparency ───────────────────────────────────────────
test("a tiny run cannot present itself as full posture", () => {
  const one = [finding({ id: "WEB-TLS-VERSION", title: "TLS ok", status: "pass", severity: "high", evidence: "TLSv1.3" })];
  const html = buildReport(new Map([["passive", makeRun("passive", one)]]));
  assert.match(html, /Assessed Security Posture/, "the label must qualify itself when coverage is partial");
  assert.match(html, /Coverage —/);
  assert.match(html, /Read the score with its coverage/);
  // Domains never exercised must be shown, not omitted.
  assert.match(html, /domain-name">Input Handling<\/div>\s*<div class="domain-score na">—</);
});

test("full coverage drops the qualifier", () => {
  const model = buildModel(new Map([["passive", makeRun("passive", [])]]));
  assert.equal(model.coverage.assessed, 0);
  assert.ok(model.coverage.applicable > 60, "the denominator is the catalogue, not the run");
  assert.equal(model.postureLabel, "Assessed Security Posture");
});

// ── Attack-path correlation ─────────────────────────────────────────
test("an attack path fires only when every control it depends on is failing", () => {
  const chain = [
    finding({ id: "API-USERID-SPOOF", title: "identity from token", status: "fail", severity: "critical", evidence: "accepted", remediation: "x", observed: "The API accepts a client-supplied identity" }),
    finding({ id: "AGENT-HIERARCHY-L2-DATA", title: "L2 rejects direct invocation", status: "fail", severity: "critical", evidence: "200", remediation: "x", observed: "L2 accepts direct invocation" }),
    finding({ id: "STORAGE-CROSS-TENANT-B", title: "tenant isolation", status: "fail", severity: "critical", evidence: "200", remediation: "x", observed: "Another tenant's prefix is readable" }),
  ];
  const html = buildReport(new Map([["all", makeRun("all", chain)]]));
  assert.match(html, /Corroborated Attack Paths/);
  assert.match(html, /Impersonation → orchestrator bypass → cross-tenant data exposure/);
  assert.match(html, /Corroborated by 3 failing control\(s\)/);

  // Break one link: the same three controls, but the storage one now holds.
  const broken = [...chain.slice(0, 2), finding({ id: "STORAGE-CROSS-TENANT-B", title: "tenant isolation", status: "pass", severity: "critical", evidence: "403" })];
  const html2 = buildReport(new Map([["all", makeRun("all", broken)]]));
  assert.doesNotMatch(html2, /Corroborated Attack Paths/, "a path must not be claimed when a required control holds");
});

test("passing controls never contribute to an attack path", () => {
  const allPass = [
    finding({ id: "API-USERID-SPOOF", title: "identity from token", status: "pass", severity: "critical", evidence: "rejected" }),
    finding({ id: "AGENT-ACL-BYPASS", title: "entitlements enforced", status: "pass", severity: "critical", evidence: "denied" }),
  ];
  const model = buildModel(new Map([["all", makeRun("all", allPass)]]));
  assert.deepEqual(model.attackPaths, []);
});
