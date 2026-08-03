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

test("coverage counts only controls that could apply to the configured surfaces", () => {
  // This config declares a web target and nothing else, so mobile, agent and storage
  // controls are out of scope and must not depress the coverage figure.
  const model = buildModel(new Map([["passive", makeRun("passive", [])]]));
  assert.equal(model.coverage.assessed, 0);
  assert.ok(model.coverage.applicable > 0, "web controls are in scope");
  assert.ok(
    model.coverage.applicable < 60,
    `an API-only target must not be marked down for unconfigured surfaces (applicable=${model.coverage.applicable})`,
  );
  assert.ok(!model.coverage.notRunIds.some((id) => id.startsWith("MOBILE-")), "mobile controls are not applicable here");
  assert.ok(model.coverage.notRunIds.some((id) => id.startsWith("WEB-")), "web controls are");
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
  assert.match(html, /Correlated Control-Failure Chains/);
  assert.match(html, /not executed end-to-end/, "the report must not claim more than it executed");
  assert.match(html, /Impersonation → orchestrator bypass → cross-tenant data exposure/);
  assert.match(html, /Corroborated by 3 failing control\(s\)/);

  // Break one link: the same three controls, but the storage one now holds.
  const broken = [...chain.slice(0, 2), finding({ id: "STORAGE-CROSS-TENANT-B", title: "tenant isolation", status: "pass", severity: "critical", evidence: "403" })];
  const html2 = buildReport(new Map([["all", makeRun("all", broken)]]));
  assert.doesNotMatch(html2, /Correlated Control-Failure Chains/, "a chain must not be claimed when a required control holds");
});

test("passing controls never contribute to an attack path", () => {
  const allPass = [
    finding({ id: "API-USERID-SPOOF", title: "identity from token", status: "pass", severity: "critical", evidence: "rejected" }),
    finding({ id: "AGENT-ACL-BYPASS", title: "entitlements enforced", status: "pass", severity: "critical", evidence: "denied" }),
  ];
  const model = buildModel(new Map([["all", makeRun("all", allPass)]]));
  assert.deepEqual(model.attackPaths, []);
});

// ── Custom-probe classification must survive the merge ──────────────
test("a partner finding keeps its domain when the combined report is built", () => {
  // A custom probe's catalogue entries are registered at run time and are gone by merge
  // time. The run JSON carries the classification; the merge must trust it rather than
  // re-deriving it and bucketing every partner finding under Other/Platform.
  const partner = finding({
    id: "ACME-GQL-CROSS-TENANT",
    title: "Tenant B cannot read Tenant A's records",
    status: "fail",
    severity: "critical",
    evidence: "HTTP 200 with foreign tenant data",
    remediation: "Scope the resolver by tenant claim",
    observed: "Cross-tenant read is permitted",
    domain: "Authorization",
    category: "Authorization — API",
  });
  assert.equal(partner.domain, "Authorization", "finding() must carry a probe-supplied domain");

  const run = makeRun("authenticated", [partner]);
  assert.equal(run.findings[0].domain, "Authorization", "the run JSON must preserve it");

  const model = buildModel(new Map([["authenticated", run]]));
  assert.ok(model.domainScores.has("Authorization"), "the merge must score it under Authorization");
  assert.ok(!model.domainScores.get("Platform"), "and must not invent a Platform bucket");

  const html = buildReport(new Map([["authenticated", run]]));
  assert.match(html, /Authorization/);
  assert.doesNotMatch(html, /ACME-GQL-CROSS-TENANT[\s\S]{0,400}?>Other</, "the finding must not be filed under Other");
});

test("an unclassified finding still falls back to the catalogue", () => {
  const builtin = finding({ id: "API-CROSS-USER", title: "t", status: "fail", severity: "high", evidence: "e", remediation: "r" });
  assert.equal(builtin.domain, undefined, "no domain is invented when the probe does not supply one");
  const run = makeRun("authenticated", [builtin]);
  assert.equal(run.findings[0].domain, "Authorization", "the catalogue fills it in at run time");
});

// ── The control, not the execution, is the unit ─────────────────────
const control = (id, status, severity, category = "Token Hygiene", domain = "Authentication") =>
  finding({ id, title: `${id} holds`, status, severity, evidence: "evidence", remediation: "fix", category, domain });

const profileRun = (profile, findings) => ({
  profile,
  name: "unit",
  target: "https://dev.example.com",
  environment: "dev",
  surfaces: [{ kind: "api", label: "API", target: "https://dev.example.com/graphql" }],
  startedAt: "2026-07-31T10:00:00.000Z",
  generatedAt: "2026-07-31T10:05:00.000Z",
  summary: {},
  findings,
});

test("collapseToControls keeps the worst outcome and records every profile that ran it", async () => {
  const { collapseToControls } = await import("../src/assessment/model.mjs");
  const collapsed = collapseToControls([
    { ...control("API-CROSS-USER", "pass", "critical"), profile: "passive" },
    { ...control("API-CROSS-USER", "fail", "critical"), profile: "authenticated" },
    { ...control("TOKEN-ALG", "pass", "high"), profile: "passive" },
  ]);

  assert.equal(collapsed.length, 2);
  const cross = collapsed.find((c) => c.id === "API-CROSS-USER");
  // A control that failed in one profile and passed in another has not held.
  assert.equal(cross.status, "fail");
  assert.deepEqual(cross.profiles, ["passive", "authenticated"]);
  // The collapse must not hide the disagreement that motivated it.
  assert.match(cross.evidence, /Across profiles: passive pass, authenticated fail/);
  assert.equal(collapsed.find((c) => c.id === "TOKEN-ALG").evidence.includes("Across profiles"), false, "a control with one outcome needs no note");
});

test("scoring by execution lets an extra profile raise the score; by control it cannot", () => {
  const reports = (extraProfiles) => {
    const map = new Map([["authenticated", profileRun("authenticated", [control("TOKEN-ALG", "pass", "high"), control("API-CROSS-USER", "fail", "critical", "Authorization — API", "Authorization")])]]);
    for (const p of extraProfiles) map.set(p, profileRun(p, [control("TOKEN-ALG", "pass", "high")]));
    return map;
  };

  const byExecution = (extra) => buildModel(reports(extra), { scoreBy: "execution" });
  const byControl = (extra) => buildModel(reports(extra), { scoreBy: "control" });

  // Nothing is fixed between these two runs — a passing control is simply executed in more
  // profiles. Under execution scoring that moves the headline number, which means a team can
  // raise its posture without touching its system.
  assert.ok(byExecution(["agent", "all"]).overallScore > byExecution([]).overallScore, "execution scoring rewards re-execution");
  assert.equal(byControl(["agent", "all"]).overallScore, byControl([]).overallScore, "control scoring does not");
  assert.equal(byControl([]).coverage.percent, byControl(["agent", "all"]).coverage.percent, "and neither does coverage");
});

test("the model reports both units so coverage cannot be overstated", () => {
  const model = buildModel(
    new Map([
      ["authenticated", profileRun("authenticated", [control("TOKEN-ALG", "pass", "high"), control("API-CROSS-USER", "fail", "critical")])],
      ["agent", profileRun("agent", [control("TOKEN-ALG", "pass", "high")])],
    ]),
    {},
  );
  assert.deepEqual(model.unitCounts, { controls: 2, executions: 3, unit: "execution" });
});

test("the report reads one card per control whatever the score is computed over", () => {
  const reports = new Map([
    ["authenticated", profileRun("authenticated", [control("TOKEN-ALG", "pass", "high")])],
    ["agent", profileRun("agent", [control("TOKEN-ALG", "pass", "high")])],
  ]);
  const cardsIn = (html) => [...html.matchAll(/<summary class="finding-sum">([\s\S]*?)<\/summary>/g)].map((m) => m[1]);

  // Deduplicating what a reader reads changes no verdict, so it is not gated behind the scoring
  // flag — otherwise the readability fix would only reach teams willing to accept a score change.
  for (const scoreBy of ["execution", "control"]) {
    const cards = cardsIn(buildReport(reports, { scoreBy }));
    assert.equal(cards.length, 1, `one card per control (scoreBy=${scoreBy})`);
    // And deduplication must not cost the attribution it replaces.
    assert.equal((cards[0].match(/env-badge/g) ?? []).length, 2);
    assert.match(cards[0], /authenticated/);
    assert.match(cards[0], /agent/);
  }
});

test("remediation groups by the fix, listing every control that fix closes", () => {
  const headerFix = "Add the response headers at the CDN.";
  const withFix = (id, remediation) => finding({ id, title: `${id} holds`, status: "fail", severity: "medium", evidence: "missing", remediation, category: "Web Hardening", domain: "Infrastructure" });
  const reports = new Map([
    ["passive", profileRun("passive", [
      withFix("WEB-HEADER-STRICT-TRANSPORT-SECURITY", headerFix),
      withFix("WEB-HEADER-CONTENT-SECURITY-POLICY", headerFix),
      withFix("WEB-HEADER-REFERRER-POLICY", headerFix),
      withFix("API-QUERY-COST", "Add a query depth limit."),
    ])],
  ]);
  const model = buildModel(reports, {});

  // Three controls that close with one change to the CDN configuration are one piece of work.
  // Listing them as three identical rows misstates the size of the job.
  assert.equal(model.remediationGroups.length, 2);
  const headers = model.remediationGroups.find((g) => g.action === headerFix);
  assert.equal(headers.group.length, 3);
  assert.match(model.remediationRows, /closes 3 controls/);
  assert.equal((model.remediationRows.match(/<tr /g) ?? []).length, 2, "two rows, not four");
});

test("the inventory stays per-execution — it is the ledger, and the profile column is its point", () => {
  const reports = new Map([
    ["authenticated", profileRun("authenticated", [control("TOKEN-ALG", "pass", "high")])],
    ["agent", profileRun("agent", [control("TOKEN-ALG", "pass", "high")])],
  ]);
  const model = buildModel(reports, {});
  assert.equal((model.inventoryRows.match(/<tr /g) ?? []).length, 2);
  assert.match(model.inventoryRows, /data-profile="authenticated"/);
  assert.match(model.inventoryRows, /data-profile="agent"/);
});

test("the report states which unit it scored by, and the formula", () => {
  const reports = new Map([["authenticated", profileRun("authenticated", [control("TOKEN-ALG", "pass", "high")])]]);
  const byExecution = buildReport(reports, { scoreBy: "execution" });
  assert.match(byExecution, /This report scores <strong>by execution<\/strong>/);
  assert.match(byExecution, /--score-by control/, "and points at the honest alternative");
  assert.match(buildReport(reports, { scoreBy: "control" }), /This report scores <strong>by control<\/strong>/);
  // A number with no stated derivation invites the distrust the report exists to remove.
  assert.match(byExecution, /score = Σ\(weight × outcome\) ÷ Σ\(weight\) × 100/);
});

test("a switched scoring unit makes two runs incomparable, and says why", async () => {
  const { deltaAgainstPrevious } = await import("../src/assessment/trends.mjs");
  const entry = (scoringUnit, score) => ({
    runId: `r-${scoringUnit}`, at: "2026-07-31T10:00:00.000Z", configHash: "same", catalogHash: "same",
    profiles: ["authenticated"], scoringUnit, score, readiness: "caution",
    coverage: { percent: 50, assessed: 5, applicable: 10 },
    counts: { pass: 5, fail: 1, warn: 0, skip: 0, blockers: 0 }, failingIds: ["API-CROSS-USER"], chains: [],
  });
  const diff = deltaAgainstPrevious({ runs: [entry("execution", 79)] }, entry("control", 61));
  assert.equal(diff.comparable, false);
  // An 18-point drop that came from changing the unit, presented as progress or regression,
  // would be the most misleading number in the report.
  assert.ok(diff.caveats.some((c) => /scoring unit changed \(execution → control\)/.test(c)));
});

// ── A skip that means "nobody looked" is not the same fact as one that cannot apply ──
test("skips carry why they were skipped, and coverage counts the kinds separately", async () => {
  const { skipped, classifySkip } = await import("../src/finding.mjs");
  assert.equal(skipped("X", "t", "config.api.endpoint is not configured").skipKind, "unconfigured");
  assert.equal(skipped("X", "t", "requires a browser: complete the callback").skipKind, "not-applicable");
  assert.equal(skipped("X", "t", "hierarchy held — the bypass path is not reachable").skipKind, "precondition");
  // The cautious default: an unrecognised reason counts against coverage rather than being
  // quietly excused as inapplicable.
  assert.equal(classifySkip("something nobody anticipated"), "unconfigured");
  assert.equal(skipped("X", "t", "anything at all", "not-applicable").skipKind, "not-applicable", "a probe that knows can say so");

  const model = buildModel(
    new Map([
      ["passive", profileRun("passive", [
        skipped("API-CROSS-USER", "Cross-user isolation", "config.api.endpoint is not configured"),
        skipped("MOBILE-CERT-PINNING", "Pinning", "requires an instrumented device: install a proxy CA"),
        control("WEB-CLICKJACKING", "pass", "medium", "Clickjacking", "Infrastructure"),
      ])],
    ]),
    {},
  );
  assert.deepEqual(model.coverage.skipsByKind, { unconfigured: 1, "not-applicable": 1, precondition: 0 });
});

test("warnings say which kind of warning they are", async () => {
  const { inconclusive } = await import("../src/finding.mjs");
  assert.equal(inconclusive("X", "t", "request failed").warnKind, "inconclusive");
  assert.equal(finding({ id: "X", title: "t", status: "warn", severity: "low", evidence: "weak" }).warnKind, "advisory");
  assert.equal(finding({ id: "X", title: "t", status: "warn", severity: "low", evidence: "e", warnKind: "partial" }).warnKind, "partial");
  // Three meanings wore one badge; the card now distinguishes them.
  const model = buildModel(new Map([["passive", profileRun("passive", [inconclusive("API-QUERY-COST", "Query cost", "ambiguous response")])]]), {});
  assert.match(model.findingCards, /class="kind-badge"[^>]*>inconclusive</);
});

test("the trend explains why the score moved, and gives the like-for-like figure", async () => {
  const { deltaAgainstPrevious } = await import("../src/assessment/trends.mjs");
  const entry = (runId, score, assessed) => ({
    runId, at: "2026-07-31T10:00:00.000Z", configHash: "same", catalogHash: "same", profiles: ["authenticated"],
    scoringUnit: "control", score, readiness: "caution", coverage: { percent: 60, assessed: assessed.length, applicable: 10 },
    counts: { pass: 1, fail: 1, warn: 0, skip: 0, blockers: 1 }, failingIds: assessed.filter((a) => a.status === "fail").map((a) => a.id),
    chains: [], assessed,
  });
  const diff = deltaAgainstPrevious(
    { runs: [entry("r1", 50, [{ id: "API-CROSS-USER", status: "fail", severity: "critical" }, { id: "TOKEN-ALG", status: "pass", severity: "high" }])] },
    entry("r2", 62, [
      { id: "API-CROSS-USER", status: "pass", severity: "critical" },
      { id: "TOKEN-ALG", status: "fail", severity: "high" },
      { id: "WEB-CLICKJACKING", status: "pass", severity: "medium" },
    ]),
  );

  // The headline rose 12 points while a control regressed — which is exactly the movement a
  // bare delta would misrepresent as progress.
  assert.equal(diff.scoreDelta, 12);
  assert.deepEqual(diff.attribution.repaired, ["API-CROSS-USER"]);
  assert.deepEqual(diff.attribution.regressed, ["TOKEN-ALG"]);
  assert.deepEqual(diff.attribution.newlyAssessed, ["WEB-CLICKJACKING"]);
  assert.equal(diff.attribution.common, 2, "the like-for-like set excludes the newly assessed control");
  assert.equal(diff.attribution.commonScoreBefore, 33);
  assert.equal(diff.attribution.commonScoreNow, 67);
});

test("--only narrows to the modules that could produce the control", async () => {
  const { modulesFor } = await import("../src/runner.mjs");
  assert.deepEqual(modulesFor("API-CROSS-USER"), ["api"]);
  assert.deepEqual(modulesFor("WEB-HEADER-"), ["web"]);
  assert.deepEqual(modulesFor("SESSION-LOGOUT"), ["api"]);
  // A partner ID belongs to no built-in prefix, so nothing is filtered out — narrowing on a
  // guess would silently skip the module that owns it.
  assert.equal(modulesFor("ACME-SSO-CLOCK-SKEW"), null);
});

test("a verbose trace reports the request without its credentials", async () => {
  const { SafeHttpClient, DEFAULT_SAFETY } = await import("../src/safety.mjs");
  const traces = [];
  const client = new SafeHttpClient(
    { name: "t", environment: "dev", targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com"] }, safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50 } },
    { onRequest: (t) => traces.push(t) },
  );
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response("ok");
  try {
    await client.request("https://dev.example.com/x", { headers: { authorization: "Bearer super-secret-token", accept: "application/json" } });
  } finally {
    globalThis.fetch = original;
  }
  assert.equal(traces.length, 1);
  assert.equal(traces[0].status, 200);
  assert.deepEqual(traces[0].headerNames.sort(), ["accept", "authorization"]);
  // Header names, never values — a trace is the last place a token should surface.
  assert.equal(JSON.stringify(traces[0]).includes("super-secret-token"), false);
});

test("remediation groups on the canonical action, not on the sentence", () => {
  // Six header controls carry six different remediation sentences and close with one change to
  // the edge configuration. Grouping on the sentence groups nothing, which is what a partner
  // reported after 1.6.0.
  const header = (id) =>
    finding({ id, title: id, status: "fail", severity: "medium", evidence: "absent", remediation: `Send the ${id} header.`, fix: "edge-response-headers", category: "Web Hardening", domain: "Infrastructure" });
  const model = buildModel(
    new Map([
      ["passive", profileRun("passive", [
        header("WEB-HEADER-STRICT-TRANSPORT-SECURITY"),
        header("WEB-HEADER-CONTENT-SECURITY-POLICY"),
        header("WEB-HEADER-REFERRER-POLICY"),
        finding({ id: "API-QUERY-COST", title: "cost", status: "fail", severity: "medium", evidence: "e", remediation: "Add a depth limit.", category: "Resource Limits", domain: "Infrastructure" }),
      ])],
    ]),
    {},
  );

  assert.equal(model.remediationGroups.length, 2, "three header controls are one piece of work");
  const grouped = model.remediationGroups.find((g) => g.group.length === 3);
  assert.match(grouped.action, /Configure security response headers at the edge/);
  assert.match(model.remediationRows, /closes 3 controls/);
  // The shared action is the ticket; the per-control sentences are what goes in it.
  assert.match(model.remediationRows, /rem-specifics/);
  assert.match(model.remediationRows, /Send the WEB-HEADER-REFERRER-POLICY header\./);
});

test("a control whose profiles disagree is flagged, not silently reduced", () => {
  const model = buildModel(
    new Map([
      ["passive", profileRun("passive", [control("AUTH-PASSWORD-BYPASS", "pass", "critical", "Authentication", "Authentication")])],
      ["authenticated", profileRun("authenticated", [control("AUTH-PASSWORD-BYPASS", "warn", "critical", "Authentication", "Authentication")])],
    ]),
    {},
  );
  const [merged] = model.displayFindings;
  assert.equal(merged.status, "warn", "worst outcome wins");
  assert.equal(merged.inconsistent, true);
  assert.match(model.findingCards, /kind-badge[^>]*>inconsistent</);
  assert.match(merged.evidence, /Across profiles: passive pass, authenticated warn/);
});
