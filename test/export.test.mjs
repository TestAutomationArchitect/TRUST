import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { toSarif } from "../src/export/sarif.mjs";
import { toJUnit } from "../src/export/junit.mjs";
import { findingKey, fingerprint } from "../src/export/identity.mjs";
import { buildBaseline, loadBaseline, writeBaseline, diffAgainstBaseline, exitCodeForDiff, BASELINE_VERSION } from "../src/baseline.mjs";
import { registerAttackPaths, matchAttackPaths } from "../src/catalog.mjs";
import { finding } from "../src/finding.mjs";

const runReport = (overrides = {}) => ({
  tool: "TRUST",
  toolVersion: "1.0.1",
  profile: "authenticated",
  name: "example-dev",
  target: "https://dev.example.com",
  environment: "dev",
  allowedHosts: ["dev.example.com"],
  surfaces: ["web", "api"],
  runId: "11111111-2222-3333-4444-555555555555",
  startedAt: "2026-07-30T10:00:00.000Z",
  generatedAt: "2026-07-30T10:04:00.000Z",
  durationMs: 240000,
  findings: [],
  ...overrides,
});

const fail = (id, severity = "high", extra = {}) =>
  finding({ id, title: `${id} control holds`, status: "fail", severity, evidence: "HTTP 200 with another user's record", remediation: "Scope it server-side.", observed: `${id} did not hold`, ...extra });
const pass = (id, severity = "critical") => finding({ id, title: `${id} control holds`, status: "pass", severity, evidence: "HTTP 403" });
const warn = (id, severity = "medium") => finding({ id, title: `${id} control holds`, status: "warn", severity, evidence: "ambiguous response" });
const skip = (id) => finding({ id, title: `${id} control holds`, status: "skip", severity: "info", evidence: "Skipped: no token" });

const withDir = async (fn) => {
  const dir = await mkdtemp(path.join(tmpdir(), "trust-export-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
};

// ── Identity ────────────────────────────────────────────────────────
test("a finding's identity is test plus target, and nothing that changes run to run", () => {
  const a = fail("API-CROSS-USER");
  const b = fail("API-CROSS-USER");
  b.evidence = "a completely different response body";
  b.status = "warn";
  // If the identity moved with the evidence, every run would look new and a baseline would be
  // worthless — which is the failure mode this guards.
  assert.equal(findingKey(a, { target: "https://dev.example.com/app" }), "API-CROSS-USER@dev.example.com");
  assert.equal(findingKey(a, { target: "https://dev.example.com" }), findingKey(b, { target: "https://dev.example.com" }));
  assert.notEqual(findingKey(a, { target: "https://dev.example.com" }), findingKey(a, { target: "https://uat.example.com" }));
  assert.equal(findingKey(a, {}), "API-CROSS-USER", "no target still yields a usable identity");
  assert.equal(fingerprint("x").length, 32);
});

// ── SARIF ───────────────────────────────────────────────────────────
test("SARIF carries failures with a level and a security severity", () => {
  const sarif = toSarif(runReport({ findings: [fail("API-CROSS-USER", "critical"), warn("API-QUERY-COST")] }), { configPath: "config/dev.json" });
  assert.equal(sarif.version, "2.1.0");
  const [run] = sarif.runs;
  assert.equal(run.tool.driver.name, "TRUST");
  assert.equal(run.results.length, 2);

  const cross = run.results.find((r) => r.ruleId === "API-CROSS-USER");
  assert.equal(cross.level, "error");
  assert.equal(cross.kind, "fail");
  assert.match(cross.message.text, /API-CROSS-USER did not hold — https:\/\/dev.example.com/);
  assert.equal(cross.properties.trustKey, "API-CROSS-USER@dev.example.com");
  assert.ok(cross.partialFingerprints.trustFindingKey, "a fingerprint is what lets a dashboard de-duplicate across runs");

  const rule = run.tool.driver.rules.find((r) => r.id === "API-CROSS-USER");
  assert.equal(rule.properties["security-severity"], "9.5");
  assert.equal(rule.properties.impactIfFailed, "critical");
  assert.match(rule.help.markdown, /\*\*Purpose\.\*\*/);
  assert.equal(run.results.find((r) => r.ruleId === "API-QUERY-COST").level, "warning");
});

test("a passing critical control never reads as an error", () => {
  // The severity is the impact *if* the control fails. A green run must not paint a security
  // dashboard red, which is what a naive severity→level mapping would do.
  const quiet = toSarif(runReport({ findings: [pass("API-CROSS-USER", "critical"), skip("STORAGE-CROSS-TENANT")] }));
  assert.equal(quiet.runs[0].results.length, 0, "passes and skips are omitted by default");

  const full = toSarif(runReport({ findings: [pass("API-CROSS-USER", "critical"), skip("STORAGE-CROSS-TENANT")] }), { includePasses: true });
  const [passing, skipped] = full.runs[0].results;
  assert.equal(passing.kind, "pass");
  assert.equal(passing.level, undefined, "a passing control carries no level at all");
  assert.equal(skipped.kind, "notApplicable");
});

test("SARIF anchors results to the config rather than inventing a source line", () => {
  const sarif = toSarif(runReport({ findings: [fail("API-CROSS-USER")] }), { configPath: "config/dev.json" });
  const [result] = sarif.runs[0].results;
  const location = result.locations[0];
  assert.equal(location.physicalLocation.artifactLocation.uri, "config/dev.json");
  assert.equal(location.physicalLocation.region.startLine, 1);
  // A fabricated file and line is a lie a reviewer would act on; the logical location carries
  // the real classification instead.
  assert.equal(location.logicalLocations[0].fullyQualifiedName, "Authorization/API-CROSS-USER");
});

test("SARIF merges profiles into one run and records the engagement boundary", () => {
  const sarif = toSarif(
    [runReport({ profile: "passive", findings: [fail("WEB-CLICKJACKING", "medium")] }), runReport({ profile: "authenticated", findings: [fail("API-CROSS-USER")] })],
    { toolVersion: "9.9.9" },
  );
  assert.equal(sarif.runs.length, 1, "one SARIF run, so a dashboard shows one assessment");
  assert.equal(sarif.runs[0].results.length, 2);
  assert.equal(sarif.runs[0].tool.driver.version, "9.9.9");
  assert.equal(sarif.runs[0].automationDetails.id, "trust/passive+authenticated");
  assert.deepEqual(sarif.runs[0].invocations[0].properties.allowedHosts, ["dev.example.com"]);
});

test("SARIF rule indices point at the rule they name", () => {
  const sarif = toSarif(runReport({ findings: [fail("API-CROSS-USER"), fail("STORAGE-CROSS-TENANT"), fail("API-CROSS-USER")] }));
  const { rules } = sarif.runs[0].tool.driver;
  for (const result of sarif.runs[0].results) {
    assert.equal(rules[result.ruleIndex].id, result.ruleId, "a mis-indexed rule silently mislabels every finding");
  }
});

test("toSarif refuses an empty input rather than emitting an empty log", () => {
  assert.throws(() => toSarif([]), /at least one run report/);
});

// ── JUnit ───────────────────────────────────────────────────────────
test("JUnit groups by trust domain and counts what a CI dashboard shows", () => {
  const xml = toJUnit(runReport({ findings: [fail("API-CROSS-USER"), pass("WEB-HEADER-CONTENT-SECURITY-POLICY"), skip("STORAGE-CROSS-TENANT"), warn("API-QUERY-COST")] }));
  assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
  assert.match(xml, /<testsuites name="TRUST" tests="4" failures="2" errors="0" skipped="1"/);
  assert.match(xml, /<testsuite name="TRUST\.Authorization"/);
  assert.match(xml, /<testsuite name="TRUST\.Infrastructure"/);
  // A warning is rendered as a failure because JUnit has no third state, and invisible is worse
  // than red for a control that could not be confirmed.
  assert.match(xml, /<failure message="[^"]*" type="warning">/);
  assert.match(xml, /<skipped message="no token"\/>/);
  assert.match(xml, /<system-out>/, "a passing control still carries its evidence, so a green run is auditable");
});

test("JUnit escapes everything that would otherwise produce invalid XML", () => {
  const nasty = finding({
    id: "INJECT-REFLECTED-XSS",
    title: 'Input is encoded <script> & "quoted"',
    status: "fail",
    severity: "high",
    evidence: 'Reflected: <img src=x onerror="alert(1)">   control bytes',
    remediation: "Encode on output.",
  });
  const xml = toJUnit(runReport({ findings: [nasty] }));
  assert.ok(!/<script>/.test(xml), "markup from a target must not become markup in the report");
  assert.ok(!/[ -]/.test(xml), "control bytes are stripped, or the XML will not parse");
  assert.match(xml, /&lt;script&gt;/);
  assert.match(xml, /&amp;/);
  // A crude well-formedness check: every opened tag name is closed somewhere.
  for (const tag of ["testsuites", "testsuite", "testcase", "failure"]) {
    assert.equal((xml.match(new RegExp(`<${tag}[ >]`, "g")) ?? []).length, (xml.match(new RegExp(`</${tag}>`, "g")) ?? []).length, `${tag} is balanced`);
  }
});

// ── Baseline ────────────────────────────────────────────────────────
test("a baseline records adverse findings only", () => {
  const baseline = buildBaseline(runReport({ findings: [fail("API-CROSS-USER"), warn("API-QUERY-COST"), pass("WEB-TLS-VERSION"), skip("STORAGE-CROSS-TENANT")] }), { note: "adopted 2026-07-30" });
  assert.equal(baseline.baselineVersion, BASELINE_VERSION);
  assert.deepEqual(baseline.findings.map((f) => f.id).sort(), ["API-CROSS-USER", "API-QUERY-COST"]);
  assert.equal(baseline.note, "adopted 2026-07-30");
  // A control that starts passing must never have to be un-baselined, which is why passes are
  // not recorded in the first place.
  assert.ok(!baseline.findings.some((f) => f.id === "WEB-TLS-VERSION"));
});

test("the diff separates new, known, worsened and fixed", () => {
  const baseline = buildBaseline(runReport({ findings: [fail("API-CROSS-USER"), warn("API-QUERY-COST"), fail("STORAGE-CROSS-TENANT")] }));
  const today = runReport({
    findings: [
      fail("API-CROSS-USER"), // known
      fail("API-QUERY-COST", "medium"), // worsened: warn → fail
      pass("STORAGE-CROSS-TENANT"), // fixed
      fail("API-USERID-SPOOF", "critical"), // new
    ],
  });
  const diff = diffAgainstBaseline(today, baseline);
  assert.deepEqual(diff.fresh.map((f) => f.id), ["API-USERID-SPOOF"]);
  assert.deepEqual(diff.known.map((f) => f.id), ["API-CROSS-USER"]);
  assert.deepEqual(diff.worsened.map((f) => f.id), ["API-QUERY-COST"]);
  assert.deepEqual(diff.fixed.map((f) => f.id), ["STORAGE-CROSS-TENANT"]);
});

test("the gate blocks on new and worsened failures, and only those", () => {
  const baseline = buildBaseline(runReport({ findings: [fail("API-CROSS-USER", "critical")] }));

  const unchanged = diffAgainstBaseline(runReport({ findings: [fail("API-CROSS-USER", "critical")] }), baseline);
  assert.equal(exitCodeForDiff(unchanged), 0, "an accepted finding does not block — that is the point");

  const regressed = diffAgainstBaseline(runReport({ findings: [fail("API-CROSS-USER", "critical"), fail("API-USERID-SPOOF", "high")] }), baseline);
  assert.equal(exitCodeForDiff(regressed), 2);

  const cosmetic = diffAgainstBaseline(runReport({ findings: [fail("WEB-SERVER-BANNER", "low")] }), baseline);
  assert.equal(exitCodeForDiff(cosmetic), 0, "the severity threshold matches the unbaselined gate");

  const worsened = diffAgainstBaseline(runReport({ findings: [fail("API-QUERY-COST", "high")] }), buildBaseline(runReport({ findings: [warn("API-QUERY-COST", "high")] })));
  assert.equal(exitCodeForDiff(worsened), 2, "a warning becoming a failure is not an accepted finding");
});

test("a baseline is scoped to its target, so a different environment is all new", () => {
  const baseline = buildBaseline(runReport({ findings: [fail("API-CROSS-USER")] }));
  const otherEnvironment = runReport({ target: "https://uat.example.com", findings: [fail("API-CROSS-USER")] });
  const diff = diffAgainstBaseline(otherEnvironment, baseline);
  assert.equal(diff.fresh.length, 1);
  assert.equal(diff.fixed.length, 1, "and the baselined one reads as absent, not as silently satisfied");
});

test("loadBaseline accepts a baseline, a run report or a directory of runs", async () => {
  await withDir(async (dir) => {
    const report = runReport({ findings: [fail("API-CROSS-USER")] });

    const reportPath = path.join(dir, "trust-authenticated.json");
    await writeFile(reportPath, JSON.stringify(report));
    const fromReport = await loadBaseline(reportPath);
    assert.deepEqual(fromReport.findings.map((f) => f.id), ["API-CROSS-USER"]);

    // A team's first baseline is whatever is already on disk; requiring a conversion step is
    // how a feature goes unused.
    const fromDir = await loadBaseline(dir);
    assert.deepEqual(fromDir.findings.map((f) => f.id), ["API-CROSS-USER"]);

    const baselinePath = await writeBaseline(buildBaseline(report), path.join(dir, "b.json"));
    const roundTripped = await loadBaseline(baselinePath);
    assert.equal(roundTripped.findings[0].key, "API-CROSS-USER@dev.example.com");

    await writeFile(path.join(dir, "future.json"), JSON.stringify({ baselineVersion: 99, findings: [] }));
    await assert.rejects(() => loadBaseline(path.join(dir, "future.json")), /newer TRUST/);
    await assert.rejects(() => loadBaseline(path.join(dir, "missing.json")), /Cannot read baseline/);
    await assert.rejects(() => loadBaseline(path.join(dir, "b.json")).then(() => writeFile(path.join(dir, "junk.json"), "{").then(() => loadBaseline(path.join(dir, "junk.json")))), /not valid JSON/);
  });
});

test("an empty baseline behaves as no baseline, not as blanket acceptance", () => {
  const diff = diffAgainstBaseline(runReport({ findings: [fail("API-CROSS-USER", "critical")] }), { findings: [] });
  assert.equal(diff.fresh.length, 1);
  assert.equal(exitCodeForDiff(diff), 2);
  assert.equal(exitCodeForDiff(diffAgainstBaseline(runReport({ findings: [fail("API-CROSS-USER", "critical")] }), null)), 2, "and so does a missing one");
});

// ── registerAttackPaths ─────────────────────────────────────────────
test("an org can declare a control-failure chain of its own", () => {
  registerAttackPaths({
    id: "PATH-ACME-BILLING",
    name: "Identity spoof → billing mutation",
    steps: ["Identity comes from the payload", "Billing mutations are not role-checked"],
    requires: ["API-USERID-SPOOF"],
    anyOf: [/^ACME-BILLING-/],
    impact: "A standard user can alter another account's billing plan.",
    blocker: true,
  });

  const matched = matchAttackPaths(new Set(["API-USERID-SPOOF", "ACME-BILLING-MUTATION"]));
  const acme = matched.find((p) => p.id === "PATH-ACME-BILLING");
  assert.ok(acme, "a registered path is matched like a built-in one");
  assert.deepEqual(acme.evidence.sort(), ["ACME-BILLING-MUTATION", "API-USERID-SPOOF"]);

  // A string is matched as a whole ID: anchoring by hand is the mistake that makes a path
  // silently never match.
  assert.equal(matchAttackPaths(new Set(["API-USERID-SPOOF-EXTRA", "ACME-BILLING-MUTATION"])).some((p) => p.id === "PATH-ACME-BILLING"), false);
  assert.equal(matchAttackPaths(new Set(["API-USERID-SPOOF"])).some((p) => p.id === "PATH-ACME-BILLING"), false, "anyOf is required, not decorative");
  assert.throws(() => registerAttackPaths({ name: "no id" }), /requires id and name/);
});

test("a baselined finding from a profile that did not run is absent, not fixed", () => {
  // A baseline is recorded from a full assessment; CI usually gates one profile. Without
  // scoping, `--profile passive` would report every authenticated finding as fixed and
  // congratulate a team for work it had not done.
  const baseline = buildBaseline([
    runReport({ profile: "passive", findings: [fail("WEB-CLICKJACKING", "medium")] }),
    runReport({ profile: "authenticated", findings: [fail("API-CROSS-USER")] }),
  ]);

  const passiveOnly = diffAgainstBaseline(runReport({ profile: "passive", findings: [fail("WEB-CLICKJACKING", "medium")] }), baseline);
  assert.deepEqual(passiveOnly.fixed, []);
  assert.deepEqual(passiveOnly.notRun.map((f) => f.id), ["API-CROSS-USER"]);
  assert.equal(exitCodeForDiff(passiveOnly), 0);

  // Running the profile that owns it, and no longer seeing it, is a genuine fix.
  const authenticated = diffAgainstBaseline(runReport({ profile: "authenticated", findings: [] }), baseline);
  assert.deepEqual(authenticated.fixed.map((f) => f.id), ["API-CROSS-USER"]);
  assert.deepEqual(authenticated.notRun.map((f) => f.id), ["WEB-CLICKJACKING"]);

  // "all" covers everything, so nothing is out of scope for it.
  const everything = diffAgainstBaseline(runReport({ profile: "all", findings: [] }), baseline);
  assert.equal(everything.fixed.length, 2);
  assert.equal(everything.notRun.length, 0);
});

test("correlation data is redacted, but a canary is not", async () => {
  const { redact, canary } = await import("../src/finding.mjs");
  assert.match(redact("GET /protected/us-east-1:a1b2c3d4-e5f6-7890-abcd-ef1234567890/x.pdf"), /\[REDACTED_IDENTITY_ID\]/);
  assert.match(redact("arn:aws:iam::123456789012:role/AppRole"), /arn:aws:iam::\[REDACTED_ACCOUNT\]:role\/AppRole/);
  // A canary is how a reader verifies a leak finding — redacting every UUID would erase the
  // proof along with the correlation risk.
  const mark = canary("LEAK");
  assert.equal(redact(`The agent echoed ${mark}`), `The agent echoed ${mark}`);
});

test("a finding baselined in two profiles keeps its worse status", () => {
  const baseline = buildBaseline([
    runReport({ profile: "authenticated", findings: [warn("API-QUERY-COST", "medium")] }),
    runReport({ profile: "all", findings: [fail("API-QUERY-COST", "medium")] }),
  ]);
  assert.equal(baseline.findings.length, 1);
  // Accepting it as a warning in one profile must not quietly accept it as a failure in another.
  assert.equal(baseline.findings[0].status, "fail");
});
