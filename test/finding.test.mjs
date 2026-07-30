import test from "node:test";
import assert from "node:assert/strict";
import { finding, redact, skipped, inconclusive, canary, summarize, exitCodeFor, headline } from "../src/finding.mjs";

test("finding enforces the canonical shape", () => {
  const f = finding({ id: "WEB-X", title: "t", status: "fail", severity: "high", evidence: "e", remediation: "r" });
  assert.deepEqual(Object.keys(f), ["id", "title", "status", "severity", "observed", "evidence", "remediation"]);
});

test("finding rejects an invalid status or severity", () => {
  assert.throws(() => finding({ id: "A", title: "t", status: "broken" }), /status must be one of/);
  assert.throws(() => finding({ id: "A", title: "t", status: "pass", severity: "spicy" }), /severity must be one of/);
  assert.throws(() => finding({ title: "t", status: "pass" }), /id is required/);
});

test("finding drops remediation on a pass", () => {
  const f = finding({ id: "A", title: "t", status: "pass", remediation: "should vanish" });
  assert.equal(f.remediation, "");
});

test("redact strips JWTs", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.s1gnatureXYZ_abc";
  const out = redact(`token=${jwt} end`);
  assert.ok(!out.includes("eyJhbGciOiJIUzI1NiJ9"));
  assert.ok(out.includes("[REDACTED"));
});

test("redact strips bearer tokens and cloud keys", () => {
  assert.match(redact("authorization: Bearer abcdef1234567890"), /Bearer \[REDACTED\]/);
  assert.match(redact("AKIAIOSFODNN7EXAMPLE"), /REDACTED_AWS_KEY_ID/);
  assert.match(redact("key: sk-abcdefghijklmnopqrstuvwx"), /REDACTED/);
});

test("redact strips key/value secrets and signed-URL signatures", () => {
  assert.doesNotMatch(redact('{"password":"hunter2000"}'), /hunter2000/);
  assert.doesNotMatch(redact("api_key=abcdef123456"), /abcdef123456/);
  // Prefixed keys, as found in a leaked .env file
  assert.doesNotMatch(redact("DB_PASSWORD=hunter2000\nSERVICE_ACCESS_KEY_2=abcdef123456"), /hunter2000|abcdef123456/);
  assert.doesNotMatch(redact("aws_session_credential: abcd1234efgh"), /abcd1234efgh/);
  assert.doesNotMatch(redact("https://s/o?X-Amz-Signature=deadbeefcafe&x=1"), /deadbeefcafe/);
});

test("redact strips private keys", () => {
  const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIB\n-----END RSA PRIVATE KEY-----";
  assert.equal(redact(pem), "[REDACTED_PRIVATE_KEY]");
});

test("redact clamps evidence length", () => {
  const out = redact("x".repeat(9000));
  assert.ok(out.length < 4200);
  assert.match(out, /truncated/);
});

test("finding redacts evidence automatically", () => {
  const f = finding({ id: "A", title: "t", status: "fail", severity: "high", evidence: "authorization: Bearer supersecrettoken1" });
  assert.doesNotMatch(f.evidence, /supersecrettoken1/);
});

test("skipped is always info severity and marked", () => {
  const f = skipped("A", "t", "no token");
  assert.equal(f.status, "skip");
  assert.equal(f.severity, "info");
  assert.match(f.evidence, /^Skipped: no token/);
});

test("inconclusive produces a low-severity warn", () => {
  const f = inconclusive("A", "t", "network error");
  assert.equal(f.status, "warn");
  assert.equal(f.severity, "low");
  assert.ok(f.remediation.length > 0);
});

test("canary markers are unique and labelled", () => {
  const a = canary("X");
  const b = canary("X");
  assert.notEqual(a, b);
  assert.match(a, /^X-[0-9A-F]{16}$/);
});

test("summarize tallies every status", () => {
  const findings = [
    finding({ id: "1", title: "a", status: "pass" }),
    finding({ id: "2", title: "b", status: "fail", severity: "low" }),
    finding({ id: "3", title: "c", status: "warn", severity: "low" }),
    skipped("4", "d", "reason"),
  ];
  assert.deepEqual(summarize(findings), { pass: 1, fail: 1, warn: 1, skip: 1, total: 4 });
});

test("exitCodeFor gates CI on critical/high/medium failures only", () => {
  assert.equal(exitCodeFor([finding({ id: "1", title: "a", status: "pass" })]), 0);
  assert.equal(exitCodeFor([finding({ id: "1", title: "a", status: "fail", severity: "low" })]), 0);
  assert.equal(exitCodeFor([finding({ id: "1", title: "a", status: "fail", severity: "medium" })]), 2);
  assert.equal(exitCodeFor([finding({ id: "1", title: "a", status: "fail", severity: "critical" })]), 2);
  assert.equal(exitCodeFor([finding({ id: "1", title: "a", status: "warn", severity: "critical" })]), 0);
});

// ── observed outcome vs expected control ────────────────────────────
test("observed is kept only where the control did not hold", () => {
  const failed = finding({ id: "A", title: "User B cannot read User A's record", status: "fail", severity: "high", observed: "Cross-user read is permitted" });
  assert.equal(failed.observed, "Cross-user read is permitted");
  const passed = finding({ id: "A", title: "User B cannot read User A's record", status: "pass", severity: "high", observed: "should be dropped" });
  assert.equal(passed.observed, "", "a passing control has nothing adverse to report");
});

test("headline never states a positive assertion for a failing control", () => {
  const assertion = "User B cannot read User A's record";
  assert.equal(headline(finding({ id: "A", title: assertion, status: "pass", severity: "high" })), assertion);
  assert.equal(
    headline(finding({ id: "A", title: assertion, status: "fail", severity: "high", observed: "Cross-user record access is permitted" })),
    "Cross-user record access is permitted",
  );
  // Without an authored observed string it must still not read as though the control held.
  assert.equal(headline(finding({ id: "A", title: assertion, status: "fail", severity: "high" })), `Control not upheld — ${assertion}`);
  assert.equal(headline(finding({ id: "A", title: assertion, status: "warn", severity: "low" })), `Not fully verified — ${assertion}`);
  assert.equal(headline(skipped("A", assertion, "no token")), `Not assessed — ${assertion}`);
});
