import test from "node:test";
import assert from "node:assert/strict";
import { SafeHttpClient, SafetyError, ConfigError, validateConfig, stripJsonComments, DEFAULT_SAFETY } from "../src/safety.mjs";
import { finding } from "../src/finding.mjs";

const baseConfig = (overrides = {}) => ({
  name: "unit",
  environment: "dev",
  targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com"] },
  safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50 },
  ...overrides,
});

test("validateConfig accepts a well-formed dev config", () => {
  assert.deepEqual(validateConfig(baseConfig()), []);
});

test("validateConfig requires a target and an allowlist", () => {
  assert.throws(() => validateConfig(baseConfig({ targets: { allowedHosts: ["a.example.com"] } })), ConfigError);
  assert.throws(() => validateConfig(baseConfig({ targets: { web: "https://a.example.com", allowedHosts: [] } })), ConfigError);
});

test("validateConfig requires the web target host to be allowlisted", () => {
  const config = baseConfig({ targets: { web: "https://other.example.com", allowedHosts: ["dev.example.com"] } });
  assert.throws(() => validateConfig(config), /not in targets.allowedHosts/);
});

test("validateConfig rejects URLs in allowedHosts", () => {
  const config = baseConfig({ targets: { web: "https://dev.example.com", allowedHosts: ["https://dev.example.com"] } });
  assert.throws(() => validateConfig(config), /bare hostnames/);
});

test("validateConfig blocks production environments without an override", () => {
  assert.throws(() => validateConfig(baseConfig({ environment: "prod" })), SafetyError);
  assert.throws(() => validateConfig(baseConfig({ environment: "production" })), SafetyError);
});

test("validateConfig blocks production-looking hostnames without an override", () => {
  const config = baseConfig({ targets: { web: "https://prod.example.com", allowedHosts: ["prod.example.com"] } });
  assert.throws(() => validateConfig(config), SafetyError);
});

test("validateConfig permits production with an explicit override and warns", () => {
  const config = baseConfig({ environment: "prod", safety: { ...DEFAULT_SAFETY, productionOverride: true } });
  const advisories = validateConfig(config);
  assert.ok(advisories.some((a) => /productionOverride/.test(a)));
});

test("validateConfig enforces a delay floor and a sane request cap", () => {
  assert.throws(() => validateConfig(baseConfig({ safety: { ...DEFAULT_SAFETY, minimumDelayMs: 10 } })), /minimumDelayMs/);
  assert.throws(() => validateConfig(baseConfig({ safety: { ...DEFAULT_SAFETY, maxRequests: 0 } })), /maxRequests/);
  assert.throws(() => validateConfig(baseConfig({ safety: { ...DEFAULT_SAFETY, maxRequests: 99999 } })), /maxRequests/);
});

test("assertUrlAllowed refuses plaintext HTTP", () => {
  const client = new SafeHttpClient(baseConfig());
  assert.throws(() => client.assertUrlAllowed("http://dev.example.com/"), /non-HTTPS/);
});

test("assertUrlAllowed refuses hosts outside the allowlist (SSRF guard)", () => {
  const client = new SafeHttpClient(baseConfig());
  assert.throws(() => client.assertUrlAllowed("https://evil.example.net/"), /not in targets.allowedHosts/);
});

test("assertUrlAllowed accepts an allowlisted HTTPS host", () => {
  const client = new SafeHttpClient(baseConfig());
  assert.equal(client.assertUrlAllowed("https://dev.example.com/a/b").hostname, "dev.example.com");
});

test("request refuses write methods unless allowWrites is set", async () => {
  const client = new SafeHttpClient(baseConfig());
  await assert.rejects(() => client.request("https://dev.example.com/", { method: "DELETE" }), /writes are disabled/);
  await assert.rejects(() => client.request("https://dev.example.com/", { method: "POST", write: true }), /writes are disabled/);
  assert.equal(client.requestCount, 0, "blocked requests must not consume the budget");
  assert.equal(client.blocked.length, 2);
});

test("request refuses agent invocations unless allowAgentInvocations is set", async () => {
  const client = new SafeHttpClient(baseConfig());
  await assert.rejects(
    () => client.request("https://dev.example.com/invoke", { method: "POST", agentInvocation: true }),
    /agent invocations are disabled/,
  );
});

test("request enforces the hard request cap", async () => {
  const config = baseConfig({ safety: { ...DEFAULT_SAFETY, maxRequests: 1, minimumDelayMs: 50 } });
  const client = new SafeHttpClient(config);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("ok", { status: 200 });
  try {
    await client.request("https://dev.example.com/");
    assert.equal(client.requestCount, 1);
    assert.equal(client.remainingRequests, 0);
    await assert.rejects(() => client.request("https://dev.example.com/"), /request cap reached/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("request enforces the minimum delay between calls", async () => {
  const config = baseConfig({ safety: { ...DEFAULT_SAFETY, minimumDelayMs: 120 } });
  const client = new SafeHttpClient(config);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("ok", { status: 200 });
  try {
    await client.request("https://dev.example.com/");
    const started = Date.now();
    await client.request("https://dev.example.com/");
    assert.ok(Date.now() - started >= 110, "second request should have been throttled");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("request never follows redirects", async () => {
  const client = new SafeHttpClient(baseConfig());
  const originalFetch = globalThis.fetch;
  let seenInit;
  globalThis.fetch = async (_url, init) => {
    seenInit = init;
    return new Response(null, { status: 302 });
  };
  try {
    await client.request("https://dev.example.com/");
    assert.equal(seenInit.redirect, "manual");
    assert.ok(seenInit.signal, "a timeout signal must be attached");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("tlsInfo refuses hosts outside the allowlist", async () => {
  const client = new SafeHttpClient(baseConfig());
  await assert.rejects(() => client.tlsInfo("evil.example.net"), /not in targets.allowedHosts/);
});

test("stripJsonComments removes comments but preserves strings", () => {
  const jsonc = `{
    // line comment
    "url": "https://x/y?a=1//not-a-comment", /* block */
    "n": 1
  }`;
  const parsed = JSON.parse(stripJsonComments(jsonc));
  assert.equal(parsed.url, "https://x/y?a=1//not-a-comment");
  assert.equal(parsed.n, 1);
});

// ── Robustness: the run must survive its own extension point ────────
test("a probe module that throws does not cost the run its findings", async () => {
  const { runProfile, defineProbe } = await import("../src/runner.mjs");
  const config = {
    name: "robust",
    environment: "dev",
    targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com"] },
    safety: { maxRequests: 10, minimumDelayMs: 50, requestTimeoutMs: 5000, allowWrites: false, allowAgentInvocations: false, productionOverride: false },
  };
  const good = defineProbe({
    name: "good",
    profiles: ["mobile"],
    catalog: { "GOOD-1": { category: "Web Hardening", purpose: "Verify the surviving probe still reports." } },
    run: async () => [finding({ id: "GOOD-1", title: "Survives a sibling crash", status: "pass", severity: "low", evidence: "ok" })],
  });
  const broken = defineProbe({ name: "broken", profiles: ["mobile"], run: async () => { throw new TypeError("probe author bug"); } });

  const result = await runProfile({ config, profile: "mobile", probes: [good, broken] });
  // The extension point invites third-party code; one partner's defect must not destroy an
  // assessment that has already produced findings.
  assert.equal(result.findings.find((f) => f.id === "GOOD-1").status, "pass");
  const crash = result.findings.find((f) => f.id === "BROKEN-ABORTED");
  assert.equal(crash.status, "warn");
  assert.match(crash.evidence, /Module crashed: TypeError: probe author bug/);
  // And it must not read as coverage.
  assert.match(crash.remediation, /unverified — treat this as no coverage/);
});

test("a config key can never reach an object's prototype", async () => {
  const { resolveExtends } = await import("../src/config.mjs");
  const { mkdtemp, writeFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const path = (await import("node:path")).default;
  const dir = await mkdtemp(path.join(tmpdir(), "trust-proto-"));
  try {
    await writeFile(path.join(dir, "base.json"), JSON.stringify({ name: "b", environment: "dev" }));
    await writeFile(path.join(dir, "child.json"), '{"extends":"./base.json","__proto__":{"polluted":"yes"},"constructor":{"x":1},"safety":{"maxRequests":50}}');
    const merged = await resolveExtends(path.join(dir, "child.json"));
    assert.equal({}.polluted, undefined, "Object.prototype must be untouched");
    assert.equal(merged.constructor?.x, undefined, "and no prototype-adjacent key survives the merge");
    assert.equal(merged.safety.maxRequests, 50, "while ordinary keys merge as before");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("SigV4 refuses a body it cannot hash rather than signing an empty one", async () => {
  const { applyCredential } = await import("../src/auth/index.mjs");
  const credential = { kind: "sigv4", aws: { accessKeyId: "AKID", secretAccessKey: "S", region: "us-east-1", service: "execute-api" } };
  const args = (body) => ({ method: "POST", url: new URL("https://dev.example.com/x"), headers: {}, body });

  const signed = applyCredential(credential, args(Buffer.from('{"a":1}')));
  const asString = applyCredential(credential, args('{"a":1}'));
  assert.equal(signed["x-amz-content-sha256"], asString["x-amz-content-sha256"], "a Buffer body signs the bytes it carries");

  // Silently signing "" would produce a valid-looking signature over the wrong payload, and
  // the target would answer SignatureDoesNotMatch — which reads as a broken credential.
  assert.throws(() => applyCredential(credential, args(new ReadableStream())), /cannot sign a ReadableStream body/);
});

test("remediation is bounded like evidence", () => {
  const huge = finding({ id: "X", title: "t", status: "fail", severity: "high", evidence: "e", remediation: "R".repeat(50000) });
  assert.ok(huge.remediation.length < 4200, "an unbounded remediation would bloat the HTML, the XML and the JSON alike");
  assert.match(huge.remediation, /truncated 46000 chars/);
});
