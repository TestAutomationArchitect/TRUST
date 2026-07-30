import test from "node:test";
import assert from "node:assert/strict";
import { SafeHttpClient, SafetyError, ConfigError, validateConfig, stripJsonComments, DEFAULT_SAFETY } from "../src/safety.mjs";

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
