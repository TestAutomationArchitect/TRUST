import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { section, resolvedSections, resolveExtends, resolveBudget, SECTION_ALIASES } from "../src/config.mjs";
import { SafeHttpClient, SafetyError, ConfigError, validateConfig, loadConfig, DEFAULT_SAFETY } from "../src/safety.mjs";
import { runPreflight } from "../src/preflight.mjs";

const withDir = async (fn) => {
  const dir = await mkdtemp(path.join(tmpdir(), "trust-config-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
};

const baseConfig = (overrides = {}) => ({
  name: "unit",
  environment: "dev",
  targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com"] },
  safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50 },
  ...overrides,
});

// ── Section aliases ─────────────────────────────────────────────────
test("a section resolves through conventional spellings", () => {
  assert.equal(section({ graphql: { endpoint: "x" } }, "api").key, "graphql");
  assert.equal(section({ appSync: { endpoint: "x" } }, "api").key, "appSync");
  assert.equal(section({ agentCore: { runtimeEndpoint: "x" } }, "agent").key, "agentCore");
  assert.equal(section({ bedrock: { runtimeEndpoint: "x" } }, "agent").key, "bedrock");
  assert.equal(section({ s3: { baseUrl: "x" } }, "storage").key, "s3");
  assert.equal(section({}, "api").value, undefined, "an absent section resolves to nothing, not an error");
});

test("an explicit canonical key always beats an alias", () => {
  const config = { api: { endpoint: "canonical" }, graphql: { endpoint: "alias" } };
  const { value, key } = section(config, "api");
  assert.equal(key, "api");
  assert.equal(value.endpoint, "canonical");
});

test("only object sections resolve, so a stray string cannot masquerade as config", () => {
  assert.equal(section({ api: "https://example.com" }, "api").value, undefined);
});

test("resolvedSections reports only the aliases actually used", () => {
  assert.deepEqual(resolvedSections({ graphql: { endpoint: "x" }, s3: { baseUrl: "y" } }), { api: "graphql", storage: "s3" });
  assert.deepEqual(resolvedSections({ api: { endpoint: "x" } }), {}, "a canonical key is not reported as an alias");
});

test("every canonical section lists itself first among its aliases", () => {
  for (const [canonical, aliases] of Object.entries(SECTION_ALIASES)) {
    assert.equal(aliases[0], canonical, `${canonical} must take precedence over its own aliases`);
  }
});

// ── Config inheritance ──────────────────────────────────────────────
test("a child config overrides only what it declares", async () => {
  await withDir(async (dir) => {
    await writeFile(
      path.join(dir, "base.json"),
      JSON.stringify({
        name: "base",
        environment: "dev",
        targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com"] },
        safety: { maxRequests: 100, minimumDelayMs: 150 },
        web: { rateLimitBurst: 8 },
      }),
    );
    await writeFile(
      path.join(dir, "uat.json"),
      JSON.stringify({ extends: "./base.json", name: "uat", environment: "uat", safety: { maxRequests: 250 } }),
    );

    const merged = await resolveExtends(path.join(dir, "uat.json"));
    assert.equal(merged.name, "uat", "child wins");
    assert.equal(merged.environment, "uat");
    assert.equal(merged.safety.maxRequests, 250, "nested override applies");
    assert.equal(merged.safety.minimumDelayMs, 150, "and siblings are inherited, not lost");
    assert.equal(merged.web.rateLimitBurst, 8, "untouched sections carry through");
    assert.equal(merged.extends, undefined, "the directive itself does not survive into the config");
    assert.equal(merged.extendsChain.length, 2);
  });
});

test("an array in a child replaces rather than merges", async () => {
  await withDir(async (dir) => {
    await writeFile(path.join(dir, "base.json"), JSON.stringify({ targets: { allowedHosts: ["a.example.com", "b.example.com"] } }));
    await writeFile(path.join(dir, "child.json"), JSON.stringify({ extends: "./base.json", targets: { allowedHosts: ["c.example.com"] } }));
    const merged = await resolveExtends(path.join(dir, "child.json"));
    // Merging allowlists would silently widen the engagement scope — a child must be able to
    // narrow it.
    assert.deepEqual(merged.targets.allowedHosts, ["c.example.com"]);
  });
});

test("an extends cycle is an error, not a hang", async () => {
  await withDir(async (dir) => {
    await writeFile(path.join(dir, "a.json"), JSON.stringify({ extends: "./b.json", name: "a" }));
    await writeFile(path.join(dir, "b.json"), JSON.stringify({ extends: "./a.json", name: "b" }));
    await assert.rejects(() => resolveExtends(path.join(dir, "a.json")), /cycle/i);
  });
});

test("loadConfig applies safety defaults on top of an inherited config", async () => {
  await withDir(async (dir) => {
    await writeFile(path.join(dir, "base.json"), JSON.stringify({ name: "b", environment: "dev", safety: { minimumDelayMs: 200 } }));
    await writeFile(path.join(dir, "dev.json"), JSON.stringify({ extends: "./base.json" }));
    const config = await loadConfig(path.join(dir, "dev.json"));
    assert.equal(config.safety.minimumDelayMs, 200, "inherited value survives");
    assert.equal(config.safety.allowWrites, false, "and defaults fill the rest");
  });
});

// ── Budgets ─────────────────────────────────────────────────────────
test("a scalar cap applies to every profile; a map applies per profile", () => {
  assert.equal(resolveBudget({ safety: { maxRequests: 120 } }, "passive").total, 120);
  const perProfile = { safety: { maxRequests: { passive: 40, agent: 200, default: 75 } } };
  assert.equal(resolveBudget(perProfile, "passive").total, 40);
  assert.equal(resolveBudget(perProfile, "agent").total, 200);
  assert.equal(resolveBudget(perProfile, "mobile").total, 75, "an unlisted profile falls back to default");
});

test("validateConfig accepts both cap shapes and rejects nonsense in either", () => {
  assert.deepEqual(validateConfig(baseConfig({ safety: { ...DEFAULT_SAFETY, maxRequests: { passive: 50 } } })), []);
  assert.throws(() => validateConfig(baseConfig({ safety: { ...DEFAULT_SAFETY, maxRequests: { passive: 0 } } })), /between 1 and 5000/);
  assert.throws(() => validateConfig(baseConfig({ safety: { ...DEFAULT_SAFETY, maxRequests: {} } })), /empty object/);
  assert.throws(() => validateConfig(baseConfig({ safety: { ...DEFAULT_SAFETY, budgets: { web: 0 } } })), /positive integer/);
});

test("a suite budget stops that suite without ending the run", async () => {
  const client = new SafeHttpClient(baseConfig(), { budget: { total: 50, suites: { web: 2 } } });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("ok");
  try {
    client.beginSuite("web");
    await client.request("https://dev.example.com/1");
    await client.request("https://dev.example.com/2");
    await assert.rejects(() => client.request("https://dev.example.com/3"), /budget for the "web" suite exhausted/);

    // A different suite still has the run budget available — the point of per-suite caps.
    client.beginSuite("api");
    await client.request("https://dev.example.com/api");
    assert.deepEqual(client.suiteSpend, { web: 2, api: 1 });
    assert.equal(client.requestCount, 3);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("remainingRequests reflects the tighter of the run and suite budgets", async () => {
  const client = new SafeHttpClient(baseConfig(), { budget: { total: 10, suites: { web: 3 } } });
  client.beginSuite("web");
  assert.equal(client.remainingRequests, 3, "suite cap is tighter");
  client.beginSuite("api");
  assert.equal(client.remainingRequests, 10, "an uncapped suite sees the run budget");
});

// ── Denial tests ────────────────────────────────────────────────────
test("a denial test needs its own switch, not blanket write permission", async () => {
  const strict = new SafeHttpClient(baseConfig());
  await assert.rejects(
    () => strict.request("https://dev.example.com/", { method: "POST", write: true, denialTest: true }),
    /denial tests are disabled/,
  );

  const permitted = new SafeHttpClient(baseConfig({ safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50, allowDenialTests: true } }));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("denied", { status: 403 });
  try {
    const response = await permitted.request("https://dev.example.com/", { method: "POST", write: true, denialTest: true });
    assert.equal(response.status, 403);
    // The narrower switch must not become a general write permit.
    await assert.rejects(() => permitted.request("https://dev.example.com/", { method: "DELETE" }), /writes are disabled/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("allowDenialTests is advertised as an advisory, like the other loosened guards", () => {
  const advisories = validateConfig(baseConfig({ safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50, allowDenialTests: true } }));
  assert.ok(advisories.some((a) => /allowDenialTests/.test(a)));
});

// ── Preflight ───────────────────────────────────────────────────────
test("preflight fails a configured endpoint outside the allowlist", async () => {
  const config = baseConfig({ graphql: { endpoint: "https://api.elsewhere.example.com/graphql" } });
  const { checks, ok } = await runPreflight(config, { profile: "authenticated", reach: false });
  assert.equal(ok, false);
  const endpoint = checks.find((c) => c.name === "graphql.endpoint");
  assert.equal(endpoint.status, "fail");
  assert.match(endpoint.detail, /NOT in targets.allowedHosts/);
});

test("preflight reports the alias a section resolved from", async () => {
  const config = baseConfig({ graphql: { endpoint: "https://dev.example.com/graphql" } });
  const { checks, ok } = await runPreflight(config, { profile: "authenticated", reach: false });
  assert.equal(ok, true);
  assert.ok(checks.some((c) => c.detail.includes('api resolved from "graphql"')));
});

test("preflight warns when the budget cannot cover the profile", async () => {
  const config = baseConfig({ safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50, maxRequests: 5 } });
  const { checks } = await runPreflight(config, { profile: "all", reach: false });
  const budget = checks.find((c) => c.name === "request budget");
  assert.equal(budget.status, "warn");
  assert.match(budget.detail, /later suites will skip/);
});

test("preflight refuses an invalid config outright rather than checking on", async () => {
  const { checks, ok } = await runPreflight({ name: "x" }, { reach: false });
  assert.equal(ok, false);
  assert.equal(checks.length, 1, "nothing after config validity is meaningful");
  assert.equal(checks[0].status, "fail");
});

test("preflight makes no HTTP requests when reach is disabled", async () => {
  const originalFetch = globalThis.fetch;
  let called = 0;
  globalThis.fetch = async () => {
    called += 1;
    return new Response("{}");
  };
  try {
    await runPreflight(baseConfig(), { profile: "passive", reach: false });
    assert.equal(called, 0, "validate must be usable offline and against production configs");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("preflight fails an auth strategy whose IdP is outside the allowlist", async () => {
  const config = baseConfig({
    auth: { strategies: { svc: { type: "client-credentials", tokenUrl: "https://idp.elsewhere.example.com/token", clientId: "a" } } },
  });
  const { checks, ok } = await runPreflight(config, { profile: "authenticated", reach: false });
  assert.equal(ok, false);
  // Acquisition goes through the guarded client, so an unlisted IdP fails at sign-in rather
  // than at the probe that needed the token.
  assert.match(checks.find((c) => c.name === "auth svc").detail, /NOT in targets.allowedHosts/);
});

test("preflight names the missing input rather than reporting a failed login", async () => {
  const config = baseConfig({
    targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com", "cognito-idp.us-east-1.amazonaws.com"] },
    auth: {
      strategies: {
        userA: { type: "cognito-srp", region: "us-east-1", userPoolId: "us-east-1_A", clientId: "c", username: "u", passwordEnv: "TRUST_TEST_UNSET_PASSWORD" },
        broken: { type: "cognito-srp", region: "us-east-1", clientId: "c" },
      },
    },
  });
  const { checks } = await runPreflight(config, { profile: "authenticated", reach: false });
  assert.match(checks.find((c) => c.name === "auth userA").detail, /TRUST_TEST_UNSET_PASSWORD not set/);
  assert.match(checks.find((c) => c.name === "auth broken").detail, /missing userPoolId, username/);
});

test("preflight catches a section pointing at an undeclared strategy", async () => {
  const config = baseConfig({
    auth: { strategies: { userA: { type: "static", tokenEnv: "T" } } },
    graphql: { endpoint: "https://dev.example.com/graphql", tokenA: "userA", tokenB: "userB" },
  });
  const { checks, ok } = await runPreflight(config, { profile: "authenticated", reach: false });
  assert.equal(ok, false);
  assert.equal(checks.find((c) => c.name === "graphql.tokenA").status, "ok");
  assert.match(checks.find((c) => c.name === "graphql.tokenB").detail, /not declared in auth.strategies/);
});

test("preflight does not authenticate — a check that costs a login stops being run", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("preflight must not sign in");
  };
  try {
    const config = baseConfig({
      targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com", "idp.example.com"] },
      auth: { strategies: { svc: { type: "client-credentials", tokenUrl: "https://idp.example.com/t", clientId: "a" } } },
    });
    const { ok } = await runPreflight(config, { profile: "authenticated", reach: false });
    assert.equal(ok, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("preflight judges the expired-token fixture by the opposite rule", async () => {
  const config = baseConfig({ api: { endpoint: "https://dev.example.com/graphql", session: { expiredTokenEnv: "TRUST_TEST_FIXTURE" } } });
  const jwt = (exp) => `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from(JSON.stringify({ sub: "a", exp })).toString("base64url")}.sig`;
  const expired = jwt(Math.floor(Date.now() / 1000) - 3600);
  const live = jwt(Math.floor(Date.now() / 1000) + 3600);

  process.env.TRUST_TEST_FIXTURE = expired;
  try {
    const { checks, ok } = await runPreflight(config, { profile: "authenticated", reach: false });
    // The fixture exists to be rejected by the target. Failing preflight on it — as 1.5.0 did —
    // blocks a run over a token whose entire purpose is to have lapsed.
    assert.equal(ok, true);
    assert.equal(checks.find((c) => c.name === "token TRUST_TEST_FIXTURE").status, "ok");

    process.env.TRUST_TEST_FIXTURE = live;
    const stillValid = await runPreflight(config, { profile: "authenticated", reach: false });
    const check = stillValid.checks.find((c) => c.name === "token TRUST_TEST_FIXTURE");
    assert.equal(check.status, "warn", "a fixture that has not lapsed cannot demonstrate anything");
    assert.match(check.detail, /still valid/);
  } finally {
    delete process.env.TRUST_TEST_FIXTURE;
  }
});
