import test from "node:test";
import assert from "node:assert/strict";
import { decodeJwt, subjectOf, runTokenProbes } from "../src/probes/token.mjs";
import { discoverParams } from "../src/probes/injection.mjs";
import { getTestMeta, domainForId } from "../src/catalog.mjs";
import { BUILTIN_PROBES, PROFILES } from "../src/runner.mjs";

/** Mint an unsigned JWT for claim-shape testing. No signature is ever verified. */
function jwt(payload, header = { alg: "RS256", kid: "test" }) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64(header)}.${b64(payload)}.c2ln`;
}

const NOW = Math.floor(Date.now() / 1000);
const baseConfig = () => ({
  name: "unit",
  environment: "dev",
  targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com"] },
  safety: { maxRequests: 20, minimumDelayMs: 50, requestTimeoutMs: 5000, allowWrites: false, allowAgentInvocations: false, productionOverride: false },
  api: { endpoint: "https://dev.example.com/graphql", tokenAEnv: "T_A", tokenBEnv: "T_B" },
});

function withEnv(vars, fn) {
  const saved = {};
  for (const [k, v] of Object.entries(vars)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  return Promise.resolve(fn()).finally(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });
}

const byId = (findings, id) => findings.find((f) => f.id === id);

// ── JWT decoding ────────────────────────────────────────────────────
test("decodeJwt reads header and payload, and rejects non-JWTs", () => {
  const decoded = decodeJwt(jwt({ sub: "user-a", exp: NOW + 600 }));
  assert.equal(decoded.header.alg, "RS256");
  assert.equal(decoded.payload.sub, "user-a");
  for (const bad of ["opaque-token", "", null, undefined, "a.b", "not.base64.$$$"]) {
    assert.equal(decodeJwt(bad), null, `${bad} must not decode`);
  }
});

test("subjectOf falls back through the usual identity claims", () => {
  assert.deepEqual(subjectOf({ sub: "s1" }), { claim: "sub", value: "s1" });
  assert.deepEqual(subjectOf({ "cognito:username": "u1" }), { claim: "cognito:username", value: "u1" });
  assert.equal(subjectOf({ unrelated: 1 }), null);
});

// ── Token probes ────────────────────────────────────────────────────
test("token probes skip cleanly with no tokens, and with opaque tokens", async () => {
  await withEnv({ T_A: undefined, T_B: undefined }, async () => {
    const findings = await runTokenProbes(baseConfig());
    assert.equal(findings.length, 1);
    assert.equal(findings[0].status, "skip");
  });
  await withEnv({ T_A: "opaque-session-cookie", T_B: undefined }, async () => {
    const findings = await runTokenProbes(baseConfig());
    assert.match(findings[0].evidence, /none are JWTs/);
  });
});

test("token probes fail an unsigned algorithm and a missing expiry", async () => {
  const bad = jwt({ sub: "a", iss: "https://idp", aud: "api", scope: "read" }, { alg: "none" });
  await withEnv({ T_A: bad, T_B: undefined }, async () => {
    const findings = await runTokenProbes(baseConfig());
    assert.equal(byId(findings, "TOKEN-ALG").status, "fail");
    assert.equal(byId(findings, "TOKEN-LIFETIME").status, "fail", "no exp claim is a failure, not a warning");
    assert.match(byId(findings, "TOKEN-LIFETIME").evidence, /NO exp CLAIM/);
  });
});

test("token probes warn on an over-long lifetime and pass a short one", async () => {
  const long = jwt({ sub: "a", iat: NOW, exp: NOW + 30 * 24 * 3600, iss: "i", aud: "a", scope: "read" });
  await withEnv({ T_A: long, T_B: undefined }, async () => {
    assert.equal(byId(await runTokenProbes(baseConfig()), "TOKEN-LIFETIME").status, "warn");
  });
  const short = jwt({ sub: "a", iat: NOW, exp: NOW + 900, iss: "i", aud: "a", scope: "read" });
  await withEnv({ T_A: short, T_B: undefined }, async () => {
    const findings = await runTokenProbes(baseConfig());
    assert.equal(byId(findings, "TOKEN-LIFETIME").status, "pass");
    assert.equal(byId(findings, "TOKEN-ALG").status, "pass");
  });
});

test("token probes flag an already-expired test token", async () => {
  const expired = jwt({ sub: "a", iat: NOW - 7200, exp: NOW - 60, iss: "i", aud: "a", scope: "read" });
  await withEnv({ T_A: expired, T_B: undefined }, async () => {
    const freshness = byId(await runTokenProbes(baseConfig()), "TOKEN-FRESHNESS");
    assert.equal(freshness.status, "warn");
    assert.match(freshness.evidence, /may reflect rejected credentials/);
  });
});

test("token probes fail an admin or wildcard scope on a test identity", async () => {
  for (const scope of ["read admin", "*", ["profile", "full_access"]]) {
    const token = jwt({ sub: "a", iat: NOW, exp: NOW + 600, iss: "i", aud: "a", scope });
    await withEnv({ T_A: token, T_B: undefined }, async () => {
      assert.equal(byId(await runTokenProbes(baseConfig()), "TOKEN-SCOPE").status, "fail", `scope ${scope} must fail`);
    });
  }
});

test("token probes catch two identities that are secretly the same principal", async () => {
  const same = { iat: NOW, exp: NOW + 600, iss: "i", aud: "a", scope: "read", sub: "user-a" };
  await withEnv({ T_A: jwt(same), T_B: jwt({ ...same, jti: "different-token" }) }, async () => {
    const distinct = byId(await runTokenProbes(baseConfig()), "TOKEN-IDENTITY-DISTINCT");
    assert.equal(distinct.status, "fail");
    assert.match(distinct.evidence, /SAME principal/);
    assert.match(distinct.remediation, /prove nothing/);
  });
  await withEnv({ T_A: jwt({ ...same, sub: "user-a" }), T_B: jwt({ ...same, sub: "user-b" }) }, async () => {
    assert.equal(byId(await runTokenProbes(baseConfig()), "TOKEN-IDENTITY-DISTINCT").status, "pass");
  });
});

test("token probes warn when both identities share a tenant", async () => {
  const base = { iat: NOW, exp: NOW + 600, iss: "i", aud: "a", scope: "read" };
  await withEnv({ T_A: jwt({ ...base, sub: "a", tenant: "t1" }), T_B: jwt({ ...base, sub: "b", tenant: "t1" }) }, async () => {
    const tenant = byId(await runTokenProbes(baseConfig()), "TOKEN-TENANT-DISTINCT");
    assert.equal(tenant.status, "warn");
    assert.match(tenant.remediation, /same tenant/);
  });
});

test("token probes compare issuer and audience against config when given", async () => {
  const token = jwt({ sub: "a", iat: NOW, exp: NOW + 600, iss: "https://wrong-idp", aud: "other-api", scope: "read" });
  const config = { ...baseConfig(), tokens: { expectedIssuer: "https://idp.example.com", expectedAudience: "my-api" } };
  await withEnv({ T_A: token, T_B: undefined }, async () => {
    const claims = byId(await runTokenProbes(config), "TOKEN-CLAIMS");
    assert.equal(claims.status, "warn");
    assert.match(claims.evidence, /expected https:\/\/idp\.example\.com/);
  });
});

test("token probes issue no HTTP requests at all", async () => {
  const token = jwt({ sub: "a", iat: NOW, exp: NOW + 600, iss: "i", aud: "a", scope: "read" });
  await withEnv({ T_A: token, T_B: undefined }, async () => {
    const originalFetch = globalThis.fetch;
    let called = 0;
    globalThis.fetch = async () => {
      called += 1;
      return new Response("{}");
    };
    try {
      await runTokenProbes(baseConfig());
      assert.equal(called, 0, "token probes must never touch the network");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ── Injection helpers ───────────────────────────────────────────────
test("discoverParams reads real parameters from links and forms before falling back", () => {
  const html = `<a href="/search?q=x&amp;sort=desc">s</a><form action="/f"><input name="email"/></form>
                <a href="https://evil.example.net/?leak=1">off-site</a>`;
  const params = discoverParams(html, "https://dev.example.com/", 6);
  assert.ok(params.includes("q") && params.includes("sort"), "query keys from same-origin links");
  assert.ok(params.includes("email"), "form input names");
  assert.ok(!params.includes("leak"), "cross-origin links must be ignored");
});

test("discoverParams still yields conventional parameters for a static page", () => {
  const params = discoverParams("<html><body>nothing</body></html>", "https://dev.example.com/", 4);
  assert.equal(params.length, 4);
  assert.ok(params.includes("q"));
});

// ── Catalog and wiring ──────────────────────────────────────────────
test("every new probe ID is catalogued and mapped to a domain", () => {
  const ids = [
    "TOKEN-ALG", "TOKEN-LIFETIME", "TOKEN-CLAIMS", "TOKEN-SCOPE", "TOKEN-FRESHNESS",
    "TOKEN-IDENTITY-DISTINCT", "TOKEN-TENANT-DISTINCT",
    "INJECT-REFLECTED-XSS", "INJECT-SQL-ERROR", "INJECT-TEMPLATE", "INJECT-PATH-TRAVERSAL",
    "INJECT-CRLF-HEADER", "INJECT-HOST-HEADER", "INJECT-SSRF",
    "WEB-HTTP-METHODS", "WEB-SERVER-BANNER", "WEB-SUBRESOURCE-INTEGRITY", "WEB-COOKIE-SCOPE",
    "WEB-CACHE-CONTROL", "WEB-DIRECTORY-LISTING",
    "API-INVENTORY-EXPOSED", "API-EXCESSIVE-DATA", "API-QUERY-COST",
    "SESSION-LOGOUT", "SESSION-EXPIRED-TOKEN",
  ];
  for (const id of ids) {
    const meta = getTestMeta(id);
    assert.notEqual(meta.category, "Other", `${id} is not catalogued`);
    assert.ok(meta.purpose.length > 20, `${id} has no usable purpose`);
    assert.notEqual(domainForId(id), "Platform", `${id} falls back to the Platform domain`);
  }
});

test("injection maps to Input Handling and error handling no longer sits under LLM Safety", () => {
  assert.equal(domainForId("INJECT-SQL-ERROR"), "Input Handling");
  assert.equal(domainForId("API-ERROR-DISCLOSURE"), "Infrastructure");
  assert.equal(domainForId("TOKEN-ALG"), "Authentication");
  assert.equal(domainForId("TOKEN-IDENTITY-DISTINCT"), "Assessment Integrity");
});

test("new modules are wired into the right profiles", () => {
  const names = BUILTIN_PROBES.map((p) => p.name);
  assert.ok(names.includes("token") && names.includes("injection"));
  assert.ok(PROFILES.passive.modules.includes("injection"), "injection is unauthenticated, so it belongs in passive");
  assert.ok(!PROFILES.passive.modules.includes("token"), "token probes need credentials");
  for (const profile of ["authenticated", "agent"]) {
    assert.ok(PROFILES[profile].modules.includes("token"), `${profile} holds tokens, so it should inspect them`);
  }
  for (const module of ["token", "injection"]) assert.ok(PROFILES.all.modules.includes(module));
});
