/**
 * Session-lifecycle verdicts.
 *
 * These two controls carry the highest severity in the API suite, and both used to conclude
 * from the *absence* of a rejection. A partner's AppSync answered HTTP 400 because the probe
 * sent a GraphQL request with no document, and the probe reported a critical failure — a false
 * alarm on the most serious control in the run. The rule that prevents the whole class: a
 * finding needs positive evidence, and anything else says so.
 */
import test from "node:test";
import assert from "node:assert/strict";

import { runApiProbes } from "../src/probes/api.mjs";
import { SafeHttpClient, DEFAULT_SAFETY } from "../src/safety.mjs";

const config = (overrides = {}) => ({
  name: "unit",
  environment: "dev",
  targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com"] },
  safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50 },
  api: {
    kind: "graphql",
    endpoint: "https://dev.example.com/graphql",
    tokenA: "userA",
    session: { verifyEndpoint: "/graphql", expiredTokenEnv: "TRUST_TEST_EXPIRED", ...overrides },
  },
});

/**
 * The API suite issues many requests, so a stub that counts them is answering the wrong ones.
 * These stubs decide from the request itself: which token carried it, and whether logout has
 * happened yet.
 */
function harness(handler, cfg = config()) {
  const client = new SafeHttpClient(cfg);
  client.credentials = new Map([["userA", { name: "userA", kind: "bearer", token: "live-token", scheme: "Bearer" }]]);
  const sent = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const auth = (init.headers && (init.headers.authorization ?? init.headers.Authorization)) || "";
    const body = init.body ? JSON.parse(init.body) : null;
    const request = { url: String(url), auth, body, withExpiredToken: auth.includes("expired.token.value") };
    sent.push(request);
    return handler(request) ?? json({ data: { __typename: "Query" } });
  };
  return { client, sent, cfg, restore: () => { globalThis.fetch = original; } };
}

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const run = async (h) => {
  try {
    return await runApiProbes(h.cfg, h.client);
  } finally {
    h.restore();
  }
};
const expired = (findings) => findings.find((f) => f.id === "SESSION-EXPIRED-TOKEN");

test.beforeEach(() => {
  process.env.TRUST_TEST_EXPIRED = "expired.token.value";
});
test.after(() => {
  delete process.env.TRUST_TEST_EXPIRED;
});

test("a GraphQL session check sends a document, not an empty body", async () => {
  const h = harness(() => json({ data: { __typename: "Query" } }));
  await run(h);
  // Sending {method:"GET", path} at a GraphQL endpoint produced {"variables":{}}, which the
  // server rejects as malformed before it ever looks at the token.
  const sessionRequests = h.sent.filter((r) => r.withExpiredToken);
  assert.ok(sessionRequests.length > 0, "the expired-token check must actually run");
  assert.ok(sessionRequests.every((r) => typeof r.body?.query === "string" && r.body.query.length > 0));
});

test("a malformed-request rejection is not evidence that an expired token was accepted", async () => {
  const h = harness((r) => (r.withExpiredToken ? json({ errors: [{ message: "Invalid request, query can't be null", errorType: "MalformedHttpRequestException" }] }, 400) : null));
  const f = expired(await run(h));

  // The exact case a partner hit: AppSync answered 400 about the request shape, and the probe
  // called it a critical authentication failure.
  assert.equal(f.status, "warn");
  assert.equal(f.warnKind, "inconclusive");
  assert.match(f.evidence, /rejected the request itself with HTTP 400 before evaluating the token/);
  assert.match(f.remediation, /not a verdict about the token/);
});

test("only a real acceptance fails, and a real refusal passes", async () => {
  const honoured = harness(() => json({ data: { __typename: "Query" } }));
  assert.equal(expired(await run(honoured)).status, "fail");

  const refused = harness((r) => (r.withExpiredToken ? new Response("Token has expired", { status: 401 }) : null));
  assert.equal(expired(await run(refused)).status, "pass");

  // A GraphQL 200 carrying an auth error is a refusal wearing a 200.
  const softRefusal = harness((r) => (r.withExpiredToken ? json({ errors: [{ message: "Token has expired" }] }) : null));
  assert.equal(expired(await run(softRefusal)).status, "pass");

  // A 200 whose errors are about something else entirely settles nothing.
  const unrelated = harness((r) => (r.withExpiredToken ? json({ errors: [{ message: "Field 'foo' is not defined" }] }) : null));
  const f = expired(await run(unrelated));
  assert.equal(f.status, "warn");
  assert.match(f.evidence, /errors that are not about authentication/);
});

test("a 5xx is inconclusive, not an accepted token", async () => {
  const h = harness((r) => (r.withExpiredToken ? new Response("upstream unavailable", { status: 502 }) : null));
  const f = expired(await run(h));
  assert.equal(f.status, "warn");
  assert.match(f.evidence, /neither an acceptance nor a denial/);
});

test("logout concludes only when the token worked beforehand", async () => {
  const cfg = config({ logoutEndpoint: "/logout" });
  cfg.safety.allowWrites = true;

  // The token is refused throughout, so the after-state proves nothing about logout.
  const brokenSetup = harness(() => new Response("Unauthorized", { status: 401 }), cfg);
  const before = (await run(brokenSetup)).find((f) => f.id === "SESSION-LOGOUT");
  assert.equal(before.status, "warn");
  assert.match(before.evidence, /not accepted before logout either/);

  // Working before, refused after: the control holds. The stub switches on the logout call
  // itself rather than on a request count, because the suite issues many others.
  let loggedOut = false;
  const revoked = harness((r) => {
    if (r.url.includes("/logout")) {
      loggedOut = true;
      return new Response(null, { status: 204 });
    }
    return loggedOut ? new Response("Unauthorized", { status: 401 }) : json({ data: { __typename: "Query" } });
  }, config({ logoutEndpoint: "/logout" }));
  revoked.cfg.safety.allowWrites = true;
  assert.equal((await run(revoked)).find((f) => f.id === "SESSION-LOGOUT").status, "pass");

  // Working before and after: the token outlived its session.
  const survives = harness(() => json({ data: { __typename: "Query" } }), config({ logoutEndpoint: "/logout" }));
  survives.cfg.safety.allowWrites = true;
  assert.equal((await run(survives)).find((f) => f.id === "SESSION-LOGOUT").status, "fail");
});
