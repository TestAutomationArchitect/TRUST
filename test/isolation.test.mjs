import test from "node:test";
import assert from "node:assert/strict";

import { chainGate, statusIndex, activationNote } from "../src/chain.mjs";
import { runIsolationProbes, ISOLATION_TYPES } from "../src/probes/isolation.mjs";
import { runIdpProbes } from "../src/probes/idp.mjs";
import { runAgentProbes } from "../src/probes/agent.mjs";
import { SafeHttpClient, DEFAULT_SAFETY } from "../src/safety.mjs";
import { domainForId } from "../src/catalog.mjs";

const baseConfig = (overrides = {}) => ({
  name: "unit",
  environment: "dev",
  targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com", "api.dev.example.com", "files.dev.example.com", "idp.example.com", "cognito-idp.us-east-1.amazonaws.com"] },
  safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50 },
  ...overrides,
});

/** A client with a resolved credential, and fetch stubbed by a handler over the request list. */
function harness(handler, { config = baseConfig(), identities = ["userA", "userB"] } = {}) {
  const client = new SafeHttpClient(config);
  client.credentials = new Map(identities.map((name) => [name, { name, kind: "bearer", token: `token-${name}`, scheme: "Bearer", subject: `${name}@example.com`, type: "static" }]));
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init, body: init?.body ? JSON.parse(init.body) : null, auth: init?.headers?.authorization });
    return handler(url, init, calls.length);
  };
  return { client, calls, config, restore: () => { globalThis.fetch = original; } };
}

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const run = async (h, config) => {
  try {
    return await runIsolationProbes(config, h.client);
  } finally {
    h.restore();
  }
};
const byId = (findings, id) => findings.find((f) => f.id === id);

// ── The chain gate ──────────────────────────────────────────────────
test("a dependent test runs when the upstream control broke, and says so", () => {
  const statuses = statusIndex([{ id: "HIERARCHY", status: "fail" }]);
  const gate = chainGate({ dependsOn: "HIERARCHY" }, statuses);
  assert.equal(gate.run, true);
  assert.equal(gate.activatedBy, "HIERARCHY");
  assert.equal(activationNote(gate.activatedBy), "Reachable because HIERARCHY failed.");
});

test("an upstream control holding is the reason the dependent test skipped", () => {
  const gate = chainGate({ dependsOn: "HIERARCHY" }, statusIndex([{ id: "HIERARCHY", status: "pass" }]));
  assert.equal(gate.run, false);
  // "Skipped" alone reads like a gap in the assessment; this reads as a statement about the
  // system, which is what it is.
  assert.match(gate.reason, /not reachable — upstream control held \(HIERARCHY passed\)/);
});

test("a dependency on a test that did not run is reported, not silently satisfied", () => {
  const gate = chainGate({ dependsOn: "TYPO-ID" }, statusIndex([{ id: "HIERARCHY", status: "fail" }]));
  assert.equal(gate.run, false);
  assert.match(gate.reason, /did not run in this profile/);
});

test("every dependency must be met, and an unknown condition is refused", () => {
  const statuses = statusIndex([{ id: "A", status: "fail" }, { id: "B", status: "pass" }]);
  assert.equal(chainGate({ dependsOn: ["A", "B"] }, statuses).run, false);
  assert.equal(chainGate({ dependsOn: ["A"] }, statuses).run, true);
  assert.equal(chainGate({ dependsOn: "B", condition: "passed" }, statuses).run, true);
  assert.equal(chainGate({ dependsOn: "B", condition: "any" }, statuses).run, true);
  assert.match(chainGate({ dependsOn: "A", condition: "maybe" }, statuses).reason, /not one of/);
  assert.equal(chainGate({}, statuses).run, true, "no dependency means always run");
});

// ── record-ownership ────────────────────────────────────────────────
const RECORD_SPEC = {
  id: "API-CROSS-USER-RECORD",
  type: "record-ownership",
  description: "User B cannot read User A's record",
  endpoint: "https://api.dev.example.com/graphql",
  queryA: "query { listMyRecords(limit: 1) { items { id } } }",
  queryB: "query($id: ID!) { getRecord(id: $id) { id owner } }",
  tokenA: "userA",
  tokenB: "userB",
};

test("record-ownership discovers A's record and attempts it as B", async () => {
  const h = harness((url, init, n) =>
    n === 1 ? json({ data: { listMyRecords: { items: [{ id: "rec-1" }] } } }) : json({ errors: [{ message: "Not Authorized to access getRecord" }], data: null }),
  );
  const [f] = await run(h, baseConfig({ isolation: [RECORD_SPEC] }));
  assert.equal(f.status, "pass");
  assert.equal(f.severity, "high");
  assert.equal(f.domain, "Authorization", "a declared boundary is classified, not filed under Other");
  // The record ID is discovered rather than pinned, so the test survives a data reseed.
  assert.equal(h.calls[1].body.variables.id, "rec-1");
  assert.equal(h.calls[0].auth, "Bearer token-userA");
  assert.equal(h.calls[1].auth, "Bearer token-userB", "the attempt is made as the other identity");
});

test("record-ownership fails when B receives A's record", async () => {
  const h = harness((url, init, n) =>
    n === 1 ? json({ data: { listMyRecords: { items: [{ id: "rec-1" }] } } }) : json({ data: { getRecord: { id: "rec-1", owner: "user-a" } } }),
  );
  const [f] = await run(h, baseConfig({ isolation: [RECORD_SPEC] }));
  assert.equal(f.status, "fail");
  assert.equal(f.observed, "Identity B can read identity A's record");
  assert.match(f.remediation, /owner-scoped authorisation/);
});

test("a boundary with one identity skips rather than claiming anything", async () => {
  const h = harness(() => json({ data: {} }), { identities: ["userA"] });
  const [f] = await run(h, baseConfig({ isolation: [RECORD_SPEC] }));
  assert.equal(f.status, "skip");
  assert.match(f.evidence, /a boundary needs two identities/);
  assert.equal(h.calls.length, 0, "and spends nothing proving it");
});

test("an undiscoverable record skips instead of reporting a boundary that was never tested", async () => {
  const h = harness(() => json({ data: { listMyRecords: { items: [] } } }));
  const [f] = await run(h, baseConfig({ isolation: [RECORD_SPEC] }));
  assert.equal(f.status, "skip");
  assert.match(f.evidence, /could not be discovered/);
});

// ── enumeration ─────────────────────────────────────────────────────
test("enumeration fails when a list returns records owned by someone else", async () => {
  const spec = {
    id: "API-ENUMERATION",
    type: "enumeration",
    endpoint: "https://api.dev.example.com/graphql",
    query: "query { listAllRecords { items { owner } } }",
    token: "userA",
    identityClaimField: "owner",
  };
  const h = harness(() => json({ data: { listAllRecords: { items: [{ owner: "userA@example.com" }, { owner: "victim@example.com" }] } } }));
  const [f] = await run(h, baseConfig({ isolation: [spec] }));
  assert.equal(f.status, "fail");
  assert.match(f.evidence, /2 distinct "owner" value\(s\).*for caller userA@example.com/s);
});

test("enumeration passes when the endpoint refuses outright", async () => {
  const spec = { id: "API-ENUMERATION", type: "enumeration", endpoint: "https://api.dev.example.com/graphql", query: "query { listAllRecords { items { owner } } }", token: "userA" };
  const h = harness(() => new Response("Forbidden", { status: 403 }));
  const [f] = await run(h, baseConfig({ isolation: [spec] }));
  assert.equal(f.status, "pass");
});

test("enumeration is inconclusive, not passing, when ownership cannot be established", async () => {
  const spec = { id: "API-ENUMERATION", type: "enumeration", endpoint: "https://api.dev.example.com/graphql", query: "query { listAllRecords { items { title } } }", token: "userA" };
  const h = harness(() => json({ data: { listAllRecords: { items: [{ title: "x" }] } } }));
  const [f] = await run(h, baseConfig({ isolation: [spec] }));
  assert.equal(f.status, "warn");
  assert.match(f.evidence, /carried no "owner" field/);
});

// ── mutation-guard ──────────────────────────────────────────────────
test("mutation-guard runs under allowDenialTests and passes on refusal", async () => {
  const spec = {
    id: "API-SELF-ESCALATION",
    type: "mutation-guard",
    endpoint: "https://api.dev.example.com/graphql",
    mutation: "mutation($input: UpdatePermissionsInput!) { updatePermissions(input: $input) { id } }",
    variables: { input: { id: "FAKE", allowedResources: ["ALL"] } },
    token: "userA",
  };
  const config = baseConfig({ isolation: [spec], safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50, allowDenialTests: true } });
  const h = harness(() => json({ errors: [{ message: "Unauthorized" }] }), { config });
  const [f] = await run(h, config);
  assert.equal(f.status, "pass");
});

test("mutation-guard is blocked, not silently skipped, when denial tests are off", async () => {
  const spec = { id: "API-SELF-ESCALATION", type: "mutation-guard", endpoint: "https://api.dev.example.com/graphql", mutation: "mutation { x }", token: "userA" };
  const h = harness(() => json({ data: { x: 1 } }));
  const [f] = await run(h, baseConfig({ isolation: [spec] }));
  // The guard refuses the request; the probe reports why rather than crashing the module.
  assert.equal(f.status, "warn");
  assert.match(f.evidence, /allowDenialTests/);
  assert.equal(h.calls.length, 0);
});

// ── identity-injection ──────────────────────────────────────────────
test("identity-injection fails when the server acts as the injected identity", async () => {
  const spec = {
    id: "API-IDENTITY-INJECTION",
    type: "identity-injection",
    endpoint: "https://api.dev.example.com/graphql",
    query: "query($input: InvokeInput!) { invoke(input: $input) }",
    variables: { input: { prompt: "hello", userid: "victim@example.com" } },
    token: "userA",
    injectedField: "userid",
    injectedValue: "victim@example.com",
    successIndicators: ["active_userid.*victim"],
    severity: "critical",
  };
  const h = harness(() => json({ data: { invoke: "active_userid=victim@example.com" } }));
  const [f] = await run(h, baseConfig({ isolation: [spec] }));
  assert.equal(f.status, "fail");
  assert.equal(f.severity, "critical");
  assert.equal(domainForId("API-IDENTITY-INJECTION"), "Platform", "the ID is unknown to the catalogue…");
  assert.equal(f.domain, "Identity Binding", "…so the probe classifies the finding itself");
});

test("identity-injection without indicators warns rather than passing on silence", async () => {
  const spec = { id: "API-IDENTITY-INJECTION", type: "identity-injection", endpoint: "https://api.dev.example.com/graphql", query: "query { x }", token: "userA", injectedField: "userid" };
  const h = harness(() => json({ data: { x: "ok" } }));
  const [f] = await run(h, baseConfig({ isolation: [spec] }));
  assert.equal(f.status, "warn");
  assert.match(f.remediation, /No successIndicators were declared/);
});

// ── prefix-scoped-storage ───────────────────────────────────────────
test("prefix-scoped-storage fails when one tenant can list another's prefix", async () => {
  const spec = {
    id: "STORAGE-CROSS-TENANT-DECLARED",
    type: "prefix-scoped-storage",
    baseUrl: "https://files.dev.example.com/",
    pathPattern: "protected/{tenant}/",
    tenantA: "tenant-a",
    tenantB: "tenant-b",
    tokenA: "userA",
    tokenB: "userB",
  };
  const h = harness(() => new Response("<ListBucketResult><Key>protected/tenant-b/report.pdf</Key></ListBucketResult>"));
  const [f] = await run(h, baseConfig({ isolation: [spec] }));
  assert.equal(f.status, "fail");
  assert.match(f.evidence, /LIST protected\/tenant-b\//);
  assert.match(f.remediation, /bucket policy or IAM condition/);
});

test("identical tenants skip — the boundary would be tested against itself", async () => {
  const spec = { id: "STORAGE-CROSS-TENANT-DECLARED", type: "prefix-scoped-storage", baseUrl: "https://files.dev.example.com/", tenantA: "same", tenantB: "same", tokenA: "userA", tokenB: "userB" };
  const h = harness(() => new Response("ok"));
  const [f] = await run(h, baseConfig({ isolation: [spec] }));
  assert.equal(f.status, "skip");
  assert.match(f.evidence, /both tenants resolve to "same"/);
});

// ── Chaining between declared boundaries ────────────────────────────
test("a chained boundary runs only when its upstream broke, and records why", async () => {
  const specs = [
    { ...RECORD_SPEC, id: "UPSTREAM" },
    { id: "DOWNSTREAM", type: "enumeration", endpoint: "https://api.dev.example.com/graphql", query: "query { listAll { items { owner } } }", token: "userA", dependsOn: "UPSTREAM" },
  ];

  // Upstream fails → downstream runs, carrying the reason it was reachable.
  const breached = harness((url, init, n) => {
    if (n === 1) return json({ data: { listMyRecords: { items: [{ id: "rec-1" }] } } });
    if (n === 2) return json({ data: { getRecord: { id: "rec-1", owner: "user-a" } } });
    return json({ data: { listAll: { items: [{ owner: "a@example.com" }, { owner: "b@example.com" }] } } });
  });
  const chained = await run(breached, baseConfig({ isolation: specs }));
  assert.equal(byId(chained, "UPSTREAM").status, "fail");
  assert.equal(byId(chained, "DOWNSTREAM").status, "fail");
  assert.equal(byId(chained, "DOWNSTREAM").activatedBy, "UPSTREAM");
  assert.match(byId(chained, "DOWNSTREAM").evidence, /Reachable because UPSTREAM failed\./);

  // Upstream holds → downstream never fires, and the skip explains the system, not the tool.
  const held = harness((url, init, n) => (n === 1 ? json({ data: { listMyRecords: { items: [{ id: "rec-1" }] } } }) : new Response("Forbidden", { status: 403 })));
  const gated = await run(held, baseConfig({ isolation: specs }));
  assert.equal(byId(gated, "UPSTREAM").status, "pass");
  assert.equal(byId(gated, "DOWNSTREAM").status, "skip");
  assert.match(byId(gated, "DOWNSTREAM").evidence, /upstream control held/);
  assert.equal(held.calls.length, 2, "and the downstream request is never issued");
});

test("a chain may depend on a finding from another probe module", async () => {
  const spec = { id: "DOWNSTREAM", type: "enumeration", endpoint: "https://api.dev.example.com/graphql", query: "query { listAll { items { owner } } }", token: "userA", dependsOn: "API-CROSS-USER" };
  const h = harness(() => json({ data: { listAll: { items: [{ owner: "userA@example.com" }] } } }));
  try {
    const findings = await runIsolationProbes(baseConfig({ isolation: [spec] }), h.client, {
      findings: [{ id: "API-CROSS-USER", status: "fail" }],
    });
    assert.equal(findings[0].status, "pass");
    assert.equal(findings[0].activatedBy, "API-CROSS-USER");
  } finally {
    h.restore();
  }
});

// ── Spec hygiene ────────────────────────────────────────────────────
test("an unknown boundary type names the ones that exist", async () => {
  const h = harness(() => new Response("ok"));
  const [f] = await run(h, baseConfig({ isolation: [{ id: "X", type: "telepathy", endpoint: "https://api.dev.example.com/" }] }));
  assert.equal(f.status, "skip");
  for (const type of ISOLATION_TYPES) assert.match(f.evidence, new RegExp(type));
});

test("no declared boundaries is a skip, not an empty pass", async () => {
  const findings = await runIsolationProbes(baseConfig(), new SafeHttpClient(baseConfig()));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].status, "skip");
});

// ── IdP pack ────────────────────────────────────────────────────────
const DISCOVERY = {
  issuer: "https://idp.example.com",
  code_challenge_methods_supported: ["S256"],
  response_types_supported: ["code"],
  token_endpoint_auth_methods_supported: ["client_secret_basic"],
};

test("the IdP pack reads the discovery document and passes a sound configuration", async () => {
  const config = baseConfig({ idp: { issuer: "https://idp.example.com" } });
  const h = harness(() => json(DISCOVERY), { config });
  try {
    const findings = await runIdpProbes(config, h.client);
    assert.equal(byId(findings, "IDP-DISCOVERY").status, "pass");
    assert.equal(byId(findings, "IDP-PKCE-SUPPORTED").status, "pass");
    assert.equal(byId(findings, "IDP-IMPLICIT-FLOW").status, "pass");
    assert.equal(byId(findings, "IDP-CLIENT-AUTH").status, "pass");
    // A network harness cannot honestly claim these, so they carry the manual procedure.
    assert.match(byId(findings, "IDP-SESSION-FIXATION").evidence, /requires a browser/);
  } finally {
    h.restore();
  }
});

test("the IdP pack catches an implicit flow, plain-only PKCE and an unauthenticated token endpoint", async () => {
  const config = baseConfig({ idp: { issuer: "https://idp.example.com" } });
  const h = harness(
    () =>
      json({
        issuer: "https://idp.example.com",
        code_challenge_methods_supported: ["plain"],
        response_types_supported: ["code", "token", "id_token token"],
        token_endpoint_auth_methods_supported: ["none"],
      }),
    { config },
  );
  try {
    const findings = await runIdpProbes(config, h.client);
    assert.equal(byId(findings, "IDP-PKCE-SUPPORTED").status, "warn");
    assert.match(byId(findings, "IDP-PKCE-SUPPORTED").observed, /only as plain/);
    assert.equal(byId(findings, "IDP-IMPLICIT-FLOW").status, "warn");
    // Public client plus no PKCE is the combination that actually matters.
    assert.equal(byId(findings, "IDP-CLIENT-AUTH").status, "fail");
    assert.equal(byId(findings, "IDP-CLIENT-AUTH").severity, "high");
  } finally {
    h.restore();
  }
});

test("the IdP pack inspects the application's own authorisation request", async () => {
  const config = baseConfig({ idp: { issuer: "https://idp.example.com", loginUrl: "https://dev.example.com/login" } });
  const h = harness((url) => {
    if (String(url).includes("openid-configuration")) return json(DISCOVERY);
    return new Response("", {
      status: 302,
      headers: { location: "https://idp.example.com/authorize?response_type=token&client_id=abc&redirect_uri=https%3A%2F%2Fdev.example.com%2Fcb" },
    });
  }, { config });
  try {
    const findings = await runIdpProbes(config, h.client);
    const authorize = byId(findings, "IDP-AUTHORIZE-REQUEST");
    // What the provider supports and what the application asks for are different questions.
    assert.equal(authorize.status, "fail");
    assert.match(authorize.observed, /response_type=token/);
    assert.match(authorize.evidence, /code_challenge: \(absent\)/);
  } finally {
    h.restore();
  }
});

test("a live Cognito password grant is a critical failure, a rejected flow is a pass", async () => {
  const config = baseConfig({ idp: { cognito: { clientId: "abc", region: "us-east-1" } } });
  const live = harness(() => json({ __type: "NotAuthorizedException", message: "Incorrect username or password." }, 400), { config });
  try {
    const findings = await runIdpProbes(config, live.client);
    const f = byId(findings, "IDP-PASSWORD-GRANT");
    assert.equal(f.status, "fail");
    assert.equal(f.severity, "critical");
    assert.match(f.evidence, /the pool checked credentials/);
    // A non-existent principal is used deliberately: nothing real can be locked out.
    assert.match(live.calls[0].body.AuthParameters.USERNAME, /example\.invalid$/);
  } finally {
    live.restore();
  }

  const closed = harness(() => json({ __type: "InvalidParameterException", message: "USER_PASSWORD_AUTH flow not enabled for this client" }, 400), { config });
  try {
    const findings = await runIdpProbes(config, closed.client);
    assert.equal(byId(findings, "IDP-PASSWORD-GRANT").status, "pass");
  } finally {
    closed.restore();
  }
});

test("the Cognito check defers when the generic password-grant probe already covers it", async () => {
  const config = baseConfig({
    idp: { cognito: { clientId: "abc", region: "us-east-1" } },
    api: { endpoint: "https://api.dev.example.com/graphql", passwordAuth: { endpoint: "https://idp.example.com/token" } },
  });
  const h = harness(() => json({}), { config });
  try {
    const findings = await runIdpProbes(config, h.client);
    // Two findings saying the same thing is worse than one.
    assert.equal(byId(findings, "IDP-PASSWORD-GRANT").status, "skip");
    assert.match(byId(findings, "IDP-PASSWORD-GRANT").evidence, /AUTH-PASSWORD-BYPASS/);
    assert.equal(h.calls.length, 0);
  } finally {
    h.restore();
  }
});

// ── Declared agent endpoints (the simple form of a tier map) ────────
test("a declared agent endpoint is denied-by-default, and its dependents gate on the breach", async () => {
  const config = baseConfig({
    safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50, allowAgentInvocations: true },
    agent: {
      runtimeEndpoint: "https://api.dev.example.com/invoke",
      accessTokenA: "userA",
      allowedAgentId: "orchestrator",
      endpoints: [
        { name: "coordinator", agentId: "coord-a", expectDenied: true },
        // Whether a sub-agent enforces its own guardrails only matters if it can be reached.
        { name: "coordinator-guardrail", agentId: "coord-a", expectDenied: false, expectPatterns: ["ACCESS-DENIED"], dependsOn: "AGENT-ENDPOINT-COORDINATOR" },
      ],
    },
  });

  const reachable = harness((url, init) => (JSON.parse(init.body).agentId === "coord-a" ? json({ reply: "ACCESS-DENIED" }) : json({ reply: "ok" })), { config });
  let findings;
  try {
    findings = await runAgentProbes(config, reachable.client);
  } finally {
    reachable.restore();
  }
  const breach = byId(findings, "AGENT-ENDPOINT-COORDINATOR");
  assert.equal(breach.status, "fail", "an internal tier that accepts an end-user token has no boundary of its own");
  assert.equal(breach.severity, "critical");
  const downstream = byId(findings, "AGENT-ENDPOINT-COORDINATOR-GUARDRAIL");
  assert.equal(downstream.status, "pass", "reached, and it refused as its own control requires");
  assert.equal(downstream.activatedBy, "AGENT-ENDPOINT-COORDINATOR");
  assert.match(downstream.evidence, /Reachable because AGENT-ENDPOINT-COORDINATOR failed\./);

  const guarded = harness(() => new Response("Access denied", { status: 403 }), { config });
  try {
    findings = await runAgentProbes(config, guarded.client);
  } finally {
    guarded.restore();
  }
  assert.equal(byId(findings, "AGENT-ENDPOINT-COORDINATOR").status, "pass");
  assert.equal(byId(findings, "AGENT-ENDPOINT-COORDINATOR-GUARDRAIL").status, "skip");
  assert.match(byId(findings, "AGENT-ENDPOINT-COORDINATOR-GUARDRAIL").evidence, /not reachable — upstream control held/);
});
