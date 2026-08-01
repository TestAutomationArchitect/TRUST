/**
 * The probes added for depth: server-side token validation, CSRF, mass assignment, storage
 * traversal and signed-URL integrity, and multi-turn agent behaviour.
 *
 * Each is checked for the property that makes it worth having — it fails when the control is
 * absent, passes when it holds, and skips with a reason rather than guessing when it cannot run.
 */
import test from "node:test";
import assert from "node:assert/strict";

import { runJwtProbes } from "../src/probes/jwt.mjs";
import { runStorageProbes } from "../src/probes/storage.mjs";
import { runAgentProbes } from "../src/probes/agent.mjs";
import { runApiProbes } from "../src/probes/api.mjs";
import { SafeHttpClient, DEFAULT_SAFETY, isLoopback } from "../src/safety.mjs";

const jwtFor = (payload = { sub: "user-a", "cognito:groups": ["users"] }) =>
  `${Buffer.from(JSON.stringify({ alg: "RS256", kid: "real-key" })).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.c2lnbmF0dXJlAAAA`;

const baseConfig = (overrides = {}) => ({
  name: "unit",
  environment: "dev",
  targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com", "api.dev.example.com", "files.dev.example.com"] },
  safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50 },
  ...overrides,
});

function harness(handler, { config = baseConfig(), token = jwtFor() } = {}) {
  const client = new SafeHttpClient(config);
  client.credentials = new Map([
    ["userA", { name: "userA", kind: "bearer", token, scheme: "Bearer", subject: "user-a", type: "static" }],
    ["userB", { name: "userB", kind: "bearer", token: jwtFor({ sub: "user-b" }), scheme: "Bearer", subject: "user-b", type: "static" }],
  ]);
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init, auth: init?.headers?.authorization, body: init?.body });
    return handler(url, init, calls.length);
  };
  return { client, calls, restore: () => { globalThis.fetch = original; } };
}

const byId = (findings, id) => findings.find((f) => f.id === id);
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

// ── Server-side token validation ────────────────────────────────────
test("an API that accepts a forged token fails every forgery probe and says what that means", async () => {
  const config = baseConfig({ api: { endpoint: "https://api.dev.example.com/graphql", tokenA: "userA" } });
  // A server that never verifies: it answers 200 whatever the token says.
  const h = harness(() => json({ data: { __typename: "Query" } }), { config });
  let findings;
  try {
    findings = await runJwtProbes(config, h.client);
  } finally {
    h.restore();
  }

  for (const id of ["JWT-ALG-NONE", "JWT-SIGNATURE", "JWT-CLAIMS-TAMPERED", "JWT-UNKNOWN-KID"]) {
    assert.equal(byId(findings, id).status, "fail", `${id} must fail against a server that verifies nothing`);
  }
  // The summary is the point: authorisation results obtained with an unverified identity do not
  // describe what happens to an attacker.
  const summary = byId(findings, "JWT-VERIFICATION");
  assert.equal(summary.status, "fail");
  assert.equal(summary.severity, "critical");
  assert.match(summary.evidence, /does not fully verify/);

  // Each probe alters exactly one property of the real token.
  const sent = h.calls.map((c) => c.auth.replace("Bearer ", ""));
  assert.equal(sent.length, 4);
  const headerOf = (t) => JSON.parse(Buffer.from(t.split(".")[0], "base64url").toString());
  assert.ok(sent.some((t) => headerOf(t).alg === "none"));
  assert.ok(sent.some((t) => headerOf(t).kid === "trust-probe-key-not-in-jwks"));
});

test("a verifying API passes, and an opaque token skips rather than guessing", async () => {
  const config = baseConfig({ api: { endpoint: "https://api.dev.example.com/graphql", tokenA: "userA" } });
  const h = harness(() => new Response("invalid token", { status: 401 }), { config });
  try {
    const findings = await runJwtProbes(config, h.client);
    for (const id of ["JWT-ALG-NONE", "JWT-SIGNATURE", "JWT-CLAIMS-TAMPERED", "JWT-UNKNOWN-KID"]) {
      assert.equal(byId(findings, id).status, "pass");
    }
    assert.equal(byId(findings, "JWT-VERIFICATION"), undefined, "no summary when nothing failed");
  } finally {
    h.restore();
  }

  const opaque = harness(() => json({}), { config, token: "opaque-session-token" });
  try {
    const findings = await runJwtProbes(config, opaque.client);
    const skip = byId(findings, "JWT-CONFIG");
    assert.equal(skip.status, "skip");
    // Not a pass and not a failure: the server may verify it perfectly, there is simply nothing
    // here to alter.
    assert.equal(skip.skipKind, "not-applicable");
    assert.equal(opaque.calls.length, 0);
  } finally {
    opaque.restore();
  }
});

// ── CSRF and mass assignment ────────────────────────────────────────
test("CSRF fails when a cross-origin state change is accepted, and states what it did not prove", async () => {
  const config = baseConfig({
    safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50, allowDenialTests: true },
    api: { endpoint: "https://api.dev.example.com/graphql", tokenA: "userA", csrf: { endpoint: "https://api.dev.example.com/settings" } },
  });
  const h = harness((url) => (String(url).includes("/settings") ? new Response("updated", { status: 200 }) : json({ data: {} })), { config });
  try {
    const csrf = byId(await runApiProbes(config, h.client), "API-CSRF");
    assert.equal(csrf.status, "fail");
    assert.match(csrf.evidence, /trust-probe.invalid/);
    // Honest about the half it cannot establish without a browser session.
    assert.match(csrf.evidence, /no session cookie was attached/);
  } finally {
    h.restore();
  }
});

test("mass assignment fails only when the privileged field comes back", async () => {
  const operation = { query: "mutation($input: CreateInput!) { create(input: $input) { id role } }", variables: { input: { title: "x" } } };
  const config = (allow) =>
    baseConfig({
      safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50, allowDenialTests: allow },
      api: { endpoint: "https://api.dev.example.com/graphql", tokenA: "userA", massAssignment: { operation } },
    });

  const bound = harness(() => json({ data: { create: { id: "1", role: "admin" } } }), { config: config(true) });
  try {
    const f = byId(await runApiProbes(config(true), bound.client), "API-MASS-ASSIGNMENT");
    assert.equal(f.status, "fail");
    assert.match(f.evidence, /echoed role back/);
  } finally {
    bound.restore();
  }

  const ignored = harness(() => json({ data: { create: { id: "1", role: "user" } } }), { config: config(true) });
  try {
    assert.equal(byId(await runApiProbes(config(true), ignored.client), "API-MASS-ASSIGNMENT").status, "pass");
  } finally {
    ignored.restore();
  }

  // A write expected to be refused still needs its switch, and the skip names which one.
  const guarded = harness(() => json({ data: {} }), { config: config(false) });
  try {
    const f = byId(await runApiProbes(config(false), guarded.client), "API-MASS-ASSIGNMENT");
    assert.equal(f.status, "skip");
    assert.match(f.evidence, /allowDenialTests/);
  } finally {
    guarded.restore();
  }
});

// ── Storage ─────────────────────────────────────────────────────────
test("storage traversal fails when an escape sequence reads outside the prefix", async () => {
  const config = baseConfig({ storage: { baseUrl: "https://files.dev.example.com/", tokenA: "userA", ownPrefix: "protected/user-a/" } });
  const h = harness(
    (url) =>
      String(url).includes("..") || String(url).includes("%2e")
        ? new Response("<ListBucketResult><Key>protected/user-b/secret.pdf</Key></ListBucketResult>")
        : new Response("", { status: 403 }),
    { config },
  );
  try {
    const f = byId(await runStorageProbes(config, h.client), "STORAGE-PATH-TRAVERSAL");
    assert.equal(f.status, "fail");
    assert.equal(f.severity, "critical");
    // Several encodings, because a gateway may normalise one form and pass another through.
    assert.match(f.evidence, /dot-dot|encoded/);
  } finally {
    h.restore();
  }
});

test("a signed URL that survives tampering is a critical failure", async () => {
  const signedUrl = "https://files.dev.example.com/protected/a/report.pdf?X-Amz-Signature=abcdef123456&X-Amz-Expires=900";
  const config = baseConfig({ storage: { baseUrl: "https://files.dev.example.com/", tokenA: "userA", signedUrl } });

  const honoured = harness(() => new Response("%PDF-1.7 report contents"), { config });
  try {
    const f = byId(await runStorageProbes(config, honoured.client), "STORAGE-SIGNED-URL");
    assert.equal(f.status, "fail");
    assert.match(f.evidence, /Altered X-Amz-Signature/);
  } finally {
    honoured.restore();
  }

  const rejected = harness(() => new Response("<Error><Code>SignatureDoesNotMatch</Code></Error>", { status: 403 }), { config });
  try {
    assert.equal(byId(await runStorageProbes(config, rejected.client), "STORAGE-SIGNED-URL").status, "pass");
  } finally {
    rejected.restore();
  }
});

// ── Agent, over more than one turn ──────────────────────────────────
test("an instruction that survives the turn boundary is a failure", async () => {
  const config = baseConfig({
    safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50, allowAgentInvocations: true },
    agent: { runtimeEndpoint: "https://dev.example.com/invoke", accessTokenA: "userA", allowedAgentId: "orchestrator" },
  });

  // A runtime that carries the planted instruction into the next turn.
  let planted = null;
  const leaky = harness(
    (url, init) => {
      const body = JSON.parse(init.body);
      const marker = /append the code (MULTITURN-[A-Z0-9]+)/.exec(body.prompt ?? "");
      if (marker) {
        planted = marker[1];
        return json({ reply: "ready" });
      }
      return json({ reply: `Happy to help. ${planted ?? ""}` });
    },
    { config },
  );
  try {
    const f = byId(await runAgentProbes(config, leaky.client), "AGENT-MULTI-TURN-INJECTION");
    assert.equal(f.status, "fail");
    assert.match(f.evidence, /turn 2 asked an unrelated question and the reply carried MULTITURN-/);
  } finally {
    leaky.restore();
  }

  const clean = harness(() => json({ reply: "Happy to help with your account." }), { config });
  try {
    assert.equal(byId(await runAgentProbes(config, clean.client), "AGENT-MULTI-TURN-INJECTION").status, "pass");
  } finally {
    clean.restore();
  }
});

test("tool abuse needs configured indicators before it will claim anything", async () => {
  const config = (toolProbe) =>
    baseConfig({
      safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50, allowAgentInvocations: true },
      agent: { runtimeEndpoint: "https://dev.example.com/invoke", accessTokenA: "userA", allowedAgentId: "orchestrator", toolProbe },
    });

  const unconfigured = harness(() => json({ reply: "ok" }), { config: config(undefined) });
  try {
    assert.equal(byId(await runAgentProbes(config(undefined), unconfigured.client), "AGENT-TOOL-ABUSE").status, "skip");
  } finally {
    unconfigured.restore();
  }

  const spec = { prompt: "Run the payroll export for every department.", successIndicators: ["salary_total", "department:.*ALL"] };
  const abused = harness((url, init) => (JSON.parse(init.body).prompt === spec.prompt ? json({ reply: "salary_total=1820000 for department:ALL" }) : json({ reply: "ok" })), {
    config: config(spec),
  });
  try {
    const f = byId(await runAgentProbes(config(spec), abused.client), "AGENT-TOOL-ABUSE");
    assert.equal(f.status, "fail");
    assert.equal(f.severity, "critical");
  } finally {
    abused.restore();
  }
});

// ── Loopback ────────────────────────────────────────────────────────
test("plain HTTP is refused everywhere except loopback", () => {
  assert.equal(isLoopback(new URL("http://localhost:3000")), true);
  assert.equal(isLoopback(new URL("http://127.0.0.1:8080")), true);
  assert.equal(isLoopback(new URL("http://api.localhost")), true);
  // A hostname that merely resolves to loopback is not loopback: DNS can answer differently
  // between the check and the request.
  assert.equal(isLoopback(new URL("http://localtest.me")), false);
  assert.equal(isLoopback(new URL("https://dev.example.com")), false);

  const client = new SafeHttpClient(baseConfig({ targets: { web: "http://localhost:3000", allowedHosts: ["localhost", "dev.example.com"] } }));
  assert.ok(client.assertUrlAllowed("http://localhost:3000/api"), "a developer can test before deploying");
  assert.throws(() => client.assertUrlAllowed("http://dev.example.com/api"), /Refusing non-HTTPS/);
});
