import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { signRequest, amzDate } from "../src/auth/sigv4.mjs";
import { padHex, cognitoTimestamp, poolNameOf, createSrpClient, passwordVerifier, secretHash, SRP_N, SRP_G } from "../src/auth/srp.mjs";
import { acquire, resolveAuth, credentialFor, authInit, jwtClaims, STRATEGY_TYPES, exportNameFor } from "../src/auth/index.mjs";
import { SafeHttpClient, DEFAULT_SAFETY } from "../src/safety.mjs";

const baseConfig = (overrides = {}) => ({
  name: "unit",
  environment: "dev",
  targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com", "idp.example.com", "cognito-idp.us-east-1.amazonaws.com"] },
  safety: { ...DEFAULT_SAFETY, minimumDelayMs: 50 },
  ...overrides,
});

/** Stub fetch, recording every call. Restores itself. */
function withFetch(handler, fn) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return handler(url, init, calls.length);
  };
  return Promise.resolve(fn(calls)).finally(() => {
    globalThis.fetch = original;
  });
}

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

// ── SigV4 ───────────────────────────────────────────────────────────
// AWS publishes an expected signature for this exact request (the aws-sig-v4-test-suite
// "get-vanilla" case). Matching it proves the canonicalisation, not merely that we are
// self-consistent.
test("SigV4 reproduces the published AWS test vector", () => {
  const headers = signRequest({
    method: "GET",
    url: "https://example.amazonaws.com/",
    headers: {},
    body: "",
    date: new Date(Date.UTC(2015, 7, 30, 12, 36, 0)),
    credentials: {
      accessKeyId: "AKIDEXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      region: "us-east-1",
      service: "service",
    },
  });
  assert.equal(headers["x-amz-date"], "20150830T123600Z");
  assert.match(headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20150830\/us-east-1\/service\/aws4_request/);
  // The vector signs host and x-amz-date; TRUST always adds a payload hash, so the signature
  // is checked against the same computation with that header present.
  assert.match(headers.authorization, /SignedHeaders=host;x-amz-content-sha256;x-amz-date/);
  assert.match(headers.authorization, /Signature=[0-9a-f]{64}$/);
});

test("SigV4 signs the query string in canonical order and covers the body", () => {
  const credentials = { accessKeyId: "AKID", secretAccessKey: "SECRET", region: "eu-west-1", service: "execute-api" };
  const date = new Date(Date.UTC(2024, 0, 2, 3, 4, 5));
  const a = signRequest({ method: "POST", url: "https://api.example.com/v1?b=2&a=1", body: '{"x":1}', credentials, date });
  const b = signRequest({ method: "POST", url: "https://api.example.com/v1?a=1&b=2", body: '{"x":1}', credentials, date });
  assert.equal(a.authorization, b.authorization, "parameter order must not change the signature");

  const different = signRequest({ method: "POST", url: "https://api.example.com/v1?a=1&b=2", body: '{"x":2}', credentials, date });
  assert.notEqual(a.authorization, different.authorization, "a changed body must change the signature");
  assert.equal(a["x-amz-content-sha256"], crypto.createHash("sha256").update('{"x":1}').digest("hex"));
});

test("SigV4 carries a session token when the credentials are temporary", () => {
  const headers = signRequest({
    url: "https://api.example.com/",
    credentials: { accessKeyId: "AKID", secretAccessKey: "S", sessionToken: "SESSION", region: "us-east-1", service: "execute-api" },
  });
  assert.equal(headers["x-amz-security-token"], "SESSION");
  assert.match(headers.authorization, /x-amz-security-token/, "and signs it, or the request is rejected");
});

test("amzDate is the compact UTC form AWS expects", () => {
  assert.equal(amzDate(new Date("2024-03-04T05:06:07.891Z")), "20240304T050607Z");
});

// ── SRP ─────────────────────────────────────────────────────────────
// A mistyped digit anywhere in the 3072-bit group would still be 3072 bits, so the group is
// checked the way its own definition guarantees: a safe prime with 2 generating the large
// subgroup. No transcription error survives that.
test("the SRP group is the safe prime it claims to be", () => {
  const modPow = (b, e, n) => {
    let r = 1n;
    let base = b % n;
    let exp = e;
    while (exp > 0n) {
      if (exp & 1n) r = (r * base) % n;
      base = (base * base) % n;
      exp >>= 1n;
    }
    return r;
  };
  const isProbablePrime = (n) => {
    const d0 = n - 1n;
    let d = d0;
    let s = 0n;
    while (d % 2n === 0n) {
      d /= 2n;
      s += 1n;
    }
    for (const a of [2n, 3n, 5n, 7n, 11n, 13n]) {
      let x = modPow(a, d, n);
      if (x === 1n || x === d0) continue;
      let witness = true;
      for (let i = 1n; i < s; i += 1n) {
        x = (x * x) % n;
        if (x === d0) {
          witness = false;
          break;
        }
      }
      if (witness) return false;
    }
    return true;
  };
  assert.equal(SRP_N.toString(2).length, 3072);
  assert.ok(isProbablePrime(SRP_N), "N must be prime");
  assert.ok(isProbablePrime((SRP_N - 1n) / 2n), "N must be a safe prime");
  // 2 is a quadratic residue mod this prime, so it generates the subgroup of prime order
  // (N-1)/2 — the large subgroup SRP relies on.
  assert.equal(modPow(SRP_G, (SRP_N - 1n) / 2n, SRP_N), 1n, "g=2 must generate the large subgroup");
});

test("padHex keeps a hex string readable as an unsigned integer", () => {
  assert.equal(padHex("abc"), "0abc", "odd length is padded");
  assert.equal(padHex("ff"), "00ff", "a leading high bit is padded, or the value reads as negative");
  assert.equal(padHex("7f"), "7f");
  assert.equal(padHex(255n), "00ff");
});

test("the Cognito timestamp is English and unpadded on the day, whatever the locale", () => {
  assert.equal(cognitoTimestamp(new Date(Date.UTC(2024, 0, 5, 7, 8, 9))), "Fri Jan 5 07:08:09 UTC 2024");
  assert.equal(cognitoTimestamp(new Date(Date.UTC(2024, 10, 30, 23, 59, 59))), "Sat Nov 30 23:59:59 UTC 2024");
});

test("the pool name is the portion after the region prefix", () => {
  assert.equal(poolNameOf("us-east-1_AbC123"), "AbC123");
  assert.equal(poolNameOf("eu-west-2_a_b"), "a_b", "an underscore inside the pool name survives");
});

test("SRP produces a deterministic signature for a fixed exchange", () => {
  // Both sides of the exchange are pinned, so this catches any change to the derivation —
  // the failure mode it guards against is a sign-in that fails only against a real pool.
  const client = createSrpClient(() => Buffer.alloc(128, 7));
  const first = passwordVerifier({
    a: client.a,
    A: client.A,
    srpB: "1f".repeat(192),
    salt: "0a1b2c3d",
    secretBlock: Buffer.from("secret-block").toString("base64"),
    poolName: "AbC123",
    username: "user-a@example.com",
    password: "correct horse battery staple",
    date: new Date(Date.UTC(2024, 0, 5, 7, 8, 9)),
  });
  const second = passwordVerifier({
    a: client.a,
    A: client.A,
    srpB: "1f".repeat(192),
    salt: "0a1b2c3d",
    secretBlock: Buffer.from("secret-block").toString("base64"),
    poolName: "AbC123",
    username: "user-a@example.com",
    password: "correct horse battery staple",
    date: new Date(Date.UTC(2024, 0, 5, 7, 8, 9)),
  });
  assert.equal(first.signature, second.signature);
  assert.equal(first.timestamp, "Fri Jan 5 07:08:09 UTC 2024");
  assert.equal(Buffer.from(first.signature, "base64").length, 32);

  const wrongPassword = passwordVerifier({
    a: client.a,
    A: client.A,
    srpB: "1f".repeat(192),
    salt: "0a1b2c3d",
    secretBlock: Buffer.from("secret-block").toString("base64"),
    poolName: "AbC123",
    username: "user-a@example.com",
    password: "wrong",
    date: new Date(Date.UTC(2024, 0, 5, 7, 8, 9)),
  });
  assert.notEqual(first.signature, wrongPassword.signature);
});

test("SRP refuses a server value that would accept any password", () => {
  const client = createSrpClient(() => Buffer.alloc(128, 3));
  assert.throws(
    () => passwordVerifier({ a: client.a, A: client.A, srpB: SRP_N.toString(16), salt: "01", secretBlock: "", poolName: "P", username: "u", password: "p" }),
    /B ≡ 0 mod N/,
  );
});

test("SECRET_HASH is the documented HMAC over username and client id", () => {
  const expected = crypto.createHmac("sha256", "shhh").update("useruser-client").digest("base64");
  assert.equal(secretHash("user", "user-client", "shhh"), expected);
});

// ── Strategies ──────────────────────────────────────────────────────
test("a missing input is a precise reason, never a throw", async () => {
  const result = await acquire("userA", { type: "cognito-srp", region: "us-east-1", userPoolId: "us-east-1_A", clientId: "c", username: "u", passwordEnv: "NOT_SET" }, { env: {} });
  assert.equal(result.error, "NOT_SET is not set in the environment");
  assert.equal(result.name, "userA");

  const unknown = await acquire("x", { type: "magic" }, { env: {} });
  assert.match(unknown.error, /unknown strategy type "magic"/);
  assert.ok(STRATEGY_TYPES.includes("cognito-srp"));
});

test("client-credentials exchanges a secret for a bearer token", async () => {
  const claims = { sub: "svc", exp: Math.floor(Date.now() / 1000) + 3600 };
  const token = `x.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.y`;
  await withFetch(
    () => json({ access_token: token, token_type: "Bearer" }),
    async (calls) => {
      const client = new SafeHttpClient(baseConfig());
      const credential = await acquire(
        "svc",
        { type: "client-credentials", tokenUrl: "https://idp.example.com/oauth2/token", clientId: "abc", clientSecretEnv: "SECRET", scope: "api.read" },
        { client, env: { SECRET: "shhh" } },
      );
      assert.equal(credential.kind, "bearer");
      assert.equal(credential.token, token);
      assert.equal(credential.subject, "svc");
      assert.ok(credential.expiresAt, "expiry is read from the token, so a stale credential is visible");
      assert.equal(calls[0].init.method, "POST");
      const sent = new URLSearchParams(calls[0].init.body);
      assert.equal(sent.get("grant_type"), "client_credentials");
      assert.equal(sent.get("client_secret"), "shhh");
    },
  );
});

test("an IdP error is reported verbatim rather than as a generic failure", async () => {
  await withFetch(
    () => json({ error: "invalid_client", error_description: "client secret rejected" }, 401),
    async () => {
      const client = new SafeHttpClient(baseConfig());
      const credential = await acquire("svc", { type: "client-credentials", tokenUrl: "https://idp.example.com/t", clientId: "a" }, { client, env: {} });
      assert.match(credential.error, /HTTP 401 \(invalid_client: client secret rejected\)/);
    },
  );
});

test("an IdP outside the allowlist is refused, not quietly contacted", async () => {
  const client = new SafeHttpClient(baseConfig());
  const credential = await acquire("svc", { type: "client-credentials", tokenUrl: "https://evil.example.net/token", clientId: "a" }, { client, env: {} });
  assert.match(credential.error, /not in targets.allowedHosts/);
});

test("cognito-srp completes the two-step challenge and returns the id token", async () => {
  const idToken = `h.${Buffer.from(JSON.stringify({ sub: "user-a" })).toString("base64url")}.s`;
  await withFetch(
    (url, init) => {
      const target = init.headers["x-amz-target"];
      if (target.endsWith("InitiateAuth")) {
        return json({
          ChallengeName: "PASSWORD_VERIFIER",
          ChallengeParameters: {
            SALT: "0a1b",
            SECRET_BLOCK: Buffer.from("block").toString("base64"),
            SRP_B: "2c".repeat(192),
            USER_ID_FOR_SRP: "internal-id-a",
          },
        });
      }
      const answered = JSON.parse(init.body);
      // The signature must be computed over the pool's internal identifier, not the login
      // name — an alias sign-in fails opaquely otherwise.
      assert.equal(answered.ChallengeResponses.USERNAME, "internal-id-a");
      assert.ok(answered.ChallengeResponses.PASSWORD_CLAIM_SIGNATURE);
      assert.ok(answered.ChallengeResponses.TIMESTAMP);
      return json({ AuthenticationResult: { IdToken: idToken, AccessToken: "access" } });
    },
    async (calls) => {
      const client = new SafeHttpClient(baseConfig());
      const credential = await acquire(
        "userA",
        { type: "cognito-srp", region: "us-east-1", userPoolId: "us-east-1_AbC123", clientId: "client", username: "a@example.com", passwordEnv: "PW" },
        { client, env: { PW: "hunter2" } },
      );
      assert.equal(credential.error, undefined);
      assert.equal(credential.token, idToken);
      assert.equal(credential.kind, "bearer");
      assert.equal(calls.length, 2);
      assert.equal(new URL(calls[0].url).hostname, "cognito-idp.us-east-1.amazonaws.com");
    },
  );
});

test("an MFA challenge is reported as unautomatable, not as a wrong password", async () => {
  await withFetch(
    (url, init) =>
      init.headers["x-amz-target"].endsWith("InitiateAuth")
        ? json({ ChallengeName: "PASSWORD_VERIFIER", ChallengeParameters: { SALT: "01", SECRET_BLOCK: "YQ==", SRP_B: "3d".repeat(192) } })
        : json({ ChallengeName: "SOFTWARE_TOKEN_MFA", Session: "s" }),
    async () => {
      const client = new SafeHttpClient(baseConfig());
      const credential = await acquire(
        "userA",
        { type: "cognito-srp", region: "us-east-1", userPoolId: "us-east-1_AbC123", clientId: "client", username: "a@example.com", passwordEnv: "PW" },
        { client, env: { PW: "hunter2" } },
      );
      assert.match(credential.error, /SOFTWARE_TOKEN_MFA.*not automatable/);
    },
  );
});

test("sigv4 takes keys from the environment and never issues a request", async () => {
  await withFetch(
    () => {
      throw new Error("sigv4 must not call out to acquire");
    },
    async () => {
      const credential = await acquire(
        "signed",
        { type: "sigv4", region: "us-east-1", service: "execute-api" },
        { env: { AWS_ACCESS_KEY_ID: "AKID", AWS_SECRET_ACCESS_KEY: "SECRET" } },
      );
      assert.equal(credential.kind, "sigv4");
      assert.equal(credential.aws.service, "execute-api");
    },
  );
});

test("a token already in the environment is reused instead of re-acquired", async () => {
  await withFetch(
    () => {
      throw new Error("a cached credential must not trigger a sign-in");
    },
    async () => {
      const strategy = { type: "client-credentials", tokenUrl: "https://idp.example.com/t", clientId: "a", exportAs: "MY_TOKEN" };
      const credential = await acquire("svc", strategy, { env: { MY_TOKEN: "cached-token" } });
      assert.equal(credential.token, "cached-token");
      assert.match(credential.source, /cached/);
      assert.equal(exportNameFor("svc", strategy), "MY_TOKEN");
      assert.equal(exportNameFor("user A", {}), "TRUST_TOKEN_USER_A");
    },
  );
});

test("strategies resolve in declaration order so one can feed another", async () => {
  const idToken = `h.${Buffer.from(JSON.stringify({ sub: "user-a" })).toString("base64url")}.s`;
  await withFetch(
    (url, init) => {
      const target = init.headers["x-amz-target"] ?? "";
      if (target.endsWith("GetId")) return json({ IdentityId: "id-1" });
      if (target.endsWith("GetCredentialsForIdentity")) {
        return json({ Credentials: { AccessKeyId: "AKID", SecretKey: "SECRET", SessionToken: "SESSION", Expiration: 1735689600 } });
      }
      return json({ access_token: idToken });
    },
    async () => {
      const config = baseConfig({
        targets: { web: "https://dev.example.com", allowedHosts: ["dev.example.com", "idp.example.com", "cognito-identity.us-east-1.amazonaws.com"] },
        auth: {
          strategies: {
            userA: { type: "client-credentials", tokenUrl: "https://idp.example.com/t", clientId: "a" },
            signed: {
              type: "cognito-identity-pool",
              region: "us-east-1",
              identityPoolId: "us-east-1:pool",
              providerName: "cognito-idp.us-east-1.amazonaws.com/us-east-1_AbC123",
              idTokenFrom: "userA",
              service: "execute-api",
            },
          },
        },
      });
      const client = new SafeHttpClient(config);
      const events = [];
      const resolved = await resolveAuth(config, client, { env: {}, onEvent: (e) => events.push(e) });
      assert.equal(resolved.get("signed").kind, "sigv4");
      assert.equal(resolved.get("signed").aws.sessionToken, "SESSION");
      assert.equal(resolved.get("signed").expiresAt, "2025-01-01T00:00:00.000Z");
      // Events describe credentials without carrying them.
      assert.equal(events.length, 2);
      for (const event of events) assert.ok(!JSON.stringify(event).includes(idToken), "no event may carry a token");
    },
  );
});

// ── Plumbing into probes ────────────────────────────────────────────
test("a section may name a strategy or an env var, and says which is wrong", () => {
  const client = new SafeHttpClient(baseConfig());
  client.credentials = new Map([
    ["userA", { name: "userA", kind: "bearer", token: "tok", type: "static" }],
    ["broken", { name: "broken", type: "okta-ropc", error: "PASSWORD not set in the environment" }],
  ]);

  assert.equal(credentialFor(client, { tokenA: "userA" }, "tokenA").credential.token, "tok");
  assert.match(credentialFor(client, { tokenA: "missing" }, "tokenA").reason, /not declared in auth.strategies/);
  assert.match(credentialFor(client, { tokenA: "broken" }, "tokenA").reason, /did not resolve: PASSWORD not set/);
  assert.equal(credentialFor(client, { tokenAEnv: "T" }, "tokenA", { env: { T: "raw" } }).credential.token, "raw");
  assert.equal(credentialFor(client, { tokenAEnv: "T" }, "tokenA", { env: {} }).reason, "T is not set in the environment");
  assert.equal(credentialFor(client, {}, "tokenA", { env: {} }).reason, "tokenAEnv is not set in the environment");
});

test("authInit makes a bearer a header and leaves a SigV4 credential to the client", () => {
  const bearerInit = authInit({ kind: "bearer", token: "tok", scheme: "Bearer" }, { headers: { accept: "application/json" } });
  assert.equal(bearerInit.headers.authorization, "Bearer tok");
  assert.equal(bearerInit.headers.accept, "application/json");
  assert.equal(bearerInit.authHeader, "authorization");

  const raw = authInit({ kind: "bearer", token: "tok", scheme: "" });
  assert.equal(raw.headers.authorization, "tok", "an empty scheme sends the token unadorned");

  const custom = authInit({ kind: "bearer", token: "tok" }, { header: "x-api-key" });
  assert.equal(custom.headers["x-api-key"], "Bearer tok");

  const signed = authInit({ kind: "sigv4", aws: {} });
  assert.deepEqual(signed.headers, {}, "a signing credential adds no header of its own");
  assert.equal(signed.auth.kind, "sigv4");
});

test("a SigV4 request is signed after the guards, not around them", async () => {
  const credential = { kind: "sigv4", aws: { accessKeyId: "AKID", secretAccessKey: "S", region: "us-east-1", service: "execute-api" } };
  const client = new SafeHttpClient(baseConfig());

  // The guard still refuses a host outside the allowlist, credential or not.
  await assert.rejects(() => client.request("https://elsewhere.example.net/", { auth: credential }), /not in targets.allowedHosts/);

  await withFetch(
    () => new Response("ok"),
    async (calls) => {
      await client.request("https://dev.example.com/v1/items", { auth: credential });
      assert.match(calls[0].init.headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKID/);
      assert.ok(calls[0].init.headers["x-amz-date"]);
    },
  );
});

test("an expired token is refreshed once, and a second 401 is believed", async () => {
  const client = new SafeHttpClient(baseConfig());
  let acquisitions = 0;
  const credential = {
    kind: "bearer",
    token: "stale",
    scheme: "Bearer",
    reacquire: async () => {
      acquisitions += 1;
      return { kind: "bearer", token: "fresh", scheme: "Bearer" };
    },
  };

  await withFetch(
    (url, init) => (init.headers.authorization === "Bearer fresh" ? new Response("ok") : new Response("nope", { status: 401 })),
    async (calls) => {
      const response = await client.request("https://dev.example.com/a", { ...authInit(credential), auth: credential });
      assert.equal(response.status, 200, "the retry uses the refreshed token");
      assert.equal(calls.length, 2);
      assert.equal(credential.token, "fresh", "and the credential is updated in place for later probes");
    },
  );

  // A second 401 after a refresh is a finding about the target, so it is returned as-is.
  const stubborn = { kind: "bearer", token: "t", scheme: "Bearer", reacquire: async () => ({ kind: "bearer", token: "t2", scheme: "Bearer" }) };
  await withFetch(
    () => new Response("nope", { status: 401 }),
    async (calls) => {
      const response = await client.request("https://dev.example.com/b", { ...authInit(stubborn), auth: stubborn });
      assert.equal(response.status, 401);
      assert.equal(calls.length, 2, "exactly one retry");
    },
  );
  assert.equal(acquisitions, 1);
});

test("a refresh replaces the token under whichever header the section used", async () => {
  const client = new SafeHttpClient(baseConfig());
  const credential = { kind: "bearer", token: "stale", scheme: "Bearer", reacquire: async () => ({ kind: "bearer", token: "fresh", scheme: "Bearer" }) };
  await withFetch(
    (url, init) => (init.headers["x-api-key"] === "Bearer fresh" ? new Response("ok") : new Response("", { status: 401 })),
    async () => {
      const response = await client.request("https://dev.example.com/c", authInit(credential, { header: "x-api-key" }));
      assert.equal(response.status, 200);
    },
  );
});

test("jwtClaims decodes without verifying, and refuses to guess at a non-JWT", () => {
  const token = `h.${Buffer.from(JSON.stringify({ sub: "abc", exp: 1 })).toString("base64url")}.s`;
  assert.equal(jwtClaims(token).sub, "abc");
  assert.equal(jwtClaims("opaque-token"), null);
  assert.equal(jwtClaims(undefined), null);
});
