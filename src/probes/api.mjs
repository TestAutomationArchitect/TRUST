/**
 * TRUST — API / authorisation probes (authenticated).
 *
 * Config-driven: the probe definitions live in config so the same code tests a
 * GraphQL API, a REST API, or both. Every isolation test needs two identities.
 */

import { finding, skipped, inconclusive, sweepVerdict } from "../finding.mjs";
import { section } from "../config.mjs";

/**
 * Execute one request spec.
 *   GraphQL: { query, variables }             → POST endpoint
 *   REST:    { method, path, body, headers }  → method endpoint+path
 */
async function execute(client, api, token, spec, { write = false, denialTest = false } = {}) {
  const scheme = api.authScheme ?? "Bearer";
  const authHeader = api.authHeader ?? "authorization";
  const headers = {
    "content-type": "application/json",
    [authHeader]: scheme ? `${scheme} ${token}` : token,
    ...(api.headers ?? {}),
    ...(spec.headers ?? {}),
  };

  const isGraphql = (api.kind ?? "graphql") === "graphql";
  const url = isGraphql ? api.endpoint : new URL(spec.path ?? "", api.endpoint).href;
  const method = isGraphql ? "POST" : (spec.method ?? "GET").toUpperCase();
  const payload = isGraphql
    ? JSON.stringify({ query: spec.query, variables: spec.variables ?? {} })
    : spec.body != null
      ? JSON.stringify(spec.body)
      : undefined;

  const response = await client.request(url, { method, headers, body: payload, write, denialTest });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* non-JSON responses are evaluated as text */
  }
  return { response, status: response.status, text, json };
}

/** A GraphQL/REST response that denied the request. */
// A 429 is the server declining to answer, not the control denying access. Treating it as a
// denial would report an isolation control as holding when it was never exercised.
function isThrottled({ status, text }) {
  return status === 429 || status === 503 || /rate.?limit|too many requests/i.test(text);
}

function isDenied({ status, text, json }) {
  if (isThrottled({ status, text })) return false;
  if (status === 401 || status === 403 || status === 404) return true;
  const errors = json?.errors ?? [];
  if (errors.length && /unauthor|not authoriz|forbidden|access denied|permission/i.test(JSON.stringify(errors))) return true;
  if (!json && /unauthor|forbidden|access denied/i.test(text)) return true;
  return false;
}

/** Did the response actually carry a data payload? */
function hasData({ json, text }) {
  if (json?.data && Object.values(json.data).some((v) => v !== null && v !== undefined)) return true;
  if (json && !json.errors && (Array.isArray(json) ? json.length > 0 : Object.keys(json).length > 0)) return true;
  return !json && text.trim().length > 32;
}

function deepFind(value, predicate, hits = []) {
  if (value == null) return hits;
  if (Array.isArray(value)) {
    for (const item of value) deepFind(item, predicate, hits);
    return hits;
  }
  if (typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (predicate(key, item)) hits.push({ key, value: item });
      deepFind(item, predicate, hits);
    }
  }
  return hits;
}

export async function runApiProbes(config, client) {
  // The canonical section, resolved through conventional spellings — an app that calls it
  // "graphql" should not have to duplicate it under "api".
  const { value: api, key: apiKey } = section(config, "api");
  if (!api?.endpoint) return [skipped("API-CONFIG", "API authorisation probe suite", "config.api.endpoint is not configured")];

  const tokenA = api.tokenAEnv ? process.env[api.tokenAEnv] : undefined;
  const tokenB = api.tokenBEnv ? process.env[api.tokenBEnv] : undefined;
  if (!tokenA) {
    return [skipped("API-CONFIG", "API authorisation probe suite", `${api.tokenAEnv ?? "api.tokenAEnv"} is not set in the environment`)];
  }

  const out = [];

  // ── Cross-user record read (User B against User A's record) ───────
  if (!api.crossUser) {
    out.push(skipped("API-CROSS-USER", "User B cannot read User A's record", "config.api.crossUser is not defined"));
  } else if (!tokenB) {
    out.push(skipped("API-CROSS-USER", "User B cannot read User A's record", `${api.tokenBEnv ?? "api.tokenBEnv"} is not set — isolation needs a second identity`));
  } else {
    try {
      const result = await execute(client, api, tokenB, api.crossUser);
      const leaked = !isDenied(result) && hasData(result);
      out.push(
        finding({
          id: "API-CROSS-USER",
          observed: "Cross-user record access is permitted",
          title: "User B cannot read User A's record",
          status: leaked ? "fail" : "pass",
          severity: "high",
          evidence: `User B requested User A's resource → HTTP ${result.status}\n${result.text.slice(0, 800)}`,
          remediation: leaked
            ? "Enforce owner-scoped authorisation at the resolver/handler using the identity claim from the verified token, not a client-supplied ID."
            : "",
        }),
      );
    } catch (error) {
      out.push(inconclusive("API-CROSS-USER", "User B cannot read User A's record", `Request failed: ${error.message}`));
    }
  }

  // ── Unscoped list query ───────────────────────────────────────────
  if (!api.unscopedList) {
    out.push(skipped("API-UNSCOPED-LIST", "List queries are owner-scoped", "config.api.unscopedList is not defined"));
  } else {
    const spec = api.unscopedList;
    try {
      const result = await execute(client, api, tokenA, spec);
      const ownerField = spec.ownerField ?? "owner";
      const expected = spec.expectedOwner;
      const owners = deepFind(result.json, (key) => key === ownerField).map((h) => String(h.value));
      const foreign = expected ? owners.filter((o) => o !== expected) : [];
      const status = isDenied(result)
        ? "pass"
        : !expected
          ? owners.length > 1 && new Set(owners).size > 1
            ? "fail"
            : "warn"
          : foreign.length
            ? "fail"
            : "pass";
      out.push(
        finding({
          id: "API-UNSCOPED-LIST",
          observed: "List queries expose records owned by other users",
          title: "List queries return only the caller's records",
          status,
          severity: "high",
          evidence:
            `HTTP ${result.status} — ${owners.length} record owner value(s) observed on field "${ownerField}"` +
            (expected ? `\nExpected owner: ${expected}` : "\nNo expectedOwner configured — verdict based on owner diversity") +
            (foreign.length ? `\nForeign owners returned: ${[...new Set(foreign)].slice(0, 10).join(", ")}` : "") +
            `\n${result.text.slice(0, 600)}`,
          remediation:
            status === "fail"
              ? "Add an owner/tenant filter derived from the token claims to the list resolver, and enforce it server-side rather than in the client query."
              : status === "warn"
                ? "Set api.unscopedList.expectedOwner so this test can reach a deterministic verdict."
                : "",
        }),
      );
    } catch (error) {
      out.push(inconclusive("API-UNSCOPED-LIST", "List queries return only the caller's records", `Request failed: ${error.message}`));
    }
  }

  // ── Permission mutation by a non-admin ────────────────────────────
  if (!api.permissionMutation) {
    out.push(skipped("API-PERMISSION-MUTATION", "Non-admin users cannot modify permissions", "config.api.permissionMutation is not defined"));
  } else if (config.safety.allowWrites !== true && config.safety.allowDenialTests !== true) {
    out.push(
      skipped(
        "API-PERMISSION-MUTATION",
        "Non-admin users cannot modify permissions",
        "neither safety.allowDenialTests nor safety.allowWrites is set — the harness would block the attempt. " +
          "allowDenialTests is the narrower switch: it permits a mutation that is expected to be refused, without enabling writes generally",
      ),
    );
  } else {
    try {
      const result = await execute(client, api, tokenA, api.permissionMutation, { write: true, denialTest: true });
      const blocked = isDenied(result) || Boolean(result.json?.errors?.length);
      out.push(
        finding({
          id: "API-PERMISSION-MUTATION",
          observed: "A non-admin user can modify permission records",
          title: "Non-admin users cannot modify permission records",
          status: blocked ? "pass" : "fail",
          severity: "critical",
          evidence: `Non-admin mutation → HTTP ${result.status}\n${result.text.slice(0, 800)}`,
          remediation: blocked
            ? ""
            : "Restrict permission-mutating operations to an admin group asserted by the token, and reject the operation at the resolver when the claim is absent.",
        }),
      );
    } catch (error) {
      out.push(inconclusive("API-PERMISSION-MUTATION", "Non-admin users cannot modify permission records", `Request failed: ${error.message}`));
    }
  }

  // ── Client-supplied identity (spoof) ──────────────────────────────
  if (!api.useridSpoof) {
    out.push(skipped("API-USERID-SPOOF", "Server derives identity from the token, not the request body", "config.api.useridSpoof is not defined"));
  } else {
    const spoofed = api.useridSpoof.spoofedUserId ?? "trust-spoofed-identity";
    try {
      const result = await execute(client, api, tokenA, api.useridSpoof, { write: api.useridSpoof.write === true });
      const accepted = !isDenied(result) && result.text.includes(spoofed);
      out.push(
        finding({
          id: "API-USERID-SPOOF",
          observed: "The API accepts a client-supplied identity",
          title: "Server derives identity from the token, not the request body",
          status: accepted ? "fail" : "pass",
          severity: "critical",
          evidence: `Submitted identity "${spoofed}" → HTTP ${result.status}\n${result.text.slice(0, 800)}`,
          remediation: accepted
            ? "Ignore any identity field in the request payload; populate it server-side from the verified token claim (sub / oid / username)."
            : "",
        }),
      );
    } catch (error) {
      out.push(inconclusive("API-USERID-SPOOF", "Server derives identity from the token, not the request body", `Request failed: ${error.message}`));
    }
  }

  // ── GraphQL introspection ─────────────────────────────────────────
  if ((api.kind ?? "graphql") === "graphql") {
    try {
      const result = await execute(client, api, tokenA, { query: "{ __schema { types { name } } }" });
      const exposed = Boolean(result.json?.data?.__schema?.types?.length);
      out.push(
        finding({
          id: "API-INTROSPECTION",
          observed: "GraphQL introspection is available to ordinary users",
          title: "GraphQL introspection is not exposed to ordinary users",
          status: exposed ? "warn" : "pass",
          severity: "low",
          evidence: exposed
            ? `Introspection returned ${result.json.data.__schema.types.length} types to a standard user token.`
            : `HTTP ${result.status} — introspection refused or empty.`,
          remediation: exposed ? "Disable introspection in non-development environments, or gate it behind an admin claim." : "",
        }),
      );
    } catch (error) {
      out.push(skipped("API-INTROSPECTION", "GraphQL introspection is not exposed to ordinary users", `request failed: ${error.message}`));
    }
  }

  // ── Error disclosure ──────────────────────────────────────────────
  const malformed = (api.kind ?? "graphql") === "graphql" ? { query: "{ trustNoSuchField_" } : { method: "GET", path: api.errorProbePath ?? "/trust-no-such-endpoint" };
  try {
    const result = await execute(client, api, tokenA, malformed);
    const leaks = [
      [/\bat\s+[\w$.<>]+\s*\((?:\/|[A-Za-z]:\\)[^)]+\)/, "stack frame with a filesystem path"],
      [/(?:\/(?:var|usr|home|opt|srv)\/|[A-Za-z]:\\+(?:Users|inetpub|app))[^\s"']{4,}/, "absolute server filesystem path"],
      [/\b(select|insert into|update .* set)\b[\s\S]{0,80}\bfrom\b/i, "SQL fragment"],
      [/\b[\w-]+\.(internal|local|rds\.amazonaws\.com|database\.windows\.net)\b/i, "internal hostname"],
      [/Traceback \(most recent call last\)/, "Python traceback"],
    ]
      .filter(([pattern]) => pattern.test(result.text))
      .map(([, label]) => label);
    out.push(
      finding({
        id: "API-ERROR-DISCLOSURE",
        observed: "API errors disclose internal implementation detail",
        title: "API errors do not disclose internal implementation detail",
        status: leaks.length ? "fail" : "pass",
        severity: "medium",
        evidence: `Malformed request → HTTP ${result.status}` + (leaks.length ? `\nDisclosed: ${leaks.join(", ")}` : "") + `\n${result.text.slice(0, 600)}`,
        remediation: leaks.length
          ? "Return a generic error envelope with a correlation ID; log the detail server-side only."
          : "",
      }),
    );
  } catch (error) {
    out.push(skipped("API-ERROR-DISCLOSURE", "API errors do not disclose internal implementation detail", `request failed: ${error.message}`));
  }

  // ── Native password authentication (SSO enforcement) ──────────────
  if (!api.passwordAuth?.endpoint) {
    out.push(skipped("AUTH-PASSWORD-BYPASS", "Native password authentication is disabled", "config.api.passwordAuth is not defined"));
  } else {
    const pa = api.passwordAuth;
    try {
      // Corroboration first. A bad-credentials error is suggestive but not conclusive: some
      // providers return one even for a disabled grant. The provider's own discovery document
      // states which grants it supports, so a FAIL is only claimed when two independent
      // sources agree. Credibility here depends on not crying wolf.
      let discovery = null;
      const discoveryUrl = pa.discoveryUrl ?? new URL("/.well-known/openid-configuration", pa.endpoint).href;
      try {
        const discoveryResponse = await client.request(discoveryUrl);
        if (discoveryResponse.status === 200) {
          const doc = JSON.parse(await discoveryResponse.text());
          if (Array.isArray(doc.grant_types_supported)) {
            discovery = {
              url: discoveryUrl,
              grants: doc.grant_types_supported,
              advertisesPassword: doc.grant_types_supported.includes("password"),
            };
          }
        }
      } catch {
        /* no discovery document, or not JSON — the verdict falls back to "probable" */
      }

      const response = await client.request(pa.endpoint, {
        method: pa.method ?? "POST",
        headers: { "content-type": "application/json", ...(pa.headers ?? {}) },
        body: JSON.stringify(pa.body ?? { username: "trust-probe@example.invalid", password: `trust-${Date.now()}` }),
      });
      const text = await response.text();
      // A *rejected flow* is what we want: the flow itself must be unavailable, not merely
      // the credentials wrong. "unsupported_grant_type" is the unambiguous good signal.
      const grantRejected = /unsupported_grant_type|grant type not supported|not enabled for this client|InvalidParameterException/i.test(text);
      const flowDisabled = grantRejected || /not enabled|unsupported|invalid.*flow|disabled|not allowed/i.test(text);
      const badCredentials = /incorrect username or password|invalid.*credential|NotAuthorized|invalid_grant/i.test(text);

      // Two sources agreeing → confirmed. One source only → probable, reported as a warning
      // so nobody files a ticket on a maybe.
      const confirmedLive = badCredentials && discovery?.advertisesPassword === true;
      // Cognito user pools omit grant_types_supported from their discovery document, so
      // corroboration is impossible there. InvalidParameterException from a Cognito endpoint
      // is itself conclusive: the flow is not enabled on the app client.
      const cognitoClosed = /InvalidParameterException/i.test(text) && /cognito|amazonaws.com/i.test(pa.endpoint);
      const confirmedClosed = grantRejected || cognitoClosed || discovery?.advertisesPassword === false;
      const status = confirmedLive ? "fail" : confirmedClosed && !badCredentials ? "pass" : badCredentials || !flowDisabled ? "warn" : "pass";

      out.push(
        finding({
          id: "AUTH-PASSWORD-BYPASS",
          observed: confirmedLive
            ? "Native password authentication is enabled and reachable"
            : "Native password authentication appears reachable (unconfirmed)",
          title: "Native password authentication is disabled (SSO-only)",
          status,
          severity: "high",
          evidence:
            `Password grant attempt → HTTP ${response.status}\n${text.slice(0, 400)}\n\n` +
            (discovery
              ? `Discovery (${discovery.url}): grant_types_supported = ${discovery.grants.join(", ")}\n` +
                `→ password grant is ${discovery.advertisesPassword ? "ADVERTISED" : "not advertised"} by the provider.`
              : `No usable discovery document at ${discoveryUrl}, so the response is the only source. ` +
                `Set api.passwordAuth.discoveryUrl to corroborate.`) +
            `\nVerdict basis: ${confirmedLive ? "two independent sources agree the flow is live" : confirmedClosed ? "the grant was rejected outright" : "single ambiguous signal — reported as probable, not confirmed"}`,
          remediation:
            confirmedLive
              ? "The password grant is enabled and only rejected the credentials. Remove it from the app client (e.g. USER_PASSWORD_AUTH on a Cognito client, or the password grant on an OAuth client) so federated SSO is the only path."
              : status === "warn"
                ? "Probable, not confirmed: the response suggests the flow is reachable but discovery did not corroborate it. Check the app client's enabled grant types directly before raising a finding."
                : "",
        }),
      );
    } catch (error) {
      out.push(inconclusive("AUTH-PASSWORD-BYPASS", "Native password authentication is disabled (SSO-only)", `Request failed: ${error.message}`));
    }
  }

  // ── API surface inventory ─────────────────────────────────────────
  // An exposed schema or spec is not a vulnerability by itself, but it converts a blind
  // attacker into an informed one, and it is often unintentional.
  const inventoryPaths = api.inventoryPaths ?? [
    "/openapi.json",
    "/swagger.json",
    "/swagger-ui.html",
    "/api-docs",
    "/.well-known/openid-configuration",
    "/graphql/playground",
    "/altair",
  ];
  const exposedSpecs = [];
  let inventoryChecked = 0;
  for (const path of inventoryPaths) {
    if (client.remainingRequests < 4) break;
    inventoryChecked += 1;
    try {
      const response = await client.request(new URL(path, api.endpoint).href);
      if (response.status !== 200) continue;
      const text = (await response.text()).slice(0, 400);
      if (/openapi|swagger|graphql|authorization_endpoint|jwks_uri|<title>/i.test(text)) exposedSpecs.push({ path, snippet: text.slice(0, 160) });
    } catch {
      /* ignore */
    }
  }
  const specsOnly = exposedSpecs.filter((s) => !s.path.includes("openid-configuration"));
  const inventorySweep = sweepVerdict({ hits: specsOnly.length, performed: inventoryChecked, planned: inventoryPaths.length });
  if (inventorySweep === "not-run") {
    // The sweep was cut short by a guard, so "nothing found" says nothing about the target.
    out.push(
      skipped(
        "API-INVENTORY-EXPOSED",
        "API schema and console endpoints are not publicly exposed",
        `the request budget ran out before any of the ${inventoryPaths.length} paths could be checked — raise safety.maxRequests, or the api suite budget, and re-run`,
      ),
    );
  } else {
  out.push(
    finding({
      id: "API-INVENTORY-EXPOSED",
      observed: "API schema or console endpoints are publicly reachable",
      title: "API schema and console endpoints are not publicly exposed",
      // A sweep that stopped early cannot claim the control holds. The status scale already has
        // a word for that: WARN is "could not be fully validated".
        status: specsOnly.length || inventorySweep === "partial" ? "warn" : "pass",
      severity: "low",
      evidence: exposedSpecs.length
        ? exposedSpecs.map((s) => `${s.path} → HTTP 200: ${s.snippet}`).join("\n") +
          "\n(A discovery document at /.well-known/openid-configuration is expected and is not counted as a finding.)"
        : `Checked ${inventoryChecked} of ${inventoryPaths.length} conventional paths; none returned a schema or console.` +
          (inventorySweep === "partial" ? " The sweep stopped early on the request budget, so this is not a complete answer." : ""),
      remediation: specsOnly.length
        ? "Serve the API specification and any GraphQL console only in development, or gate them behind authentication."
        : "",
    }),
  );
  }

  // ── Excessive data exposure ───────────────────────────────────────
  // Does a normal read return fields the client has no business receiving?
  const SENSITIVE_FIELDS = [
    [/"(password|passwd|pwd|password_hash|hashed_password)"\s*:/i, "credential field"],
    [/"(ssn|social_security|national_id|tax_id)"\s*:/i, "national identifier"],
    [/"(card_number|cvv|iban|account_number)"\s*:/i, "payment field"],
    [/"(secret|api_?key|access_?token|refresh_?token|private_?key)"\s*:/i, "secret material"],
    [/"(internal_|__)[a-z_]+"\s*:/i, "internal-only field"],
  ];
  if (api.crossUser || api.unscopedList) {
    const spec = api.unscopedList ?? api.crossUser;
    try {
      const result = await execute(client, api, tokenA, spec);
      const exposedFields = SENSITIVE_FIELDS.filter(([pattern]) => pattern.test(result.text)).map(([, name]) => name);
      out.push(
        finding({
          id: "API-EXCESSIVE-DATA",
          observed: "Responses carry credential, secret or internal-only fields",
          title: "Responses do not carry fields the client should never receive",
          status: exposedFields.length ? "fail" : "pass",
          severity: "high",
          evidence: exposedFields.length
            ? `A standard read returned: ${exposedFields.join(", ")}\n${result.text.slice(0, 500)}`
            : `HTTP ${result.status} — no credential, secret or internal-only field patterns in the response body.`,
          remediation: exposedFields.length
            ? "Shape responses with an explicit allowlist of fields per role instead of serialising the whole record, and keep secrets out of the read model entirely."
            : "",
        }),
      );
    } catch (error) {
      out.push(skipped("API-EXCESSIVE-DATA", "Responses do not carry fields the client should never receive", `request failed: ${error.message}`));
    }
  }

  // ── Query cost / unrestricted consumption ─────────────────────────
  // One small request that asks for a lot: 500 aliases of a free field. A server with no
  // complexity or depth limit answers all of them.
  if ((api.kind ?? "graphql") === "graphql") {
    const aliasCount = api.aliasProbeCount ?? 500;
    const aliases = Array.from({ length: aliasCount }, (_, i) => `a${i}: __typename`).join(" ");
    try {
      const result = await execute(client, api, tokenA, { query: `query TrustCostProbe { ${aliases} }` });
      const returned = (result.text.match(/"a\d+":/g) ?? []).length;
      const rejected = result.status >= 400 || Boolean(result.json?.errors?.length) || returned < aliasCount;
      out.push(
        finding({
          id: "API-QUERY-COST",
          observed: "No query complexity or depth limit is enforced",
          title: "GraphQL enforces a query complexity or depth limit",
          status: rejected ? "pass" : "fail",
          severity: "medium",
          evidence: rejected
            ? `A ${aliasCount}-alias query was rejected or truncated → HTTP ${result.status}, ${returned} field(s) returned.\n${result.text.slice(0, 300)}`
            : `A ${aliasCount}-alias query was answered in full (HTTP ${result.status}, ${returned} fields). A single request can therefore multiply server work without limit.`,
          remediation: rejected
            ? ""
            : "Enforce a query cost/complexity budget and a maximum depth at the gateway or resolver layer, and cap aliases per request.",
        }),
      );
    } catch (error) {
      out.push(inconclusive("API-QUERY-COST", "GraphQL enforces a query complexity or depth limit", `Probe failed: ${error.message}`));
    }
  }

  // ── Session lifecycle ─────────────────────────────────────────────
  // Two questions a client can answer: is a token accepted after logout, and is an expired
  // token accepted. Both need a caller-supplied endpoint, so both skip cleanly without one.
  const session = api.session;
  if (!session?.verifyEndpoint) {
    out.push(
      skipped(
        "SESSION-LOGOUT",
        "Tokens stop working after logout",
        "config.api.session.verifyEndpoint is not defined (needs an authenticated endpoint to re-check the token against)",
      ),
    );
  } else if (!session.logoutEndpoint) {
    out.push(skipped("SESSION-LOGOUT", "Tokens stop working after logout", "config.api.session.logoutEndpoint is not defined"));
  } else if (config.safety.allowWrites !== true) {
    out.push(skipped("SESSION-LOGOUT", "Tokens stop working after logout", "logout changes server state, so it requires safety.allowWrites"));
  } else {
    try {
      const before = await execute(client, api, tokenA, { method: "GET", path: session.verifyEndpoint });
      await client.request(new URL(session.logoutEndpoint, api.endpoint).href, {
        method: session.logoutMethod ?? "POST",
        headers: { [api.authHeader ?? "authorization"]: `${api.authScheme ?? "Bearer"} ${tokenA}` },
        write: true,
      });
      const after = await execute(client, api, tokenA, { method: "GET", path: session.verifyEndpoint });
      const stillValid = !isDenied(after) && !isDenied(before);
      out.push(
        finding({
          id: "SESSION-LOGOUT",
          observed: "Tokens continue to work after logout",
          title: "Tokens stop working after logout",
          status: stillValid ? "fail" : "pass",
          severity: "high",
          evidence: `Before logout: HTTP ${before.status}\nAfter logout: HTTP ${after.status}\n${after.text.slice(0, 300)}`,
          remediation: stillValid
            ? "Revoke the session server-side on logout — add the token to a denylist, or bind it to a session record that logout deletes. A stateless token that outlives its session cannot be withdrawn after theft."
            : "",
        }),
      );
    } catch (error) {
      out.push(inconclusive("SESSION-LOGOUT", "Tokens stop working after logout", `Probe failed: ${error.message}`));
    }
  }

  const expiredToken = session?.expiredTokenEnv ? process.env[session.expiredTokenEnv] : undefined;
  if (!session?.verifyEndpoint || !expiredToken) {
    out.push(
      skipped(
        "SESSION-EXPIRED-TOKEN",
        "Expired tokens are rejected",
        session?.expiredTokenEnv
          ? `${session.expiredTokenEnv} is not set`
          : "config.api.session.expiredTokenEnv is not defined (supply a known-expired token to test this)",
      ),
    );
  } else {
    try {
      const result = await execute(client, api, expiredToken, { method: "GET", path: session.verifyEndpoint });
      const rejected = isDenied(result);
      out.push(
        finding({
          id: "SESSION-EXPIRED-TOKEN",
          observed: "An expired token is still accepted",
          title: "Expired tokens are rejected",
          status: rejected ? "pass" : "fail",
          severity: "critical",
          evidence: `A known-expired token against ${session.verifyEndpoint} → HTTP ${result.status}\n${result.text.slice(0, 300)}`,
          remediation: rejected ? "" : "Validate exp on every request. An accepted expired token means revocation and session limits are not enforced at all.",
        }),
      );
    } catch (error) {
      out.push(inconclusive("SESSION-EXPIRED-TOKEN", "Expired tokens are rejected", `Probe failed: ${error.message}`));
    }
  }

  // ── Extra REST authorisation checks ───────────────────────────────
  for (const extra of api.extraChecks ?? []) {
    const id = `API-REST-${String(extra.name ?? "CHECK").toUpperCase().replace(/[^A-Z0-9]+/g, "-")}`;
    const identity = extra.identity === "B" ? tokenB : tokenA;
    if (!identity) {
      out.push(skipped(id, extra.title ?? id, `token for identity ${extra.identity ?? "A"} is not set`));
      continue;
    }
    try {
      const result = await execute(client, api, identity, extra, { write: extra.write === true });
      const denied = isDenied(result);
      const expectDenied = extra.expect !== "allow";
      const ok = expectDenied ? denied : !denied;
      out.push(
        finding({
          id,
          title: extra.title ?? `Endpoint ${extra.path ?? ""} enforces authorisation`,
          status: ok ? "pass" : "fail",
          severity: extra.severity ?? "high",
          evidence: `${extra.method ?? "GET"} ${extra.path ?? api.endpoint} as identity ${extra.identity ?? "A"} → HTTP ${result.status}\n${result.text.slice(0, 600)}`,
          remediation: ok ? "" : (extra.remediation ?? "Enforce authorisation for this endpoint server-side using token claims."),
        }),
      );
    } catch (error) {
      out.push(inconclusive(id, extra.title ?? id, `Request failed: ${error.message}`));
    }
  }

  return out;
}
