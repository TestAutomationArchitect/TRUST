/**
 * TRUST — declarative isolation boundaries.
 *
 * Most real security bugs are authorisation failures, and the shape of the test never changes:
 * act as identity A, act as identity B against A's resource, ask whether it was refused. Until
 * now expressing that meant writing a probe module — custom queries, custom response parsing,
 * custom verdict logic — which put the highest-value test category behind the highest barrier.
 *
 * Here a team declares the *boundary* and TRUST supplies the test:
 *
 *   "isolation": [
 *     { "id": "API-CROSS-USER-RECORD", "type": "record-ownership",
 *       "endpoint": "https://api.example.com/graphql",
 *       "queryA": "query { listMyRecords(limit: 1) { items { id } } }",
 *       "queryB": "query($id: ID!) { getRecord(id: $id) { id owner } }",
 *       "tokenA": "userA", "tokenB": "userB", "severity": "high" }
 *   ]
 *
 * Five boundary types cover the great majority of authorisation bugs:
 *
 *   record-ownership       B reads A's record by ID
 *   prefix-scoped-storage  B lists and reads A's object prefix
 *   enumeration            a list endpoint returns only the caller's own records
 *   mutation-guard         a privileged mutation is refused
 *   identity-injection     a client-supplied identity field does not override the token
 *
 * Two rules keep a declared test as trustworthy as a hand-written one. A boundary claim needs
 * two identities, so a spec with one identity skips rather than guessing. And a verdict is a
 * pattern match on status and body, never an interpretation — an ambiguous response is a
 * warning that says what was ambiguous about it.
 */

import { finding, skipped, inconclusive, DENIAL_LANGUAGE } from "../finding.mjs";
import { getDomain } from "../catalog.mjs";
import { authInit, credentialFor } from "../auth/index.mjs";
import { chainGate, statusIndex, activationNote } from "../chain.mjs";

/** Boundary type → how the finding is classified in the report. */
const CATEGORY_OF_TYPE = {
  "record-ownership": "Authorization — API",
  "prefix-scoped-storage": "Authorization — Storage",
  enumeration: "Authorization — API",
  "mutation-guard": "Authorization — API",
  "identity-injection": "Identity Spoofing",
};

export const ISOLATION_TYPES = Object.keys(CATEGORY_OF_TYPE);

const DEFAULT_DENIAL_PATTERNS = [DENIAL_LANGUAGE, /not.{0,10}owner/i, /not.{0,10}admin/i, /AccessDenied/];

const DENIED_STATUS = new Set([401, 403]);

/** Did the target refuse this request? Status first, body patterns second. */
function isDenied({ status, text }, spec) {
  if (DENIED_STATUS.has(status)) return true;
  const patterns = spec.denialPatterns ? spec.denialPatterns.map((p) => new RegExp(p, "i")) : DEFAULT_DENIAL_PATTERNS;
  return patterns.some((pattern) => pattern.test(text));
}

/** A GraphQL 200 carrying only errors is a denial, not data. */
function hasData(json) {
  if (!json || typeof json !== "object") return false;
  if (!("data" in json)) return true; // a REST body is its own data
  const data = json.data;
  if (data == null) return false;
  return Object.values(data).some((value) => value != null && (!Array.isArray(value) || value.length > 0));
}

/** Every scalar in a response body, for checking who the returned records belong to. */
function collectValues(node, field, found = []) {
  if (node == null) return found;
  if (Array.isArray(node)) {
    for (const item of node) collectValues(item, field, found);
    return found;
  }
  if (typeof node === "object") {
    for (const [key, value] of Object.entries(node)) {
      if (key === field && (typeof value === "string" || typeof value === "number")) found.push(String(value));
      else collectValues(value, field, found);
    }
  }
  return found;
}

/** One request, as the spec describes it. GraphQL when a query is given, REST otherwise. */
async function execute(client, spec, credential, { query, variables, path, method, body, write = false, denialTest = false } = {}) {
  const auth = authInit(credential, {
    header: spec.authHeader ?? "authorization",
    scheme: spec.authScheme ?? "Bearer",
    headers: { "content-type": "application/json", ...(spec.headers ?? {}) },
  });
  const isGraphql = Boolean(query);
  const url = isGraphql || !path ? spec.endpoint : new URL(path, spec.endpoint).href;
  const payload = isGraphql ? JSON.stringify({ query, variables: variables ?? {} }) : body != null ? JSON.stringify(body) : undefined;

  const response = await client.request(url, {
    ...auth,
    method: isGraphql ? "POST" : (method ?? "GET").toUpperCase(),
    body: payload,
    write,
    denialTest,
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* a non-JSON body is still evidence, and the verdict falls back to status + patterns */
  }
  return { status: response.status, text, json, url };
}

/**
 * A boundary that could not be tested. It keeps the spec's own category, so a skipped storage
 * boundary is reported against storage rather than falling into "Other" — a skip still has to
 * appear in the right place for coverage to mean anything.
 */
const boundarySkip = (spec, reason) =>
  finding({
    id: spec.id,
    title: spec.title ?? spec.description ?? spec.id,
    status: "skip",
    severity: "info",
    evidence: `Skipped: ${reason}`,
    category: CATEGORY_OF_TYPE[spec.type],
    domain: CATEGORY_OF_TYPE[spec.type] ? getDomain(CATEGORY_OF_TYPE[spec.type]) : "",
  });

const verdict = (spec, { status, observed, evidence, remediation, activatedBy }) =>
  finding({
    id: spec.id,
    title: spec.title ?? spec.description ?? `Isolation boundary ${spec.id} holds`,
    status,
    severity: spec.severity ?? "high",
    observed,
    evidence: [activationNote(activatedBy), evidence].filter(Boolean).join("\n"),
    remediation: status === "pass" ? "" : remediation,
    category: CATEGORY_OF_TYPE[spec.type],
    domain: getDomain(CATEGORY_OF_TYPE[spec.type]),
    activatedBy: activatedBy ?? "",
  });

// ── Boundary types ──────────────────────────────────────────────────

/**
 * B reads A's record by ID. The record ID is discovered as A rather than pinned in config, so
 * the test does not rot the first time the fixture data is reseeded.
 */
async function recordOwnership(client, spec, { credA, credB, activatedBy }) {
  const idField = spec.idField ?? "id";
  const discovery = await execute(client, spec, credA, { query: spec.queryA, variables: spec.variablesA, path: spec.pathA, method: spec.methodA });
  const ids = collectValues(discovery.json ?? {}, idField);
  if (!ids.length) {
    return boundarySkip(
      spec,
      `identity A's own record could not be discovered (no "${idField}" in the response to queryA, HTTP ${discovery.status}) — nothing to attempt cross-user access against`,
    );
  }

  const recordId = ids[0];
  const attempt = await execute(client, spec, credB, {
    query: spec.queryB,
    variables: { ...(spec.variablesB ?? {}), [spec.idVariable ?? "id"]: recordId },
    path: spec.pathB ? spec.pathB.replace("{id}", encodeURIComponent(recordId)) : undefined,
    method: spec.methodB,
  });
  const denied = isDenied(attempt, spec);
  const leaked = !denied && hasData(attempt.json ?? attempt.text);

  return verdict(spec, {
    status: leaked ? "fail" : denied ? "pass" : "warn",
    observed: "Identity B can read identity A's record",
    activatedBy,
    evidence:
      `Identity A holds record ${recordId} (HTTP ${discovery.status}).\n` +
      `Identity B requested it → HTTP ${attempt.status}\n${attempt.text.slice(0, 600)}`,
    remediation: leaked
      ? "Enforce owner-scoped authorisation in the resolver or handler using the identity claim from the verified token, not an ID supplied by the client."
      : "The response was neither a denial nor recognisable data. Add denialPatterns for this API's refusal shape so the verdict is unambiguous.",
  });
}

/** B lists and reads A's object prefix. Two operations, because a bucket can refuse one. */
async function prefixScopedStorage(client, spec, { credA, credB, activatedBy, env }) {
  const tenantA = spec.tenantA ?? (spec.tenantAEnv ? env[spec.tenantAEnv] : undefined);
  const tenantB = spec.tenantB ?? (spec.tenantBEnv ? env[spec.tenantBEnv] : undefined);
  if (!tenantA || !tenantB) {
    return boundarySkip(spec, `${spec.tenantAEnv ?? "tenantA"} / ${spec.tenantBEnv ?? "tenantB"} are not both set — cross-tenant isolation needs two tenants`);
  }
  if (tenantA === tenantB) {
    return boundarySkip(spec, `both tenants resolve to "${tenantA}" — the boundary would be tested against itself`);
  }

  const prefix = (spec.pathPattern ?? "{tenant}/").replace("{tenant}", tenantB);
  const listUrl = new URL(`?${new URLSearchParams({ "list-type": "2", prefix })}`, spec.baseUrl).href;
  const objectUrl = spec.objectKey ? new URL(`${prefix}${spec.objectKey}`, spec.baseUrl).href : null;

  // Identity A reaches for tenant B's prefix. Listing and reading are separate grants, so a
  // bucket that refuses one and serves the other is exactly the case worth catching.
  const listing = await execute(client, { ...spec, endpoint: listUrl }, credA, { method: "GET" });
  const read = objectUrl ? await execute(client, { ...spec, endpoint: objectUrl }, credA, { method: "GET" }) : null;

  const listable = !isDenied(listing, spec) && listing.status === 200 && listing.text.includes("<Key>");
  const readable = read ? !isDenied(read, spec) && (read.status === 200 || read.status === 206) && read.text.length > 0 : false;
  const exposed = listable || readable;

  return verdict(spec, {
    status: exposed ? "fail" : "pass",
    observed: `Tenant ${tenantA}'s credentials can ${listable ? "list" : "read"} tenant ${tenantB}'s objects`,
    activatedBy,
    evidence:
      `LIST ${prefix} as the other tenant → HTTP ${listing.status}${listable ? " (keys returned)" : ""}\n` +
      (read ? `GET ${prefix}${spec.objectKey} → HTTP ${read.status}${readable ? " (content returned)" : ""}\n` : "GET not attempted — no objectKey in the spec, so only listing was tested\n") +
      listing.text.slice(0, 400),
    remediation: exposed
      ? "Scope the bucket policy or IAM condition to the caller's tenant prefix (aws:PrincipalTag, or a condition on s3:prefix), and enforce it in the credential-vending layer rather than in the client."
      : "",
  });
}

/** A list endpoint returns only the caller's own records. */
async function enumeration(client, spec, { credA, activatedBy }) {
  const result = await execute(client, spec, credA, { query: spec.query, variables: spec.variables, path: spec.path, method: spec.method });
  if (isDenied(result, spec)) {
    return verdict(spec, {
      status: "pass",
      activatedBy,
      evidence: `The enumeration endpoint refused the request outright → HTTP ${result.status}\n${result.text.slice(0, 400)}`,
    });
  }

  const claimField = spec.identityClaimField ?? "owner";
  const owners = new Set(collectValues(result.json ?? {}, claimField));
  const identity = spec.identityValue ?? (credA?.subject ?? null);
  if (owners.size === 0) {
    return inconclusive(
      spec.id,
      spec.title ?? spec.description ?? spec.id,
      `The response carried no "${claimField}" field, so ownership of the returned records cannot be established. HTTP ${result.status}\n${result.text.slice(0, 300)}`,
      `Set identityClaimField to the attribute this API returns for record ownership.`,
    );
  }

  const foreign = identity ? [...owners].filter((owner) => owner !== identity) : [...owners].slice(1);
  const leaked = identity ? foreign.length > 0 : owners.size > 1;
  return verdict(spec, {
    status: leaked ? "fail" : "pass",
    observed: "A list query returns records belonging to other users",
    activatedBy,
    evidence:
      `${owners.size} distinct "${claimField}" value(s) in the response` +
      (identity ? ` for caller ${identity}` : " (caller identity unknown — a token subject would sharpen this)") +
      `\nHTTP ${result.status}\n${result.text.slice(0, 500)}`,
    remediation: leaked
      ? "Apply an owner or tenant filter derived from the token claims inside the list resolver. A filter applied by the client is not a control."
      : "",
  });
}

/** A privileged mutation is refused. The request is expected to change nothing. */
async function mutationGuard(client, spec, { credA, activatedBy }) {
  const result = await execute(client, spec, credA, {
    query: spec.mutation,
    variables: spec.variables,
    path: spec.path,
    method: spec.method ?? "POST",
    body: spec.body,
    // Marked as a mutation that is expected to be refused: it runs under allowDenialTests
    // without enabling writes generally, because if the control holds nothing is written.
    write: true,
    denialTest: true,
  });
  const denied = isDenied(result, spec);
  const errored = Boolean(result.json?.errors?.length);
  const accepted = !denied && !errored && hasData(result.json ?? result.text);

  return verdict(spec, {
    status: accepted ? "fail" : denied || errored ? "pass" : "warn",
    observed: "A privileged mutation was accepted from an ordinary identity",
    activatedBy,
    evidence: `The mutation was attempted as an ordinary identity → HTTP ${result.status}\n${result.text.slice(0, 600)}`,
    remediation: accepted
      ? "Authorise the mutation server-side against a group or role claim asserted by the token, and reject it in the resolver when the claim is absent."
      : "The response was neither a denial nor a recognisable error. Add denialPatterns so this verdict is unambiguous, and confirm by hand whether anything was written.",
  });
}

/** A client-supplied identity field does not override the token. */
async function identityInjection(client, spec, { credA, activatedBy }) {
  const injectedValue = spec.injectedValue ?? spec.variables?.[spec.injectedField];
  const result = await execute(client, spec, credA, { query: spec.query, variables: spec.variables, path: spec.path, method: spec.method, body: spec.body });
  const indicators = (spec.successIndicators ?? []).map((p) => new RegExp(p, "i"));
  const honoured = indicators.some((pattern) => pattern.test(result.text));
  const denied = isDenied(result, spec);

  return verdict(spec, {
    status: honoured ? "fail" : denied ? "pass" : "warn",
    observed: `The server acted on the client-supplied "${spec.injectedField}" field instead of the token identity`,
    activatedBy,
    evidence:
      `Request carried ${spec.injectedField}=${injectedValue} while authenticated as a different identity → HTTP ${result.status}\n` +
      result.text.slice(0, 600),
    remediation: honoured
      ? "Derive identity from the verified token server-side and ignore any identity field in the request payload. A client-supplied identity is an assertion, not a credential."
      : indicators.length === 0
        ? "No successIndicators were declared, so acceptance could not be detected. Add a pattern that would appear in a response acting as the injected identity."
        : "The field appears to have been ignored, but the request was not refused either. Confirm the server did not silently act on it.",
  });
}

const HANDLERS = {
  "record-ownership": recordOwnership,
  "prefix-scoped-storage": prefixScopedStorage,
  enumeration,
  "mutation-guard": mutationGuard,
  "identity-injection": identityInjection,
};

/** Which identities a type needs before it can claim anything. */
const NEEDS_TWO_IDENTITIES = new Set(["record-ownership", "prefix-scoped-storage"]);

export async function runIsolationProbes(config, client, context = {}) {
  const specs = config.isolation ?? [];
  if (specs.length === 0) return [skipped("ISOLATION-CONFIG", "Declared isolation boundaries", "config.isolation is not defined")];

  const out = [];
  const env = context.env ?? process.env;
  // Chains may reach across probe modules, so the gate sees everything produced so far in the
  // run, not only this module's own findings.
  const statuses = statusIndex(context.findings ?? []);

  for (const spec of specs) {
    const title = spec.title ?? spec.description ?? spec.id;
    if (!spec.id) {
      out.push(inconclusive("ISOLATION-CONFIG", "Declared isolation boundaries", "an isolation spec has no id, so its result could not be attributed"));
      continue;
    }
    if (!HANDLERS[spec.type]) {
      out.push(boundarySkip(spec, `type "${spec.type ?? "(none)"}" is not one of: ${ISOLATION_TYPES.join(", ")}`));
      continue;
    }
    if (!spec.endpoint && !spec.baseUrl) {
      out.push(boundarySkip(spec, "neither endpoint nor baseUrl is defined"));
      continue;
    }

    const gate = chainGate(spec, statuses);
    if (!gate.run) {
      // The upstream control holding is the reason, and it is a result worth stating.
      out.push(boundarySkip(spec, gate.reason));
      continue;
    }

    const { credential: credA, reason: reasonA } = credentialFor(client, spec, "tokenA", { env });
    const { credential: credB, reason: reasonB } = credentialFor(client, spec, "tokenB", { env });
    // A single-identity boundary is usually written with "token" rather than "tokenA", so the
    // skip must name the field the spec actually declared — a reason pointing at a field the
    // author never wrote sends them looking in the wrong place.
    const fallback = credentialFor(client, spec, "token", { env });
    const single = credA ?? fallback.credential;
    if (!single) {
      out.push(boundarySkip(spec, spec.token || spec.tokenEnv ? fallback.reason : reasonA));
      continue;
    }
    if (NEEDS_TWO_IDENTITIES.has(spec.type) && !credB) {
      // A boundary claim made with one identity is not a boundary claim.
      out.push(boundarySkip(spec, `a boundary needs two identities: ${reasonB}`));
      continue;
    }

    try {
      out.push(await HANDLERS[spec.type](client, spec, { credA: single, credB, activatedBy: gate.activatedBy, env }));
    } catch (error) {
      out.push(inconclusive(spec.id, title, `Probe failed: ${error.message}`));
    }
    statuses.set(spec.id, out[out.length - 1].status);   // a later spec may depend on this one
  }

  return out;
}
