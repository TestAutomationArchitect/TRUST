/**
 * TRUST — token validation, tested against the running server.
 *
 * The token probes inspect claims offline: they can tell you a token declares RS256 and carries
 * an audience. What they cannot tell you is whether the *server* checks any of it. Those are
 * different questions, and only the second one is a control. A gateway that accepts
 * `{"alg":"none"}`, or accepts a token whose signature has been altered, has no authentication
 * at all — every authorisation result in the rest of the report is then meaningless, because
 * anyone can mint the identity it was tested with.
 *
 * Each probe takes the *real* token the run already holds, alters exactly one property of it,
 * and sends it to an endpoint that requires authentication. The expected answer is 401 or 403.
 * A 200 is the finding.
 *
 * Nothing here is a plausible attack payload: the altered tokens are invalid by construction and
 * cannot authorise anything on a server that checks them. Against a server that does not, they
 * demonstrate exactly that, which is the point.
 */

import crypto from "node:crypto";
import { finding, skipped, inconclusive, DENIAL_LANGUAGE } from "../finding.mjs";
import { section } from "../config.mjs";
import { authInit, credentialFor, jwtClaims } from "../auth/index.mjs";
import { decodeJwt } from "./token.mjs";

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");

/** Re-sign nothing: build a token with the algorithm removed, the shape `alg:none` attacks use. */
function algNone(jwt) {
  return `${b64({ ...jwt.header, alg: "none" })}.${b64(jwt.payload)}.`;
}

/** Same header and claims, a signature that cannot verify. */
function brokenSignature(jwt, original) {
  const [header, payload] = original.split(".");
  // Flip the signature deterministically rather than randomly, so the same run is reproducible
  // and the evidence can state exactly what was changed.
  const flipped = jwt.signature.length
    ? jwt.signature.slice(0, -4) + (jwt.signature.slice(-4) === "AAAA" ? "BBBB" : "AAAA")
    : crypto.randomBytes(32).toString("base64url");
  return `${header}.${payload}.${flipped}`;
}

/** A key ID the issuer never published — tests whether the server pins its key set. */
function foreignKid(jwt, original) {
  const [, payload, signature] = original.split(".");
  return `${b64({ ...jwt.header, kid: "trust-probe-key-not-in-jwks" })}.${payload}.${signature}`;
}

/** Claims altered without re-signing: the signature no longer covers what the body says. */
function tamperedClaims(jwt, original) {
  const [header, , signature] = original.split(".");
  const payload = { ...jwt.payload };
  // Elevate whatever the token actually carries, rather than inventing a claim the API ignores.
  if (Array.isArray(payload["cognito:groups"])) payload["cognito:groups"] = ["admin", ...payload["cognito:groups"]];
  else if (payload.scope) payload.scope = `${payload.scope} admin`;
  else if (payload.roles) payload.roles = ["admin"];
  else payload.admin = true;
  payload.sub = `${payload.sub ?? "user"}-trust-probe`;
  return `${header}.${b64(payload)}.${signature}`;
}

const FORGERIES = [
  {
    id: "JWT-ALG-NONE",
    title: "The API rejects an unsigned token",
    observed: "The API accepts a token with alg:none — the signature is not verified at all",
    severity: "critical",
    build: algNone,
    what: "algorithm changed to none and the signature removed",
    remediation:
      "Pin the accepted algorithms explicitly at the verifier and reject `none`. A library that infers the algorithm from the token header lets a caller choose it, which means the caller can choose not to have one.",
  },
  {
    id: "JWT-SIGNATURE",
    title: "The API rejects a token whose signature does not verify",
    observed: "The API accepts a token with an altered signature — signatures are not checked",
    severity: "critical",
    build: brokenSignature,
    what: "last four characters of the signature altered",
    remediation:
      "Verify the signature against the issuer's public key on every request. An API that reads claims without verifying them is trusting whatever the caller wrote.",
  },
  {
    id: "JWT-CLAIMS-TAMPERED",
    title: "The API rejects a token whose claims no longer match its signature",
    observed: "The API accepts claims the signature does not cover — privileges can be self-granted",
    severity: "critical",
    build: tamperedClaims,
    what: "group/scope claim elevated and subject changed, signature left untouched",
    remediation: "Verify before reading. Any claim used for authorisation must come from a payload whose signature has already been checked.",
  },
  {
    id: "JWT-UNKNOWN-KID",
    title: "The API rejects a token naming an unknown signing key",
    observed: "The API accepts a token naming a key that is not in the issuer's key set",
    severity: "high",
    build: foreignKid,
    what: "kid replaced with an identifier the issuer never published",
    remediation:
      "Resolve `kid` against the issuer's published JWKS and reject anything absent from it, rather than falling back to a default key when the lookup fails.",
  },
];

/** Did the server refuse this token? Anything other than a refusal is the finding. */
const refused = (status, text) =>
  status === 401 || status === 403 || /invalid.*token|unauthor|not authenticated|signature|jwt/i.test(text);

export async function runJwtProbes(config, client) {
  const { value: api, key: apiKey } = section(config, "api");
  const endpoint = api?.session?.verifyEndpoint ? new URL(api.session.verifyEndpoint, api.endpoint).href : api?.endpoint;
  if (!endpoint) {
    return [skipped("JWT-CONFIG", "Server-side token validation probe suite", `config.${apiKey ?? "api"}.endpoint is not configured`)];
  }

  const { credential, reason } = credentialFor(client, api, "tokenA");
  if (!credential) return [skipped("JWT-CONFIG", "Server-side token validation probe suite", reason)];
  if (credential.kind !== "bearer") {
    return [
      skipped(
        "JWT-CONFIG",
        "Server-side token validation probe suite",
        `identity A is a ${credential.kind} credential — these probes alter a JWT, so they need a bearer token`,
        "not-applicable",
      ),
    ];
  }

  const jwt = decodeJwt(credential.token);
  if (!jwt) {
    return [
      skipped(
        "JWT-CONFIG",
        "Server-side token validation probe suite",
        "identity A's token is opaque rather than a JWT, so there is nothing to alter — the server may still be validating it correctly",
        "not-applicable",
      ),
    ];
  }

  const isGraphql = (api.kind ?? "graphql") === "graphql" && endpoint === api.endpoint;
  const out = [];

  for (const forgery of FORGERIES) {
    const forged = forgery.build(jwt, credential.token);
    try {
      const auth = authInit({ ...credential, token: forged }, {
        header: api.authHeader ?? "authorization",
        scheme: api.authScheme ?? "Bearer",
        headers: { "content-type": "application/json", ...(api.headers ?? {}) },
      });
      const response = await client.request(endpoint, {
        ...auth,
        method: isGraphql ? "POST" : (api.session?.verifyMethod ?? "GET"),
        body: isGraphql ? JSON.stringify({ query: api.session?.verifyQuery ?? "query { __typename }" }) : undefined,
      });
      const text = (await response.text()).slice(0, 400);
      const held = refused(response.status, text);

      out.push(
        finding({
          id: forgery.id,
          title: forgery.title,
          observed: forgery.observed,
          status: held ? "pass" : "fail",
          severity: forgery.severity,
          category: "Token Hygiene",
          domain: "Authentication",
          evidence:
            `Sent identity A's own token with the ${forgery.what}, to ${endpoint} → HTTP ${response.status}\n${text}\n` +
            `Verdict basis: ${held ? "the server refused it, so this property is verified server-side" : "the server answered as though the token were valid"}`,
          remediation: held ? "" : forgery.remediation,
        }),
      );
    } catch (error) {
      out.push(inconclusive(forgery.id, forgery.title, `Request failed: ${error.message}`));
    }
  }

  // ── Audience binding across services ──────────────────────────────
  //
  // A token is minted *for* something. The `aud` claim says which service, and a service that
  // does not check it will happily accept a token issued for its neighbour — which is how a
  // compromised or over-shared machine credential turns into access it was never granted. This
  // is the multi-service half of verification: the forgeries above ask whether a token is
  // genuine, and this asks whether a genuine token is genuine *here*.
  //
  // Declared rather than inferred, because only the operator knows which credential belongs to
  // which surface, and sending the wrong token at the wrong endpoint on a guess would produce
  // findings about a boundary nobody drew.
  const crossService = api.crossService ?? config.tokens?.crossService ?? [];
  if (crossService.length === 0) {
    // Worth naming when there is more than one identity to cross, and silent when there is not.
    const identities = [...(client.credentials?.values() ?? [])].filter((c) => c.kind === "bearer" && !c.error);
    const audiences = new Set(identities.map((c) => jwtClaims(c.token)?.aud).filter(Boolean).map(String));
    out.push(
      skipped(
        "JWT-AUDIENCE-BINDING",
        "A token is only accepted by the service it was issued for",
        audiences.size > 1
          ? `config.api.crossService is not defined, and this run holds tokens for ${audiences.size} different audiences (${[...audiences].join(", ")}) — declare which token should be refused by which endpoint and this control can be tested`
          : "config.api.crossService is not defined (name a token and an endpoint it should NOT be accepted by)",
      ),
    );
  } else {
    for (const spec of crossService) {
      const id = `JWT-AUDIENCE-${String(spec.name ?? "CROSS").toUpperCase().replace(/[^A-Z0-9]+/g, "-")}`;
      const title = spec.title ?? `A token issued for another service is refused by ${spec.name ?? spec.endpoint}`;
      const { credential, reason } = credentialFor(client, spec, "token");
      if (!credential) {
        out.push(skipped(id, title, reason));
        continue;
      }
      if (credential.kind !== "bearer") {
        out.push(skipped(id, title, `${spec.token} is a ${credential.kind} credential — audience binding applies to bearer tokens`, "not-applicable"));
        continue;
      }

      const claims = jwtClaims(credential.token);
      const audience = claims?.aud ? [claims.aud].flat().join(", ") : null;
      // A token that already names this service is the wrong instrument for the test: it would
      // be accepted correctly, and reporting that as a pass would be meaningless.
      if (spec.expectedAudience && audience && [claims.aud].flat().map(String).includes(String(spec.expectedAudience))) {
        out.push(
          skipped(
            id,
            title,
            `${spec.token} carries aud=${audience}, which is the audience this endpoint expects — crossing it proves nothing. Point this spec at a token minted for a different service.`,
            "precondition",
          ),
        );
        continue;
      }

      try {
        const isGraphql = spec.query || (spec.kind ?? "") === "graphql";
        const auth = authInit(credential, {
          header: spec.authHeader ?? api.authHeader ?? "authorization",
          scheme: spec.authScheme ?? api.authScheme ?? "Bearer",
          headers: { "content-type": "application/json", ...(spec.headers ?? {}) },
        });
        const response = await client.request(spec.endpoint, {
          ...auth,
          method: spec.method ?? (isGraphql || spec.body ? "POST" : "GET"),
          body: isGraphql ? JSON.stringify({ query: spec.query ?? "query { __typename }", variables: spec.variables ?? {} }) : spec.body ? JSON.stringify(spec.body) : undefined,
          // An agent runtime counts as an invocation whoever is asking.
          agentInvocation: spec.agentInvocation === true,
        });
        const text = (await response.text()).slice(0, 400);

        // Positive evidence, as everywhere else: an answer is acceptance, a refusal is the
        // control holding, and anything else settles nothing.
        const refusedIt = refused(response.status, text) || DENIAL_LANGUAGE.test(text);
        const answered = response.status >= 200 && response.status < 300 && !DENIAL_LANGUAGE.test(text);
        const unroutable = response.status === 404 || /UnknownOperation|not found/i.test(text);

        out.push(
          finding({
            id,
            title,
            observed: `A token issued for ${audience ?? "another service"} was accepted by ${spec.name ?? spec.endpoint}`,
            status: answered && !unroutable ? "fail" : refusedIt && !unroutable ? "pass" : "warn",
            warnKind: "inconclusive",
            severity: spec.severity ?? "high",
            category: "Token Hygiene",
            domain: "Authentication",
            fix: "token-verification",
            evidence:
              `${spec.token} (aud=${audience ?? "absent"}) sent to ${spec.endpoint} → HTTP ${response.status}
${text}
` +
              `Verdict basis: ${
                unroutable
                  ? "the endpoint did not route this request, so nothing was learned about audience binding"
                  : answered
                    ? "the service answered a token that was not issued for it"
                    : refusedIt
                      ? "the service refused a token issued for another audience"
                      : "the response was neither an answer nor a refusal"
              }`,
            remediation:
              answered && !unroutable
                ? "Validate the `aud` claim against this service's own identifier, and reject anything else. A service that verifies only the signature accepts every token the same issuer ever minted — including one belonging to a neighbour with different privileges."
                : unroutable
                  ? "Point this spec at an endpoint that answers for a valid caller, so the refusal being tested is an authorisation decision rather than a routing error."
                  : "",
          }),
        );
      } catch (error) {
        out.push(inconclusive(id, title, `Request failed: ${error.message}`));
      }
    }
  }

  // One statement a reader should not have to assemble from four rows.
  const broken = out.filter((f) => f.status === "fail");
  if (broken.length) {
    out.push(
      finding({
        id: "JWT-VERIFICATION",
        title: "Token verification is enforced by the API",
        observed: `The API accepts ${broken.length} of ${FORGERIES.length} deliberately invalid tokens`,
        status: "fail",
        severity: "critical",
        category: "Token Hygiene",
        domain: "Authentication",
        evidence:
          `Accepted: ${broken.map((f) => f.id).join(", ")}.\n` +
          "Every authorisation result in this report was obtained with a token this API does not fully verify, so those results describe what the API does for a caller it believes — not what it does for an attacker who can mint that belief.",
        remediation: "Fix token verification first. Owner scoping, RBAC and tenant isolation are all downstream of an identity the server can actually trust.",
      }),
    );
  }

  return out;
}
