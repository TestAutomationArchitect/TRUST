/**
 * TRUST — token hygiene probes.
 *
 * These issue **no HTTP requests at all**: every verdict comes from decoding the tokens the
 * harness was given. That makes them the cheapest checks in the suite and the safest to run
 * anywhere, and they catch a class of misconfiguration that traffic-based probing misses —
 * an over-broad scope or a year-long lifetime is invisible from the outside.
 *
 * Signatures are NOT verified: the harness holds no keys, and a client cannot meaningfully
 * verify the issuer's signature. Everything here is a claim-shape assertion, which is stated
 * in the evidence so nobody mistakes it for cryptographic validation.
 *
 * TOKEN-IDENTITY-DISTINCT deserves special mention: if User A and User B turn out to be the
 * same subject, every cross-user isolation test in the run is vacuous — they would "pass" by
 * accident. That check protects the credibility of the whole report.
 */

import { finding, skipped } from "../finding.mjs";
import { section } from "../config.mjs";

/** Decode a JWT without verifying it. Returns null for opaque tokens. */
export function decodeJwt(token) {
  if (typeof token !== "string") return null;
  const parts = token.trim().split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (typeof header !== "object" || typeof payload !== "object") return null;
    return { header, payload, signature: parts[2] };
  } catch {
    return null;
  }
}

/** The claim an identity provider uses for "who" varies; check the usual suspects in order. */
const SUBJECT_CLAIMS = ["sub", "oid", "user_id", "username", "cognito:username", "preferred_username", "upn", "email"];
export function subjectOf(payload) {
  for (const claim of SUBJECT_CLAIMS) {
    if (payload?.[claim]) return { claim, value: String(payload[claim]) };
  }
  return null;
}

const WEAK_ALGS = new Set(["none", "HS1", "RS1"]);
const DEFAULT_MAX_LIFETIME_SECONDS = 12 * 3600;
const BROAD_SCOPE = /(^|[\s:/])(\*|admin|superuser|root|full_access|all)([\s:/]|$)/i;

/** Which tokens are configured, across every section, without duplicating a value. */
function collectTokens(config) {
  // Sections resolve through their conventional spellings, so tokens declared under
  // "graphql" or "agentCore" are inspected just like those under "api" or "agent".
  const api = section(config, "api").value;
  const storage = section(config, "storage").value;
  const agent = section(config, "agent").value;
  const mobile = section(config, "mobile").value;
  const sources = [
    ["A", api?.tokenAEnv, "api"],
    ["B", api?.tokenBEnv, "api"],
    ["A", storage?.tokenAEnv, "storage"],
    ["B", storage?.tokenBEnv, "storage"],
    ["A", agent?.accessTokenAEnv, "agent"],
    ["B", agent?.accessTokenBEnv, "agent"],
    ["A", mobile?.tokenEnv, "mobile"],
  ];
  const out = [];
  // Named sectionName, not section: the imported resolver is in scope here and shadowing it
  // would break any later use inside this loop.
  for (const [identity, envName, sectionName] of sources) {
    if (!envName) continue;
    const value = process.env[envName];
    if (!value) continue;
    if (out.some((t) => t.value === value)) continue;
    out.push({ identity, envName, section: sectionName, value });
  }
  return out;
}

export async function runTokenProbes(config) {
  const tokens = collectTokens(config);
  if (tokens.length === 0) {
    return [skipped("TOKEN-CONFIG", "Token hygiene probe suite", "no token env vars are configured or set")];
  }

  const out = [];
  const decoded = tokens.map((t) => ({ ...t, jwt: decodeJwt(t.value) }));
  const jwts = decoded.filter((t) => t.jwt);

  if (jwts.length === 0) {
    return [
      skipped(
        "TOKEN-CONFIG",
        "Token hygiene probe suite",
        `${tokens.length} token(s) present but none are JWTs — claim inspection does not apply to opaque tokens`,
      ),
    ];
  }

  const label = (t) => `${t.envName} (identity ${t.identity}, ${t.section})`;
  const maxLifetime = config.tokens?.maxLifetimeSeconds ?? DEFAULT_MAX_LIFETIME_SECONDS;
  const nowSeconds = Math.floor(Date.now() / 1000);

  // ── 1. Algorithm ─────────────────────────────────────────────────
  const algIssues = jwts
    .map((t) => {
      const alg = String(t.jwt.header.alg ?? "");
      if (!alg) return `${label(t)}: no alg header`;
      if (WEAK_ALGS.has(alg) || alg.toLowerCase() === "none") return `${label(t)}: alg=${alg}`;
      if (!t.jwt.signature) return `${label(t)}: alg=${alg} but the signature segment is empty`;
      return null;
    })
    .filter(Boolean);
  out.push(
    finding({
      id: "TOKEN-ALG",
      observed: "Tokens declare a weak or absent signing algorithm",
      title: "Tokens are signed with a strong algorithm",
      status: algIssues.length ? "fail" : "pass",
      severity: "high",
      evidence: algIssues.length
        ? `${algIssues.join("\n")}\n(Signature verification is out of scope — this asserts the declared algorithm only.)`
        : jwts.map((t) => `${label(t)}: alg=${t.jwt.header.alg}, kid=${t.jwt.header.kid ?? "(none)"}`).join("\n"),
      remediation: algIssues.length
        ? "Reject tokens whose alg is 'none' or a symmetric algorithm where an asymmetric one is expected, and pin the accepted algorithm set server-side rather than trusting the header."
        : "",
    }),
  );

  // ── 2. Lifetime ──────────────────────────────────────────────────
  const lifetimes = jwts.map((t) => {
    const { exp, iat, nbf } = t.jwt.payload;
    return {
      label: label(t),
      exp,
      lifetime: exp && iat ? exp - iat : null,
      expired: exp ? exp < nowSeconds : null,
      remaining: exp ? exp - nowSeconds : null,
      hasNbf: nbf !== undefined,
    };
  });
  const noExp = lifetimes.filter((l) => !l.exp);
  const tooLong = lifetimes.filter((l) => l.lifetime && l.lifetime > maxLifetime);
  out.push(
    finding({
      id: "TOKEN-LIFETIME",
      observed: "Tokens carry no expiry, or an over-long one",
      title: "Tokens carry a bounded expiry",
      status: noExp.length ? "fail" : tooLong.length ? "warn" : "pass",
      severity: "medium",
      evidence:
        lifetimes
          .map(
            (l) =>
              `${l.label}: ${l.exp ? `exp in ${Math.round((l.remaining ?? 0) / 60)} min` : "NO exp CLAIM"}` +
              `${l.lifetime ? `, issued for ${Math.round(l.lifetime / 60)} min` : ""}${l.hasNbf ? ", nbf present" : ""}`,
          )
          .join("\n") + `\nPolicy: lifetime must not exceed ${Math.round(maxLifetime / 60)} min (config.tokens.maxLifetimeSeconds).`,
      remediation: noExp.length
        ? "Issue tokens with an exp claim and reject any token that lacks one — a token without an expiry is a permanent credential."
        : tooLong.length
          ? "Shorten the access-token lifetime and rely on refresh-token rotation for continuity."
          : "",
    }),
  );

  // A token that has already expired makes every other result in the run suspect.
  const expired = lifetimes.filter((l) => l.expired);
  if (expired.length) {
    out.push(
      finding({
        id: "TOKEN-FRESHNESS",
        observed: "Supplied test tokens have already expired",
        title: "Supplied test tokens are still valid",
        status: "warn",
        severity: "low",
        evidence: `Expired token(s) in use: ${expired.map((l) => l.label).join(", ")}. Authenticated findings in this run may reflect rejected credentials rather than enforced controls.`,
        remediation: "Refresh the tokens in .env and re-run before acting on any authenticated finding.",
      }),
    );
  }

  // ── 3. Issuer and audience ───────────────────────────────────────
  const expectedIssuer = config.tokens?.expectedIssuer;
  const expectedAudience = config.tokens?.expectedAudience;
  const claimIssues = jwts
    .map((t) => {
      const { iss, aud } = t.jwt.payload;
      const problems = [];
      if (!iss) problems.push("no iss");
      else if (expectedIssuer && iss !== expectedIssuer) problems.push(`iss=${iss} (expected ${expectedIssuer})`);
      if (!aud) problems.push("no aud");
      else if (expectedAudience && ![].concat(aud).includes(expectedAudience)) problems.push(`aud=${[].concat(aud).join(",")} (expected ${expectedAudience})`);
      return problems.length ? `${label(t)}: ${problems.join("; ")}` : null;
    })
    .filter(Boolean);
  out.push(
    finding({
      id: "TOKEN-CLAIMS",
      observed: "Tokens are not bound to an issuer and audience",
      title: "Tokens are scoped to an issuer and an audience",
      status: claimIssues.length ? "warn" : "pass",
      severity: "medium",
      evidence: claimIssues.length
        ? claimIssues.join("\n") +
          (expectedIssuer || expectedAudience ? "" : "\nSet config.tokens.expectedIssuer / expectedAudience for a strict comparison.")
        : jwts.map((t) => `${label(t)}: iss=${t.jwt.payload.iss}, aud=${[].concat(t.jwt.payload.aud).join(",")}`).join("\n"),
      remediation: claimIssues.length
        ? "Validate iss and aud on every request. A token minted for another audience must be rejected even when its signature is valid."
        : "",
    }),
  );

  // ── 4. Scope breadth ─────────────────────────────────────────────
  const scoped = jwts.map((t) => {
    const p = t.jwt.payload;
    const scope = p.scope ?? p.scp ?? p.permissions ?? p.roles ?? p["cognito:groups"] ?? null;
    const flat = scope === null ? "" : Array.isArray(scope) ? scope.join(" ") : String(scope);
    return { label: label(t), flat, broad: BROAD_SCOPE.test(flat) };
  });
  const broad = scoped.filter((s) => s.broad);
  const unscoped = scoped.filter((s) => !s.flat);
  out.push(
    finding({
      id: "TOKEN-SCOPE",
      observed: "A test identity holds administrative or wildcard scope",
      title: "Test identities do not hold administrative or wildcard scope",
      status: broad.length ? "fail" : unscoped.length === scoped.length ? "warn" : "pass",
      severity: "high",
      evidence: broad.length
        ? broad.map((s) => `${s.label}: ${s.flat}`).join("\n") +
          "\nAn ordinary test identity holding admin scope means authorisation findings understate real-world risk."
        : scoped.map((s) => `${s.label}: ${s.flat || "no scope/roles claim found"}`).join("\n"),
      remediation: broad.length
        ? "Re-issue the test identities with least-privilege scope. Re-run afterwards: authorisation results obtained with an over-privileged token are not evidence that the control works for ordinary users."
        : unscoped.length === scoped.length
          ? "No scope, roles or groups claim was found, so privilege level could not be established. Confirm authorisation is not derived from an absent claim."
          : "",
    }),
  );

  // ── 5. Two identities must genuinely differ ──────────────────────
  const aTokens = jwts.filter((t) => t.identity === "A");
  const bTokens = jwts.filter((t) => t.identity === "B");
  if (aTokens.length === 0 || bTokens.length === 0) {
    out.push(
      skipped(
        "TOKEN-IDENTITY-DISTINCT",
        "The two test identities are genuinely different principals",
        "only one identity is configured — cross-user isolation cannot be asserted",
      ),
    );
  } else {
    const subjectA = subjectOf(aTokens[0].jwt.payload);
    const subjectB = subjectOf(bTokens[0].jwt.payload);
    const same = subjectA && subjectB && subjectA.value === subjectB.value;
    out.push(
      finding({
        id: "TOKEN-IDENTITY-DISTINCT",
        observed: "The two test identities are the same principal",
        title: "The two test identities are genuinely different principals",
        status: !subjectA || !subjectB ? "warn" : same ? "fail" : "pass",
        severity: "high",
        evidence:
          `Identity A: ${subjectA ? `${subjectA.claim}=${subjectA.value}` : "no recognisable subject claim"}\n` +
          `Identity B: ${subjectB ? `${subjectB.claim}=${subjectB.value}` : "no recognisable subject claim"}` +
          (same ? "\nBoth tokens represent the SAME principal — every cross-user isolation test in this run is vacuous." : ""),
        remediation: same
          ? "Provision two distinct users and re-run. Cross-user and cross-tenant results from a single principal prove nothing."
          : !subjectA || !subjectB
            ? "Could not read a subject claim, so distinctness is unconfirmed. Verify the two tokens belong to different users."
            : "",
      }),
    );

    // Tenant separation, where the provider exposes it.
    const tenantClaims = ["tenant", "tenant_id", "tid", "org", "org_id", "department", "custom:department"];
    const tenantOf = (payload) => {
      for (const claim of tenantClaims) if (payload?.[claim]) return `${claim}=${payload[claim]}`;
      return null;
    };
    const tenantA = tenantOf(aTokens[0].jwt.payload);
    const tenantB = tenantOf(bTokens[0].jwt.payload);
    if (tenantA || tenantB) {
      out.push(
        finding({
          id: "TOKEN-TENANT-DISTINCT",
          observed: "Both test identities sit in the same tenant",
          title: "The two test identities sit in different tenants",
          status: tenantA && tenantB ? (tenantA === tenantB ? "warn" : "pass") : "warn",
          severity: "medium",
          evidence: `Identity A: ${tenantA ?? "no tenant claim"}\nIdentity B: ${tenantB ?? "no tenant claim"}`,
          remediation:
            tenantA === tenantB
              ? "Both identities are in the same tenant, so cross-tenant storage and API isolation were not genuinely exercised. Provision a second tenant to validate that boundary."
              : "Tenant membership could not be read for both identities — confirm the cross-tenant tests were meaningful.",
        }),
      );
    }
  }

  return out;
}
