/**
 * TRUST — declarative auth strategies.
 *
 * TRUST used to assume a bearer token sitting in .env. Real deployments do not work that way:
 * they authenticate against an IdP, exchange the result for scoped credentials, and sign the
 * request. Field use ranked this the single biggest adoption blocker, because the workaround —
 * acquire a token by hand, paste it into .env, re-paste it an hour later — cannot run in CI.
 *
 * A strategy is declared in config, resolved once before probes run, and referenced by name:
 *
 *   "auth": {
 *     "strategies": {
 *       "userA": { "type": "cognito-srp", "region": "…", "userPoolId": "…", "clientId": "…",
 *                  "username": "a@example.com", "passwordEnv": "USER_A_PASSWORD" },
 *       "svc":   { "type": "sigv4", "region": "us-east-1", "service": "execute-api" }
 *     }
 *   },
 *   "api": { "endpoint": "…", "tokenA": "userA", "tokenB": "userB" }
 *
 * Three rules hold for every strategy:
 *
 *   - **No strategy may weaken SafeHttpClient.** Acquisition goes *through* the guarded client,
 *     so an IdP host must be in targets.allowedHosts like any other host, and signing happens
 *     inside request() on a URL the guards have already approved.
 *   - **Missing inputs degrade to a precise skip**, never a throw and never a silent pass. A
 *     failed acquisition is reported with the reason the probe would otherwise have to guess.
 *   - **Nothing prints a secret.** Credentials carry tokens; the reporting surface carries
 *     names, kinds and expiry.
 */

import { signRequest } from "./sigv4.mjs";
import { createSrpClient, passwordVerifier, poolNameOf, secretHash } from "./srp.mjs";

export { signRequest, amzDate } from "./sigv4.mjs";

/** Decode a JWT payload without verifying it — for expiry reporting only, never for a verdict. */
export function jwtClaims(token) {
  const parts = String(token ?? "").split(".");
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch {
    return null;
  }
}

const envOf = (name, env) => (name ? env[name] : undefined);

function bearer({ name, type, token, source, scheme = "Bearer", reacquire = null }) {
  const claims = jwtClaims(token);
  return {
    name,
    type,
    kind: "bearer",
    token,
    scheme,
    source,
    expiresAt: claims?.exp ? new Date(claims.exp * 1000).toISOString() : null,
    subject: claims?.sub ?? claims?.username ?? null,
    reacquire,
  };
}

function awsCredential({ name, type, credentials, source, expiresAt = null, reacquire = null }) {
  return { name, type, kind: "sigv4", aws: credentials, source, expiresAt, reacquire, token: null };
}

class AuthError extends Error {}
const fail = (message) => {
  throw new AuthError(message);
};

// ── Transport ───────────────────────────────────────────────────────
/** Post a form-encoded body to a token endpoint and parse the JSON response. */
async function postForm(client, url, form, headers = {}) {
  const response = await client.request(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json", ...headers },
    body: new URLSearchParams(form).toString(),
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* handled below — a non-JSON body is reported verbatim, truncated */
  }
  if (!response.ok || !json) {
    // The IdP's own error is far more useful than "authentication failed", and these bodies
    // carry error codes, not secrets.
    fail(`token endpoint returned HTTP ${response.status}${json?.error ? ` (${json.error}${json.error_description ? `: ${json.error_description}` : ""})` : `: ${text.slice(0, 200)}`}`);
  }
  return json;
}

/** Call an AWS JSON-1.1 API (Cognito's own protocol) through the guarded client. */
async function postAwsJson(client, url, target, body) {
  const response = await client.request(url, {
    method: "POST",
    headers: { "content-type": "application/x-amz-json-1.1", "x-amz-target": target },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* handled below */
  }
  if (!response.ok) {
    const code = (json?.__type ?? "").split("#").pop();
    fail(`${target.split(".").pop()} returned HTTP ${response.status}${code ? ` ${code}` : ""}${json?.message ? `: ${json.message}` : ""}`);
  }
  return json ?? fail(`${target} returned a non-JSON body`);
}

// ── Strategies ──────────────────────────────────────────────────────
const STRATEGIES = {
  /** Today's behaviour, named — so a config can mix a pasted token with an acquired one. */
  async static(strategy, { name, env }) {
    const token = envOf(strategy.tokenEnv, env);
    if (!token) fail(`${strategy.tokenEnv ?? "tokenEnv"} is not set in the environment`);
    return bearer({ name, type: "static", token, source: strategy.tokenEnv, scheme: strategy.scheme });
  },

  /** OAuth2 client credentials — machine-to-machine, the one grant CI can always use. */
  async "client-credentials"(strategy, { name, env, client }) {
    const tokenUrl = strategy.tokenUrl ?? fail("tokenUrl is required");
    const secret = envOf(strategy.clientSecretEnv, env);
    if (strategy.clientSecretEnv && !secret) fail(`${strategy.clientSecretEnv} is not set in the environment`);
    const json = await postForm(client, tokenUrl, {
      grant_type: "client_credentials",
      client_id: strategy.clientId ?? fail("clientId is required"),
      ...(secret ? { client_secret: secret } : {}),
      ...(strategy.scope ? { scope: strategy.scope } : {}),
      ...(strategy.audience ? { audience: strategy.audience } : {}),
    });
    return bearer({ name, type: "client-credentials", token: json.access_token ?? fail("response carried no access_token"), source: tokenUrl, scheme: strategy.scheme });
  },

  /**
   * Okta resource-owner password grant. Only usable where the org has deliberately enabled it;
   * a disabled grant is reported as such rather than as a credential failure.
   */
  async "okta-ropc"(strategy, { name, env, client }) {
    const tokenUrl = strategy.tokenUrl ?? (strategy.issuer ? `${String(strategy.issuer).replace(/\/$/, "")}/v1/token` : fail("tokenUrl or issuer is required"));
    const password = envOf(strategy.passwordEnv, env);
    if (!password) fail(`${strategy.passwordEnv ?? "passwordEnv"} is not set in the environment`);
    const secret = envOf(strategy.clientSecretEnv, env);
    const json = await postForm(client, tokenUrl, {
      grant_type: "password",
      username: strategy.username ?? fail("username is required"),
      password,
      client_id: strategy.clientId ?? fail("clientId is required"),
      ...(secret ? { client_secret: secret } : {}),
      scope: strategy.scope ?? "openid profile",
    });
    const use = strategy.use ?? "accessToken";
    const token = use === "idToken" ? json.id_token : json.access_token;
    return bearer({ name, type: "okta-ropc", token: token ?? fail(`response carried no ${use === "idToken" ? "id_token" : "access_token"}`), source: tokenUrl, scheme: strategy.scheme });
  },

  /**
   * Cognito USER_SRP_AUTH. SRP rather than USER_PASSWORD_AUTH because the alternative asks a
   * partner to enable a plaintext-password grant on their user pool to be assessed.
   */
  async "cognito-srp"(strategy, { name, env, client }) {
    const region = strategy.region ?? String(strategy.userPoolId ?? "").split("_")[0] ?? fail("region is required");
    const userPoolId = strategy.userPoolId ?? fail("userPoolId is required");
    const clientId = strategy.clientId ?? fail("clientId is required");
    const username = strategy.username ?? fail("username is required");
    const password = envOf(strategy.passwordEnv, env);
    if (!password) fail(`${strategy.passwordEnv ?? "passwordEnv"} is not set in the environment`);
    const clientSecret = envOf(strategy.clientSecretEnv, env);
    if (strategy.clientSecretEnv && !clientSecret) fail(`${strategy.clientSecretEnv} is not set in the environment`);

    const url = strategy.endpoint ?? `https://cognito-idp.${region}.amazonaws.com/`;
    const poolName = poolNameOf(userPoolId);
    const { a, A, srpA } = createSrpClient();

    const challenge = await postAwsJson(client, url, "AWSCognitoIdentityProviderService.InitiateAuth", {
      AuthFlow: "USER_SRP_AUTH",
      ClientId: clientId,
      AuthParameters: {
        USERNAME: username,
        SRP_A: srpA,
        ...(clientSecret ? { SECRET_HASH: secretHash(username, clientId, clientSecret) } : {}),
      },
    });
    if (challenge.ChallengeName !== "PASSWORD_VERIFIER") {
      fail(`user pool answered with ${challenge.ChallengeName ?? "no challenge"} — TRUST implements PASSWORD_VERIFIER only`);
    }

    const params = challenge.ChallengeParameters ?? {};
    // USER_ID_FOR_SRP, not the login name: an alias sign-in (email, phone) returns the pool's
    // internal identifier here, and signing the login name instead fails opaquely.
    const userIdForSrp = params.USER_ID_FOR_SRP ?? username;
    const { signature, timestamp } = passwordVerifier({
      a,
      A,
      srpB: params.SRP_B ?? fail("challenge carried no SRP_B"),
      salt: params.SALT ?? fail("challenge carried no SALT"),
      secretBlock: params.SECRET_BLOCK ?? fail("challenge carried no SECRET_BLOCK"),
      poolName,
      username: userIdForSrp,
      password,
    });

    const answered = await postAwsJson(client, url, "AWSCognitoIdentityProviderService.RespondToAuthChallenge", {
      ChallengeName: "PASSWORD_VERIFIER",
      ClientId: clientId,
      ChallengeResponses: {
        USERNAME: userIdForSrp,
        PASSWORD_CLAIM_SECRET_BLOCK: params.SECRET_BLOCK,
        PASSWORD_CLAIM_SIGNATURE: signature,
        TIMESTAMP: timestamp,
        ...(clientSecret ? { SECRET_HASH: secretHash(userIdForSrp, clientId, clientSecret) } : {}),
      },
      Session: challenge.Session,
    });

    const result = answered.AuthenticationResult;
    if (!result) fail(`sign-in returned a further challenge (${answered.ChallengeName ?? "unknown"}) — MFA and forced password changes are not automatable`);
    const use = strategy.use ?? "idToken";
    const token = use === "accessToken" ? result.AccessToken : result.IdToken;
    const credential = bearer({ name, type: "cognito-srp", token: token ?? fail(`sign-in returned no ${use}`), source: url, scheme: strategy.scheme });
    credential.idToken = result.IdToken ?? null;
    return credential;
  },

  /**
   * Exchange an identity-pool login for temporary AWS credentials, which are then used to
   * sign requests. `idTokenFrom` names another strategy, so the pair is declared once.
   */
  async "cognito-identity-pool"(strategy, { name, env, client, resolved }) {
    const region = strategy.region ?? String(strategy.identityPoolId ?? "").split(":")[0] ?? fail("region is required");
    const identityPoolId = strategy.identityPoolId ?? fail("identityPoolId is required");
    const providerName = strategy.providerName ?? fail("providerName is required (e.g. cognito-idp.us-east-1.amazonaws.com/us-east-1_AbC123)");

    const upstream = strategy.idTokenFrom ? resolved.get(strategy.idTokenFrom) : null;
    if (strategy.idTokenFrom && !upstream) fail(`idTokenFrom "${strategy.idTokenFrom}" is not a resolved strategy`);
    if (upstream?.error) fail(`idTokenFrom "${strategy.idTokenFrom}" did not resolve: ${upstream.error}`);
    const idToken = upstream ? (upstream.idToken ?? upstream.token) : envOf(strategy.idTokenEnv, env);
    if (!idToken) fail(strategy.idTokenEnv ? `${strategy.idTokenEnv} is not set in the environment` : "idTokenFrom or idTokenEnv is required");

    const url = strategy.endpoint ?? `https://cognito-identity.${region}.amazonaws.com/`;
    const logins = { [providerName]: idToken };
    const { IdentityId } = await postAwsJson(client, url, "AWSCognitoIdentityService.GetId", {
      IdentityPoolId: identityPoolId,
      Logins: logins,
    });
    const { Credentials } = await postAwsJson(client, url, "AWSCognitoIdentityService.GetCredentialsForIdentity", {
      IdentityId: IdentityId ?? fail("GetId returned no IdentityId"),
      Logins: logins,
    });
    if (!Credentials?.AccessKeyId) fail("GetCredentialsForIdentity returned no credentials");
    return awsCredential({
      name,
      type: "cognito-identity-pool",
      source: url,
      expiresAt: Credentials.Expiration ? new Date(Number(Credentials.Expiration) * 1000).toISOString() : null,
      credentials: {
        accessKeyId: Credentials.AccessKeyId,
        secretAccessKey: Credentials.SecretKey,
        sessionToken: Credentials.SessionToken,
        region,
        service: strategy.service ?? "execute-api",
      },
    });
  },

  /** Long-lived or assumed AWS keys, taken from the environment and used to sign. */
  async sigv4(strategy, { name, env }) {
    const accessKeyId = envOf(strategy.accessKeyIdEnv ?? "AWS_ACCESS_KEY_ID", env);
    const secretAccessKey = envOf(strategy.secretAccessKeyEnv ?? "AWS_SECRET_ACCESS_KEY", env);
    if (!accessKeyId || !secretAccessKey) {
      fail(`${strategy.accessKeyIdEnv ?? "AWS_ACCESS_KEY_ID"} / ${strategy.secretAccessKeyEnv ?? "AWS_SECRET_ACCESS_KEY"} are not both set in the environment`);
    }
    return awsCredential({
      name,
      type: "sigv4",
      source: strategy.accessKeyIdEnv ?? "AWS_ACCESS_KEY_ID",
      credentials: {
        accessKeyId,
        secretAccessKey,
        sessionToken: envOf(strategy.sessionTokenEnv ?? "AWS_SESSION_TOKEN", env),
        region: strategy.region ?? fail("region is required"),
        service: strategy.service ?? "execute-api",
      },
    });
  },
};

export const STRATEGY_TYPES = Object.keys(STRATEGIES);

/** The env var a strategy's token is cached in, so `trust tokens` and a run agree on it. */
export const exportNameFor = (name, strategy) => strategy.exportAs ?? `TRUST_TOKEN_${String(name).toUpperCase().replace(/[^A-Z0-9]+/g, "_")}`;

/**
 * Acquire one strategy. Never throws: an unresolvable strategy comes back as
 * `{ name, type, error }`, which probes turn into a skip that names the actual cause.
 */
export async function acquire(name, strategy, { client, env = process.env, resolved = new Map(), useCache = true } = {}) {
  const type = strategy?.type ?? "static";
  const implementation = STRATEGIES[type];
  if (!implementation) return { name, type, error: `unknown strategy type "${type}" (expected one of: ${STRATEGY_TYPES.join(", ")})` };

  // A token already in the environment — from `trust tokens`, or from a previous profile in
  // the same run — is reused rather than re-acquired. Re-authenticating per profile burns
  // request budget and, on some IdPs, trips sign-in rate limits mid-assessment.
  if (useCache && type !== "sigv4" && type !== "cognito-identity-pool") {
    const cached = env[exportNameFor(name, strategy)];
    if (cached) return bearer({ name, type, token: cached, source: `${exportNameFor(name, strategy)} (cached)`, scheme: strategy.scheme });
  }

  try {
    const credential = await implementation(strategy, { name, env, client, resolved });
    credential.reacquire = () => acquire(name, strategy, { client, env, resolved, useCache: false });
    return credential;
  } catch (error) {
    return { name, type, error: error.message };
  }
}

/**
 * Resolve every declared strategy, in declaration order so `idTokenFrom` can reference one
 * declared above it. Returns a Map of name → credential-or-failure.
 */
export async function resolveAuth(config, client, { env = process.env, onEvent = () => {} } = {}) {
  const declared = config?.auth?.strategies ?? {};
  const resolved = new Map();
  for (const [name, strategy] of Object.entries(declared)) {
    const credential = await acquire(name, strategy, { client, env, resolved });
    resolved.set(name, credential);
    onEvent({
      type: "credential",
      name,
      strategy: credential.type,
      ok: !credential.error,
      // Never the token: names, kinds and expiry are what a run report may carry.
      detail: credential.error ?? `${credential.kind}${credential.expiresAt ? `, expires ${credential.expiresAt}` : ""}`,
    });
  }
  return resolved;
}

/**
 * The credential a probe section asks for.
 *
 *   "tokenA": "userA"        → the named strategy
 *   "tokenAEnv": "TOKEN_A"   → a bearer token straight from the environment (unchanged)
 *
 * Returns { credential } or { reason } — the reason is written for a skip message.
 */
export function credentialFor(client, sectionValue, key, { env = process.env } = {}) {
  const reference = sectionValue?.[key];
  if (typeof reference === "string" && reference) {
    const credential = client?.credentials?.get(reference);
    if (!credential) return { reason: `${key} names strategy "${reference}", which is not declared in auth.strategies` };
    if (credential.error) return { reason: `strategy "${reference}" did not resolve: ${credential.error}` };
    return { credential };
  }
  const envName = sectionValue?.[`${key}Env`];
  const token = envName ? env[envName] : undefined;
  if (!token) return { reason: `${envName ?? `${key}Env`} is not set in the environment` };
  return { credential: bearer({ name: envName, type: "static", token, source: envName, scheme: sectionValue.authScheme }) };
}

/**
 * Request init for a credential: a bearer token becomes a header, a SigV4 credential is
 * handed to the client, which signs after the guards have approved the request.
 */
export function authInit(credential, { header = "authorization", scheme = "Bearer", headers = {} } = {}) {
  if (!credential) return { headers: { ...headers } };
  // The header name travels with the request so a refreshed token can replace the stale one
  // wherever the section put it, rather than only in `authorization`.
  if (credential.kind === "sigv4") return { headers: { ...headers }, auth: credential, authHeader: header };
  const value = credential.scheme === "" || scheme === "" ? credential.token : `${credential.scheme ?? scheme} ${credential.token}`;
  return { headers: { [header]: value, ...headers }, auth: credential, authHeader: header };
}

/** Apply a credential to an outgoing request. Called by SafeHttpClient, after every guard. */
export function applyCredential(credential, { method, url, headers, body }) {
  if (credential?.kind !== "sigv4") return headers;
  // The signature must cover the bytes actually sent. Coercing an unhashable body to "" would
  // produce a valid-looking signature over the wrong payload, and the target would reject it
  // with SignatureDoesNotMatch — which reads as a broken credential rather than a probe that
  // sent something this code cannot sign. Fail where the cause is visible instead.
  const payload = body == null ? "" : typeof body === "string" || ArrayBuffer.isView(body) || body instanceof ArrayBuffer ? body : null;
  if (payload === null) {
    throw new TypeError(`SigV4 cannot sign a ${body?.constructor?.name ?? typeof body} body — pass a string or a Buffer, since the signature must cover the exact bytes sent`);
  }
  return { ...headers, ...signRequest({ method, url, headers, body: payload, credentials: credential.aws }) };
}
