/**
 * TRUST — identity-provider configuration probes.
 *
 * This pack catches the class of failure where the application is sound and the IdP undoes it:
 * a password grant left enabled beside federated SSO, an implicit flow still advertised, PKCE
 * offered only as `plain`. They are one-line configuration mistakes with critical impact, and
 * none of them are visible from inside the application.
 *
 * Everything here is HTTP-observable and unauthenticated. Checks that need a browser — session
 * fixation across a real login, the code-verifier cookie after a callback — are reported as
 * skips carrying the manual procedure, because a network harness cannot honestly claim them.
 */

import { finding, skipped, inconclusive } from "../finding.mjs";
import { section } from "../config.mjs";

const discoveryUrlFor = (idp) => idp.discoveryUrl ?? (idp.issuer ? `${String(idp.issuer).replace(/\/$/, "")}/.well-known/openid-configuration` : null);

/** Fetch and parse the OIDC discovery document. Everything downstream depends on it. */
async function fetchDiscovery(client, url) {
  const response = await client.request(url);
  const text = await response.text();
  if (response.status !== 200) return { ok: false, status: response.status, text };
  try {
    return { ok: true, status: response.status, doc: JSON.parse(text), text };
  } catch {
    return { ok: false, status: response.status, text, parseError: true };
  }
}

export async function runIdpProbes(config, client) {
  const { value: idp, key: idpKey } = section(config, "idp");
  if (!idp || (!idp.discoveryUrl && !idp.issuer && !idp.loginUrl && !idp.cognito)) {
    return [skipped("IDP-CONFIG", "Identity provider configuration probe suite", "config.idp is not configured")];
  }

  const out = [];
  const label = idpKey ?? "idp";

  // ── 1. Discovery document ─────────────────────────────────────────
  const discoveryUrl = discoveryUrlFor(idp);
  let doc = null;
  if (!discoveryUrl) {
    out.push(skipped("IDP-DISCOVERY", "The provider publishes a well-formed discovery document", `config.${label}.issuer or discoveryUrl is not defined`));
  } else {
    try {
      const result = await fetchDiscovery(client, discoveryUrl);
      doc = result.doc ?? null;
      const issuerHttps = typeof doc?.issuer === "string" && doc.issuer.startsWith("https://");
      out.push(
        finding({
          id: "IDP-DISCOVERY",
          title: "The provider publishes a well-formed discovery document",
          observed: result.ok ? "The discovery document does not declare an HTTPS issuer" : "The discovery document could not be read",
          status: result.ok && issuerHttps ? "pass" : "warn",
          severity: "low",
          evidence: result.ok
            ? `${discoveryUrl} → HTTP ${result.status}\nissuer: ${doc?.issuer ?? "(absent)"}\ngrants: ${(doc?.grant_types_supported ?? []).join(", ") || "(not advertised)"}`
            : `${discoveryUrl} → HTTP ${result.status}${result.parseError ? " (not JSON)" : ""}\n${result.text.slice(0, 300)}`,
          remediation: result.ok && issuerHttps ? "" : "Without a readable discovery document the remaining IdP checks fall back to warnings. Confirm the issuer URL, and that the document is reachable from the network the assessment runs on.",
        }),
      );
    } catch (error) {
      out.push(inconclusive("IDP-DISCOVERY", "The provider publishes a well-formed discovery document", `Request failed: ${error.message}`));
    }
  }

  // ── 2. PKCE ───────────────────────────────────────────────────────
  if (!doc) {
    out.push(skipped("IDP-PKCE-SUPPORTED", "The provider requires PKCE with SHA-256 challenges", "the discovery document was not readable"));
  } else {
    const methods = doc.code_challenge_methods_supported ?? [];
    const s256 = methods.includes("S256");
    const onlyPlain = methods.length > 0 && !s256;
    out.push(
      finding({
        id: "IDP-PKCE-SUPPORTED",
          fix: "idp-client-config",
        title: "The provider supports PKCE with SHA-256 challenges",
        observed: onlyPlain ? "PKCE is offered only as plain, which provides no protection" : "PKCE support is not advertised",
        status: s256 ? "pass" : "warn",
        severity: "medium",
        evidence: `code_challenge_methods_supported: ${methods.join(", ") || "(absent)"}`,
        remediation: s256
          ? ""
          : onlyPlain
            ? "Enable S256 on the authorisation server. A plain challenge is the verifier itself, so an attacker who intercepts the authorisation request can complete the exchange. Note that this is what the provider *supports*; whether your application asks for it is IDP-AUTHORIZE-REQUEST."
            : "The provider does not advertise PKCE at all, so no client of it can protect an authorisation code. This is a provider setting, not an application one: check the app client's allowed flows. IDP-AUTHORIZE-REQUEST reports separately on what your application actually requests.",
      }),
    );

    // ── 3. Implicit flow ────────────────────────────────────────────
    const responseTypes = doc.response_types_supported ?? [];
    const implicit = responseTypes.filter((type) => /\btoken\b/.test(type));
    out.push(
      finding({
        id: "IDP-IMPLICIT-FLOW",
          fix: "idp-client-config",
        title: "The implicit flow is not offered",
        observed: "The provider still advertises the implicit flow",
        status: implicit.length ? "warn" : "pass",
        severity: "medium",
        evidence: `response_types_supported: ${responseTypes.join(", ") || "(absent)"}`,
        remediation: implicit.length
          ? `Response types ${implicit.join(", ")} return tokens in the URL fragment, where they land in browser history, referrer headers and logs. OAuth 2.1 removes the flow. This is advisory for *your* application — IDP-AUTHORIZE-REQUEST reports what it asks for — but any client of this provider may use the flow, so disable it on the authorisation server and move clients to code + PKCE.`
          : "",
      }),
    );

    // ── 4. Client authentication ────────────────────────────────────
    const authMethods = doc.token_endpoint_auth_methods_supported ?? [];
    const allowsNone = authMethods.includes("none");
    // A public client is legitimate for an SPA — but only with PKCE. Without it, "none" means
    // anyone holding an authorisation code can redeem it.
    out.push(
      finding({
        id: "IDP-CLIENT-AUTH",
          fix: "idp-client-config",
        title: "Unauthenticated token requests are compensated by PKCE",
        observed: "The token endpoint accepts unauthenticated clients and PKCE is not advertised",
        status: allowsNone && !s256 ? "fail" : "pass",
        severity: "high",
        evidence: `token_endpoint_auth_methods_supported: ${authMethods.join(", ") || "(absent)"}\ncode_challenge_methods_supported: ${methods.join(", ") || "(absent)"}`,
        remediation:
          allowsNone && !s256
            ? "The token endpoint accepts public clients while PKCE is unavailable, so an intercepted authorisation code can be redeemed by anyone. Require S256, or require client authentication."
            : "",
      }),
    );
  }

  // ── 5. The application's own authorisation request ────────────────
  // What the provider *supports* and what the application *asks for* are different questions,
  // and only the second one is the application's posture.
  if (!idp.loginUrl) {
    out.push(skipped("IDP-AUTHORIZE-REQUEST", "The application requests an authorisation code with PKCE", `config.${label}.loginUrl is not defined (the app path that redirects into the IdP)`));
  } else {
    try {
      const response = await client.request(idp.loginUrl);
      const location = response.headers.get("location") ?? "";
      if (!location) {
        out.push(
          inconclusive(
            "IDP-AUTHORIZE-REQUEST",
            "The application requests an authorisation code with PKCE",
            `${idp.loginUrl} → HTTP ${response.status} with no Location header, so the authorisation request could not be inspected. A login route that renders a page rather than redirecting needs a browser to test.`,
          ),
        );
      } else {
        const params = new URL(location, idp.loginUrl).searchParams;
        const responseType = params.get("response_type") ?? "";
        const challenge = params.get("code_challenge");
        const method = params.get("code_challenge_method");
        const codeFlow = responseType === "code";
        const pkce = Boolean(challenge) && method === "S256";
        out.push(
          finding({
            id: "IDP-AUTHORIZE-REQUEST",
          fix: "idp-client-config",
            title: "The application requests an authorisation code with PKCE",
            observed: !codeFlow ? `The application requests response_type=${responseType}, returning tokens in the URL` : "The authorisation request carries no S256 PKCE challenge",
            status: codeFlow && pkce ? "pass" : "fail",
            severity: "high",
            // The Location URL carries a state parameter and a challenge, neither secret, but
            // only the fields under test are quoted.
            evidence:
              `${idp.loginUrl} → HTTP ${response.status}\n` +
              `response_type: ${responseType || "(absent)"}\ncode_challenge_method: ${method ?? "(absent)"}\ncode_challenge: ${challenge ? "present" : "(absent)"}`,
            remediation:
              codeFlow && pkce
                ? ""
                : !codeFlow
                  ? "Switch the client to the authorisation-code flow. response_type=token returns the access token in the URL fragment, where it is exposed to history, extensions and referrers."
                  : "Send code_challenge with code_challenge_method=S256. Without it an intercepted authorisation code can be redeemed by whoever intercepted it.",
          }),
        );
      }
    } catch (error) {
      out.push(inconclusive("IDP-AUTHORIZE-REQUEST", "The application requests an authorisation code with PKCE", `Request failed: ${error.message}`));
    }
  }

  // ── 6. Cognito native password grant ──────────────────────────────
  const passwordAuthConfigured = Boolean(section(config, "api").value?.passwordAuth?.endpoint);
  if (!idp.cognito?.clientId) {
    out.push(skipped("IDP-PASSWORD-GRANT", "The user pool refuses direct username/password authentication", `config.${label}.cognito.clientId is not defined`));
  } else if (passwordAuthConfigured) {
    // AUTH-PASSWORD-BYPASS already tests this against the generic token endpoint. Two findings
    // saying the same thing is worse than one.
    out.push(skipped("IDP-PASSWORD-GRANT", "The user pool refuses direct username/password authentication", "already covered by AUTH-PASSWORD-BYPASS, which is configured via api.passwordAuth"));
  } else {
    const region = idp.cognito.region ?? String(idp.cognito.userPoolId ?? "").split("_")[0];
    const url = idp.cognito.endpoint ?? `https://cognito-idp.${region}.amazonaws.com/`;
    try {
      // A deliberately non-existent principal: the question is whether the *flow* is enabled,
      // and the answer is in which error the pool returns. Nothing is authenticated and no real
      // account is touched, so this cannot lock anyone out.
      const response = await client.request(url, {
        method: "POST",
        headers: { "content-type": "application/x-amz-json-1.1", "x-amz-target": "AWSCognitoIdentityProviderService.InitiateAuth" },
        body: JSON.stringify({
          AuthFlow: "USER_PASSWORD_AUTH",
          ClientId: idp.cognito.clientId,
          AuthParameters: { USERNAME: "trust-probe@example.invalid", PASSWORD: "trust-probe-not-a-real-password" },
        }),
      });
      const text = await response.text();
      // "Flow not enabled" is the secure answer. "Incorrect username or password" proves the
      // flow is live: the pool got far enough to check credentials.
      const flowDisabled = /InvalidParameterException|not enabled for this client|auth flow.{0,20}not.{0,20}(enabled|configured)/i.test(text);
      const credentialsChecked = /NotAuthorizedException|UserNotFoundException|Incorrect username or password/i.test(text);
      const live = credentialsChecked && !flowDisabled;
      out.push(
        finding({
          id: "IDP-PASSWORD-GRANT",
          fix: "idp-client-config",
          title: "The user pool refuses direct username/password authentication",
          observed: "USER_PASSWORD_AUTH is enabled, so federated sign-in can be bypassed entirely",
          status: live ? "fail" : flowDisabled ? "pass" : "warn",
          severity: "critical",
          evidence: `USER_PASSWORD_AUTH against ${url} → HTTP ${response.status}\n${text.slice(0, 300)}\nVerdict basis: ${live ? "the pool checked credentials, which it only does when the flow is enabled" : flowDisabled ? "the pool rejected the flow itself" : "neither error shape was recognised"}`,
          remediation: live
            ? "Remove USER_PASSWORD_AUTH (and ALLOW_USER_PASSWORD_AUTH) from the app client's explicit auth flows. While it is enabled, any account with a password can sign in directly, bypassing the identity provider and every control attached to it — including MFA."
            : flowDisabled
              ? ""
              : "The response matched neither a disabled flow nor a credential check. Confirm the app client's enabled auth flows directly before drawing a conclusion.",
        }),
      );
    } catch (error) {
      out.push(inconclusive("IDP-PASSWORD-GRANT", "The user pool refuses direct username/password authentication", `Request failed: ${error.message}`));
    }
  }

  // ── 7. What a network harness cannot honestly claim ───────────────
  out.push(
    skipped(
      "IDP-SESSION-FIXATION",
      "The session identifier changes on authentication",
      "requires a browser: capture the session cookie before sign-in, complete the flow, and confirm the value differs afterwards",
    ),
    skipped(
      "IDP-CODE-VERIFIER-CLEARED",
      "The PKCE code verifier is cleared after the callback",
      "requires a browser: complete the callback and confirm the verifier cookie is expired (Max-Age=0) or absent",
    ),
  );

  return out;
}
