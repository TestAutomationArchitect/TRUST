/**
 * TRUST — mobile probes.
 *
 * A network harness can only verify the server side of a mobile posture. Deep-link
 * validation, app-site association and device-attestation enforcement are all
 * observable over HTTP; pinning and sandbox storage are not, so they SKIP with a
 * precise manual-test instruction rather than pretending to a verdict.
 */

import { finding, skipped, inconclusive } from "../finding.mjs";
import { section } from "../config.mjs";
import { authInit, credentialFor } from "../auth/index.mjs";

export async function runMobileProbes(config, client) {
  // The canonical section, resolved through conventional spellings — an app that calls it
  // "app" should not have to duplicate it under "mobile".
  const { value: mobile, key: mobileKey } = section(config, "mobile");
  if (!mobile) return [skipped("MOBILE-CONFIG", "Mobile probe suite", "config.mobile is not configured")];

  const out = [];
  const base = mobile.baseUrl ?? config.targets?.web;

  // ── 1. Deep-link parameter validation ─────────────────────────────
  if (!mobile.deepLinkEndpoint) {
    out.push(skipped("MOBILE-DEEP-LINK", "Deep-link parameters are validated server-side", "config.mobile.deepLinkEndpoint is not defined"));
  } else {
    const evil = "https://trust-probe.invalid/steal";
    const param = mobile.deepLinkParam ?? "target";
    try {
      const url = new URL(mobile.deepLinkEndpoint);
      url.searchParams.set(param, evil);
      const response = await client.request(url.href);
      const body = (await response.text()).slice(0, 600);
      const location = response.headers.get("location") ?? "";
      const reflected = location.includes("trust-probe.invalid") || body.includes(evil);
      out.push(
        finding({
          id: "MOBILE-DEEP-LINK",
          title: "Deep-link parameters cannot redirect the app to an untrusted destination",
          status: reflected ? "fail" : "pass",
          severity: "high",
          evidence: `${url.href} → HTTP ${response.status}` + (location ? `\nLocation: ${location}` : "") + `\n${body}`,
          remediation: reflected
            ? "Validate deep-link destinations against a server-side allowlist of app routes; never pass an absolute URL through to the client handler."
            : "",
        }),
      );
    } catch (error) {
      out.push(inconclusive("MOBILE-DEEP-LINK", "Deep-link parameters cannot redirect the app to an untrusted destination", `Request failed: ${error.message}`));
    }
  }

  // ── 2. App-site association files ─────────────────────────────────
  if (!base) {
    out.push(skipped("MOBILE-UNIVERSAL-LINK", "App-site association files are correctly scoped", "no base URL available"));
  } else {
    const checks = [
      { path: "/.well-known/apple-app-site-association", platform: "iOS", expect: /applinks|webcredentials/i },
      { path: "/.well-known/assetlinks.json", platform: "Android", expect: /delegate_permission|sha256_cert_fingerprints/i },
    ];
    const results = [];
    for (const check of checks) {
      try {
        const response = await client.request(new URL(check.path, base).href);
        const text = (await response.text()).slice(0, 800);
        results.push({
          ...check,
          status: response.status,
          contentType: response.headers.get("content-type") ?? "",
          valid: response.status === 200 && check.expect.test(text),
          wildcard: /"\*"|\*\./.test(text),
          text,
        });
      } catch (error) {
        results.push({ ...check, status: 0, valid: false, error: error.message });
      }
    }
    const served = results.filter((r) => r.valid);
    const wildcarded = results.filter((r) => r.valid && r.wildcard);
    out.push(
      finding({
        id: "MOBILE-UNIVERSAL-LINK",
        title: "App-site association files are served and scoped",
        status: served.length === 0 ? "warn" : wildcarded.length ? "warn" : "pass",
        severity: "low",
        evidence: results
          .map((r) => `${r.platform} ${r.path} → HTTP ${r.status}${r.valid ? " (valid)" : ""}${r.wildcard ? " [wildcard path]" : ""}${r.error ? ` (${r.error})` : ""}`)
          .join("\n"),
        remediation:
          served.length === 0
            ? "Serve apple-app-site-association and assetlinks.json over HTTPS with content-type application/json so universal/app links verify."
            : wildcarded.length
              ? "Narrow the association paths to the routes the app actually handles instead of a wildcard."
              : "",
      }),
    );
  }

  // ── 3. Device-attestation / rooted-device enforcement ─────────────
  if (!mobile.apiEndpoint) {
    out.push(skipped("MOBILE-ROOT-DETECTION", "API refuses traffic from compromised devices", "config.mobile.apiEndpoint is not defined"));
  } else {
    const { credential: token, reason } = credentialFor(client, mobile, "token");
    if (!token) {
      out.push(skipped("MOBILE-ROOT-DETECTION", "API refuses traffic from compromised devices", reason));
    } else {
      try {
        const response = await client.request(mobile.apiEndpoint, {
          ...authInit(token, {
            header: mobile.authHeader ?? "authorization",
            headers: {
              "user-agent": mobile.userAgent ?? "TRUST-MobileProbe/1.0",
              // Attestation headers a legitimate client would supply, deliberately
              // asserting a compromised device.
              [mobile.attestationHeader ?? "x-device-integrity"]: "compromised",
              "x-device-rooted": "true",
            },
          }),
        });
        const text = (await response.text()).slice(0, 500);
        const refused = response.status === 401 || response.status === 403 || /integrity|attestation|rooted|jailbroken/i.test(text);
        out.push(
          finding({
            id: "MOBILE-ROOT-DETECTION",
            title: "API refuses traffic that asserts a compromised device",
            status: refused ? "pass" : "warn",
            severity: "medium",
            evidence: `Request with device-integrity=compromised → HTTP ${response.status}\n${text}`,
            remediation: refused
              ? ""
              : "Require a Play Integrity / App Attest assertion on sensitive endpoints and reject requests whose attestation is missing or failing. Note: a header-based probe only proves the header is ignored — confirm real attestation verification server-side.",
          }),
        );
      } catch (error) {
        out.push(inconclusive("MOBILE-ROOT-DETECTION", "API refuses traffic that asserts a compromised device", `Request failed: ${error.message}`));
      }
    }
  }

  // ── 4. Controls that require a device, not a network harness ───────
  out.push(
    skipped(
      "MOBILE-CERT-PINNING",
      "Certificate pinning is enforced by the app",
      "requires an instrumented device: install a proxy CA, run the app, and confirm the TLS handshake is rejected",
    ),
    skipped(
      "MOBILE-LOCAL-STORAGE",
      "Credentials are held in the platform keystore, not plaintext files",
      "requires an instrumented device: inspect the app sandbox (Keychain / EncryptedSharedPreferences) after login",
    ),
  );

  return out;
}
