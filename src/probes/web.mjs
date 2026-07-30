/**
 * TRUST — passive web / infrastructure probes.
 * No authentication required. Every verdict is a pattern match on status codes,
 * headers or body content — never an LLM judgement.
 */

import { finding, skipped, inconclusive } from "../finding.mjs";

const SECURITY_HEADERS = [
  {
    header: "strict-transport-security",
    id: "WEB-HEADER-STRICT-TRANSPORT-SECURITY",
    label: "Strict-Transport-Security",
    severity: "medium",
    remediation: "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.",
    validate: (value) => {
      const maxAge = Number(/max-age=(\d+)/i.exec(value)?.[1] ?? 0);
      if (maxAge < 15552000) return `max-age=${maxAge} is below the recommended 15552000 (180 days)`;
      return null;
    },
  },
  {
    header: "content-security-policy",
    id: "WEB-HEADER-CONTENT-SECURITY-POLICY",
    label: "Content-Security-Policy",
    severity: "medium",
    remediation: "Deploy a restrictive CSP with an explicit default-src and no 'unsafe-inline' in script-src.",
    validate: (value) => {
      const issues = [];
      if (!/default-src/i.test(value)) issues.push("no default-src directive");
      if (/script-src[^;]*'unsafe-inline'/i.test(value)) issues.push("script-src allows 'unsafe-inline'");
      if (/script-src[^;]*'unsafe-eval'/i.test(value)) issues.push("script-src allows 'unsafe-eval'");
      return issues.length ? issues.join("; ") : null;
    },
  },
  {
    header: "x-content-type-options",
    id: "WEB-HEADER-X-CONTENT-TYPE-OPTIONS",
    label: "X-Content-Type-Options",
    severity: "low",
    remediation: "Send `X-Content-Type-Options: nosniff`.",
    validate: (value) => (/nosniff/i.test(value) ? null : `expected "nosniff", got "${value}"`),
  },
  {
    header: "referrer-policy",
    id: "WEB-HEADER-REFERRER-POLICY",
    label: "Referrer-Policy",
    severity: "low",
    remediation: "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
    validate: (value) =>
      /no-referrer|strict-origin|same-origin/i.test(value) ? null : `"${value}" still leaks referrer data cross-origin`,
  },
  {
    header: "permissions-policy",
    id: "WEB-HEADER-PERMISSIONS-POLICY",
    label: "Permissions-Policy",
    severity: "low",
    remediation: "Send a Permissions-Policy that disables unused capabilities, e.g. `camera=(), microphone=(), geolocation=()`.",
    validate: () => null,
  },
];

const DEFAULT_SENSITIVE_PATHS = [
  "/.env",
  "/.git/config",
  "/.git/HEAD",
  "/config.json",
  "/appsettings.json",
  "/amplify_outputs.json",
  "/aws-exports.js",
  "/.aws/credentials",
  "/backup.zip",
  "/server-status",
  "/actuator/env",
  "/.well-known/security.txt",
];

/** A body that looks like real content rather than an SPA fallback page. */
function looksLikeRealContent(path, body, contentType) {
  if (!body || body.length < 8) return false;
  if (/<!doctype html|<html/i.test(body)) return false; // SPA catch-all
  if (path.endsWith(".env")) return /^[A-Z0-9_]+\s*=/m.test(body);
  if (path.includes(".git")) return /\[core\]|^ref:|^[0-9a-f]{40}$/im.test(body.trim());
  if (path.endsWith(".json")) {
    try {
      const parsed = JSON.parse(body);
      return parsed && typeof parsed === "object" && Object.keys(parsed).length > 0;
    } catch {
      return false;
    }
  }
  if (path.endsWith(".js")) return /=|function|const |var /.test(body);
  return (contentType ?? "").includes("text/plain") || body.length > 32;
}

export async function runWebProbes(config, client) {
  const target = config.targets?.web;
  if (!target) return [skipped("WEB-CONFIG", "Passive web probe suite", "targets.web is not configured")];

  const web = config.web ?? {};
  const out = [];
  const baseUrl = new URL(target);

  // ── 1. Baseline request: headers, cookies, body ───────────────────
  let response = null;
  let headers = new Headers();
  let body = "";
  try {
    response = await client.request(baseUrl.href, { headers: { "user-agent": "TRUST/1.0 (security-verification)" } });
    headers = response.headers;
    body = await response.text();
  } catch (error) {
    out.push(
      inconclusive(
        "WEB-CONFIG",
        "Passive web probe suite",
        `Baseline request to ${baseUrl.href} failed: ${error.message}`,
        "Confirm the target is reachable over HTTPS and allowlisted, then re-run.",
      ),
    );
    return out;
  }

  // ── 2. Security response headers ──────────────────────────────────
  for (const spec of SECURITY_HEADERS) {
    const value = headers.get(spec.header);
    if (!value) {
      out.push(
        finding({
          id: spec.id,
          title: `Security header ${spec.label} is deployed`,
          status: "fail",
          severity: spec.severity,
          evidence: `HTTP ${response.status} on ${baseUrl.href} — ${spec.label} header is absent.`,
          remediation: spec.remediation,
        }),
      );
      continue;
    }
    const weakness = spec.validate(value);
    out.push(
      finding({
        id: spec.id,
        title: `Security header ${spec.label} is deployed`,
        status: weakness ? "warn" : "pass",
        severity: spec.severity,
        evidence: weakness ? `${spec.label}: ${value}\nWeakness: ${weakness}` : `${spec.label}: ${value}`,
        remediation: weakness ? spec.remediation : "",
      }),
    );
  }

  // ── 3. Clickjacking + frame-ancestors ─────────────────────────────
  const csp = headers.get("content-security-policy") ?? "";
  const xfo = headers.get("x-frame-options") ?? "";
  const frameAncestors = /frame-ancestors([^;]*)/i.exec(csp)?.[1]?.trim() ?? "";
  const framingBlocked = Boolean(frameAncestors) || /deny|sameorigin/i.test(xfo);
  out.push(
    finding({
      id: "WEB-CLICKJACKING",
      observed: "The application can be framed by any origin",
      title: "Application cannot be framed by an unauthorised origin",
      status: framingBlocked ? "pass" : "fail",
      severity: "medium",
      evidence: framingBlocked
        ? `CSP frame-ancestors: ${frameAncestors || "(none)"} / X-Frame-Options: ${xfo || "(none)"}`
        : "Neither CSP frame-ancestors nor X-Frame-Options is present — the page can be embedded by any origin.",
      remediation: framingBlocked ? "" : "Add `frame-ancestors 'self' <approved parents>` to the CSP, and X-Frame-Options as a legacy fallback.",
    }),
  );

  if (Array.isArray(web.expectedFrameAncestors) && web.expectedFrameAncestors.length) {
    const missing = web.expectedFrameAncestors.filter((origin) => !frameAncestors.includes(origin));
    const wildcard = /\*/.test(frameAncestors);
    out.push(
      finding({
        id: "WEB-FRAME-ANCESTORS",
        observed: "frame-ancestors is missing, wildcarded or incomplete",
        title: "CSP frame-ancestors is restricted to approved parent origins",
        status: !frameAncestors ? "fail" : wildcard || missing.length ? "warn" : "pass",
        severity: "medium",
        evidence: !frameAncestors
          ? "No frame-ancestors directive found in the CSP."
          : `frame-ancestors ${frameAncestors}` +
            (missing.length ? `\nExpected origins not present: ${missing.join(", ")}` : "") +
            (wildcard ? "\nDirective contains a wildcard." : ""),
        remediation:
          !frameAncestors || wildcard || missing.length
            ? `Set frame-ancestors to exactly: ${web.expectedFrameAncestors.join(" ")}`
            : "",
      }),
    );
  }

  // ── 4. Cookie flags ───────────────────────────────────────────────
  const cookies = headers.getSetCookie?.() ?? [];
  if (cookies.length === 0) {
    out.push(skipped("WEB-COOKIE-FLAGS", "Session cookies use Secure, HttpOnly and SameSite", "no Set-Cookie headers on the baseline response"));
  } else {
    const weak = cookies
      .map((cookie) => {
        const name = cookie.split("=")[0];
        const missing = [];
        if (!/;\s*secure/i.test(cookie)) missing.push("Secure");
        if (!/;\s*httponly/i.test(cookie)) missing.push("HttpOnly");
        if (!/;\s*samesite/i.test(cookie)) missing.push("SameSite");
        return missing.length ? `${name}: missing ${missing.join(", ")}` : null;
      })
      .filter(Boolean);
    out.push(
      finding({
        id: "WEB-COOKIE-FLAGS",
        observed: "Session cookies are missing Secure, HttpOnly or SameSite",
        title: "Session cookies use Secure, HttpOnly and SameSite",
        status: weak.length ? "fail" : "pass",
        severity: "medium",
        evidence: weak.length ? weak.join("\n") : `${cookies.length} cookie(s) all carry Secure, HttpOnly and SameSite.`,
        remediation: weak.length ? "Set Secure, HttpOnly and SameSite=Lax (or Strict) on every session cookie." : "",
      }),
    );
  }

  // ── 5. Client-side token storage ──────────────────────────────────
  const scriptUrls = [...body.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map((m) => m[1])
    .filter((src) => !/^https?:/i.test(src) || src.startsWith(baseUrl.origin))
    .slice(0, web.maxScriptsToScan ?? 3);

  let scanned = body;
  const scannedNames = ["(index)"];
  for (const src of scriptUrls) {
    try {
      const scriptResponse = await client.request(new URL(src, baseUrl).href);
      if (scriptResponse.status === 200) {
        scanned += `\n${await scriptResponse.text()}`;
        scannedNames.push(src);
      }
    } catch {
      /* a bundle we cannot fetch simply is not scanned */
    }
  }
  const storageHits = [
    ...scanned.matchAll(/(localStorage|sessionStorage)\.setItem\(\s*["'`]([^"'`]{0,60})["'`]/gi),
  ]
    .filter((m) => /token|jwt|auth|credential|secret|id_?token|access/i.test(m[2]))
    .map((m) => `${m[1]}.setItem("${m[2]}", …)`);
  const uniqueHits = [...new Set(storageHits)];
  out.push(
    finding({
      id: "WEB-TOKEN-STORAGE",
      observed: "Authentication tokens are written to web storage",
      title: "Authentication tokens are not stored in web storage",
      status: uniqueHits.length ? "fail" : "pass",
      severity: "medium",
      evidence: uniqueHits.length
        ? `Token-like keys written to web storage:\n${uniqueHits.join("\n")}\nScanned: ${scannedNames.join(", ")}`
        : `No token-like web-storage writes found. Scanned: ${scannedNames.join(", ")}`,
      remediation: uniqueHits.length
        ? "Hold tokens in memory and persist sessions in Secure/HttpOnly cookies so XSS cannot read them."
        : "",
    }),
  );

  // ── 6. Source maps ────────────────────────────────────────────────
  const mapRefs = [...scanned.matchAll(/sourceMappingURL=([^\s*"']+)/g)].map((m) => m[1]);
  if (mapRefs.length === 0) {
    out.push(
      finding({
        id: "WEB-SOURCE-MAPS",
        observed: "Production bundles reference source maps",
        title: "Production bundles do not reference source maps",
        status: "pass",
        severity: "low",
        evidence: `No sourceMappingURL references in ${scannedNames.join(", ")}.`,
      }),
    );
  } else {
    out.push(
      finding({
        id: "WEB-SOURCE-MAPS",
        title: "Production bundles do not reference source maps",
        status: "warn",
        severity: "low",
        evidence: `sourceMappingURL references found: ${mapRefs.slice(0, 5).join(", ")}`,
        remediation: "Disable source-map emission for production builds, or upload maps to the error tracker instead of the CDN.",
      }),
    );
  }

  // ── 7. Sensitive file exposure ────────────────────────────────────
  const paths = web.sensitivePaths ?? DEFAULT_SENSITIVE_PATHS;
  for (const path of paths) {
    const slug = path.replace(/[^A-Za-z0-9]+/g, "-").replace(/^-+|-+$/g, "").toUpperCase();
    const id = `WEB-EXPOSED-${slug}`;
    const title = `Sensitive resource is not exposed: ${path}`;
    try {
      const probe = await client.request(new URL(path, baseUrl).href);
      const text = probe.status === 200 ? (await probe.text()).slice(0, 600) : "";
      const exposed = probe.status === 200 && looksLikeRealContent(path, text, probe.headers.get("content-type"));
      out.push(
        finding({
          id,
          title,
          observed: `Sensitive resource is publicly accessible: ${path}`,
          status: exposed ? "fail" : "pass",
          severity: /\.env|credentials|\.git|appsettings|config\.json/i.test(path) ? "high" : "medium",
          evidence: exposed
            ? `HTTP 200 with real content at ${path}:\n${text}`
            : `HTTP ${probe.status} at ${path}${probe.status === 200 ? " (SPA fallback / not real content)" : ""}`,
          remediation: exposed ? `Remove ${path} from the deployed artefact and block the path at the edge.` : "",
        }),
      );
    } catch (error) {
      out.push(skipped(id, title, `request failed: ${error.message}`));
    }
  }

  // ── 8. CORS policy ────────────────────────────────────────────────
  const evilOrigin = "https://trust-probe.invalid";
  try {
    const cors = await client.request(baseUrl.href, { method: "OPTIONS", headers: { origin: evilOrigin, "access-control-request-method": "GET" } });
    const allowOrigin = cors.headers.get("access-control-allow-origin") ?? "";
    const allowCreds = cors.headers.get("access-control-allow-credentials") ?? "";
    const reflected = allowOrigin === evilOrigin;
    const wildcardWithCreds = allowOrigin === "*" && /true/i.test(allowCreds);
    out.push(
      finding({
        id: "WEB-CORS-POLICY",
        observed: "The CORS policy reflects arbitrary origins",
        title: "CORS policy does not reflect arbitrary origins",
        status: reflected || wildcardWithCreds ? "fail" : "pass",
        severity: "high",
        evidence:
          `Origin: ${evilOrigin} → HTTP ${cors.status}\n` +
          `access-control-allow-origin: ${allowOrigin || "(absent)"}\n` +
          `access-control-allow-credentials: ${allowCreds || "(absent)"}`,
        remediation:
          reflected || wildcardWithCreds
            ? "Validate the Origin header against a static allowlist; never echo it back, and never pair a wildcard with credentials."
            : "",
      }),
    );
  } catch (error) {
    out.push(inconclusive("WEB-CORS-POLICY", "CORS policy does not reflect arbitrary origins", `Preflight failed: ${error.message}`));
  }

  // ── 9. Open redirect ──────────────────────────────────────────────
  const redirectParams = web.redirectParams ?? ["redirect", "next", "returnUrl", "url"];
  const evilTarget = "https://trust-probe.invalid/pwned";
  let redirectVerdict = null;
  for (const param of redirectParams) {
    const url = new URL(baseUrl.href);
    url.searchParams.set(param, evilTarget);
    try {
      const probe = await client.request(url.href);
      const location = probe.headers.get("location") ?? "";
      if (probe.status >= 300 && probe.status < 400 && location.includes("trust-probe.invalid")) {
        redirectVerdict = { param, status: probe.status, location };
        break;
      }
    } catch {
      /* keep testing remaining parameters */
    }
  }
  out.push(
    finding({
      id: "WEB-OPEN-REDIRECT",
      observed: "The application follows unvalidated redirect parameters",
      title: "Application does not follow unvalidated redirect parameters",
      status: redirectVerdict ? "fail" : "pass",
      severity: "medium",
      evidence: redirectVerdict
        ? `?${redirectVerdict.param}=${evilTarget} → HTTP ${redirectVerdict.status} Location: ${redirectVerdict.location}`
        : `Tested parameters ${redirectParams.join(", ")} — no external redirect issued.`,
      remediation: redirectVerdict
        ? "Resolve redirect targets against an allowlist of internal paths; reject absolute URLs to other hosts."
        : "",
    }),
  );

  // ── 10. Rate limiting ─────────────────────────────────────────────
  const burst = Math.min(web.rateLimitBurst ?? 8, Math.max(0, client.remainingRequests - paths.length));
  if (burst < 4) {
    out.push(skipped("WEB-RATE-LIMIT", "Server-side rate limiting is enforced", "insufficient remaining request budget for a burst test"));
  } else {
    const statuses = [];
    try {
      for (let i = 0; i < burst; i++) {
        const probe = await client.request(new URL(`${baseUrl.pathname}?trust-burst=${i}`, baseUrl).href);
        statuses.push(probe.status);
      }
      const limited = statuses.some((s) => s === 429 || s === 503);
      out.push(
        finding({
          id: "WEB-RATE-LIMIT",
          observed: "No server-side rate limiting was observed",
          title: "Server-side rate limiting is enforced",
          status: limited ? "pass" : "warn",
          severity: "medium",
          evidence: `${burst} requests at the configured delay floor returned: ${statuses.join(", ")}`,
          remediation: limited
            ? ""
            : "No 429 observed. A polite burst may sit under the threshold — confirm WAF/API-gateway throttling is configured, then re-test with an authorised load profile.",
        }),
      );
    } catch (error) {
      out.push(inconclusive("WEB-RATE-LIMIT", "Server-side rate limiting is enforced", `Burst aborted: ${error.message}`));
    }
  }

  // ── 11. Dangerous HTTP methods ─────────────────────────────────────
  // TRACE enables cross-site tracing; PUT/DELETE reachable on a content path means the
  // write surface is wider than the application intends.
  const methodResults = [];
  for (const method of ["OPTIONS", "TRACE"]) {
    try {
      const probe = await client.request(baseUrl.href, { method });
      methodResults.push({ method, status: probe.status, allow: probe.headers.get("allow") ?? "" });
    } catch {
      /* a refused method is the desired outcome */
    }
  }
  const advertised = methodResults.flatMap((r) => r.allow.split(",").map((m) => m.trim().toUpperCase())).filter(Boolean);
  const traceOpen = methodResults.some((r) => r.method === "TRACE" && r.status >= 200 && r.status < 300);
  const writeAdvertised = advertised.filter((m) => ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"].includes(m));
  out.push(
    finding({
      id: "WEB-HTTP-METHODS",
      observed: "Dangerous HTTP methods are enabled",
      title: "Dangerous HTTP methods are not enabled",
      status: traceOpen || writeAdvertised.length ? "fail" : "pass",
      severity: traceOpen ? "medium" : "low",
      evidence:
        methodResults.map((r) => `${r.method} → HTTP ${r.status}${r.allow ? ` (Allow: ${r.allow})` : ""}`).join("\n") ||
        "OPTIONS and TRACE were both refused.",
      remediation:
        traceOpen || writeAdvertised.length
          ? `Disable ${[traceOpen ? "TRACE" : null, ...writeAdvertised].filter(Boolean).join(", ")} at the web server or CDN and restrict the Allow set to the methods the application serves.`
          : "",
    }),
  );

  // ── 12. Server banner / version disclosure ────────────────────────
  const banners = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]
    .map((name) => ({ name, value: headers.get(name) }))
    .filter((b) => b.value);
  const versioned = banners.filter((b) => /\d+\.\d+/.test(b.value));
  out.push(
    finding({
      id: "WEB-SERVER-BANNER",
      observed: "Response headers disclose software versions",
      title: "Response headers do not disclose software versions",
      status: versioned.length ? "fail" : banners.length ? "warn" : "pass",
      severity: "low",
      evidence: banners.length ? banners.map((b) => `${b.name}: ${b.value}`).join("\n") : "No server or framework banner headers were returned.",
      remediation: versioned.length
        ? "Suppress version numbers in Server/X-Powered-By. They hand an attacker a shortlist of known CVEs to try."
        : banners.length
          ? "Consider removing the banner entirely; it offers no benefit to clients."
          : "",
    }),
  );

  // ── 13. Subresource integrity on third-party scripts ──────────────
  const externalScripts = [...body.matchAll(/<script\b[^>]*src=["']([^"']+)["'][^>]*>/gi)]
    .map((m) => ({ tag: m[0], src: m[1] }))
    .filter((s) => /^https?:\/\//i.test(s.src) && !s.src.startsWith(baseUrl.origin));
  const withoutSri = externalScripts.filter((s) => !/\bintegrity=/i.test(s.tag));
  out.push(
    finding({
      id: "WEB-SUBRESOURCE-INTEGRITY",
      observed: "Third-party scripts are loaded without integrity pinning",
      title: "Third-party scripts are pinned with subresource integrity",
      status: externalScripts.length === 0 ? "pass" : withoutSri.length ? "fail" : "pass",
      severity: "medium",
      evidence:
        externalScripts.length === 0
          ? "No cross-origin scripts are loaded by the landing page."
          : withoutSri.length
            ? `Cross-origin scripts without an integrity attribute:\n${withoutSri.map((s) => s.src).join("\n")}`
            : `${externalScripts.length} cross-origin script(s), all carrying integrity attributes.`,
      remediation: withoutSri.length
        ? "Add integrity and crossorigin attributes to third-party script tags, or self-host the asset. Without it, a compromise of the CDN is a compromise of your application."
        : "",
    }),
  );

  // ── 14. Cookie scope ──────────────────────────────────────────────
  if (cookies.length) {
    const scopeIssues = cookies
      .map((cookie) => {
        const name = cookie.split("=")[0];
        const domain = /;\s*domain=([^;]+)/i.exec(cookie)?.[1]?.trim();
        const path = /;\s*path=([^;]+)/i.exec(cookie)?.[1]?.trim();
        const problems = [];
        // A cookie scoped to the registrable domain is sent to every sibling subdomain.
        if (domain && baseUrl.hostname.endsWith(domain.replace(/^\./, "")) && domain.replace(/^\./, "") !== baseUrl.hostname) {
          problems.push(`Domain=${domain} widens it to all subdomains`);
        }
        if (path && path !== "/" && false) problems.push(`Path=${path}`);
        if (/^__(Secure|Host)-/.test(name) === false && /session|auth|token|sid/i.test(name) && !/;\s*secure/i.test(cookie)) {
          problems.push("session cookie without the Secure attribute");
        }
        return problems.length ? `${name}: ${problems.join("; ")}` : null;
      })
      .filter(Boolean);
    out.push(
      finding({
        id: "WEB-COOKIE-SCOPE",
        observed: "Cookies are scoped wider than the exact host",
        title: "Cookies are scoped to the exact host",
        status: scopeIssues.length ? "warn" : "pass",
        severity: "low",
        evidence: scopeIssues.length ? scopeIssues.join("\n") : `${cookies.length} cookie(s) are host-scoped.`,
        remediation: scopeIssues.length
          ? "Omit the Domain attribute so the cookie stays host-only, and consider the __Host- prefix to make that guarantee explicit to the browser."
          : "",
      }),
    );
  }

  // ── 15. Caching of credentialed responses ─────────────────────────
  const cacheControl = headers.get("cache-control") ?? "";
  const setsCookie = cookies.length > 0;
  const publiclyCacheable = /public/i.test(cacheControl) || (!cacheControl && !headers.get("pragma"));
  out.push(
    finding({
      id: "WEB-CACHE-CONTROL",
      observed: "A response that sets a cookie is publicly cacheable",
      title: "Responses that set cookies are not publicly cacheable",
      status: setsCookie && publiclyCacheable ? "fail" : "pass",
      severity: "medium",
      evidence:
        `Cache-Control: ${cacheControl || "(absent)"} · Set-Cookie present: ${setsCookie ? "yes" : "no"}` +
        (setsCookie && publiclyCacheable ? "\nA shared cache may store this response together with its cookie." : ""),
      remediation:
        setsCookie && publiclyCacheable
          ? "Send `Cache-Control: no-store` on any response that sets a session cookie or carries user data, so intermediary caches cannot serve one user's response to another."
          : "",
    }),
  );

  // ── 16. Directory listing ─────────────────────────────────────────
  const listingPaths = web.listingPaths ?? ["/assets/", "/static/", "/uploads/", "/files/", "/js/", "/images/"];
  const listings = [];
  for (const path of listingPaths) {
    if (client.remainingRequests < 4) break;
    try {
      const probe = await client.request(new URL(path, baseUrl).href);
      if (probe.status !== 200) continue;
      const text = (await probe.text()).slice(0, 500);
      if (/<title>Index of|Directory listing for|\[To Parent Directory\]/i.test(text)) listings.push({ path, text });
    } catch {
      /* ignore */
    }
  }
  out.push(
    finding({
      id: "WEB-DIRECTORY-LISTING",
      observed: "Directory listing is enabled",
      title: "Directory listing is disabled",
      status: listings.length ? "fail" : "pass",
      severity: "medium",
      evidence: listings.length
        ? listings.map((l) => `${l.path} returns an index page:\n${l.text.slice(0, 200)}`).join("\n\n")
        : `Checked ${listingPaths.join(", ")} — no index pages returned.`,
      remediation: listings.length
        ? "Disable autoindex/directory browsing at the web server or bucket, and serve an explicit 404 for directory paths."
        : "",
    }),
  );

  // ── 17. TLS ───────────────────────────────────────────────────────
  try {
    const tlsInfo = await client.tlsInfo(baseUrl.hostname, Number(baseUrl.port) || 443);
    const modern = /TLSv1\.[23]/.test(tlsInfo.protocol ?? "");
    out.push(
      finding({
        id: "WEB-TLS-VERSION",
        observed: "The transport negotiates a deprecated TLS version",
        title: "Transport negotiates TLS 1.2 or higher",
        status: modern ? "pass" : "fail",
        severity: "high",
        evidence: `Negotiated ${tlsInfo.protocol} with ${tlsInfo.cipher}`,
        remediation: modern ? "" : "Disable TLS 1.0/1.1 at the load balancer or CDN and require TLS 1.2 as a minimum.",
      }),
      finding({
        id: "WEB-TLS-CERTIFICATE",
        observed: "The server certificate does not validate",
        title: "Server certificate validates against the public trust store",
        status: tlsInfo.authorized ? "pass" : "fail",
        severity: "high",
        evidence: tlsInfo.authorized
          ? `Valid certificate from ${tlsInfo.issuer ?? "unknown issuer"}, expires ${tlsInfo.validTo ?? "unknown"}`
          : `Certificate validation failed: ${tlsInfo.authorizationError}`,
        remediation: tlsInfo.authorized ? "" : "Install a certificate chain issued by a publicly trusted CA and keep it renewed.",
      }),
    );
  } catch (error) {
    out.push(inconclusive("WEB-TLS-VERSION", "Transport negotiates TLS 1.2 or higher", `TLS handshake failed: ${error.message}`));
  }

  return out;
}
