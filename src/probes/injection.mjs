/**
 * TRUST — input-handling probes (OWASP A03).
 *
 * Scope discipline matters here. TRUST is a trust-boundary verifier, not a scanner: these
 * probes answer "is the boundary obviously absent?", never "can I exploit it?". They are
 * read-only GETs carrying a unique canary, and every verdict is a pattern match on what came
 * back — the same technique the agent probes use.
 *
 * That means:
 *   - A PASS is not proof the target is free of injection. It means these specific,
 *     unmistakable signatures were absent. A real assessment still needs a scanner and a
 *     human. The report says so in the finding evidence.
 *   - Payloads are inert. No stacked queries, no time delays, no destructive verbs, nothing
 *     that writes. A reflected canary and an unhandled database error are the only signals.
 *   - Parameters are discovered from the page's own links and forms where possible, so the
 *     probes exercise real inputs rather than invented ones.
 */

import { finding, skipped, inconclusive, canary } from "../finding.mjs";

/** Query parameters worth testing when the target exposes none of its own. */
const FALLBACK_PARAMS = ["q", "search", "id", "name", "page", "filter", "sort", "lang", "view"];

/** Database error signatures. Deliberately narrow — a false positive here is expensive. */
const SQL_ERRORS = [
  [/SQL syntax.{0,40}(MySQL|MariaDB)/i, "MySQL/MariaDB syntax error"],
  [/valid MySQL result|mysqli?_/i, "MySQL client error"],
  [/PostgreSQL.{0,30}ERROR|pg_query|unterminated quoted string/i, "PostgreSQL error"],
  [/Microsoft (OLE DB|SQL Server)|Unclosed quotation mark|Incorrect syntax near/i, "SQL Server error"],
  [/ORA-\d{5}|Oracle error|PLS-\d{5}/i, "Oracle error"],
  [/SQLite\/JDBCDriver|SQLite3?::|sqlite3\.OperationalError|no such column/i, "SQLite error"],
  [/org\.hibernate\.|JDBCException|SQLGrammarException/i, "Hibernate/JDBC error"],
  [/MongoError|BSONError|\$where/i, "MongoDB error"],
  [/Npgsql\.|System\.Data\.SqlClient/i, ".NET data provider error"],
];

/** File-content signatures for traversal. Requires actual file content, not just a 200. */
const FILE_SIGNATURES = [
  [/root:[x*!]?:0:0:/, "/etc/passwd content"],
  [/\[(fonts|extensions|mci extensions)\]/i, "win.ini content"],
  [/^\s*<\?xml[\s\S]{0,200}<web-app/im, "web.xml content"],
  [/DB_(PASSWORD|HOST)\s*=|APP_KEY\s*=/i, ".env content"],
];

async function safeGet(client, url, init = {}) {
  const response = await client.request(url, init);
  const text = await response.text();
  return { response, status: response.status, text, headers: response.headers };
}

/**
 * Which parameters does the target actually use? Read them off its own links and forms;
 * fall back to a conventional list so a static page still gets exercised.
 */
export function discoverParams(html, baseUrl, limit = 6) {
  const found = new Set();
  for (const m of html.matchAll(/(?:href|action)=["']([^"']+)["']/gi)) {
    let parsed;
    try {
      // Real markup encodes the separator, so "?a=1&amp;b=2" must be decoded first or the
      // second parameter is discovered as "amp;b".
      parsed = new URL(m[1].replace(/&amp;/gi, "&"), baseUrl);
    } catch {
      continue;
    }
    if (parsed.hostname !== new URL(baseUrl).hostname) continue;
    for (const key of parsed.searchParams.keys()) found.add(key);
  }
  for (const m of html.matchAll(/<input[^>]+name=["']([^"']+)["']/gi)) found.add(m[1]);
  for (const key of FALLBACK_PARAMS) {
    if (found.size >= limit) break;
    found.add(key);
  }
  return [...found].slice(0, limit);
}

export async function runInjectionProbes(config, client) {
  const target = config.targets?.web;
  if (!target) return [skipped("INJECT-CONFIG", "Input-handling probe suite", "targets.web is not configured")];

  const baseUrl = new URL(target);
  const out = [];
  const caveat = "\nNote: this asserts the absence of an unmistakable signature. It is not proof the target is free of injection.";

  // Read the landing page once, to discover real parameters.
  let html = "";
  try {
    const base = await safeGet(client, baseUrl.href);
    html = base.text;
  } catch (error) {
    return [inconclusive("INJECT-CONFIG", "Input-handling probe suite", `Baseline request failed: ${error.message}`)];
  }
  const params = config.injection?.params ?? discoverParams(html, baseUrl.href, config.injection?.maxParams ?? 5);
  const budget = () => client.remainingRequests;

  // ── 1. Reflected XSS ─────────────────────────────────────────────
  // The canary carries HTML-significant characters; if they come back unencoded inside the
  // body, the response is not escaping output.
  const xssMark = canary("XSS");
  // Variants matter: a quote can send the request down an error-handling path that never
  // reflects anything, so the quoteless payload goes first. Angle brackets alone are
  // sufficient evidence that output is not encoded.
  const xssVariants = [
    { name: "element", payload: `<svg/onload=1>${xssMark}`, signature: /<svg\/onload/i },
    { name: "attribute-break", payload: `"><b>${xssMark}`, signature: /"><b>|<b>/i },
    { name: "js-string", payload: `';${xssMark}//`, signature: new RegExp(`';${xssMark}`) },
  ];
  const reflected = [];
  let xssAttempts = 0;
  for (const param of params) {
    for (const variant of xssVariants) {
      if (budget() < 3) break;
      xssAttempts += 1;
      const url = new URL(baseUrl.href);
      url.searchParams.set(param, variant.payload);
      try {
        const { text, status, headers } = await safeGet(client, url.href);
        const isHtml = (headers.get("content-type") ?? "").includes("html");
        if (!isHtml || !text.includes(xssMark)) continue;
        const at = text.indexOf(xssMark);
        const window = text.slice(Math.max(0, at - 140), at + 60);
        // Encoded reflection is correct behaviour; only a raw payload is a finding.
        if (variant.signature.test(window)) {
          reflected.push({ param, variant: variant.name, status, window });
          break;
        }
      } catch {
        /* a parameter that errors is not evidence either way */
      }
    }
  }
  out.push(
    finding({
      id: "INJECT-REFLECTED-XSS",
      observed: "User input is reflected into HTML unencoded",
      title: "User input is not reflected into HTML unencoded",
      status: reflected.length ? "fail" : "pass",
      severity: "high",
      evidence: reflected.length
        ? reflected.map((r) => `?${r.param}= (${r.variant} variant) → HTTP ${r.status}, payload reflected raw:\n…${r.window}…`).join("\n\n")
        : `${xssAttempts} attempt(s) across ${params.length} parameter(s) and ${xssVariants.length} context variants ` +
          `(${xssVariants.map((v) => v.name).join(", ")}); the canary was absent or encoded every time.${caveat}`,
      remediation: reflected.length
        ? "Encode on output for the context you are writing into (HTML body, attribute, JS, URL), and deploy a CSP without 'unsafe-inline' as defence in depth."
        : "",
    }),
  );

  // ── 2. Error-based SQL injection ──────────────────────────────────
  // Inert quote/paren payloads. If an unhandled database error surfaces, input is reaching a
  // query uncontrolled — which is a finding regardless of whether it is exploitable.
  const sqlPayloads = ["'", "'\"", "')", "1'--"];
  const sqlHits = [];
  for (const param of params) {
    if (budget() < 3) break;
    for (const payload of sqlPayloads) {
      const url = new URL(baseUrl.href);
      url.searchParams.set(param, payload);
      try {
        const { text, status } = await safeGet(client, url.href);
        const matched = SQL_ERRORS.filter(([pattern]) => pattern.test(text)).map(([, name]) => name);
        if (matched.length) {
          sqlHits.push({ param, payload, status, matched, snippet: text.slice(0, 300) });
          break;
        }
      } catch {
        /* keep going */
      }
    }
  }
  out.push(
    finding({
      id: "INJECT-SQL-ERROR",
      observed: "Untrusted input surfaces database errors",
      title: "Untrusted input does not surface database errors",
      status: sqlHits.length ? "fail" : "pass",
      severity: "critical",
      evidence: sqlHits.length
        ? sqlHits.map((h) => `?${h.param}=${h.payload} → HTTP ${h.status}, ${h.matched.join(", ")}\n${h.snippet}`).join("\n\n")
        : `Tested ${params.length} parameter(s) with ${sqlPayloads.length} inert payload(s); no database error signature returned.${caveat}`,
      remediation: sqlHits.length
        ? "Use parameterised queries or an ORM binding for every user-supplied value, and return a generic error envelope so query structure is never disclosed. Treat this as exploitable until proven otherwise."
        : "",
    }),
  );

  // ── 3. Server-side template injection ─────────────────────────────
  // If 7*7 comes back as 49, input is being evaluated rather than rendered.
  const sstiPayloads = ["${7*7}", "{{7*7}}", "<%=7*7%>", "#{7*7}"];
  const sstiHits = [];
  for (const param of params.slice(0, 3)) {
    if (budget() < 3) break;
    for (const payload of sstiPayloads) {
      const url = new URL(baseUrl.href);
      const marker = `${payload}`;
      url.searchParams.set(param, marker);
      try {
        const { text, status } = await safeGet(client, url.href);
        // 49 only counts when the payload itself is gone — otherwise it is plain reflection.
        if (!text.includes(payload) && /(^|[^\d])49([^\d]|$)/.test(text) && !html.includes("49")) {
          sstiHits.push({ param, payload, status });
          break;
        }
      } catch {
        /* keep going */
      }
    }
  }
  out.push(
    finding({
      id: "INJECT-TEMPLATE",
      observed: "Untrusted input is evaluated as a template expression",
      title: "Untrusted input is not evaluated as a template expression",
      status: sstiHits.length ? "fail" : "pass",
      severity: "critical",
      evidence: sstiHits.length
        ? sstiHits.map((h) => `?${h.param}=${h.payload} → HTTP ${h.status}, expression evaluated to 49`).join("\n")
        : `Tested ${Math.min(params.length, 3)} parameter(s) with ${sstiPayloads.length} expression syntaxes; none were evaluated.${caveat}`,
      remediation: sstiHits.length
        ? "Never build a template from user input. Pass values as template *context*, and if a user-authored template is genuinely required, render it in a sandboxed engine."
        : "",
    }),
  );

  // ── 4. Path traversal ─────────────────────────────────────────────
  const traversalPayloads = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
  ];
  const traversalHits = [];
  const traversalParams = config.injection?.fileParams ?? params.filter((p) => /file|path|doc|name|template|page|view|download/i.test(p));
  for (const param of traversalParams.length ? traversalParams : params.slice(0, 2)) {
    if (budget() < 3) break;
    for (const payload of traversalPayloads) {
      const url = new URL(baseUrl.href);
      url.searchParams.set(param, payload);
      try {
        const { text, status } = await safeGet(client, url.href);
        const matched = FILE_SIGNATURES.filter(([pattern]) => pattern.test(text)).map(([, name]) => name);
        if (matched.length) {
          traversalHits.push({ param, payload, status, matched });
          break;
        }
      } catch {
        /* keep going */
      }
    }
  }
  out.push(
    finding({
      id: "INJECT-PATH-TRAVERSAL",
      observed: "File parameters escape the base directory",
      title: "File parameters cannot escape their base directory",
      status: traversalHits.length ? "fail" : "pass",
      severity: "critical",
      evidence: traversalHits.length
        ? traversalHits.map((h) => `?${h.param}=${h.payload} → HTTP ${h.status}, returned ${h.matched.join(", ")}`).join("\n")
        : `No file content was returned for traversal payloads on: ${(traversalParams.length ? traversalParams : params.slice(0, 2)).join(", ")}.${caveat}`,
      remediation: traversalHits.length
        ? "Resolve the requested path and confirm it stays inside the intended directory, or better, map an opaque identifier to a server-side path so no user input reaches the filesystem."
        : "",
    }),
  );

  // ── 5. CRLF / response-header injection ───────────────────────────
  const crlfMark = canary("CRLF").toLowerCase();
  let crlfHit = null;
  let crlfAttempts = 0;
  // The payload must reach the server still percent-encoded, so the query string is built
  // by hand: URLSearchParams would escape the % and the target would only ever see the
  // literal text "%0d%0a".
  const crlfEncodings = ["%0d%0a", "%0D%0A", "%0a", "%E5%98%8A%E5%98%8D"];
  for (const encoding of crlfEncodings) {
    if (budget() < 2) break;
    crlfAttempts += 1;
    const param = params[0] ?? "q";
    const url = `${baseUrl.origin}${baseUrl.pathname}?${param}=trust${encoding}x-trust-injected:${crlfMark}`;
    try {
      const { response, status } = await safeGet(client, url);
      const injected = response.headers.get("x-trust-injected");
      if (injected) {
        crlfHit = { status, injected, encoding };
        break;
      }
    } catch {
      /* ignore */
    }
  }
  out.push(
    finding({
      id: "INJECT-CRLF-HEADER",
      observed: "Untrusted input can inject response headers",
      title: "Untrusted input cannot inject response headers",
      status: crlfHit ? "fail" : "pass",
      severity: "high",
      evidence: crlfHit
        ? `Encoded CRLF (${crlfHit.encoding}) in a query parameter produced header x-trust-injected: ${crlfHit.injected} (HTTP ${crlfHit.status})`
        : `${crlfAttempts} encoding variant(s) tried (${crlfEncodings.join(", ")}); none produced an injected response header.${caveat}`,
      remediation: crlfHit
        ? "Strip CR and LF from any user value placed into a response header or redirect Location, and prefer a framework API that rejects them outright."
        : "",
    }),
  );

  // ── 6. Host-header handling ───────────────────────────────────────
  // A target that trusts the Host header will build absolute links — password-reset links
  // especially — pointing at an attacker's domain.
  const evilHost = "trust-probe.invalid";
  let hostHit = null;
  if (budget() >= 2) {
    try {
      // The request still goes to the allowlisted host; only the Host header is spoofed.
      const { text, response, status } = await safeGet(client, baseUrl.href, {
        headers: { host: evilHost, "x-forwarded-host": evilHost },
      });
      const location = response.headers.get("location") ?? "";
      const inBody = new RegExp(`https?://${evilHost.replace(".", "\\.")}`).test(text);
      if (location.includes(evilHost) || inBody) hostHit = { status, location, inBody };
    } catch (error) {
      out.push(inconclusive("INJECT-HOST-HEADER", "Absolute URLs are not built from the Host header", `Request failed: ${error.message}`));
    }
  }
  if (!out.some((f) => f.id === "INJECT-HOST-HEADER")) {
    out.push(
      finding({
        id: "INJECT-HOST-HEADER",
        observed: "Absolute URLs are built from the caller-supplied Host header",
        title: "Absolute URLs are not built from a caller-supplied Host header",
        status: hostHit ? "fail" : "pass",
        severity: "medium",
        evidence: hostHit
          ? `Host/X-Forwarded-Host: ${evilHost} → HTTP ${hostHit.status}` +
            (hostHit.location ? `\nLocation: ${hostHit.location}` : "") +
            (hostHit.inBody ? "\nThe spoofed host appears in absolute links in the response body." : "")
          : `Spoofed Host and X-Forwarded-Host were not reflected into links or redirects.${caveat}`,
        remediation: hostHit
          ? "Build absolute URLs from configuration, not the request. Validate Host against an allowlist at the edge and ignore X-Forwarded-Host unless it comes from a trusted proxy."
          : "",
      }),
    );
  }

  // ── 7. SSRF (shallow, honest) ─────────────────────────────────────
  // Without an out-of-band listener a client cannot confirm the server made the request.
  // What is detectable: the target fetching an unresolvable host and leaking the attempt in
  // an error, or echoing the URL back. Anything else is explicitly reported as unverified.
  const ssrfParams = config.injection?.urlParams ?? params.filter((p) => /url|uri|link|src|dest|redirect|callback|webhook|image|feed|proxy/i.test(p));
  const ssrfTarget = `https://ssrf-${canary("T").toLowerCase()}.invalid/probe`;
  const ssrfEvidence = [];
  let ssrfHit = null;
  for (const param of ssrfParams) {
    if (budget() < 3) break;
    const url = new URL(baseUrl.href);
    url.searchParams.set(param, ssrfTarget);
    try {
      const { text, status } = await safeGet(client, url.href);
      const leaked = /(getaddrinfo|ENOTFOUND|EAI_AGAIN|dns|connect ECONNREFUSED|UnknownHost|Name or service not known|Could not resolve)/i.test(text);
      ssrfEvidence.push(`?${param}= → HTTP ${status}${leaked ? " — resolution error leaked, the server attempted the fetch" : ""}`);
      if (leaked) {
        ssrfHit = { param, status, snippet: text.slice(0, 300) };
        break;
      }
    } catch {
      /* ignore */
    }
  }
  if (ssrfParams.length === 0) {
    out.push(
      skipped(
        "INJECT-SSRF",
        "URL parameters are not fetched server-side",
        "no URL-shaped parameter was found or configured (set config.injection.urlParams to test specific ones)",
      ),
    );
  } else {
    out.push(
      finding({
        id: "INJECT-SSRF",
        observed: "Server-side fetching of caller-supplied URLs is unconfirmed",
        title: "URL parameters are not fetched server-side",
        status: ssrfHit ? "fail" : "warn",
        severity: "high",
        evidence: ssrfHit
          ? `The server tried to resolve an attacker-supplied host:\n?${ssrfHit.param}= → HTTP ${ssrfHit.status}\n${ssrfHit.snippet}`
          : `${ssrfEvidence.join("\n")}\nNo resolution error surfaced. Confirming SSRF requires an out-of-band listener, which this harness deliberately does not run — treat this as UNVERIFIED rather than clean.`,
        remediation: ssrfHit
          ? "Do not fetch user-supplied URLs. Where a fetch is required, resolve the host first and reject private, link-local and metadata ranges, pin the scheme and port, and route the call through an egress proxy with an allowlist."
          : "Verify manually with a collaborator/listener endpoint, or configure config.injection.urlParams so the right parameters are covered.",
      }),
    );
  }

  return out;
}
