I now have a complete picture of the entire codebase. Here is the comprehensive review:

---

# TRUST Framework — Deep Engineering Review

## 1. ARCHITECTURE

### Module Boundaries & Dependency Flow

The data flow is clean and unidirectional:

```
CLI (cli.mjs)
  → loadConfig / validateConfig (safety.mjs)
  → runProfile (runner.mjs)
    → SafeHttpClient (safety.mjs)
    → probe modules (probes/*.mjs)
      → finding() factory (finding.mjs)
    → buildRunReport / writeRunReport (report.mjs)
  → writeCombinedReport (assessment/index.mjs)
    → loadReports → buildModel (assessment/model.mjs)
    → section renderers (assessment/sections/*.mjs)
```

**Strengths:**

- **Strict separation of concerns.** The runner never writes to the console. The CLI never issues HTTP requests. Probes never read configs from disk. The finding factory enforces a single shape. This is textbook clean architecture.
- **The `SafeHttpClient` is a chokepoint.** Every HTTP request in the entire platform flows through one guarded path. This is the right design for a security tool — the harness is structurally incapable of making an unguarded request.
- **The assessment pipeline is model/view.** `buildModel()` derives everything; section renderers are pure functions of that model. Adding a new output format (SARIF, JSON dashboard feed) means consuming `buildModel()` without touching any HTML.
- **Custom probes are first-class.** `defineProbe()` + `loadCustomProbes()` + `registerCatalogEntries()` means partner probes score, group, and report identically to built-ins. The extension contract is well-designed.
- **No circular dependencies.** Every module imports downward: `cli → runner → probes → finding`. The catalog is a shared registry, not a circular import.

**Weaknesses:**

- **`assessment/model.mjs` (534 lines) is doing too much.** It computes scores, builds HTML fragments for finding cards, remediation rows, retest rows, inventory rows, workstream rows, attack path rows, executive bullets, root cause rows, trust-verified items, scope rows, coverage stats, and facets — all in one function. This is a single 400-line function `buildModel()` that returns a 40-field object. It's testable in theory but unwieldy in practice.
- **The catalog is a mutable global.** `registerCatalogEntries()` mutates the `CATALOG` object, `registerDomains()` mutates `TRUST_DOMAINS` and `DOMAIN_ORDER`, etc. This means parallel test runs in the same process would contaminate each other. Not a problem for CLI usage, but a footgun for library embedders running multiple profiles concurrently.

### Verdict: Architecture is strong — 8/10

The design is thoughtful, the separation is real, and the data flow is clean. The model.mjs monolith and mutable globals are the only notable debts.

---

## 2. SECURITY OF THE TOOL ITSELF

### Token/Credential Handling

**Good:**
- `.env` values are **never logged**. [env.mjs](node_modules/@automationarchitect/trust/src/env.mjs) line 60-62: only key *names* are logged, never values. The docstring at line 15 makes this an explicit design rule.
- `loadEnv()` skips keys already present in `process.env` (line 57), so CI-injected secrets always win over a stale local `.env`.
- Tokens are accessed via `process.env[envVarName]` at probe call time — they are never stored in the config object on disk.

**Concern:**
- **Tokens transit through `finding.evidence`** before redaction. Each probe constructs evidence strings containing HTTP response text (which could contain tokens), then `finding()` calls `redact()`. If a probe calls `finding()` with the wrong field — e.g. puts a token in `title` instead of `evidence` — it bypasses redaction. The `title` and `remediation` fields are *not* redacted ([finding.mjs](node_modules/@automationarchitect/trust/src/finding.mjs) lines 88-92). This is by design (titles shouldn't contain secrets), but a custom probe author could trip over it.

### Redaction — `redact()` Analysis

The redaction engine at [finding.mjs](node_modules/@automationarchitect/trust/src/finding.mjs) lines 18-43 handles:

| Pattern | Coverage |
|---------|----------|
| JWTs (`eyJ...`) | Good — matches the three-segment base64url structure |
| Bearer/Basic tokens | Good |
| AWS key IDs (AKIA/ASIA) | Good |
| GitHub tokens (ghp/gho/ghs/ghu/ghr) | Good |
| OpenAI keys (sk-) | Good |
| Slack tokens (xox[abprs]) | Good |
| Key/value pairs (password=, secret:, etc.) | Sophisticated — handles quoted and unquoted, various separators |
| Signed URL parameters | Good |
| PEM private keys | Good |

**Gaps in redaction:**
- **Azure SAS tokens** (`?sv=...&sig=...`) — the signed-URL rule covers `sig=` and `sv=` but only when preceded by `?` or `&`. An Azure SAS token in a different position could slip through.
- **Google Cloud service account keys** (JSON with `"private_key": "..."`) — the key-value rule should catch `private_key`, but only if the value is on one line and doesn't contain quote-breaking characters.
- **No Anthropic/Cohere/HuggingFace token patterns.** Only `sk-` is covered.
- **No redaction for `observed` field when status is fail/warn.** Looking at line 90: `observed: status === "fail" || status === "warn" ? String(observed ?? "") : ""` — this passes through raw, unredacted. A probe that puts sensitive data in `observed` leaks it.

### allowedHosts Enforcement

[safety.mjs](node_modules/@automationarchitect/trust/src/safety.mjs) — the enforcement is sound:

1. **`assertUrlAllowed()`** (lines 188-199) parses the URL, checks `protocol === "https:"`, checks hostname against the allowlist Set, and checks for production pattern. This runs on every `request()` and `tlsInfo()` call.
2. **Protocol enforcement is absolute** — no HTTP, no `file://`, no `data:`. Line 192: `if (parsed.protocol !== "https:") throw SafetyError`.
3. **`redirect: "manual"`** is hardcoded in `request()` (line 225). The client never follows redirects, so a target cannot redirect TRUST to an off-allowlist host.
4. **The URL is re-parsed** from `parsed.href` (line 225), not from the user-supplied string — this prevents URL-parsing discrepancies.

**One edge case:**
- **No port restriction.** A host in `allowedHosts` is a bare hostname, but `assertUrlAllowed()` checks only `parsed.hostname`. An attacker who controls DNS for an allowed host could run a service on a non-standard port. This is a minimal risk since TRUST is the client, not the target, but worth noting.
- **No IPv4/IPv6 literal check.** If someone puts `127.0.0.1` in allowedHosts, it would be allowed. The `validateConfig()` function doesn't reject IP addresses.

### `safety.maxRequests` — Race Conditions

The counter at [safety.mjs](node_modules/@automationarchitect/trust/src/safety.mjs) line 207 uses a private field `#count`. Checking and incrementing happen at lines 215 and 220:

```js
if (this.#count >= this.safety.maxRequests) { ... }
await this.#throttle();
this.#count += 1;
```

**No race condition.** JavaScript is single-threaded. The `await this.#throttle()` yields to the event loop, but `this.#count` is only incremented synchronously after the yield. Since probes are `await`ed sequentially in [runner.mjs](node_modules/@automationarchitect/trust/src/runner.mjs) line 161 (`produced = await probe.run(config, client)`), and within probes requests are serial (each `await client.request(...)` completes before the next), there's no interleaving that could skip the cap. The design is correct.

### Report Output — File Permissions

[report.mjs](node_modules/@automationarchitect/trust/src/report.mjs) lines 155-156:
```js
await writeFile(jsonPath, JSON.stringify(report, null, 2), { mode: 0o600 });
await writeFile(htmlPath, buildRunHtml(report), { mode: 0o600 });
```

`mode: 0o600` (owner read/write only) is correct for security-sensitive reports. The combined assessment in [assessment/index.mjs](node_modules/@automationarchitect/trust/src/assessment/index.mjs) line 74 also uses `mode: 0o600`.

**Note:** On Windows, `mode` is largely ignored — Node.js doesn't enforce Unix file permissions on NTFS. The setting is correct for Linux/macOS deployments.

### HTML Escaping

The `esc()` function at [html.mjs](node_modules/@automationarchitect/trust/src/assessment/html.mjs) line 7 and [report.mjs](node_modules/@automationarchitect/trust/src/report.mjs) line 102 both escape `& < > " '`. This is comprehensive for HTML body and attribute contexts.

**Every interpolation of target-controlled text I can find goes through `esc()`.** The finding cards in model.mjs, the inventory rows, the remediation rows — all use `esc()`. The report is a single self-contained HTML file with inline script, and the script itself (`client.mjs`) doesn't `innerHTML` any user data.

**One subtle concern in `report.mjs` line 110:**
```js
<td>${esc(headline(f))}<div class="det">...
```
The `headline()` function returns `f.observed || f.title`, both of which were already sanitized by `finding()` as plain strings. But `f.evidence` goes through `redact()` which only strips secrets — it doesn't HTML-escape. The HTML-escaping happens at render time via `esc()`. This is correct.

### Dependency Surface

```json
"dependencies": {},
"devDependencies": {}
```

**Zero runtime dependencies.** This is exceptional for a security tool. No `node_modules` supply chain risk beyond Node.js itself. The tool uses only built-in modules: `node:fs/promises`, `node:path`, `node:url`, `node:crypto`, `node:tls`. This is a genuine strength — the attack surface is minimal.

### Code Injection via Config or Probe

- **Config is JSON** parsed via `JSON.parse()` after `stripJsonComments()`. No `eval()`, no `Function()`, no template literals evaluated from config data. Safe.
- **Custom probes are loaded via `import()`** ([runner.mjs](node_modules/@automationarchitect/trust/src/runner.mjs) line 102). This is code execution by design — a probe *is* code. But it's guarded: the path resolves against the config file's directory, and `defineProbe()` validates the shape. A malicious probe is a user who has write access to the repo, which is already game-over.
- **`stripJsonComments()`** ([safety.mjs](node_modules/@automationarchitect/trust/src/safety.mjs) lines 71-96) is a hand-rolled JSONC parser. I reviewed it for edge cases: it handles string escaping, `//` comments, `/* */` comments, and nested quotes correctly. No injection path visible.

### Security Verdict: Strong — 8.5/10

The tool practices what it preaches. Zero dependencies, strict allowlisting, redaction before disk, `0o600` file permissions, HTML escaping on every interpolation. The `observed` field not being redacted is the main gap.

---

## 3. PROBE QUALITY

### `probes/web.mjs` — Web Infrastructure (606 lines)

**Coverage:** 17 distinct checks covering HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, clickjacking, cookies, token storage, source maps, sensitive file exposure, CORS, open redirect, rate limiting, HTTP methods, server banner, SRI, cookie scope, cache control, directory listing, TLS version, TLS certificate.

**Strengths:**
- **CSP validation is substantive** (lines 26-34): checks for `default-src`, `unsafe-inline` in `script-src`, `unsafe-eval` in `script-src`. Not just presence but policy quality.
- **Token storage detection** (lines 201-218) scans actual JavaScript bundles for `localStorage.setItem` / `sessionStorage.setItem` with token-like key names. This is a real check, not a header check.
- **Sensitive file exposure** (lines 237-263) uses `looksLikeRealContent()` to distinguish a real `.env` file from an SPA fallback returning HTML. This prevents false positives on SPAs that return 200 for everything.
- **CORS** (lines 270-292) tests both origin reflection *and* wildcard-with-credentials. Both are real attack patterns.

**Weaknesses / Edge Cases:**
- **Rate limit test** (lines 305-330) sends a burst at the configured delay floor and looks for 429/503. Verdict is `warn` (not fail) when no rate limiting is observed, which is honest — a polite burst may be below the threshold. But the test is fundamentally limited: 8 requests at 150ms intervals (1.2 seconds) won't trigger most WAF rate limits, which are typically 100+ requests/minute.
- **Token storage detection** only catches `localStorage.setItem("token", ...)` — it won't catch `window.localStorage["token"] = ...` or `localStorage.token = ...` or indirect references. But it's honest about this in the evidence text.
- **Open redirect** (lines 294-315) only tests query parameters, not path-based redirects or fragment-based redirects. If a target uses `?url=` but URL-encodes-validates only the `redirect` parameter, the probe could miss it.
- **Cookie flags** (lines 173-198) checks all cookies, not just session cookies. A tracking cookie without HttpOnly is not the same severity as a session cookie without HttpOnly. The probe doesn't differentiate.
- **`web.maxScriptsToScan` defaults to 3** (line 198). On a complex SPA with many bundles, token storage detection could miss a problematic bundle.

### `probes/api.mjs` — API Authorization (558 lines)

**Strengths:**
- **Cross-user isolation** (lines 100-120) is a genuine IDOR test: it sends User B's token with User A's resource identifier and checks if data comes back.
- **`isDenied()`** (lines 51-57) checks both HTTP status codes AND response body for authorization errors. This handles the GraphQL case where the server returns 200 with `errors: [{message: "unauthorized"}]`.
- **Password auth bypass** (lines 270-340) uses a two-source corroboration model: it won't claim FAIL unless both the token endpoint response AND the OIDC discovery document agree. This avoids false positives where `invalid_credentials` doesn't necessarily mean the grant is enabled.
- **Query cost probe** (lines 382-410) sends 500 aliases of `__typename` — a real complexity attack that any production GraphQL API should reject.

**Weaknesses / Edge Cases:**
- **`isDenied()` doesn't check for 429** (rate limiting). A rate-limited response would be treated as "not denied", potentially causing a false negative on cross-user checks.
- **Excessive data detection** (lines 350-370) uses regex to match field names like `"password"`, `"ssn"`, `"secret"`. This will miss fields with non-English names or obfuscated names. It also can't detect *values* that look like secrets — only field name patterns.
- **Error disclosure** (lines 235-260) probes with a single malformed request. A target might sanitize errors on some endpoints but not others. Testing a single path provides limited coverage.
- **Session logout** (lines 416-445) tests whether a token works after logout, but the test reuses the same token. If the IdP returns a new token on each auth, and logout invalidates only the current token, the test is valid. But if the target uses opaque sessions and the token is a reference, the semantics are correct.

### `probes/agent.mjs` — AI Agent Runtime (499 lines)

**Strengths:**
- **Canary-based verdicts** are the right approach for LLM testing. No model judges — a UUID is planted and its presence/absence is checked. This is deterministic and repeatable.
- **Direct injection** (line 148-170) embeds the canary in a realistic support-ticket context with `IGNORE ALL PREVIOUS INSTRUCTIONS`. This tests the actual attack vector, not a synthetic one.
- **Indirect injection** (line 176-210) embeds the canary in a simulated retrieved document with an HTML comment. This tests the data/instruction separation boundary.
- **Hierarchy probe** (lines 289-340) tests whether sub-agents reject direct invocation with an end-user token. This is a genuine architecture test, not a superficial one.
- **Conditional ACL/guardrail probes** (lines 345-400) only run when a hierarchy breach was found, which is methodologically sound — you only test the sub-agent's own controls when you've proven the orchestrator can be bypassed.

**Weaknesses / Edge Cases:**
- **Single-shot injection test.** The direct injection uses one prompt variant. LLMs are non-deterministic — the agent might resist one phrasing but not another. A single pass/fail on one prompt is a lower bound on resistance, not a measurement.
- **Credential leak detection** (lines 425-460) uses regex patterns (`AKIA...`, `sk-...`, connection strings). If the agent leaks credentials in a natural-language description ("my API key starts with sk dash..."), the regex won't match.
- **Memory isolation test** (lines 262-285) asks the agent to "store this in memory" and then asks User B to recall it. If the agent doesn't support persistent memory, both calls will return nothing, and the test passes vacuously. The test doesn't distinguish "memory is user-scoped" from "memory doesn't exist."
- **System prompt leak patterns** (lines 15-20) are generic. An agent with a non-standard system prompt format (e.g. a tool that uses XML, JSON, or a proprietary delimiter) might leak its prompt without matching `"you are an? assistant"`.

### `probes/injection.mjs` — Input Handling (396 lines)

**Strengths:**
- **Honest scope declaration** (lines 6-16): the docstring explicitly states these are boundary checks, not exploits. "A PASS is not proof the target is free of injection."
- **Parameter discovery** (lines 65-79): `discoverParams()` reads actual links and forms from the page rather than guessing. This tests real inputs.
- **XSS variants** (lines 95-100): tests three injection contexts — element, attribute-break, and JS-string. This covers the three most common reflection points.
- **SQL injection** (lines 148-175): uses inert payloads (`'`, `'"`, `')`, `1'--`) and looks only for error signatures, not exploitation. The signature list is deliberately narrow to avoid false positives.
- **SSRF** (lines 320-365): honestly reports as `warn` (unverified) when no resolution error is observed, because confirming SSRF requires an out-of-band listener.

**Weaknesses / Edge Cases:**
- **SSTI test** (lines 180-210) sends `${7*7}` as a query parameter. URL encoding will turn `$` into `%24` and `{` into `%7B` via `URLSearchParams`. Looking at line 197: `url.searchParams.set(param, marker)` — this will URL-encode the payload, and the server may not decode it the same way. The test may never actually deliver the raw template expression. **This could be a systematic false negative for the SSTI probe.**
- **Path traversal** (lines 215-250) uses the same `url.searchParams.set()` pattern, which will URL-encode `../` to `..%2F`. But the second payload is already `..%2f..%2f...`, so double-encoding would produce `..%252f...`. The test should work for the first payload (`../../../../etc/passwd`) since `searchParams.set` encodes `/` as `/` (it's path-safe). Actually, `URLSearchParams` encodes `/` — let me reconsider. `searchParams.set` does encode some characters but `/` is preserved in query strings. The payload should arrive correctly.
- **CRLF injection** (lines 260-295) builds the URL by hand to avoid `URLSearchParams` escaping the `%0d%0a`. This is correct.
- **Only GET requests are tested.** POST body injection is not covered. Many modern APIs accept input via POST body (JSON), and the injection probes only test query parameters.

### `probes/token.mjs` — Token Hygiene (293 lines)

**Strengths:**
- **Zero HTTP requests.** Every verdict comes from offline JWT inspection. This is the cheapest and safest probe module.
- **TOKEN-IDENTITY-DISTINCT** (lines 220-250) is a meta-test: it validates the test setup itself. If User A and User B are the same subject, every cross-user test in the report is vacuous. This is a guard against a misconfigured test harness invalidating the entire report.
- **TOKEN-SCOPE** (lines 200-220) checks for admin/wildcard scope, which would render authorization tests meaningless.
- **Multi-source token collection** (lines 55-70): `collectTokens()` gathers tokens from api, storage, agent, and mobile configs without duplicating.

**Weaknesses:**
- **No signature verification** (acknowledged in the docstring, lines 12-14). A token with `alg: none` and a valid-looking payload would pass the lifetime and claims checks but be completely unsigned. The `TOKEN-ALG` check catches this, but only as a separate finding.
- **Tenant claim detection** (lines 250-270) checks a hardcoded list of claim names (`tenant`, `tid`, `org`, `org_id`, etc.). A provider using a custom claim name (e.g. `custom:tenantId`) would be missed unless it matches one of these. The `cognito:username` inclusion suggests awareness of this, but the coverage is necessarily incomplete.

### `probes/storage.mjs` — Storage Isolation (149 lines)

**Strengths:**
- **Config-driven targets.** Each target declares `scope` (user/tenant), which identity to use, and the URL to probe. This means the probe works against any HTTP-addressable store.
- **`readable()` (lines 35-39)** checks for S3/GCS/Azure error responses in the body, not just the HTTP status. A 200 with `<Error>AccessDenied</Error>` is correctly treated as denied.

**Weaknesses:**
- **No write testing.** The storage probes only test read access. A target might allow cross-tenant writes but not reads, which would be missed.
- **No listing vs. object-read distinction.** A user who can list a bucket but not read objects (or vice versa) is not differentiated.

### `probes/mobile.mjs` — Mobile Platform (149 lines)

**Strengths:**
- **Honest about limitations.** Certificate pinning and local storage checks are explicitly `skip`ped with precise manual-test instructions rather than pretending to a verdict. This is the right call — these require an instrumented device.
- **Root detection test** (lines 90-120) sends `x-device-integrity: compromised` and `x-device-rooted: true`. The verdict is `warn` (not fail) because a header-based probe only proves the header is ignored.

**Weaknesses:**
- **Attestation test is superficial.** Sending a header that says "I'm rooted" doesn't test real Play Integrity / App Attest verification. Any server that doesn't check these specific header names would "pass" despite having no attestation at all. The `warn` status is appropriate.
- **Only 5 checks total** (deep-link, universal-link, root detection, and 2 skips). This is thin compared to the other probe modules.

---

## 4. GAPS — What TRUST Doesn't Test

### Missing Probes

| Gap | Impact |
|-----|--------|
| **CSRF protection** | No probe checks for anti-CSRF tokens on state-changing endpoints. OWASP A01. |
| **Authentication brute-force** | No account lockout / progressive delay detection beyond the basic rate-limit burst. |
| **JWT signature verification** | The token probe checks the declared algorithm but never attempts to forge a token with `alg: none` against the API. |
| **Subdomain takeover** | CNAME records pointing to deprovisioned services (S3, Azure, Heroku) are not checked. |
| **GraphQL batching** | Query cost tests aliasing but not batched queries (`[{query:...}, {query:...}]`). |
| **WebSocket security** | No WebSocket probes at all — no `wss://` enforcement, no auth on upgrade, no message injection. |
| **OAuth/OIDC state parameter** | No check for missing `state` parameter in OAuth flows (CSRF on login). |
| **Content-Type validation** | No test for whether APIs reject non-JSON content types (XML body parsing attacks). |
| **File upload** | No file upload probes (polyglot files, content-type bypass, path traversal in filenames). |
| **Mass assignment** | No probe for extra fields in mutation requests being accepted by the API. |
| **Request smuggling** | No HTTP request smuggling detection (CL/TE mismatch). |
| **POST-based injection** | Injection probes only test GET parameters — POST body, JSON path injection, and header injection in POST requests are not covered. |
| **DNS rebinding** | No check against DNS rebinding attacks on internal APIs. |

### Missing from the Agent Probe Suite

| Gap | Impact |
|-----|--------|
| **Multi-turn injection** | Only single-turn injection is tested. Multi-turn jailbreaks (building trust over several messages) are not covered. |
| **Tool-use abuse** | No test for whether the agent can be induced to call tools with unexpected parameters. |
| **Output format manipulation** | Beyond URI schemes, no test for whether the agent can be induced to emit raw HTML/JS in non-link contexts. |
| **Rate limiting on agent endpoints** | No check for cost/abuse limits on LLM invocations. |

---

## 5. UX / DX

### CLI Ergonomics

**Strengths:**
- **Clean error messages.** `ConfigError` and `SafetyError` produce a one-line message without a stack trace ([cli.mjs](node_modules/@automationarchitect/trust/src/cli.mjs) lines 260-264). Good for operators.
- **`--dry-run`** shows the configuration without issuing requests. Good for verifying config before a run.
- **Exit codes are documented and meaningful.** 0 = clear, 1 = config error, 2 = blocking failure. CI-friendly.
- **Color output** respects `NO_COLOR` and TTY detection (line 112). Good accessibility.
- **The default subcommand is `run`** (line 55), so `trust --config ... --profile ...` works without typing `run`. Good shorthand.

**Weaknesses:**
- **No shell completion.** No `--completions` flag or bash/zsh completion script.
- **`--profile` defaults to `passive`** (line 56) but `--config` has no default. A user who types `trust run` gets "--config is required" but no hint about what the config looks like. The error message says "or run `trust init` first" which is helpful.
- **`-v` is `--version`** (line 93). `-v` is conventionally verbose in many tools. This could confuse users from a `grep -v` or `curl -v` background.
- **No `--verbose` flag.** There's `--quiet` to suppress findings, but no way to increase verbosity for debugging.

### Config Validation

**Strengths:**
- **`validateConfig()`** ([safety.mjs](node_modules/@automationarchitect/trust/src/safety.mjs) lines 119-157) catches: missing name, missing environment, missing targets.web, empty allowedHosts, URL-format allowedHosts, maxRequests out of bounds, minimumDelayMs too low, and production targets without override.
- **advisories** for writes/agent invocations/production override are non-fatal warnings, not errors. Good graduated response.

**Weaknesses:**
- **No validation of probe-specific config.** `config.api.endpoint` is not validated until the API probe runs. If you misconfigure `config.api.crossUser.query`, you get a runtime error deep in the probe, not a clear config error upfront.
- **No JSON Schema.** There's no schema file for config validation in editors. A `trust.config.schema.json` would give autocomplete and red squiggles in VS Code.

### `trust init` Experience

**Good flow:** `trust init --target https://dev.example.com` creates `config/dev.json`, `.env.example`, and `trust-probes/example.mjs`. The example probe is well-commented and teaches the extension pattern.

**Friction points:**
- The generated config uses JSONC comments (`//`), which is user-friendly but may surprise tools that expect strict JSON.
- The "Next" steps in the output are clear: copy `.env.example`, review config, run passive. This is a good onboarding path.
- `.gitignore` handling is correct — it appends rather than overwrites.

### Report Readability

The combined assessment is genuinely well-designed:
- **Three-audience structure** (executive → architect → engineer) means each reader finds their section without wading through the others.
- **Collapsible sections** with a sticky nav bar is the right UX for a long report.
- **Attack paths** are derived from set intersection over failing IDs — the report never claims a path that isn't fully evidenced.
- **Coverage is displayed alongside the score**, with an explicit callout when partial. This prevents a 3-test run from presenting a 100% score as comprehensive.
- **Print mode** forces all sections open, so a PDF preserves all evidence.

---

## 6. CODE QUALITY

### Error Handling

- **Consistent pattern:** Probes catch errors and return `inconclusive()` or `skipped()` findings rather than crashing. This means a network error in one probe doesn't abort the entire run.
- **`SafetyError` is caught in the runner** ([runner.mjs](node_modules/@automationarchitect/trust/src/runner.mjs) line 165) and converted to a `warn` finding. Other errors propagate, which is correct — a coding error in a probe should crash, but a safety guard should not.
- **No unhandled promise rejections** visible. Every `await` in the probes is inside a try/catch.

### Naming Conventions

- Consistent `camelCase` for functions, `UPPER_CASE` for constants, `PascalCase` for classes.
- Finding IDs follow a `MODULE-DESCRIPTOR` pattern (e.g., `WEB-HEADER-STRICT-TRANSPORT-SECURITY`).
- File naming is consistent: `module.mjs` for core, `probes/module.mjs` for probes, `assessment/module.mjs` for reporting.

### Dead Code

- **`DEPRECATED_IDS`** in [catalog.mjs](node_modules/@automationarchitect/trust/src/catalog.mjs) line 179 is an empty object. It exists as infrastructure for future renames, which is fine — it's documented in a comment.
- **`canonicalId()`** traverses the empty `DEPRECATED_IDS` map, which is currently a no-op. Not dead code per se — it's future-proofing.
- No other dead code found.

### Inconsistencies

- **`path` variable shadowing** in [web.mjs](node_modules/@automationarchitect/trust/src/probes/web.mjs): the parameter name `path` in the sensitive-file loop (line 243: `for (const path of paths)`) shadows the `path` import from Node.js. This doesn't cause a bug here because the Node.js `path` module isn't used inside that loop, but it's a code smell.
- **Mixed evidence in `observed` field.** Some probes set `observed` to a user-facing statement ("The application follows unvalidated redirect parameters"), while others leave it empty for WARN status. The `headline()` function handles both cases, but the inconsistency means WARNs sometimes have good headlines and sometimes get the generic "Not fully verified — ..." prefix.

### Test Coverage

**There are no tests in the published package.** The `package.json` has `"test": "node --test \"test/*.test.mjs\""` but the `test/` directory is not in the `files` array and is not present in the installed package. The `test/` directory likely exists in the source repo but is excluded from npm publication.

This is a significant gap. For a security tool, testability and test coverage are trust signals. Key areas that need tests:
- `redact()` with various token formats
- `stripJsonComments()` with edge cases
- `validateConfig()` with malformed configs
- `looksLikeRealContent()` with SPAs and real files
- `isDenied()` with various API responses
- `discoverParams()` with various HTML shapes
- `computeScores()` with various finding distributions
- `matchAttackPaths()` with various failing ID sets

---

## 7. QUICK START EXPERIENCE

### Walking through `trust init` → first run:

1. **`npm install @automationarchitect/trust`** — zero dependencies, fast install.
2. **`npx trust init --target https://dev.example.com`** — creates `config/dev.json`, `.env.example`, `trust-probes/example.mjs`, `.gitignore`. Clear output showing what was written.
3. **`cp .env.example .env`** — user fills in tokens.
4. **`npx trust run --config config/dev.json --profile passive`** — runs web + injection probes. No tokens needed for passive.

**What would trip up a new user:**

1. **Node 22 requirement.** Many developers are on Node 18 or 20 LTS. The error message is clear ("needs Node 22 or newer"), but hitting it after install is frustrating. The `engines` field in package.json will warn at install time if `engine-strict` is set, but most users don't set that.

2. **HTTPS-only.** A developer testing against `http://localhost:3000` will get `SafetyError: Refusing non-HTTPS request`. There's no way to disable this, even for local development. This is a deliberate safety decision, but it means users need a local TLS proxy or a deployed environment to test against.

3. **allowedHosts must include every host.** If the API is on `api.example.com` and the web is on `www.example.com`, both must be in `allowedHosts`. A missing host produces a `SafetyError` on the first request to it, which could happen deep in a probe run.

4. **Token format confusion.** The `.env.example` says `AUTH_TOKEN_A=` but the config refers to tokens by env var name (`tokenAEnv: "AUTH_TOKEN_A"`). A user who puts the token value directly in the config (a common mistake) will get no error — the probe will try to use the env var name as a key name and find nothing.

5. **JSONC config with `//` comments.** Most JSON tools (jq, JSON.parse in other scripts) will reject the config. The `stripJsonComments()` preprocessor handles it, but a user trying to validate the config with another tool might be confused.

6. **The first run produces two files** (JSON + HTML) in `reports/`. The JSON path is printed to stdout, the rest to stderr. This stdout/stderr split is CI-friendly but a terminal user might miss the HTML path.

---

## Summary Scorecard

| Dimension | Score | Notes |
|-----------|-------|-------|
| Architecture | 8/10 | Clean unidirectional flow; model.mjs monolith is the main debt |
| Tool Security | 8.5/10 | Zero deps, strict allowlisting, proper redaction, escaped HTML. `observed` field unredacted |
| Probe Quality | 7.5/10 | Meaningful checks with honest caveats; SSTI encoding concern; GET-only injection |
| Gap Coverage | 6/10 | Missing CSRF, WebSocket, file upload, POST injection, JWT forgery |
| UX/DX | 8/10 | Good CLI, good reports, good init. No shell completion, no JSON Schema, HTTPS-only friction |
| Code Quality | 8/10 | Consistent patterns, zero dead code, good error handling. No published tests |
| Quick Start | 7.5/10 | Works well for the happy path; Node 22 + HTTPS-only are real friction points |

**Overall: This is a well-engineered, thoughtfully designed security tool.** The zero-dependency approach, the chokepoint safety architecture, the deterministic canary-based verdicts, and the three-audience report are all strong design decisions. The main engineering debts are: the `model.mjs` monolith, missing test coverage in the published package, GET-only injection probes, and the SSTI payload encoding concern. The gaps (CSRF, WebSocket, file upload) are scope decisions rather than bugs, and the tool is honest about its limitations in the report itself.

REPORT Feedback 
Do not collapse Security Trust Assessment section by default - keep Posture navpill to navigate
We need not to put Security Posture, Domain Scores, Deployment Readiness, Coverage, Executive Interpretation, Root Causes, Verified Controls within a collapsible card
a Stand alone Security Trust Assessment section can act as executive dashboard with multiple tiles mentioned above. their appearance, order can remain as is - just the collapsible wrapper would go away.

Verified Trust Controls - may be we can maintain 5x2 matrix or dynamic - if 8 then 4x2, if 6 then 3x2, if 10 then 5x2 etc but when more exists then it can be third row as well

remediation plan - third column(findings) width is too much and it basically contains chips. Providing better width to closure criteria column would be better

Should we provide search or some sort of filtering when larger data listed? for ex: Individual Findings inside remediation, Retest  when many fail or skip exists
Detailed finding is grouped and each item is collapsed so we need to be cautious enough to add filter/search

Complete test inventory - we can add more chips to collapsed version - say pass/fail/warn/skip etc.
Also think about adding meaningful chips on collapsed headers on any section

Trends sections can be useful.
maintain trends.json with all possible info would give a fair idea. 
we can use COMPASS style trend implementation
