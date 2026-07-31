# TRUST

**T**rust **R**eporting & **U**nified **S**ecurity **T**esting — a security verification platform for web, API, storage, AI-agent and mobile targets.

TRUST turns a target into a **Trust Assessment**: a posture score, a deployment-readiness verdict, architectural root causes, and per-finding evidence with remediation.

```bash
npx trust-verify init --target https://dev.example.com      # scaffold config + .env template
trust preflight --config config/dev.json                    # will this run work? (seconds, no probing)
trust run       --config config/dev.json --profile passive  # probe, write JSON + HTML
trust report    --dir reports                               # merge into one Trust Assessment
```

## Install

```bash
npm i -D trust-verify        # in the repo whose target you are testing
npx trust-verify init --target https://dev.example.com
```

Nothing is compiled and there is no install script, so `npm ci --ignore-scripts` works.

Releases are published from CI via [npm trusted publishing](https://docs.npmjs.com/trusted-publishers),
so no long-lived token exists anywhere, and they carry a provenance attestation you can verify
with `npm audit signatures`. Where a release was published by hand instead — because a trusted
publisher cannot be attached to a package that does not yet exist, or was not yet configured —
the changelog says so for that version, and `npm audit signatures` will report no attestation.
Check it rather than taking this paragraph's word for it.

Airgapped partners can install the checksummed tarball attached to each release:
`npm i ./trust-verify-1.5.0.tgz`.

### Commands

| Command | Purpose |
|---|---|
| `trust init --target <url>` | Scaffold `config/<env>.json`, `.env.example`, an example org probe, `.gitignore` entries |
| `trust run --config <path> --profile <name>` | Run a profile; exit 2 on a blocking failure |
| `trust report --dir reports` | Merge the latest run per profile into one Trust Assessment |
| `trust preflight --config <path>` | Check the run will work before it spends the budget: config, allowlist coverage, tokens, budget, reachability |
| `trust validate --config <path>` | Config and allowlist checks only — no network, no tokens, safe against a production config |
| `trust tokens --config <path>` | Acquire every declared auth strategy once and write the tokens to a 0600 file, so a CI job signs in once |
| `trust baseline --dir reports` | Record today's findings as accepted, so the gate means "nothing got worse" |
| `trust catalog [--json]` | List every test with its category and trust domain |

### As a library

`runProfile()` never writes to the console and never calls `process.exit`, so it embeds cleanly in an existing harness:

```js
import { loadConfig, runProfile, writeCombinedReport } from "trust-verify";

const config = await loadConfig("config/dev.json");
for (const profile of ["passive", "authenticated"]) {
  const { summary, findings } = await runProfile({
    config,
    profile,
    out: "reports",
    onEvent: (e) => e.type === "finding" && myLogger.info(e.finding),
  });
  await pushToDashboard(findings);       // report JSON is the integration surface
}
const { outPath } = await writeCombinedReport({ dir: "reports" });
```

### Org-specific probes, without forking

Partners add their own tests by pointing config at a probe module — resolved relative to the config file:

```jsonc
{ "probes": ["./trust-probes/acme.mjs"] }
```

```js
import { defineProbe, finding, skipped } from "trust-verify";

export default defineProbe({
  name: "acme-sso",
  profiles: ["authenticated"],
  // Ships its own metadata, so these findings score, group and get a root cause
  // exactly like built-in ones.
  catalog: { "ACME-SSO-CLOCK-SKEW": { category: "Authentication", purpose: "Verify the assertion window rejects a skewed clock." } },
  async run(config, client) {
    if (!config.acme?.metadataUrl) return [skipped("ACME-SSO-CLOCK-SKEW", "Assertion window", "acme.metadataUrl not configured")];
    /* … */
  },
});
```

`registerDomains()`, `registerRootCauses()` and `registerSummaryRules()` are available for tests that describe a new architectural area. `trust init` writes a working example probe to start from.

---

## Design guarantees

| Guarantee | How it is enforced |
|---|---|
| **Zero dependencies** | Node ≥ 22 standard library only — `fetch`, `node:tls`, `node:crypto`, `node:test`, `--env-file`. No install step, nothing to audit. |
| **Deterministic verdicts** | Every test returns PASS / FAIL / WARN / SKIP from a pattern match on status codes, headers or bodies. No model judges a result. |
| **Evidence-backed findings** | Every finding carries purpose, evidence and remediation. No finding without proof. |
| **Incapable of harm** | All traffic passes through `SafeHttpClient`: HTTPS-only, host allowlist, hard request cap, delay floor, timeouts, manual redirects, production block, write guard, agent-invocation guard. |
| **Redaction by default** | JWTs, bearer tokens, cloud keys, connection strings, signed-URL signatures, PEM blocks and `KEY=value` secrets are stripped before evidence reaches disk. |
| **A skip is never a pass** | Missing credentials and unmet preconditions produce SKIP, are excluded from scoring, and are listed under Retest Requirements. A sweep that could not finish reports how far it got: nothing performed is a skip, a partial sweep is a warning, and only a complete sweep can pass. |
| **Credentials are acquired, never printed** | `auth.strategies` signs in through the same guarded client, so an IdP host must be allowlisted like any other. Config stores env var *names*; the console, the run JSON and the exports carry names, kinds and expiry — never a token. |
| **Nothing routes around a guard** | A SigV4 signature is computed inside `request()`, after every check has passed. A mutation expected to be refused runs under its own switch (`allowDenialTests`) rather than by enabling writes. |

---

## Layout

```
trust/
├── config/
│   ├── dev.json              worked example — every probe section documented
│   └── minimal.json          passive-only, no credentials required
├── src/
│   ├── index.mjs             public API — everything partners may import
│   ├── cli.mjs               init / run / report / preflight / tokens / baseline / catalog
│   ├── runner.mjs            runProfile(), defineProbe(), custom probe loading
│   ├── init.mjs              scaffolding written by `trust init`
│   ├── env.mjs               .env loading for the CLI (never for the library)
│   ├── safety.mjs            SafeHttpClient + config validation
│   ├── preflight.mjs         `trust preflight` / `trust validate` checks
│   ├── config.mjs            section aliases, `extends`, request budgets
│   ├── auth/                 declarative strategies: SRP, OAuth2 grants, SigV4 signing
│   ├── chain.mjs             dependsOn / condition — conditional execution
│   ├── baseline.mjs          accepted findings, and what changed against them
│   ├── export/               SARIF 2.1.0, JUnit XML, stable finding identity
│   ├── finding.mjs           finding() factory, redact(), canary(), headline()
│   ├── catalog.mjs           test metadata, domains, root causes, attack paths  ← source of truth
│   ├── report.mjs            per-run JSON + standalone HTML + surface derivation
│   ├── assessment/           the Trust Assessment: model, theme, client, sections/×8
│   └── probes/
│       ├── token.mjs         offline JWT claim hygiene — issues no requests
│       ├── web.mjs           headers, TLS, cookies, CORS, methods, exposure, SRI, caching
│       ├── injection.mjs     XSS, SQL error, SSTI, traversal, CRLF, host header, SSRF
│       ├── api.mjs           cross-user, scoping, RBAC, identity, inventory, query cost, session
│       ├── storage.mjs       object-store isolation, public access
│       ├── idp.mjs           OIDC discovery, PKCE, implicit flow, native password grant
│       ├── isolation.mjs     declared authorisation boundaries — five types, config-driven
│       ├── agent.mjs         AI runtime: hierarchy, sessions, memory, injection, disclosure
│       └── mobile.mjs        deep links, app-site association, attestation
├── scripts/
│   ├── preflight.mjs         publish gate: no deps, no install scripts, no secrets shipped
│   └── combined-report.mjs   deprecated shim → `trust report`
├── test/                     181 tests over safety, auth, config, isolation, export, probes
└── reports/                  generated output (gitignored)
```

---

## Profiles

| Profile | Auth needed | Modules |
|---|---|---|
| `passive` | none | web, idp, injection |
| `authenticated` | identity tokens (two users) | token, api, storage, isolation |
| `agent` | bearer tokens + `allowAgentInvocations` | token, agent |
| `mobile` | optional | mobile |
| `all` | all tokens | every module |

`token` probes issue **no HTTP requests** — they inspect the claims of the tokens you supply, so they cost nothing and cannot touch the target.

---

## Configuration

Config drives everything. **It stores env var *names*, never secret values** — secrets live in `.env` (gitignored; see `.env.example`).

`trust run` and `trust report` load `.env` from the working directory automatically. Real environment variables always win, so CI secrets are never shadowed by a stale local file. Override the path with `--env-file <path>`, or disable with `--no-env`.

```jsonc
{
  "name": "example-app-dev",
  "environment": "dev",                  // prod|production|live is refused
  "targets": {
    "web": "https://dev.example.com",
    "allowedHosts": ["dev.example.com", "api.dev.example.com"]
  },
  "safety": {
    "maxRequests": 120,                  // hard cap; blocked requests do not consume it
    "minimumDelayMs": 150,               // floor between requests (min 50)
    "requestTimeoutMs": 30000,
    "allowWrites": false,                // PUT/PATCH/DELETE and write-marked POSTs
    "allowAgentInvocations": false,      // live LLM calls
    "productionOverride": false          // requires written authorisation
  },
  "api": { "endpoint": "…", "tokenAEnv": "AUTH_TOKEN_A", "tokenBEnv": "AUTH_TOKEN_B", /* probe specs */ },
  "storage": { "baseUrl": "…", "targets": [ /* who accesses whose prefix */ ] },
  "agent": { "runtimeEndpoint": "…", "allowedAgentId": "…", "subAgents": [ … ] }
}
```

Probe bodies (GraphQL queries, REST paths, spoofed identifiers, storage keys) are **declared in config**, so pointing TRUST at a new target is configuration, not code. See [config/dev.json](config/dev.json) for a fully annotated example. Comments are permitted in config files.

Validate before you run — `--dry-run` checks the config and prints the plan without issuing a request:

```
node src/cli.mjs --config config/dev.json --profile all --dry-run
```

---

### Config resolution

Sections resolve through conventional spellings, so an application that already calls its
API section `graphql` or `appSync`, or its agent section `agentCore` or `bedrock`, does not
have to duplicate the same endpoint under a second key:

| Canonical | Also accepted as |
|---|---|
| `api` | `graphql`, `appSync`, `rest`, `backend` |
| `agent` | `agentCore`, `bedrock`, `llm`, `aiAgent` |
| `storage` | `s3`, `objectStore`, `blob`, `bucket` |
| `mobile` | `app`, `device` |

An explicit canonical key always wins, and the run records which key each section resolved
from, so resolution is visible rather than guessed.

Environments inherit. A child overrides only what differs, and arrays replace rather than
merge — so a child can *narrow* an allowlist, never silently widen it:

```jsonc
{ "extends": "./base.json", "environment": "uat", "safety": { "maxRequests": 250 } }
```

### Request budgets

`safety.maxRequests` takes a number, or a map keyed by profile. `safety.budgets` optionally
caps individual suites, which stops a long web sweep exhausting the run before the storage
and agent probes execute:

```jsonc
"safety": {
  "maxRequests": { "passive": 100, "authenticated": 150, "agent": 200, "default": 120 },
  "budgets": { "web": 50, "injection": 25, "api": 20 }
}
```

Spend is recorded per suite in the run JSON, and an exhausted budget names the suite that
consumed it. A sweep that could not complete reports what it managed — no checks performed
is a **skip**, a partial sweep is a **warning** that says how far it got, and only a complete
sweep can pass.

### Testing that a mutation is refused

`safety.allowDenialTests` permits a mutation that is *expected to be denied*, without
enabling writes generally. Proving a permission mutation is rejected previously required
turning on every destructive path in the harness. If the target accepts the request, that
acceptance is the finding.
### Authentication

Real deployments do not keep a bearer token in `.env`; they sign in against an IdP, exchange
the result for scoped credentials, and sign the request. TRUST declares that in config and
resolves it once, before any probe runs:

```jsonc
"auth": {
  "strategies": {
    "userA": { "type": "cognito-srp", "region": "us-east-1", "userPoolId": "us-east-1_AbC123",
               "clientId": "…", "username": "a@example.com", "passwordEnv": "USER_A_PASSWORD" },
    "userB": { "type": "cognito-srp", "…": "…", "username": "b@example.com", "passwordEnv": "USER_B_PASSWORD" },
    "signed": { "type": "cognito-identity-pool", "region": "us-east-1", "identityPoolId": "…",
                "providerName": "cognito-idp.us-east-1.amazonaws.com/us-east-1_AbC123",
                "idTokenFrom": "userA", "service": "execute-api" }
  }
},
"api": { "endpoint": "https://api.dev.example.com/graphql", "tokenA": "userA", "tokenB": "userB" }
```

| Strategy | What it does |
|---|---|
| `static` | Today's behaviour, named — a bearer token from an env var |
| `cognito-srp` | Cognito `USER_SRP_AUTH`. SRP, so no plaintext-password grant has to be enabled on the pool to be assessed |
| `cognito-identity-pool` | Exchanges an ID token for temporary AWS credentials, then signs |
| `okta-ropc` | Okta resource-owner password grant |
| `client-credentials` | OAuth2 machine-to-machine — the grant CI can always use |
| `sigv4` | AWS SigV4 from keys in the environment |

Three properties hold for every strategy, and they are the reason this is worth having in the
tool rather than in a shell script around it:

- **Nothing weakens `SafeHttpClient`.** Acquisition goes *through* the guarded client, so an IdP
  host must appear in `targets.allowedHosts` like any other host, and a SigV4 signature is
  computed inside `request()` on a URL the guards have already approved.
- **Config still stores names, never secrets.** `passwordEnv`, `clientSecretEnv` and
  `accessKeyIdEnv` name environment variables. Nothing prints a token: the run report and the
  console carry strategy names, kinds and expiry.
- **A missing input is a precise skip.** "`USER_A_PASSWORD` is not set in the environment"
  rather than a failed login that reads like a finding about the target. `trust preflight`
  reports the same thing without signing in at all — a check that costs a login is a check
  teams stop running.

A long run outlives a short-lived token, so a 401 triggers **one** refresh and a retry. A second
401 is believed and reported: after that it is a statement about the target, not the harness.

For CI, acquire once and share:

```bash
trust tokens --config config/dev.json --out .trust-credentials.env   # 0600, tokens never printed
trust run --dotenv .trust-credentials.env --config config/dev.json --profile authenticated
```

## Probe catalog

**Web / infrastructure** (passive) — HSTS, CSP (with weak-directive detection), X-Content-Type-Options, Referrer-Policy, Permissions-Policy, clickjacking, frame-ancestors allowlist, cookie flags, token-in-web-storage, source maps, sensitive-file exposure (with SPA-fallback discrimination), CORS reflection, open redirect, rate limiting, TLS version, certificate validity.

**API / authorisation** (authenticated) — cross-user record read, owner-scoped lists, permission-mutation RBAC, client-supplied identity, GraphQL introspection, error disclosure, native password-grant availability, plus arbitrary `extraChecks` per endpoint.

**Storage** — anonymous listing/read, cross-tenant prefix access, cross-user object access, from both directions when two identities are supplied.

**AI agent** — unauthorised agent target, identity spoofing, direct and indirect prompt injection, dangerous URI output, cross-session inheritance, memory isolation, sub-agent hierarchy bypass, and — *conditionally, only when the hierarchy is breached* — sub-agent ACL and guardrail bypass. Then system-prompt, credential and tool-schema disclosure.

**Mobile** — deep-link destination validation, app-site association files, device-attestation enforcement. Certificate pinning and sandbox storage SKIP with the exact manual procedure, because a network harness cannot verify them.

**Identity provider** (passive) — discovery document, PKCE with S256, implicit flow still advertised, an unauthenticated token endpoint uncompensated by PKCE, what the application's own authorisation request asks for, and a Cognito user pool still accepting `USER_PASSWORD_AUTH`. Session fixation and the post-callback verifier cookie SKIP with the manual procedure, for the same reason.

**Declared boundaries** — whatever `config.isolation` states: record ownership, storage prefixes, enumeration, privileged mutations and client-supplied identity. These are the tests a team writes about its own data model, without writing code.

Injection and leak tests use the **canary technique**: plant a unique UUID, assert on its absence. No interpretation, no false confidence.

---

## Reports

Each run writes `reports/<name>-<profile>-<timestamp>.json` (machine-readable, the artefact CI keeps) and a matching standalone HTML view.

`trust report` merges the latest run per profile into one Trust Assessment:

```
1. Posture score (0–100)      severity-weighted: critical 10, high 5, medium 3, low 1, info 0.5
2. Deployment readiness       Ready / Caution / Not Ready
3. Domain cards               worst-first, so a strong composite cannot hide a weak domain
4. Impact summary             blockers / high priority / config improvements / controls validated
5. Executive interpretation   what failed, in prose, grouped by category
6. Root causes                architectural observations, not a fix list
7. Verified trust controls    grouped and summarised — families collapse into one statement
8. Detailed findings          purpose, evidence, remediation; failures expanded by default
9. Remediation plan + retest + searchable inventory + methodology
```

Adding a test means adding **one entry to `src/catalog.mjs`** — category, domain, root cause, scoring and every report section follow automatically.

The same JSON is the integration surface: `--sarif` and `--junit` translate it for a security
dashboard and a CI test view, and `--baseline` compares it with what a team has already
accepted. See [CI/CD](#cicd).



## Declaring what to test

Four things are stated in config rather than written as code. Each is a config section,
each degrades to a precise skip when its inputs are missing, and each is covered in full by
[trust.config.schema.json](trust.config.schema.json) — which your editor will read.

### Declared isolation boundaries

Most real security bugs are authorisation failures, and the test never changes shape: act as A,
act as B against A's resource, ask whether it was refused. Declaring the boundary is enough —
TRUST supplies the test, the verdict and the report entry:

```jsonc
"isolation": [
  { "id": "API-CROSS-USER-RECORD", "type": "record-ownership",
    "description": "User B cannot read User A's record",
    "endpoint": "https://api.dev.example.com/graphql",
    "queryA": "query { listMyRecords(limit: 1) { items { id } } }",
    "queryB": "query($id: ID!) { getRecord(id: $id) { id owner } }",
    "tokenA": "userA", "tokenB": "userB", "severity": "high" }
]
```

| Type | What it does | Identities |
|---|---|---|
| `record-ownership` | Discovers a record as A, requests it as B | two |
| `prefix-scoped-storage` | Lists and reads another tenant's object prefix | two |
| `enumeration` | Checks a list endpoint returns only the caller's own records | one |
| `mutation-guard` | Attempts a privileged mutation, expecting refusal | one |
| `identity-injection` | Sends a client-supplied identity field, expecting it to be ignored | one |

The record ID is discovered rather than pinned in config, so a declared boundary survives a data
reseed. A boundary needing two identities **skips** when only one is available rather than
reporting a pass it did not earn, and an ambiguous response is a warning that says what was
ambiguous — add `denialPatterns` for how your API phrases a refusal and the verdict sharpens.
`mutation-guard` runs under `safety.allowDenialTests`, because a control that holds writes
nothing.

### Conditional execution

A downstream test often only means something if an upstream boundary broke. Declare that, and
the chain does two useful things — it saves the request, and it turns a skip into a statement
about the system:

```jsonc
{ "id": "ACL-BYPASS", "dependsOn": "AGENT-ENDPOINT-COORDINATOR", "condition": "failed" }
```

```
AGENT-ENDPOINT-COORDINATOR   FAIL  An external token reaches coordinator directly
ACL-BYPASS                   FAIL  Reachable because AGENT-ENDPOINT-COORDINATOR failed.

AGENT-ENDPOINT-EXECUTOR      PASS  An external token cannot reach executor
ACL-BYPASS-EXECUTOR          SKIP  Not reachable — upstream control held (…-EXECUTOR passed)
```

`condition` is `failed` (the default), `passed` or `any`. Dependencies may point at any finding
in the run, including one from a different probe module, and a `dependsOn` naming a test that
never ran is reported rather than silently satisfying the gate. `trust preflight` catches that
before the run.

### Agent tiers

An agent hierarchy is a list of endpoints with expectations, not a topology language:

```jsonc
"agent": {
  "runtimeEndpoint": "https://agents.dev.example.com/invoke",
  "accessTokenA": "userA",
  "endpoints": [
    { "name": "coordinator", "agentId": "coord-a", "expectDenied": true },
    { "name": "coordinator-acl", "agentId": "coord-a", "expectDenied": false,
      "expectPatterns": ["ACCESS-DENIED"], "dependsOn": "AGENT-ENDPOINT-COORDINATOR" }
  ]
}
```

An internal tier that accepts an end-user token has no boundary of its own — whatever the
orchestrator enforces can be walked around by calling it directly, which is why `expectDenied`
defaults to true and its failure is critical.

### Identity provider posture

The `idp` section checks the provider itself, unauthenticated: the discovery document, PKCE with
S256, whether the implicit flow is still advertised, whether an unauthenticated token endpoint is
compensated by PKCE, what the application's *own* authorisation request asks for, and whether a
Cognito user pool still accepts `USER_PASSWORD_AUTH` — which bypasses federated sign-in and
everything attached to it, including MFA. Checks that genuinely need a browser (session fixation
across a real login, the code-verifier cookie after callback) are reported as skips carrying the
manual procedure rather than guessed at.

## CI/CD

Exit codes: `0` clear (or low/info only) · `1` config or safety error, nothing tested · `2` critical/high/medium failure — fail the pipeline.

### A pipeline, end to end

```yaml
# Cheap checks first: preflight fails in seconds on an expired token, an unlisted host or a
# budget too small for the profile — rather than after half an hour of probing that produces
# a wall of skips reading like findings about the target.
- run: npx trust preflight --config config/$ENV.json --profile all

# Acquire once, so the pipeline does not sign in per step and trip the IdP's rate limit.
- run: npx trust tokens --config config/$ENV.json --out .trust-credentials.env

- run: npx trust run --dotenv .trust-credentials.env --config config/$ENV.json --profile passive
- run: npx trust run --dotenv .trust-credentials.env --config config/$ENV.json --profile authenticated

# One assessment across every profile, plus the formats the rest of the pipeline reads.
- run: npx trust report --dir reports --sarif trust.sarif --junit trust-junit.xml
         --baseline .trust-baseline.json

- uses: github/codeql-action/upload-sarif@v3      # needs security-events: write
  with: { sarif_file: trust.sarif }
- uses: actions/upload-artifact@v4
  with: { name: trust-assessment, path: reports/ }
```

| Output | Where it lands |
|---|---|
| `--sarif <file>` | A security dashboard (GitHub's Security tab, and anything else that reads SARIF 2.1.0) |
| `--junit <file>` | The test-results view of any CI |
| `--baseline <file>` | Nothing new — it changes which findings may **block** the build |

SARIF carries the severity as `security-severity` **and** as `impactIfFailed`, and only failures
get a `level`: a passing CRITICAL control is normal in TRUST, and must not paint a dashboard
red. Results are anchored to the config file rather than to a fabricated source line, because an
invented file and line is a lie a reviewer would act on. Each result carries a stable
fingerprint — test plus target, never evidence — so a dashboard de-duplicates across runs
instead of re-raising everything each night.

JUnit renders a warning as a failure. JUnit has no third state, and the honest options are red
or invisible; invisible is worse for a control that could not be confirmed. The build gate is
the exit code, which distinguishes them properly.

### Baselines

A team adopting TRUST mid-life inherits findings it did not cause and cannot fix this week.
Without a baseline the choice is to fail every build until the backlog clears — which nobody
does — or to stop gating on the tool, which is the same as removing it.

```bash
trust baseline --dir reports --note "adopted at rollout"   # writes .trust-baseline.json
trust run --baseline .trust-baseline.json --config config/dev.json --profile authenticated
```

```
baseline: 1 new · 0 worsened · 12 known · 2 fixed
    new      critical API-USERID-SPOOF — Server derives identity from the token
    fixed    high     API-CROSS-USER   — User B cannot read User A's record
```

A baseline hides nothing: the report still shows everything, and only the exit code changes.
Fixed findings are reported as loudly as new ones, a warning that becomes a failure is
**worsened** rather than accepted, and a baselined finding whose profile did not run this time
is reported as absent rather than fixed — a gate that congratulates a team for skipping a
profile is worse than no gate. Commit the baseline file; it is a policy record, not a cache.

A ready-made GitHub Actions workflow is in [.github/workflows/trust.yml](.github/workflows/trust.yml).

### Trends and history

`trust report` records each run in `.trends/trends.json` and renders a Trends section once
there is more than one run: posture, coverage and blockers over time, per-domain movement,
and which controls were newly introduced, fixed or are still failing.

History is **state, not output**. It lives in `.trends/` rather than `reports/` because
reports are regenerated, published and wiped between runs — deleting `reports/` must not
destroy the series. Both directories are gitignored.

In CI the directory has to be restored before the run and persisted after it, or every run
looks like the first:

```yaml
- uses: actions/cache@v4        # simplest option
  with:
    path: .trends
    key: trust-trends-${{ github.ref_name }}-${{ github.run_id }}
    restore-keys: trust-trends-${{ github.ref_name }}-
```

For a shared store, sync it instead — the shape is the same:

```bash
aws s3 sync s3://bucket/trust-trends .trends   # before
trust run --config config/dev.json --profile all && trust report --dir reports
aws s3 sync .trends s3://bucket/trust-trends   # after
```


TRUST does not talk to object storage itself: that would mean shipping a cloud SDK and
holding bucket write credentials inside a zero-dependency security harness. Your pipeline
already has both. Use `--trends-dir <path>` or `TRUST_TRENDS_DIR` to point it elsewhere,
and `--no-trends` for a one-off report that must not touch history.

---

## Versioning

TRUST is consumed by other organisations' pipelines, and two things make its compatibility
surface wider than an ordinary library. **Finding IDs and severities are an API**: partners gate
CI on them (`exit 2`), chart them, and file tickets against them, so renaming an ID or promoting
a finding from medium to high silently changes someone's build outcome. **The run JSON is an
API**: dashboards parse `findings[].status`, `.severity`, `.domain` and the `summary` block. The
semver contract therefore covers the catalogue as well as the code.

| | What it covers |
|---|---|
| **Major** | Removing or renaming a finding ID (the old ID must also be added to `DEPRECATED_IDS`); raising a severity; changing verdict logic so a previously passing control now fails; removing or renaming a run-JSON field or a profile; removing a package export; raising the minimum Node version; changing scoring weights or readiness thresholds |
| **Minor** | New probes, catalogue entries, profiles, config keys with safe defaults, exports, report sections and extension points. A new test may of course fail — that is the point — but no existing verdict changes. Lowering a severity, or a verdict becoming *less* strict |
| **Patch** | Fixing a probe that produced a wrong verdict, documented in the changelog with the before and after; redaction improvements; evidence wording, report layout and styling; performance, error messages, docs |

An ID is never edited in place. It is aliased in `DEPRECATED_IDS`, both IDs resolve to the same
metadata, and the rename ships in a major — so a partner's dashboard keeps working across the
upgrade rather than silently losing a series.

## Extending

**A new built-in probe module** — write `src/probes/<surface>.mjs` exporting `async run…(config, client)` that returns findings, add it to `BUILTIN_PROBES` and a profile in [src/runner.mjs](src/runner.mjs), then add catalog entries. To extend TRUST from *outside* the package, use `defineProbe` and `config.probes` as shown above — no fork required.

Rules for probes: check prerequisites and SKIP (never crash) on missing config or tokens; use two identities for any isolation claim; use a canary for any leak claim; gate conditional probes on the prerequisite actually failing; never mutate data unless `allowWrites` is set, and clean up if you do.

## Tests

```
npm test        # node --test "test/*.test.mjs"
```

181 tests cover the safety guards (HTTPS-only, allowlist, per-run and per-suite caps, throttle, write/agent/denial guards, production block), the auth strategies (SigV4 against AWS's published test vector, the SRP group by its own defining property), config resolution and inheritance, declared isolation boundaries and conditional execution, the finding factory and every redaction rule, SARIF and JUnit output, baseline diffing, report construction, HTML escaping, scoring, domain ordering and catalogue integrity.

They are not shipped in the package — a partner installing TRUST should not pay for the test suite — so run them from a clone.

---

## Licence and authorisation

Licensed under [Apache-2.0](LICENSE) — see [NOTICE](NOTICE) for the attribution that must travel with redistributions. Before your first publish, set the copyright holder in `NOTICE`.

The licence governs copying and modification. It grants **no authorisation to test any particular system** — that is a separate question, covered by [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md). In short: run TRUST only against systems you have written permission to test, keep `targets.allowedHosts` identical to your agreed scope, and treat `safety.productionOverride` as requiring named authorisation rather than convenience. Production targets are refused without it, reports are written `0600`, and they are classified Internal — Security Sensitive.
