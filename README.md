# TRUST

**T**rust **R**eporting & **U**nified **S**ecurity **T**esting — a security verification platform for web, API, storage, AI-agent and mobile targets.

TRUST turns a target into a **Trust Assessment**: a posture score, a deployment-readiness verdict, architectural root causes, and per-finding evidence with remediation.

```bash
npx @automationarchitect/trust init --target https://dev.example.com   # scaffold config + .env template
trust run    --config config/dev.json --profile passive     # probe, write JSON + HTML
trust report --dir reports                                  # merge into one Trust Assessment
```

## Install

```bash
npm i -D @automationarchitect/trust        # in the repo whose target you are testing
npx @automationarchitect/trust init --target https://dev.example.com
```

Nothing is compiled and there is no install script, so `npm ci --ignore-scripts` works. Releases are published from CI via [npm trusted publishing](https://docs.npmjs.com/trusted-publishers) — no long-lived token exists anywhere — and carry a provenance attestation you can verify with `npm audit signatures`. Airgapped partners can install the checksummed tarball attached to each GitHub release: `npm i ./automationarchitect-trust-1.0.0.tgz`.

> **Before your first publish**, confirm the npm scope exists and you can publish to it (`npm org ls testautomationarchitect`). `scripts/preflight.mjs` refuses to publish a package that still carries a placeholder name, has gained a dependency, or would ship secrets.

### Commands

| Command | Purpose |
|---|---|
| `trust init --target <url>` | Scaffold `config/<env>.json`, `.env.example`, an example org probe, `.gitignore` entries |
| `trust run --config <path> --profile <name>` | Run a profile; exit 2 on a blocking failure |
| `trust report --dir reports` | Merge the latest run per profile into one Trust Assessment |
| `trust catalog [--json]` | List every test with its category and trust domain |

### As a library

`runProfile()` never writes to the console and never calls `process.exit`, so it embeds cleanly in an existing harness:

```js
import { loadConfig, runProfile, writeCombinedReport } from "@automationarchitect/trust";

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
import { defineProbe, finding, skipped } from "@automationarchitect/trust";

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
| **A skip is never a pass** | Missing credentials and unmet preconditions produce SKIP, are excluded from scoring, and are listed under Retest Requirements. |

---

## Layout

```
trust/
├── config/
│   ├── dev.json              worked example — every probe section documented
│   └── minimal.json          passive-only, no credentials required
├── src/
│   ├── index.mjs             public API — everything partners may import
│   ├── cli.mjs               init / run / report / catalog subcommands
│   ├── runner.mjs            runProfile(), defineProbe(), custom probe loading
│   ├── init.mjs              scaffolding written by `trust init`
│   ├── env.mjs               .env loading for the CLI (never for the library)
│   ├── safety.mjs            SafeHttpClient + config validation
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
│       ├── agent.mjs         AI runtime: hierarchy, sessions, memory, injection, disclosure
│       └── mobile.mjs        deep links, app-site association, attestation
├── scripts/
│   ├── preflight.mjs         publish gate: no deps, no install scripts, no secrets shipped
│   └── combined-report.mjs   deprecated shim → `trust report`
├── test/                     79 tests over safety, findings, reporting, packaging, probes
└── reports/                  generated output (gitignored)
```

---

## Profiles

| Profile | Auth needed | Modules |
|---|---|---|
| `passive` | none | web, injection |
| `authenticated` | identity tokens (two users) | token, api, storage |
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

## Probe catalog

**Web / infrastructure** (passive) — HSTS, CSP (with weak-directive detection), X-Content-Type-Options, Referrer-Policy, Permissions-Policy, clickjacking, frame-ancestors allowlist, cookie flags, token-in-web-storage, source maps, sensitive-file exposure (with SPA-fallback discrimination), CORS reflection, open redirect, rate limiting, TLS version, certificate validity.

**API / authorisation** (authenticated) — cross-user record read, owner-scoped lists, permission-mutation RBAC, client-supplied identity, GraphQL introspection, error disclosure, native password-grant availability, plus arbitrary `extraChecks` per endpoint.

**Storage** — anonymous listing/read, cross-tenant prefix access, cross-user object access, from both directions when two identities are supplied.

**AI agent** — unauthorised agent target, identity spoofing, direct and indirect prompt injection, dangerous URI output, cross-session inheritance, memory isolation, sub-agent hierarchy bypass, and — *conditionally, only when the hierarchy is breached* — sub-agent ACL and guardrail bypass. Then system-prompt, credential and tool-schema disclosure.

**Mobile** — deep-link destination validation, app-site association files, device-attestation enforcement. Certificate pinning and sandbox storage SKIP with the exact manual procedure, because a network harness cannot verify them.

Injection and leak tests use the **canary technique**: plant a unique UUID, assert on its absence. No interpretation, no false confidence.

---

## Reports

Each run writes `reports/<name>-<profile>-<timestamp>.json` (machine-readable, the artefact CI keeps) and a matching standalone HTML view.

`scripts/combined-report.mjs` merges the latest run per profile into one Trust Assessment:

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

---

## CI/CD

Exit codes: `0` clear (or low/info only) · `1` config or safety error, nothing tested · `2` critical/high/medium failure — fail the pipeline.

```yaml
- run: node --env-file=.env src/cli.mjs --config config/$ENV.json --profile passive
- run: node --env-file=.env src/cli.mjs --config config/$ENV.json --profile authenticated
- run: node scripts/combined-report.mjs --dir reports
  # publish reports/*.html and reports/*.json as artifacts
```

A ready-made GitHub Actions workflow is in [.github/workflows/trust.yml](.github/workflows/trust.yml).

---

## Versioning

Finding IDs and severities are a **public API** — partners gate CI on them and chart them. An ID is never edited in place; it is aliased in `DEPRECATED_IDS` and the rename ships in a major. Full contract, including what counts as a breaking verdict change, in [docs/VERSIONING.md](docs/VERSIONING.md).

## Extending

**A new built-in probe module** — write `src/probes/<surface>.mjs` exporting `async run…(config, client)` that returns findings, add it to `BUILTIN_PROBES` and a profile in [src/runner.mjs](src/runner.mjs), then add catalog entries. To extend TRUST from *outside* the package, use `defineProbe` and `config.probes` as shown above — no fork required.

Rules for probes: check prerequisites and SKIP (never crash) on missing config or tokens; use two identities for any isolation claim; use a canary for any leak claim; gate conditional probes on the prerequisite actually failing; never mutate data unless `allowWrites` is set, and clean up if you do.

## Tests

```
npm test        # node --test "test/*.test.mjs"
```

40 tests cover the safety guards (HTTPS-only, allowlist, cap, throttle, write/agent guards, production block), the finding factory and every redaction rule, report construction, HTML escaping, scoring, domain ordering and catalog integrity.

---

## Licence and authorisation

Licensed under [Apache-2.0](LICENSE) — see [NOTICE](NOTICE) for the attribution that must travel with redistributions. Before your first publish, set the copyright holder in `NOTICE`.

The licence governs copying and modification. It grants **no authorisation to test any particular system** — that is a separate question, covered by [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md). In short: run TRUST only against systems you have written permission to test, keep `targets.allowedHosts` identical to your agreed scope, and treat `safety.productionOverride` as requiring named authorisation rather than convenience. Production targets are refused without it, reports are written `0600`, and they are classified Internal — Security Sensitive.
