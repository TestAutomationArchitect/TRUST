# TRUST roadmap

Derived from two field-test documents — `Engineering_Review.md` (code review + report feedback)
and `Issues.md` (14 enhancement proposals from enterprise field usage) — triaged against what
the code actually does. Where a claim was checked, the evidence is recorded; where a claim did
not hold, that is recorded too, so it is not implemented later on trust.

Companion to [REVIEW-BACKLOG.md](REVIEW-BACKLOG.md), which covers report-semantics findings from
earlier review rounds. Items from that backlog are folded into the releases below.

---

## Verification log

Claims that changed after checking them against the code.

| Claim | Verdict | Evidence |
|---|---|---|
| **§14a** Combined report buckets custom findings into "Other"/"Platform" | **Confirmed — P0** | `report.mjs:89` writes `domain`/`category` into the run JSON at run time, but `model.mjs` (14 sites) and `scoring.mjs:15` re-derive from `getTestMeta(f.id)` at merge time, when custom catalogue entries are not loaded. |
| **§14h** `npx trust` is broken on Windows | **Not reproducible as stated** | `npx trust --version`, `npx trust run`, and `trust.cmd` all work in PowerShell and Git Bash (npm 11.12.1, Node 25). The real failure is narrower — see below. |
| **`--env-file` is intercepted** | **Confirmed — new finding** | `npx trust run --env-file .env …` and `--env-file=.env` both fail with `node: .env: not found`, in PowerShell *and* through `trust.cmd`. Node claims the flag before TRUST's parser sees it, so TRUST's own `--env-file` is unusable through the bin shim. This is almost certainly what the field team hit; their workaround (`node --env-file=.env …/cli.mjs`) is what you reach for when the flag "does not work". |
| **§Probe quality** SSTI payload may be mangled by `URLSearchParams` | **Not borne out** | The probe fired correctly against a deliberately vulnerable target: `FAIL critical INJECT-TEMPLATE`. Percent-encoding is decoded server-side, which is the normal path. Keep the test as-is; no change. |
| **§14e** `finding()` cannot carry `domain`/`category` | **Confirmed** | Signature at `finding.mjs:74` accepts neither. |
| **Redaction** `observed` is not redacted | **Confirmed** | `finding.mjs:89` passes `observed` through raw while `evidence` goes through `redact()`. |
| **Tests are absent from the published package** | **Confirmed, and intended** | `test/` is excluded from `files`. Shipping tests inflates every install. The fix is visibility (CI badge, coverage statement in README), not shipping them. |

---

## 1.0.1 — Correctness (ship first, days not weeks)

Everything here is a defect in shipped behaviour. No new capability.

| Item | Source | Notes |
|---|---|---|
| **Preserve `domain`/`category` recorded at run time** | §14a | `f.domain ?? domainForId(f.id)` and `f.category ?? getTestMeta(f.id).category` at every site in `model.mjs` and `scoring.mjs`. The report currently misrepresents where custom findings belong — a data-integrity bug, not cosmetics. |
| **`finding()` accepts `domain` and `category`** | §14e | Lets one probe emit findings in different domains, and makes §14a robust rather than incidental. |
| **Rename the env flag to `--env`** | new | Node claims `--env-file` before TRUST sees it through the bin shim. Keep accepting `--env-file` for the rare direct `node src/cli.mjs` invocation, and document `--env`. Note that `.env` is auto-loaded, so most users need neither. |
| **Redact `observed`** | Eng. review | Same treatment as `evidence`. A custom probe author will eventually put a response fragment there. |
| **Redaction patterns** | §8 | Azure SAS (`sig=`/`se=`/`sp=` anywhere, not only after `?`/`&`), GCP service-account `private_key`, Anthropic `sk-ant-`, HuggingFace `hf_`, Cohere. Trivial. |
| **Cognito password-grant corroboration** | §14f | Cognito's discovery document omits `grant_types_supported`, so a clearly-closed grant reports WARN. Treat `InvalidParameterException` from a Cognito user pool as a confirmed-closed signal, and document which IdPs yield clean PASS/FAIL. |
| **"Corroborated attack path" → "Correlated control-failure chain"** | backlog | Components are each proven; no run executes the chain end to end. Add: *"Each component weakness was independently confirmed. The complete chain was not executed end-to-end."* |
| **Coverage denominator scoped by configured surfaces** | backlog | An API-only target is currently penalised for unconfigured mobile/agent probes and under-reports coverage. Use `run.surfaces`. |
| **Domain glossary completeness** | backlog | `Assessment Integrity` and `Input Handling` appear on cards but are undefined. |
| **Category-aware root causes** | backlog | The only Infrastructure failure being error disclosure should not read "browser and transport hardening is incomplete". |
| **Score bands must not imply blockers** | backlog | Bands describe assessed-control performance; readiness is computed independently. |

---

## 1.1 — Report as an executive dashboard

Direct from the report feedback in `Engineering_Review.md`. All of it is agreed.

| Item | Detail |
|---|---|
| **Un-collapse the Trust Assessment section** | Posture, domain scores, readiness, coverage, executive interpretation, root causes and verified controls become a standalone dashboard — same content, same order, no collapsible wrapper. The Posture nav pill still scrolls to it. Everything below (Scope, Findings, Profiles, Remediation, Retest, Inventory, Definitions) stays collapsible. |
| **Verified controls as a responsive matrix** | Dynamic columns: 6 → 3×2, 8 → 4×2, 10 → 5×2, more → additional rows. CSS grid with `auto-fit` and a column cap, not hard-coded counts. |
| **Remediation column widths** | The Findings column holds chips and is over-wide; closure criteria is the column that needs room. Constrain chips, give the remainder to criteria. |
| **Search and filter for long lists** | Individual Findings (inside Remediation), Retest, and Detailed Findings. **Care needed**: Detailed Findings is grouped and collapsed, so filtering must operate on cards and hide empty category headers, not just table rows. Reuse the inventory's filter model. |
| **Richer chips on collapsed headers** | Inventory gains pass/fail/warn/skip counts; every collapsible header gains its most decision-relevant numbers. |
| **Trends** | Maintain `trends.json` across runs and add a trends section, COMPASS-style. This subsumes the backlog's run-over-run delta: newly introduced / fixed / still failing, posture over time, coverage over time. Needs a stable run identity — see evidence-chain metadata below. |
| **Evidence-chain metadata** | Run ID, start/finish with timezone, git SHA, TRUST version, catalogue version, config hash, previous run ID. Prerequisite for trends, and it is what makes a filed report defensible. |

---

## 1.2 — Config and scale (unblocks larger estates)

| Item | Source | Decision |
|---|---|---|
| **Config key fallbacks** | §14b | Take **Option C** — probes resolve `config.api ?? config.graphql ?? config.appSync`, `config.agent ?? config.agentCore ?? config.bedrock`. No `$ref` indirection, no new schema concept. A one-line resolver per probe suite, and the report records which key was used. |
| **Per-profile / per-suite request budgets** | §14d | Real: the field run needed ~120 requests against a cap of 100 and silently skipped storage and AI probes. Support `maxRequests: { passive: 100, authenticated: 150 }` **and** per-suite budgets, keeping the scalar form working. When a budget is exhausted, say which suite consumed it — a silent skip is the worst outcome. |
| **`allowDenialTests`** | §14c | Agreed and important. Testing that a mutation is *denied* should not require enabling writes globally. Gate: the probe must treat any 2xx as a **failure of the control**, and must never retry. |
| **Multi-environment config** | their "missing" list | Config inheritance: `extends: "./base.json"` with per-environment overrides. Prevents copy-paste drift across dev/staging. |
| **`trust preflight`** | §11 | Connectivity, token validity, allowlist coverage, config sanity — before spending the request budget. A weekend feature that saves every first run. |
| **Config JSON Schema** | Eng. review | `trust.config.schema.json` for editor autocomplete and validation, plus `trust validate`. |

---

## 1.3 — Auth strategies (the adoption blocker) — **done**

Both documents rank this first for enterprise adoption, and I agree: TRUST assumes a bearer token
in `.env`, while real deployments exchange an ID token for scoped credentials and sign requests.

| Item | Source | Decision |
|---|---|---|
| **Declarative auth strategies** | §1 | `auth.strategies` in config, resolved before probes run, producing named credentials probes reference. Start with `static` (today's behaviour), `cognito-srp`, `cognito-identity-pool`, `okta-ropc`, `client-credentials`. |
| **SigV4 signing** | §2 | Fold into §1 as a strategy rather than a separate feature, exactly as their own critique suggests. ~50 lines of `node:crypto`, no dependency. |
| **`trust tokens`** | §6 | Acquire and export/write credentials so CI runs unattended. Must never print a token to stdout by default. |
| **Token refresh mid-run** | §6 | Long agent runs outlive short-lived tokens. Refresh on 401 once, then fail honestly. |

**Constraint:** every strategy must degrade to `skipped()` with a precise reason when its inputs
are missing. No strategy may weaken `SafeHttpClient` — signing happens *inside* the guarded path,
never around it.

**As built.** `src/auth/` — `srp.mjs` (RFC 5054 over the 3072-bit MODP group, checked in the
tests as a safe prime rather than by eye), `sigv4.mjs` (verified against AWS's published
`get-vanilla` vector), `index.mjs` (strategies, resolution order, `credentialFor`/`authInit`).
Acquisition spends from the run budget under the `auth` suite and is visible in the run JSON as
names, kinds and expiry — never tokens. `trust preflight` checks strategies declaratively
without signing in; `trust tokens` performs the real acquisition. Deliberately not implemented:
MFA and forced-password-change challenges, which are reported as unautomatable rather than
worked around.

---

## 1.4 — Declarative isolation and chaining — **done**

| Item | Source | Decision |
|---|---|---|
| **Declarative isolation boundaries** | §3 | The highest-ROI feature in the document. Most real bugs are authorisation failures, and the pattern is universal: identity, resource, expectation. Making it config-driven moves TRUST from "tool for security engineers" to "tool for engineering teams". |
| **Conditional / chained execution** | §7 | `dependsOn` / `condition`. The agent probes already do this ad hoc (ACL and guardrail probes only run when the hierarchy is breached); generalise it. Feeds the correlated-chain narrative with *executed* chains — which is what would let the report legitimately upgrade that wording. |
| **Agent topology — simplified** | §4 | Build the simple form their own critique recommends: `endpoints[]` with `expectDenied: true`. Skip the topology DSL until someone has three tiers and asks for it. |
| **IdP misconfiguration probes** | §5 / §5b | Worth a probe pack. HTTP-observable only — anything needing a browser stays out. |

**As built.** `src/chain.mjs` (the gate), `src/probes/isolation.mjs` (five boundary types),
`src/probes/idp.mjs` (six checks plus two documented browser-only skips), and
`agent.endpoints[]`. Chains may cross probe modules: the runner now hands each probe what the
run has produced so far. Deliberately not implemented: the §3 `auth: "sigv4"` spec field, since
1.3 already resolves a credential by name and a second way to say it would be a second thing to
learn; and §5b's S6/S10 (unauthenticated API status, error-body leakage), which
`API-INVENTORY-EXPOSED` and `API-ERROR-DISCLOSURE` already cover — a second finding saying the
same thing is worse than one.

---

## 1.5 — Integration surface

| Item | Source | Notes |
|---|---|---|
| **SARIF export** | backlog | Puts findings in a partner's GitHub Security tab. Biggest adoption lever after auth strategies; the model layer already holds everything needed. |
| **JUnit export** | backlog | Findings render as test results in any CI. |
| **Baseline diffing** | their "missing" list | Overlaps the 1.1 trends work; the report side lands there, the CLI gate (`--baseline <run>`, fail only on *new* findings) lands here. |
| **`registerAttackPaths()`** | backlog | Every other catalogue facet is extensible; paths are not. |
| **Findings lifecycle / issue tracker** | their "missing" list | **Deferred, not declined.** Export stable finding identities so an external system can own the lifecycle; TRUST should not become a ticket tracker. |

---

## Declined, with reasons

| Proposal | Decision |
|---|---|
| **§13 AI verdict assist** | **Declined outright.** "No model judges a verdict" is a foundational guarantee of this tool, stated in the report's own methodology. Their document reaches the same conclusion by a different route — if a human reviews every AI verdict, the AI saved nothing, and if they do not, a missed bypass is a liability. |
| **§10 AI rendering safety (general XSS)** | **Declined as scoped.** `AGENT-LINK-SAFETY` already covers dangerous URI schemes in agent output, which is a trust-boundary question. Testing the frontend's sanitisation of arbitrary HTML is DAST territory and dilutes the product. |
| **§9 passive-extended, partially** | GraphQL introspection already exists. Open redirect already exists. The remaining suggestions push toward general scanning — take only what tests a boundary. |
| **§13 `trust generate-probe`** | Low value. People who write probes can write code, and NL→code accuracy is poor for security-sensitive logic. |
| **Parallel probe execution** | **Declined as stated.** Concurrency conflicts directly with the delay floor and the request cap, which exist to make the harness incapable of harming a target. If runtime becomes a real complaint, the answer is per-host budgets with bounded concurrency, not "run 20 probes at once". |
| **§13 MCP server** | **Not declined — deferred to 2.0 and worth a spike.** A security harness an AI agent can invoke during development is a genuine differentiator, and it fits: TRUST's outputs are already structured and deterministic. Needs a stable tool surface first, which means 1.1–1.3 should land before committing. |
| **`trust discover`** | Deferred with MCP. Schema analysis producing inert config marked `humanReviewed: false` is defensible, but it is a 2.0 concern. |

---

## Engineering debts (fold into the releases above)

| Debt | Where |
|---|---|
| **`model.mjs` is a 400-line function returning 40 fields** | Split during 1.1, when the dashboard and trends work touches it anyway: `scoring`, `narrative`, `fragments`, `coverage`. |
| **Catalogue is a mutable global** | Contaminates parallel in-process runs by library embedders. Scope the registry per run, or document the constraint. Do it with 1.3, when strategies add more shared state. |
| **`isDenied()` treats 429 as "not denied"** | A rate-limited response can produce a false negative on a cross-user check. Fix in 1.0.1 if cheap; it is a correctness issue. |
| **Injection probes are GET-only** | POST/JSON body injection is untested, and modern APIs are POST-first. Pair with the 1.4 isolation work, which already needs request specs. |
| **Test visibility** | Tests exist but are not shipped (correctly). Add a CI badge and state coverage in the README so the absence is not mistaken for having none. |
| **`path` shadowing in `web.mjs`** | Cosmetic; fix opportunistically. |

---

## Sequencing rationale

1.0.1 first because a report that misfiles findings undermines everything else the tool claims.
1.1 next because the field team is *using* the report daily and the friction is immediate.
1.2 before 1.3 because per-profile budgets and config fallbacks are what make a large estate
runnable at all — auth strategies are pointless if the run exhausts its budget before reaching
storage. 1.3 and 1.4 are the adoption unlock, in the order both documents recommend. 1.5 is the
integration surface, which only matters once teams run TRUST continuously.
