# Review backlog

Triaged findings from external reviews of the generated Trust Assessment, kept so the work
survives between sessions. Each item records the verdict reached, not just the suggestion —
where a review was factually wrong or over-reaching, that is recorded too, so it is not
implemented later by accident.

Scores from the reviewing party, for reference only: round 1 **7.9/10**, round 2 **8.8/10**
(executive usefulness 6.8 → 8.6, methodology 7.2 → 8.2, auditability 7.6 → 8.5).

---

## Done

| Item | What changed |
|---|---|
| Failed titles read as passing controls | `observed` on `finding()` + `headline()`; failing cards headline the observed outcome and keep the assertion as *Expected control* |
| Severity looked like observed harm | Severity is impact **if the control fails**; neutral dashed badge on a pass, documented in the glossary |
| Score overstated posture | Coverage (assessed / applicable), *Assessed* Security Posture label, unassessed domains shown rather than omitted |
| Findings reported in isolation | Six deterministic attack-path rules; a path fires only when every control it depends on failed in the same run |
| Password-grant false positive | Corroborated against the provider's OIDC discovery document; single-signal results are WARN (probable), not FAIL |
| Root causes overstated as confirmed | Renamed **Likely Root Causes** |
| Remediation was ten unrelated rows | Six workstreams with P0/P1/P2, owners, attack-path membership and closure criteria |
| Retest said only "remediation deployed" | Each row carries the control, the condition that closes it, and the re-run command |
| Blocker count paired with all failing domains | Verdict now counts blocker domains only, and names medium/low domains separately |
| Test-purpose language leaked into the executive summary | Three agent disclosure probes and five header probes were passing `observed` into a spec object instead of the `finding()` call, so it was inert. Fixed; trailing full stops de-duplicated |
| `.env` was never loaded by the CLI | `src/env.mjs`; real environment variables still win. This broke `trust init`'s own printed instructions |

---

## Agreed, not yet done

### 1. "Corroborated attack path" overstates what was executed — **highest priority**
Every component control failed independently, but no single end-to-end execution traversed the
whole chain. Rename to **Correlated control-failure chain** (or *Correlated attack scenario*)
and add the sentence: *"Each component weakness was independently confirmed. The complete chain
was not executed end-to-end."* Reserve **Confirmed Attack Path** for a future mode that actually
executes the traversal. This is a one-word credibility problem in the most differentiating
section of the report.

### 2. Infrastructure root cause does not match its evidence
The only Infrastructure failure is `API-ERROR-DISCLOSURE`, but the root cause reads *"Browser and
transport security hardening is incomplete."* Root causes are currently one string per domain,
which is too coarse — the domain spans transport, headers, error handling and caching. Make the
root cause **category-aware**, falling back to the domain string. For error handling: *"Detailed
server-side errors are returned to clients without a sanitised error boundary."* Rename the
workstream from *Platform and transport hardening* to **Error handling and information
disclosure** when that is what actually failed.

### 3. Two of eight domains are undefined in the glossary
`Assessment Integrity` and `Input Handling` appear on domain cards but the Trust Domains column
defines only the original six. Add both:
- **Assessment Integrity** — whether the test setup itself supports the conclusions: distinct
  identities, distinct tenants, live credentials, scope honoured.
- **Input Handling** — validation, encoding and interpreter boundaries for untrusted input:
  injection, traversal, template evaluation, header and host handling.

### 4. Scope outcome column contradicts the finding
The identity-provider row reads *"Controls held"* while `AUTH-PASSWORD-BYPASS` is a WARN. The
surface outcome only counts `failed`, so warnings are invisible. Add a warning state:
**"1 warning — manual confirmation required"**.

### 5. Score bands imply blockers
Definitions say *below 60: blockers present*, yet this assessment scores 60 **with** seven
blockers. Bands must describe assessed-control performance only (*strong / moderate / weak*),
plus an explicit note: *"Deployment readiness is calculated independently — any critical or
high-severity failure yields Not Ready regardless of the score."* The readiness logic is already
independent; only the wording is wrong.

### 6. AI PASS claims are too broad
`AGENT-DIRECT-INJECTION` passing means *one canary was not followed in one response*, not that
the agent resists injection. Two steps: (a) retitle to a single-observation claim, (b) run N
variants × R repetitions and report *"0 of 12 variants succeeded across 3 repetitions."* The
multi-variant machinery already exists in `injection.mjs` and should be reused. A model's output
is not deterministic even when the verdict logic is.

### 7. Two API passes rest on weak evidence
`API-INTROSPECTION` ("introspection refused or empty") and `API-QUERY-COST` ("zero fields
returned") both treat an empty response as proof of a control. An unrelated resolver error or an
auth failure produces the same shape. Require a recognisable complexity/depth-limit error, or
compare against a valid baseline query in the same run.

### 8. Retest should target a control, not a whole profile
Ship `trust run --profile agent --test AGENT-IDENTITY-SPOOF` (or `trust retest <ID>`), and
disambiguate duplicated rows by profile (`TOKEN-CONFIG@agent`, `TOKEN-CONFIG@authenticated`).
The run JSON should also record the config path so the report can emit the real command instead
of `<config>`.

### 9. Evidence-chain metadata for audit-grade filing
Add to the cover: run ID, start/finish timestamps **with timezone**, git commit SHA, TRUST
version, catalogue version, configuration hash, evidence-manifest hash, previous baseline run
ID. Most are cheap; the hashes are what make a filed HTML report defensible as evidence.

---

## Own findings, not from the reviews

1. **Coverage denominator counts inapplicable modules.** `applicable` includes every catalogued
   assertion, so an API-only target is penalised for unconfigured mobile and agent probes and
   reports ~37% when it may have covered everything applicable. Scope the denominator by
   `run.surfaces`.
2. **Custom profiles are unreachable from the CLI.** `defineProbe({ profiles: ["nightly"] })`
   works through the library but `parseArgs` rejects `--profile nightly`.
3. **Injection probes only target `targets.web`.** Wrong surface for an SPA, where the shell
   HTML reflects nothing and the real risk sits behind the API.
4. **`INJECT-SSRF` and `WEB-RATE-LIMIT` can never pass** — structurally warn-only. A permanent
   warning trains readers to ignore warnings. Give them an opt-in mechanism or reclassify.
5. **Session probes mostly skip**: `SESSION-LOGOUT` needs three config keys plus `allowWrites`.
   Refresh-token rotation would deliver more for less configuration.
6. **No SARIF or JUnit export.** Biggest remaining adoption lever for partner CI; the model
   layer already holds everything needed.
7. **Partners cannot register attack paths** — every other catalogue facet is extensible.
8. **No run-over-run delta** (newly introduced / fixed / still failing).

---

## Rejected or amended

- **"Coverage: 24 of 62 applicable controls"** — the denominator in the round-1 review was
  invented. Compute it from the catalogue instead; never quote a figure the code cannot derive.
- **"Show response temperature where known"** — the harness cannot know it. Do not add a field
  that can only be populated by guessing.
- **"Earlier positioning used *Threat & Risk Unified Security Testing*"** — no such expansion has
  ever existed in this repository. The *argument* (reporting is an output, not the product) is
  reasonable, so the rename remains an open choice, but it is not a correction.
- **Executive Interpretation as hand-written prose** — the suggested wording is a narrative built
  from correlated findings, so it must be generated from the path engine. Writing it any other
  way means asserting impact the evidence does not support.
