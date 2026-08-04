# Changelog

All notable changes are documented here. This project follows the semver contract in the
[README](README.md#versioning) — note that finding IDs and severities are part of the public
API, and any change to a verdict is called out under **Verdict changes**.

## [1.6.1] — 2026-08-03

Field fixes from the first full-battery run of 1.6.0 against a live target. That run exercised
the new probes for the first time — server-side token validation, CSRF, mass assignment,
body injection, storage traversal and multi-turn agent injection all executed against a real
system, and the IdP pack found a missing PKCE challenge.

### Fixed

- **Remediation grouping did not group.** 1.6.0 grouped by remediation *text*, and the six
  security-header controls carry six different sentences while closing with a single change to
  the edge configuration — so nothing collapsed and the partner correctly reported the feature
  as absent. Findings now carry a canonical `fix` key; the report groups on that and keeps the
  per-control sentences nested beneath the shared action. Seven rows become one that says
  "closes 7 controls".
- **A control whose profiles disagree is now flagged** with an `inconsistent` badge, not only
  described inside its evidence. Reported against `AUTH-PASSWORD-BYPASS`, which read WARN in one
  profile and PASS in others with nothing in the report explaining why.

### Added

- **Probe tags and compliance mapping.** Every control carries tags derived from its category —
  `owasp-api-1`…`owasp-api-10`, `authn`, `authz`, `ai`, `injection`, `hardening`, and its trust
  domain. `trust run --tag owasp-api-2` reports only the controls in that group, and
  `trust catalog --tag ai` lists them. Derived rather than stored per control, so one mapping
  stays in step instead of ninety-seven drifting; `registerTags()` extends it for a partner
  category.
- **Setup problems are listed apart from security findings.** A control nobody configured is a
  fact about the run, not about the target, and reading past "config.api.csrf.endpoint is not
  defined" to find the security results made the list longer than the assessment. They now
  appear in Scope under *Setup, not findings* — and still count against coverage, because an
  unassessed control is exactly what coverage exists to report. A control that *cannot* apply
  here stays with the findings, since nothing would fix it.
- **Every warning says what to do next.** The three kinds need three different next steps —
  re-run and verify, raise the budget and finish the sweep, or treat as hardening — and a
  warning with no next step is a dead end for a reader.
- **Every control is addressable.** Each finding card carries an anchor and a copy-link button;
  opening `…#control-API-CROSS-USER` expands the section that holds it, opens the card and marks
  it briefly. Sharing a finding was previously "scroll to Authorization and look for it", which
  at 129 cards is not a link.
- **A category index in Findings**, leading with where the failures are, so landing on the
  section does not mean paging through everything that held to reach the three things that did
  not. It sticks under the header while the cards are read — an index that scrolls away is one
  you have to scroll back for — and highlights the group currently in view.
- **The inventory filters by tag**, the way a run does — including a combined "OWASP API Top 10"
  option — and SARIF rules carry the same tags, so a security dashboard can filter by framework
  rather than only by severity.
- **Coverage reports two numbers.** Controls assessed as a share of what applies, and as a share
  of what this *configuration* can reach. "We have not configured this yet" and "this cannot
  apply here" are different debts, and only the first shrinks by editing a config file.
- **Retest lists what a re-run could change.** A control that cannot be verified over HTTP at all
  — certificate pinning needs a device — no longer gets a row telling you to re-run; its manual
  procedure is on the finding. Controls waiting on configuration are named in Setup instead,
  with a pointer from Retest, because a config change is not a re-run.
- **Run provenance in the report.** Generated timestamp with timezone, run IDs, commit and
  branch, tool version, configuration hash, catalogue hash and size, and how each identity was
  obtained. The two hashes are what make a trend comparison honest: change either and the runs
  measure different things, which the report now says where a reader looks it up.
- **`trust preflight` forecasts what will skip.** Every control that applies to a configured
  surface but is one setting short now appears before the run, naming the control and the key:
  *"API-CSRF — add api.csrf.endpoint"*. Declared isolation boundaries are forecast from their own
  shape — a `record-ownership` spec with no `queryA` cannot discover the record it needs, and a
  pinned ID goes stale. Four of the partner's five config issues were exactly this, learned
  after a run instead of before one.
- **IdP warnings say which half they describe.** What a provider *supports* and what an
  application *asks for* are different questions; `IDP-PKCE-SUPPORTED` and `IDP-IMPLICIT-FLOW`
  now say so and point at `IDP-AUTHORIZE-REQUEST` for the other half.

## [1.6.0] — 2026-07-31

Positioning, robustness, report honesty and probe depth, from a second round of partner field
testing.

### Added — probe depth

- **Server-side token validation** (`JWT-*`). The token probes read claims offline; these take
  the real token, alter exactly one property — `alg:none`, a broken signature, claims the
  signature does not cover, an unknown `kid` — and check the API refuses each. An API that
  accepts any of them has no authentication, and the suite says so plainly: every authorisation
  result in the run was obtained with an identity that API does not verify. The altered tokens
  are invalid by construction and cannot authorise anything on a server that checks them.
- **CSRF** (`API-CSRF`) — a state-changing request from an untrusted origin, expected to be
  refused. It states what it does not prove: no session cookie is attached, so it establishes
  whether the origin is checked, not that a logged-in victim's browser would succeed.
- **Mass assignment** (`API-MASS-ASSIGNMENT`) — privileged fields (`role`, `tenantId`) sent in
  the payload, with the response echoing them back as the evidence. The write-side twin of
  identity spoofing.
- **JSON-body injection** (`INJECT-BODY`) — the same payloads as the query-string probes, in a
  request body, because a POST-first API was otherwise untested by a suite that only wrote to
  query strings. Config-driven: a guessed schema returns 400 and reads as clean.
- **Storage path traversal** (`STORAGE-PATH-TRAVERSAL`) in four encodings, since a prefix check
  against an un-normalised key is not an authorisation boundary — and **signed-URL integrity**
  (`STORAGE-SIGNED-URL`): altering the signature or extending the expiry must invalidate it.
- **Multi-turn agent injection** (`AGENT-MULTI-TURN-INJECTION`) — an instruction planted in one
  turn and claimed in a later one, after the guardrail that read the first turn has stopped
  paying attention. A single-turn probe reports a boundary it never exercised.
- **Tool-use abuse** (`AGENT-TOOL-ABUSE`) — the agent's tools are its real privilege. Requires
  configured success indicators, because only the operator knows what an out-of-scope tool
  result looks like in their answers.
- **Loopback exception to HTTPS-only.** Plain HTTP is permitted on `localhost`, `127.0.0.1` and
  `::1` — never a hostname that merely resolves there — so verification can happen before
  deployment rather than after it.

### Changed

- **The README now states what TRUST is for, and what it is not.** It was inviting comparison
  with scanners — 84 probes, OWASP coverage, injection payloads — and then being judged on
  scanner metrics it will never win: payload counts, fuzzing, adaptivity. The frame is control
  assurance, not vulnerability discovery: the unit is a control, the verdict is deterministic,
  and the output is an assurance artifact. "Run this before the pentest, not instead of it" is
  now the first thing a reader sees rather than something a reviewer discovers on day two.
- **Zero dependencies is stated as supply-chain hygiene**, not engineering purity, with the
  escape hatch named: anything genuinely needing weight ships as a separate optional package.
- **Determinism is defined for stochastic targets.** An LLM agent is not deterministic; the
  *decision rule* is — a fixed number of attempts, and a canary in any of them is a failure.

### Added

- **Skips say why they were skipped.** `unconfigured` means nobody looked — the config does not
  say where — and the target may well have the problem. `not-applicable` cannot apply here or
  cannot be checked over HTTP at all. `precondition` means the harness looked and could not
  proceed. The coverage callout counts them separately, because "we did not configure this" and
  "this cannot apply" are different debts, and collapsing them is how a run reads as safer than
  it is. Probes may state the kind; otherwise it is inferred from the reason they already write,
  defaulting to the cautious `unconfigured`.
- **Warnings say which kind of warning they are** — `inconclusive` (the harness could not tell),
  `partial` (the check did not complete, so absence proves nothing) or `advisory` (present but
  weaker than it should be). Three meanings wore one badge.
- **`trust run --only <ID>`** narrows to the probe module that could produce that control and
  reports only it, so debugging one control no longer costs a full profile. **`--verbose`**
  traces every guarded request — method, status, duration, and header *names* only, because a
  trace is the last place a token should surface.
- **The trend explains why the score moved.** "▲1" invites the reading that something improved;
  it might equally mean three new passing controls were configured. The report now separates
  what regressed, what was repaired, what was assessed for the first time and what is no longer
  assessed — and gives the **common-control score**: the same controls in both runs, scored the
  same way, which is the only genuinely like-for-like comparison available. The trend history
  records each run's assessed controls to make this possible; identity and status only, never
  evidence.
- **The report groups by control.** Cards, remediation and retest deduplicate a control that ran
  in several profiles into one entry, with the executing profiles named on it — a 58-control run
  no longer renders 161 cards. Remediation groups by the *fix* rather than by the finding, so
  seven controls that close with one configuration change are one row saying "closes 7 controls"
  instead of seven identical ones. The inventory stays per-execution, because it is the ledger
  and its profile column is its purpose. None of this changes a verdict, so it is not behind a
  flag — the readability fix should not require accepting a score change.
- **`trust report --score-by control`.** A control executed in several profiles is counted once,
  at its worst outcome, with the executing profiles listed on the finding and any disagreement
  between them kept in the evidence. This fixes a real defect in the headline number: scoring and
  coverage counted *executions*, so a control that ran in three profiles carried three times the
  weight of one that ran in one, and a team could raise its score by adding a profile. On a
  representative run the difference is 79 → 61 for the score and 22% → 13% for coverage.

  Not the default in 1.x, because changing it changes every published score and finding verdicts
  are part of the public API. It becomes the default in 2.0. A switched unit is recorded in the
  trend history and marks the two runs incomparable, so the movement is never presented as
  progress. The report now also states which unit it scored by, and the formula it used.

### Fixed

- **A probe module that threw destroyed the entire run.** Only `SafetyError` was caught, so any
  other exception discarded every finding already produced and wrote nothing to disk. The
  extension point invites third-party code, so one partner's defect must not cost an assessment:
  the module is now recorded as crashed, with the error as evidence and remediation that says
  plainly the module's controls are unverified — never a pass.
- **`trust preflight` failed on the deliberately-expired token fixture.** `api.session.expiredTokenEnv`
  was checked like a real identity, so preflight exited 1 over a token whose entire purpose is
  to have lapsed. It is now judged by the opposite rule: expired is correct, still-valid is a
  warning, opaque says so rather than implying a pass.
- **SigV4 signed an empty body for any non-string payload.** A Buffer body produced a valid
  signature over the wrong bytes, which a target answers with `SignatureDoesNotMatch` — reading
  as a broken credential rather than an unsupported body type. Buffers and typed arrays are now
  signed as sent, and anything unhashable throws where the cause is visible.
- **`remediation` was unbounded** while evidence was clamped, so a probe that interpolated a
  response body into it would bloat the HTML, the JUnit XML and the SARIF alike.
- **Config keys can no longer reach an object's prototype** through `extends`. Nothing was
  exploitable — `Object.prototype` was never reachable — but a config is a file that may be
  generated, inherited or vendored, and `__proto__` in one is never what an author meant.

## [1.5.0] — 2026-07-30

The adoption release: credentials TRUST acquires rather than expects, authorisation boundaries
a team declares rather than codes, and findings delivered where CI already looks. Everything
here comes from partner field testing of 1.0.

A minor version, not a major: every addition is additive, no finding ID moved, and no existing
verdict changed. A run configured for 1.0.1 produces the same results on 1.5.0.

Published by hand rather than from CI, so **this version carries no provenance attestation** —
`npm audit signatures` will report none for 1.5.0. The package's trusted publisher was not yet
accepting this repository's OIDC identity at release time; the workflow and the release contents
are otherwise unchanged, and attestation returns as soon as that is configured.

### Upgrading

Nothing is required. Three things are worth adopting, in this order:

1. `trust preflight --config <path>` before your next pipeline run — it catches an expired
   token, an unlisted host or a too-small budget in seconds, without spending the run.
2. `trust baseline --dir reports` if you have inherited findings, so CI can gate on
   regressions while the backlog is worked through.
3. `auth.strategies` if identities are currently pasted into `.env` by hand.

### Added

- **SARIF 2.1.0 and JUnit export** (`--sarif`, `--junit` on `run` and `report`). Findings land in
  a partner's security dashboard and CI test view instead of an HTML file someone has to
  remember to open. Only failures carry a SARIF `level`, since a passing CRITICAL control is
  normal here and must not paint a dashboard red; results are anchored to the config rather than
  to a fabricated source line; each carries a stable fingerprint so a dashboard de-duplicates
  across runs.
- **Baselines** (`trust baseline`, `--baseline` on `run` and `report`). The gate becomes "nothing
  got worse", which is a promise a team can keep while it works through inherited findings.
  Fixed findings are reported as loudly as new ones, a warning that becomes a failure is
  *worsened* rather than accepted, and a baselined finding whose profile did not run is reported
  as absent rather than fixed.
- **`registerAttackPaths()`.** Every other catalogue facet was extensible and this one was not,
  so an org whose architecture has a control-failure chain the built-ins do not describe had no
  way to say so. String IDs are matched whole, since hand-anchoring is the mistake that makes a
  path silently never match.
- **Declared isolation boundaries.** `config.isolation` states an authorisation boundary and
  TRUST supplies the test, the verdict and the report entry — `record-ownership`,
  `prefix-scoped-storage`, `enumeration`, `mutation-guard` and `identity-injection`. The
  highest-value test category previously required writing a probe module, which put it behind
  the highest barrier. A record ID is discovered as identity A rather than pinned in config, so a
  boundary survives a data reseed; a boundary needing two identities skips rather than reporting
  a pass it did not earn.
- **Conditional execution.** `dependsOn` and `condition` on an isolation spec or an agent
  endpoint. A dependent test runs only when the upstream control broke, carries `activatedBy`
  into the run JSON, and otherwise skips with the upstream control *holding* as the reason —
  which states something about the system rather than reading as a gap in the assessment. A
  dependency naming a test that never ran is reported instead of silently satisfying the gate.
- **Declared agent endpoints.** `agent.endpoints[]` with `expectDenied`, the simple form of a
  tier map: an internal sub-agent that accepts an end-user token has no boundary of its own.
- **IdP posture probes** (`config.idp`), unauthenticated and HTTP-only: discovery document, PKCE
  with S256, implicit flow still advertised, an unauthenticated token endpoint uncompensated by
  PKCE, the application's own authorisation request, and a Cognito user pool still accepting
  `USER_PASSWORD_AUTH` — which bypasses federated sign-in and everything attached to it. Checks
  that need a browser are skips carrying the manual procedure.
- **Declarative auth strategies.** `auth.strategies` acquires credentials instead of expecting a
  bearer token pasted into `.env` — `cognito-srp` (SRP, so no plaintext-password grant has to be
  enabled on the pool), `cognito-identity-pool`, `okta-ropc`, `client-credentials`, `sigv4` and
  `static`. A section names a strategy (`"tokenA": "userA"`) where it used to name an env var,
  and `tokenAEnv` keeps working unchanged. Acquisition runs through `SafeHttpClient`, so an IdP
  host must be allowlisted like any other; a SigV4 signature is computed inside `request()`
  after every guard has passed. A missing input degrades to a skip that names it.
- **Token refresh mid-run.** A 401 triggers one re-acquisition and a retry; a second 401 is
  reported as-is, because at that point it describes the target.
- **`trust tokens`** acquires every strategy once and writes the tokens to a 0600 file for a CI
  job to load, so a pipeline signs in once rather than once per step. Tokens are never printed.
- **`trust preflight` and `trust validate`** answer "will this run work?" before the request
  budget is spent: config validity, allowlist coverage of every configured endpoint and IdP,
  token presence, expiry and distinctness, budget against the profile's typical spend, and TLS
  reachability. `validate` is the same checks with no network at all. Preflight never signs in —
  a check that costs a login is a check teams stop running.
- **`trust.config.schema.json`**, shipped with the package and referenced by scaffolded configs,
  so editors validate and autocomplete a config as it is written.
- **Config section aliases and inheritance.** An application that calls its API section `graphql`
  or `appSync`, or its agent section `agentCore` or `bedrock`, no longer duplicates the endpoint
  under a second key. A config may `extend` another and override only what differs; arrays
  replace rather than merge, so a child can narrow an allowlist but never silently widen one.
  The run records which key each section resolved from.
- **Per-profile and per-suite request budgets.** `safety.maxRequests` accepts a map keyed by
  profile, and `safety.budgets` caps individual suites — the fix for a long web sweep exhausting
  the run before the storage and agent probes execute. Spend is recorded per suite.
- **`safety.allowDenialTests`** permits a mutation that is *expected to be refused* without
  enabling writes generally. Proving one permission control holds previously required turning on
  every destructive path in the harness.
- **Executive dashboard, list filters and trends** in the Trust Assessment: an un-collapsed
  posture summary with a one-paragraph synopsis, dropdown filters for status, severity and
  category with a clear control, and a trends section with sparklines over run history.

### Changed

- **History is state, not output.** Run history lives in `.trends/trends.json`, not in the
  reports directory, so publishing reports as a CI artifact no longer publishes the history and
  wiping reports no longer resets it. A legacy `reports/trends.json` is migrated on first run.

### Fixed

- **A sweep that could not complete no longer passes.** `API-INVENTORY-EXPOSED` reported PASS
  having checked zero paths when the budget ran out first. Verdicts now carry sweep
  completeness: nothing performed is a skip, a partial sweep is a warning that says how far it
  got, and only a complete sweep can pass.
- **`--env-file` was declared twice in the argument parser**, so the secrets flag silently did
  nothing and its value was read as an environment name. The flag is `--dotenv`; `--env` belongs
  to `trust init`.
- **The token probe shadowed the imported `section` resolver** with a loop variable.
- **The run JSON dropped the credential provenance** the runner had already computed, so a
  reader could not tell how a run had authenticated. Names, kinds and expiry now travel in the
  report — never tokens.
- **Coverage counted IdP controls against targets with no IdP configured**, the same defect
  1.0.1 fixed for mobile and agent probes. The IdP is now its own declared surface.
- **Correlation data in evidence.** Cognito identity IDs and AWS account IDs in ARNs are
  redacted. Bare UUIDs deliberately are not: TRUST plants canaries and session identifiers in
  its own evidence, and blanket redaction would erase the proof along with the risk.
- **The agent probe module was missing its `auth` imports**, so any run selecting the agent
  profile would have thrown `credentialFor is not defined`. Introduced with the auth strategies
  above and caught by the first test to exercise that module; it never reached a release.

## [1.0.1] — 2026-07-30

Renamed to `trust-verify` and published unscoped. The previous scope named the author
rather than the product, the inverse of the usual convention (`@sentry/node`,
`@playwright/test`), and read as a personal project on the install line. Security tools
are conventionally unscoped single names. The CLI binary is unchanged, so `trust run`
and `trust report` work exactly as before; only the install name moves.
`@automationarchitect/trust` 1.0.0 was unpublished inside npm's 72-hour window, with no
dependents.

Plus correctness fixes from partner field testing. No new capability.

### Fixed

- **The combined report misfiled every custom-probe finding (P0, data integrity).** Runs record
  each finding's domain and category while the probe's catalogue entries are loaded; the merge
  step then re-derived both from a catalogue that no longer holds partner entries, so custom
  findings were scored and displayed under "Other" / "Platform". 14 call sites in
  `assessment/model.mjs` and one in `scoring.mjs` now prefer what the run recorded. A partner
  running 18 custom probes lost four trust domains' worth of classification to this.
- **`observed` was not redacted** while `evidence` was. Any probe putting a response fragment
  in that field wrote it to disk unredacted.
- **`--env-file` never reached TRUST** through an installed binary: Node claims the flag first,
  producing `node: .env: not found`. The flag is now `--env`; `--env-file` still works for a
  direct `node src/cli.mjs` invocation. (`.env` is auto-loaded, so most runs need neither.)
- **A throttled response counted as an authorisation denial.** A 429 or 503 during a cross-user
  check reported the isolation control as holding when it was never exercised.
- **Cognito password-grant checks always reported WARN.** Cognito omits `grant_types_supported`
  from its discovery document, so corroboration was impossible; `InvalidParameterException` from
  a Cognito endpoint is now treated as conclusive.
- **Coverage counted controls that could not apply.** An API-only target was marked down for
  unconfigured mobile and agent probes. The denominator is now scoped by the surfaces the run
  actually declared.
- **Root causes were attributed at domain granularity**, so an error-disclosure finding read as
  "browser and transport security hardening is incomplete". Where every failure in a domain
  shares one category, the category's own root cause is used.
- **Partner findings were assigned to a "Platform" owner** in the remediation plan. The owner
  now falls back to the finding's trust domain.
- Score bands implied that a low score means blockers are present; readiness is computed
  independently and a report can sit in the moderate band and still be blocked.
- `Assessment Integrity` and `Input Handling` appeared on domain cards but were undefined in
  the glossary.

### Changed

- **"Corroborated attack path" → "Correlated control-failure chain."** Each component control is
  proven to have failed, but no run executes the chain end to end. The report now says so
  explicitly. The stronger wording returns when TRUST can traverse a chain in a single run.
- `finding()` accepts optional `domain` and `category`, so a probe can classify an individual
  finding rather than relying solely on its catalogue entry.
- Redaction adds Azure SAS parameters (anywhere, not only after `?`/`&`), GCP service-account
  `private_key` in JSON, Anthropic `sk-ant-`, HuggingFace `hf_` and Cohere keys, and now
  handles quoted JSON values containing spaces.

### Verdict changes

| Test | Before | After |
|---|---|---|
| Any custom-probe finding | scored under Platform | scored under its declared domain |
| `AUTH-PASSWORD-BYPASS` on Cognito | WARN (uncorroborated) | PASS when the grant is rejected |
| Cross-user checks under rate limiting | could PASS while throttled | inconclusive rather than a false pass |
| Coverage percentage | depressed by inapplicable controls | scoped to configured surfaces, so it rises |

## [1.0.0] — 2026-07-30

First distributable release: TRUST is now installable as a package rather than cloned.

### Added

- **Library API** (`trust-verify`) — `runProfile()`, `defineProbe()`, `loadConfig()`,
  `validateConfig()`, `finding()`, `writeCombinedReport()` and the catalogue registration
  helpers, so a partner can embed TRUST in an existing harness instead of shelling out.
- **`trust init`** — scaffolds `config/<env>.json`, `.env.example`, an example org-specific
  probe and the `.gitignore` entries into a consumer repository.
- **`trust report`** — replaces `node scripts/combined-report.mjs`, so consumers never reach
  into `node_modules/`.
- **`trust catalog [--json]`** — lists every test with its category and trust domain; useful
  for generating partner documentation and for dashboard schemas.
- **Third-party probes** — `config.probes: ["./trust-probes/mine.mjs"]` loads probe modules
  relative to the config file. A probe may ship its own catalogue entries, domains, root
  causes and summary rules, so partner findings score and group like built-in ones.
- **`DEPRECATED_IDS` alias map** and `canonicalId()`, so a renamed finding ID keeps
  resolving for historical reports and partner dashboards.
- **Publish preflight** (`scripts/preflight.mjs`, wired to `prepublishOnly`) — blocks a
  publish that still carries the placeholder scope, has gained a dependency or an install
  script, would ship `.env`/`reports/`/`test/`/keys, or has failing tests.
- **Provenance publishing** via GitHub Actions OIDC, plus a checksummed tarball on the
  release for airgapped partners.
- **25 new security assertions (42 → 67)**: offline token hygiene (`TOKEN-ALG`, `LIFETIME`,
  `CLAIMS`, `SCOPE`, `FRESHNESS`, `IDENTITY-DISTINCT`, `TENANT-DISTINCT` — no HTTP requests at
  all); input handling / OWASP A03 (`INJECT-REFLECTED-XSS`, `SQL-ERROR`, `TEMPLATE`,
  `PATH-TRAVERSAL`, `CRLF-HEADER`, `HOST-HEADER`, `SSRF`); web misconfiguration
  (`WEB-HTTP-METHODS`, `SERVER-BANNER`, `SUBRESOURCE-INTEGRITY`, `COOKIE-SCOPE`,
  `CACHE-CONTROL`, `DIRECTORY-LISTING`); API surface and limits (`API-INVENTORY-EXPOSED`,
  `EXCESSIVE-DATA`, `QUERY-COST`); session lifecycle (`SESSION-LOGOUT`, `EXPIRED-TOKEN`).
  Two new trust domains: **Input Handling** and **Assessment Integrity**.
- **Corroborated attack paths** — six deterministic rules that fire only when every control a
  path depends on failed in the same run. Set intersection over evidence, no model involved.
- **Coverage reporting** — assessed / applicable controls, unassessed domains shown rather
  than omitted, and the score labelled *Assessed* Security Posture below 100%.
- **Remediation workstreams** with P0/P1/P2, attack-path membership and closure criteria;
  retest rows now carry the exact re-run command and the condition that closes the control.
- **`observed` on findings** plus `headline()`, so a failing control is headlined by what was
  seen and keeps its assertion as *Expected control*.
- 16 packaging tests and 16 probe tests, covering the package contract, extension points,
  scaffolding, the CLI surface, token decoding, coverage and attack-path matching (79 total).

- **Apache-2.0 licence**, with `NOTICE` for redistribution attribution and
  [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md) covering authorisation to test — a concern the
  licence itself cannot address.

### Changed

- **The combined report is modular.** The 975-line `scripts/combined-report.mjs` became
  `src/assessment/`: `model.mjs` derives, `theme.mjs` holds every colour and token,
  `client.mjs` the inline script, `html.mjs` the escaping primitives, and one module per
  report section under `sections/`. A new output format can reuse `buildModel()` as-is, and
  re-theming for a partner's brand means editing one token block.
- **Sections are collapsible cards driven by the nav pills.** The report opens as a readable
  index rather than a wall of tables: only the Trust summary is expanded, each collapsed
  header still carries its headline numbers, and a pill opens its section while closing the
  others. Finding cards no longer auto-open on failure — the Findings panel has an
  Expand all control instead. Printing forces every panel and card open, so a filed PDF can
  never hide evidence, and `#section-findings` deep links open their target.
- **The Definitions section is a COMPASS/AVANI glossary** — a three-column grid of definition
  lists instead of nested tables. Same content, scannable presentation.
- **Scope is derived, not described.** Runs now record a `surfaces` block (built from the
  config, with query strings stripped from endpoints), and the report cross-references each
  surface with the findings it produced — reporting "not exercised" for anything configured
  but only skipped. The Authorised Boundary block lists the allowlisted hosts. A hand-written
  `architecture` string is now optional and clearly labelled as supplied by config.
- The report header reads **TRUST**; the assessment name moved to the subtitle.
- CLI is now subcommand-based (`init` / `run` / `report` / `catalog`). `trust --config … --profile …`
  with no subcommand still means `run`.

### Deprecated

- `node scripts/combined-report.mjs` — forwards to `trust report` and prints a notice.
  Removal no earlier than 2.0.0.

### Fixed

- `redact()` missed secrets whose key carried a prefix (`DB_PASSWORD=…`, `SERVICE_ACCESS_KEY_2=…`),
  so a leaked `.env` could be echoed into a report verbatim.
- `WEB-TLS-VERSION` / `WEB-TLS-CERTIFICATE` were inconclusive against any target on a
  non-443 port — the TLS probe ignored the URL's port.
- Suffixed storage IDs (`STORAGE-CROSS-TENANT-<name>`) fell through to the "Other" category
  and the Platform domain instead of Authorization.
- `API-ERROR-DISCLOSURE` missed stack frames written as `at handler (/var/task/index.js:12)`
  and bare absolute server paths.
- `WEB-EXPOSED-*` IDs for dot-prefixed paths gained a double dash (`WEB-EXPOSED--ENV`).
- `trust init` re-appended its `.gitignore` header on every run instead of being idempotent.
- **`.env` was never loaded.** Following `trust init`'s own instructions ("copy `.env.example`
  to `.env`", then `trust run`) produced a run where every authenticated probe skipped for a
  missing token — a silent failure that looked like a target misconfiguration. The CLI now
  reads `.env` itself (real environment variables still win); `--env-file` and `--no-env`
  override it. An installed binary gives the user nowhere to pass Node's own `--env-file`.
- An older Node now fails with one sentence naming the required version, not a stack trace.
- The CRLF probe built its payload with `URLSearchParams`, which percent-encoded the `%` so
  the target only ever saw the literal text `%0d%0a` — the probe could not have detected
  header injection. It now builds the query string directly and tries four encodings.
- The reflected-XSS probe used a single quote-bearing payload, which on some targets triggers
  an error page that reflects nothing, silently passing. It now tries three context variants.
- `discoverParams()` did not decode `&amp;`, so the second parameter of every real-world link
  was discovered as `amp;<name>`.
- Surface test counts in Scope double-counted when two runs shared an ID prefix.
- `severity` was rendered as though it described the observed result, so a passing control
  showed a red CRITICAL badge. It describes impact **if the control fails** and is now neutral
  on a pass, with the meaning documented in the glossary.

### Verdict changes

The redaction, TLS-port and error-disclosure fixes above can change results against a target
that was previously scanned:

| Test | Before | After |
|---|---|---|
| `WEB-TLS-VERSION`, `WEB-TLS-CERTIFICATE` | WARN (inconclusive) on non-443 targets | a real PASS/FAIL verdict |
| `API-ERROR-DISCLOSURE` | could PASS while leaking a stack trace | FAIL when a frame or absolute path is present |
| `STORAGE-CROSS-TENANT-*` | scored under the Platform domain | scored under Authorization |
| `AUTH-PASSWORD-BYPASS` | FAIL from a bad-credentials response alone | **WARN (probable)** unless the provider's OIDC discovery document also advertises the password grant — a deliberate reduction in false positives |
| `INJECT-CRLF-HEADER` | always passed (payload was double-encoded) | can now fail |
| `INJECT-REFLECTED-XSS` | could pass on targets that error on quotes | can now fail |
