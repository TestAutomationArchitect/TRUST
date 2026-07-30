# Changelog

All notable changes are documented here. This project follows the semver contract in
[docs/VERSIONING.md](docs/VERSIONING.md) — note that finding IDs and severities are part
of the public API, and any change to a verdict is called out under **Verdict changes**.

## [1.0.0] — 2026-07-30

First distributable release: TRUST is now installable as a package rather than cloned.

### Added

- **Library API** (`@testautomationarchitect/trust`) — `runProfile()`, `defineProbe()`, `loadConfig()`,
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
