# Versioning policy

TRUST is consumed by other organisations' pipelines. Two things make its compatibility surface wider than an ordinary library:

1. **Finding IDs and severities are an API.** Partners gate CI on them (`exit 2`), chart them, and file tickets against them. Renaming `AGENT-HIERARCHY-L2-DATA`, or promoting a finding from `medium` to `high`, silently changes a partner's build outcome.
2. **Report JSON is an API.** Dashboards parse `findings[].status`, `.severity`, `.domain` and the `summary` block.

So the semver contract below covers both the code and the catalogue.

## Major — may break a pipeline

- Removing or renaming a finding ID (the old ID **must** also be added to `DEPRECATED_IDS`)
- Raising a severity, or changing verdict logic so a previously passing control now fails
- Removing or renaming a field in the run JSON, or a profile name
- Removing an export from the package root, or raising the minimum Node version
- Changing scoring weights or the readiness thresholds

## Minor — additive, safe to take automatically

- New probes and new catalogue entries (a new test may of course fail, which is the point — but no existing verdict changes)
- New profiles, new config keys with safe defaults, new exports
- New report sections or fields
- Lowering a severity, or a verdict becoming *less* strict
- New extension points (`registerX`, new `defineProbe` fields)

## Patch

- Fixing a probe that produced a wrong verdict (a false positive or false negative), documented in the changelog with the before/after
- Redaction improvements, evidence wording, report layout and styling
- Performance, error messages, docs

> A false-negative fix can turn a partner's green build red. That is a patch, not a major — the previous green was wrong — but it must be called out explicitly in `CHANGELOG.md` under **Verdict changes**.

## Renaming an ID

Never edit an ID in place. Instead:

```js
// src/catalog.mjs
export const DEPRECATED_IDS = {
  "GQL-USERID-SPOOF": "API-USERID-SPOOF",   // renamed in 2.0.0
};
```

`getTestMeta()` and `domainForId()` resolve aliases, so historical report JSON and partner dashboards keyed on the old ID keep resolving to the right category, domain and root cause. Aliases are kept for at least two majors.

## Deprecation process

1. Ship the replacement in a minor, with both paths working.
2. Warn on the old path (`console.error` from the CLI; a note in the changelog for library callers).
3. Remove in the next major, no sooner than 90 days after step 1.

`scripts/combined-report.mjs` is currently in step 2 — it forwards to `trust report` and prints a deprecation note.

## Release checklist

- [ ] `npm test` green
- [ ] `CHANGELOG.md` updated, with a **Verdict changes** section if any verdict moved
- [ ] Version bumped per the rules above
- [ ] Any renamed ID added to `DEPRECATED_IDS`
- [ ] `node scripts/preflight.mjs` passes (runs automatically on publish)
- [ ] Tag `v<version>` pushed — the publish workflow does the rest with provenance
