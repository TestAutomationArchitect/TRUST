/**
 * TRUST — SARIF 2.1.0 export.
 *
 * SARIF is what puts findings in a partner's GitHub Security tab, next to CodeQL and everything
 * else, instead of in an HTML file someone has to remember to open. The model already holds
 * what SARIF wants; this is a translation, not an analysis, and it invents nothing.
 *
 * Two translation decisions are worth stating, because both could be done sloppily:
 *
 * **Severity is the impact if the control fails, not the outcome.** A passing CRITICAL control
 * is normal in TRUST, so severity is only mapped to a SARIF `level` for results that actually
 * failed. Passes and skips are emitted with `kind` and no level, which is what stops a green
 * run painting the Security tab red.
 *
 * **A finding has no file or line.** Inventing one would be a lie a reviewer acts on, so every
 * result is anchored to the config that declared the target, and the target URL travels in the
 * message and in properties. That keeps the result clickable without pretending it came from
 * a line of source.
 */

import { getTestMeta, domainForId } from "../catalog.mjs";
import { findingKey, fingerprint } from "./identity.mjs";
import { headline } from "../finding.mjs";

export { findingKey, fingerprint } from "./identity.mjs";

const SARIF_VERSION = "2.1.0";
const SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/** Only failures carry a level; a pass or a skip is a kind. */
const LEVEL_OF_SEVERITY = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
/** GitHub reads this to place a finding in its own severity bands. */
const SECURITY_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };
const KIND_OF_STATUS = { pass: "pass", fail: "fail", warn: "review", skip: "notApplicable" };

function ruleFor(finding) {
  const meta = getTestMeta(finding.id);
  const category = finding.category ?? meta.category;
  const domain = finding.domain ?? domainForId(finding.id);
  return {
    id: finding.id,
    name: finding.id.replace(/[^A-Za-z0-9]/g, ""),
    shortDescription: { text: finding.title },
    fullDescription: { text: meta.purpose || finding.title },
    help: {
      // GitHub renders markdown here, and this is the only place a reviewer sees *why* the
      // control exists rather than only that it broke.
      text: [meta.purpose, finding.remediation].filter(Boolean).join("\n\n") || finding.title,
      markdown: [meta.purpose && `**Purpose.** ${meta.purpose}`, finding.remediation && `**Remediation.** ${finding.remediation}`].filter(Boolean).join("\n\n") || finding.title,
    },
    defaultConfiguration: { level: LEVEL_OF_SEVERITY[finding.severity] ?? "note" },
    properties: {
      tags: ["security", domain, category].filter(Boolean),
      "security-severity": SECURITY_SEVERITY[finding.severity] ?? "1.0",
      category,
      domain,
      // The severity is a property of the control, so it is stated as such rather than being
      // inferred from a result that may well be a pass.
      impactIfFailed: finding.severity,
    },
  };
}

/**
 * Build a SARIF log.
 *
 *   reports   one run report, or an array of them (one per profile)
 *   configPath  the file results are anchored to; defaults to the config that declared the run
 */
export function toSarif(reports, { configPath = "trust.config.json", toolVersion = "", includePasses = false } = {}) {
  const runs = [reports].flat().filter(Boolean);
  if (runs.length === 0) throw new Error("toSarif requires at least one run report");

  const rules = new Map();
  const results = [];
  const target = runs[0].target ?? "";

  for (const report of runs) {
    for (const finding of report.findings ?? []) {
      // A pass is real information, but a Security tab full of passing controls buries the
      // failures, so passes are opt-in.
      if (!includePasses && (finding.status === "pass" || finding.status === "skip")) continue;
      if (!rules.has(finding.id)) rules.set(finding.id, ruleFor(finding));

      const key = findingKey(finding, { target: report.target ?? target });
      const failed = finding.status === "fail";
      results.push({
        ruleId: finding.id,
        ruleIndex: [...rules.keys()].indexOf(finding.id),
        kind: KIND_OF_STATUS[finding.status] ?? "review",
        // Only a failure gets a level. A passing CRITICAL control must not read as an error.
        ...(failed || finding.status === "warn" ? { level: failed ? (LEVEL_OF_SEVERITY[finding.severity] ?? "warning") : "warning" } : {}),
        message: {
          text: `${headline(finding)} — ${report.target ?? target}${finding.evidence ? `\n\n${finding.evidence}` : ""}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: configPath, uriBaseId: "%SRCROOT%" },
              region: { startLine: 1 },
            },
            logicalLocations: [{ name: finding.id, kind: "member", fullyQualifiedName: `${finding.domain ?? domainForId(finding.id)}/${finding.id}` }],
          },
        ],
        partialFingerprints: { trustFindingKey: fingerprint(key) },
        properties: {
          trustKey: key,
          status: finding.status,
          severity: finding.severity,
          profile: report.profile,
          environment: report.environment,
          target: report.target ?? target,
          ...(finding.activatedBy ? { activatedBy: finding.activatedBy } : {}),
        },
      });
    }
  }

  return {
    $schema: SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: "TRUST",
            fullName: "TRUST — Trust Reporting & Unified Security Testing",
            version: toolVersion || runs[0].toolVersion || "0.0.0",
            informationUri: "https://www.npmjs.com/package/trust-verify",
            rules: [...rules.values()],
          },
        },
        automationDetails: { id: `trust/${runs.map((r) => r.profile).join("+")}`, guid: runs[0].runId ?? undefined },
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: runs[0].startedAt,
            endTimeUtc: runs[runs.length - 1].generatedAt,
            // The engagement boundary belongs in the export: it is what makes the scope of a
            // green result legible to someone reading it months later.
            properties: { allowedHosts: runs[0].allowedHosts ?? [], surfaces: runs[0].surfaces ?? [] },
          },
        ],
        results,
      },
    ],
  };
}
