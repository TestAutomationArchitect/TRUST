/**
 * TRUST — combined Trust Assessment.
 *
 * Reads the latest JSON run per profile and composes one HTML assessment serving three
 * readers at once:
 *
 *   Executive  → posture score, deployment readiness, root causes
 *   Architect  → trust domain cards, verified controls, impact tiers
 *   Engineer   → individual findings with evidence and remediation
 *
 * The split is model / theme / sections: buildModel() derives, section modules render.
 * The SECTIONS array below *is* the information hierarchy — worst news first, proof last.
 */

import { readdir, readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { buildModel } from "./model.mjs";
import { renderHead, renderFoot } from "./shell.mjs";
import { renderSummary } from "./sections/summary.mjs";
import { renderScope } from "./sections/scope.mjs";
import { renderFindings } from "./sections/findings.mjs";
import { renderProfiles } from "./sections/profiles.mjs";
import { renderRemediation } from "./sections/remediation.mjs";
import { renderRetest } from "./sections/retest.mjs";
import { renderInventory } from "./sections/inventory.mjs";
import { renderDefinitions } from "./sections/definitions.mjs";

export { buildModel } from "./model.mjs";
export { computeScores } from "./scoring.mjs";
export { STYLE } from "./theme.mjs";

/** Section renderers in report order. Reordering this array reorders the document. */
export const SECTIONS = [
  renderSummary,
  renderScope,
  renderFindings,
  renderProfiles,
  renderRemediation,
  renderRetest,
  renderInventory,
  renderDefinitions,
];

export async function loadReports(dir) {
  const absDir = path.resolve(dir);
  const files = (await readdir(absDir)).filter((f) => f.endsWith(".json")).sort();
  const latest = new Map();
  for (const file of files) {
    let content;
    try {
      content = JSON.parse(await readFile(path.join(absDir, file), "utf8"));
    } catch {
      continue;
    }
    if (!content?.profile || !Array.isArray(content.findings)) continue;
    const existing = latest.get(content.profile);
    if (!existing || new Date(content.generatedAt) >= new Date(existing.generatedAt)) {
      latest.set(content.profile, { file, ...content });
    }
  }
  return latest;
}

/** Compose the HTML document from a map of profile → run JSON. */
export function buildReport(reports, { title = "" } = {}) {
  const model = buildModel(reports, { title });
  return renderHead(model) + SECTIONS.map((render) => render(model)).join("\n\n") + renderFoot(model);
}

/** Read every run, build the assessment and write it. Returns the path written. */
export async function writeCombinedReport({ dir = "reports", out = "", title = "" } = {}) {
  const reports = await loadReports(dir);
  if (reports.size === 0) throw new Error(`No TRUST JSON reports found in ${dir}`);
  const html = buildReport(reports, { title });
  const outPath = out || path.join(path.resolve(dir), `trust-assessment-${new Date().toISOString().slice(0, 10)}.html`);
  await mkdir(path.dirname(outPath), { recursive: true });
  await writeFile(outPath, html, { mode: 0o600 });
  return { outPath, profiles: [...reports.keys()], html };
}
