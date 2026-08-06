/**
 * TRUST — per-profile report writer.
 *
 * Writes one JSON document per run (the machine-readable artefact that the combined
 * report consumes) and a compact standalone HTML view of the same run.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { summarize, headline } from "./finding.mjs";
import { getTestMeta, domainForId, CATALOG } from "./catalog.mjs";
import { section } from "./config.mjs";

// Kept in step with package.json by a test, rather than read at runtime: a report states the
// version that produced it, and reading the manifest on every import costs startup for a value
// that changes once per release.
export const TOOL = { name: "TRUST", version: "1.6.3", tagline: "Trust Reporting & Unified Security Testing" };

/** A URL with its query string dropped — search params can carry tokens. */
function safeEndpoint(url) {
  try {
    const parsed = new URL(url);
    parsed.search = "";
    parsed.username = "";
    parsed.password = "";
    return parsed.href;
  } catch {
    return String(url ?? "");
  }
}

/**
 * What surface did this config actually put in scope?
 *
 * Derived from the config rather than described by hand, so the report cannot claim to
 * have tested an architecture that was never configured. Recorded per run and merged by
 * the combined report.
 */
export function deriveSurfaces(rawConfig) {
  // Resolve aliases first, so a target configured as "graphql" still appears in Scope.
  const config = {
    ...rawConfig,
    api: section(rawConfig, "api").value,
    agent: section(rawConfig, "agent").value,
    storage: section(rawConfig, "storage").value,
    mobile: section(rawConfig, "mobile").value,
  };
  const surfaces = [];
  const add = (kind, label, target, detail = "") => {
    if (target) surfaces.push({ kind, label, target: safeEndpoint(target), detail });
  };

  add("web", "Web / browser surface", config.targets?.web);
  if (config.api?.endpoint) {
    add("api", `API — ${config.api.kind ?? "graphql"}`, config.api.endpoint, config.api.tokenBEnv ? "two identities configured" : "single identity");
  }
  if (config.api?.passwordAuth?.endpoint) add("auth", "Identity provider — token endpoint", config.api.passwordAuth.endpoint);
  // The IdP is its own surface: its controls are the provider's configuration, not the
  // application's, and counting them when no IdP is declared would mark a run down for
  // controls that cannot apply to it.
  if (config.idp) {
    add("idp", "Identity provider — OIDC configuration", config.idp.issuer ?? config.idp.discoveryUrl ?? config.idp.loginUrl ?? config.targets?.web, config.idp.cognito ? "Cognito user pool declared" : "");
  }
  if (Array.isArray(config.isolation) && config.isolation.length) {
    add("isolation", "Declared isolation boundaries", config.targets?.web, `${config.isolation.length} boundar${config.isolation.length === 1 ? "y" : "ies"}`);
  }
  if (config.storage) {
    add("storage", "Object storage", config.storage.baseUrl ?? config.storage.publicListingUrl, `${config.storage.targets?.length ?? 0} isolation target(s)`);
  }
  if (config.agent) {
    const subAgents = config.agent.subAgents?.length ?? 0;
    add(
      "agent",
      "AI agent runtime",
      config.agent.runtimeEndpoint ?? config.agent.endpointTemplate,
      [config.agent.allowedAgentId && `entry agent "${config.agent.allowedAgentId}"`, subAgents && `${subAgents} sub-agent(s)`].filter(Boolean).join(", "),
    );
  }
  if (config.mobile) add("mobile", "Mobile platform", config.mobile.apiEndpoint ?? config.mobile.baseUrl, config.mobile.deepLinkEndpoint ? "deep links configured" : "");
  return surfaces;
}

/**
 * Evidence-chain metadata.
 *
 * A filed report has to answer "what exactly was assessed, when, and against which build?"
 * long after the run. None of this is derivable later, so it is captured at run time:
 *
 *   runId          identity for this run, and the key trends compare across
 *   timezone       the ISO timestamps are UTC; this records where the run happened
 *   commit         the consumer's checked-out revision — which build was tested
 *   configHash     detects a config edited between runs, which invalidates a comparison
 *   catalogHash    detects a catalogue change, which can move findings between domains
 *
 * Nothing here may contain a secret: the config hash is computed over the config, which by
 * design holds env var *names* and never values.
 */
function evidenceChain(config) {
  const commit =
    process.env.GITHUB_SHA ??
    process.env.CI_COMMIT_SHA ??
    process.env.BUILD_SOURCEVERSION ??
    (() => {
      try {
        // No shell: a repo path with a space must not become an injection point.
        return execFileSync("git", ["rev-parse", "HEAD"], { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
      } catch {
        return null; // not a git checkout, or git is unavailable — both are fine
      }
    })();

  const digest = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex").slice(0, 16);

  return {
    runId: randomUUID(),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone ?? "UTC",
    commit,
    branch: process.env.GITHUB_REF_NAME ?? process.env.CI_COMMIT_REF_NAME ?? null,
    ci: Boolean(process.env.CI),
    configHash: digest(config),
    catalogHash: digest(Object.keys(CATALOG).sort()),
    catalogSize: Object.keys(CATALOG).length,
  };
}

/** Build the canonical JSON document for a run. */
export function buildRunReport({ config, profile, findings, requestCount, blocked = [], budget = null, sectionAliases = {}, credentials = [], startedAt, finishedAt }) {
  return {
    tool: TOOL.name,
    toolVersion: TOOL.version,
    profile,
    name: config.name,
    target: config.targets?.web ?? "",
    environment: config.environment,
    allowedHosts: config.targets?.allowedHosts ?? [],
    surfaces: deriveSurfaces(config),
    architecture: config.architecture ?? null,
    limitations: config.limitations ?? [],
    safety: {
      maxRequests: config.safety.maxRequests,
      minimumDelayMs: config.safety.minimumDelayMs,
      requestTimeoutMs: config.safety.requestTimeoutMs,
      allowWrites: config.safety.allowWrites,
      allowAgentInvocations: config.safety.allowAgentInvocations,
      productionOverride: config.safety.productionOverride,
    },
    ...evidenceChain(config),
    startedAt,
    generatedAt: finishedAt,
    durationMs: new Date(finishedAt) - new Date(startedAt),
    requestCount,
    budget,
    // Which config key each canonical section resolved to, so "api" resolving to "graphql" is
    // visible rather than inferred.
    sectionAliases,
    // How each identity was obtained, and when it expires — names, kinds and expiry only. A
    // reader asking "was this run authenticated as who it claims?" should not have to guess,
    // and a token must never appear in a document that gets forwarded.
    credentials,
    blockedRequests: blocked,
    summary: summarize(findings),
    // A probe may classify a finding itself; the catalogue is the fallback, not the override.
    findings: findings.map((f) => ({ ...f, category: f.category ?? getTestMeta(f.id).category, domain: f.domain ?? domainForId(f.id) })),
  };
}

const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

/** Minimal single-run HTML. The rich multi-profile view is scripts/combined-report.mjs. */
export function buildRunHtml(report) {
  const order = { fail: 0, warn: 1, pass: 2, skip: 3 };
  const rows = [...report.findings]
    .sort((a, b) => order[a.status] - order[b.status])
    .map(
      (f) => `<tr class="s-${f.status}">
  <td><span class="tag ${f.status}">${f.status.toUpperCase()}</span></td>
  <td><span class="sev ${f.status === "pass" || f.status === "skip" ? "latent" : f.severity}">${f.severity}${f.status === "pass" || f.status === "skip" ? " control" : ""}</span></td>
  <td><code>${esc(f.id)}</code></td>
  <td>${esc(headline(f))}<div class="det">${f.status === "pass" ? "" : `<b>Expected control</b><p>${esc(f.title)}</p>`}<b>Evidence</b><pre>${esc(f.evidence)}</pre>${f.remediation ? `<b>Remediation</b><p>${esc(f.remediation)}</p>` : ""}</div></td>
</tr>`,
    )
    .join("\n");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TRUST — ${esc(report.name)} — ${esc(report.profile)}</title>
<style>
:root{--bg:#0a0a12;--panel:#111120;--line:rgba(255,255,255,.08);--ink:#f1f5f9;--muted:#94a3b8;
--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--accent:#2563eb}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font:14px/1.6 Inter,system-ui,sans-serif;padding:28px}
h1{font-size:20px;margin-bottom:4px}.sub{color:var(--muted);font-size:13px;margin-bottom:20px}
.kpis{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 18px;min-width:96px}
.kpi b{display:block;font-size:24px}.kpi span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th{text-align:left;padding:10px 12px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:1px solid var(--line)}
td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
code{font:12px ui-monospace,Consolas,monospace;color:var(--muted)}
.tag{padding:2px 9px;border-radius:6px;font-size:11px;font-weight:700}
.tag.pass{background:rgba(22,163,74,.15);color:var(--ok)}.tag.fail{background:rgba(220,38,38,.15);color:var(--bad)}
.tag.warn{background:rgba(217,119,6,.15);color:var(--warn)}.tag.skip{background:rgba(148,163,184,.12);color:var(--muted)}
.sev{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.sev.critical,.sev.high{color:var(--bad)}.sev.medium{color:var(--warn)}.sev.latent{color:var(--muted);opacity:.8}
.det{margin-top:8px}.det b{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--accent)}
pre{background:#0e0e1c;border:1px solid var(--line);border-radius:6px;padding:10px;margin:4px 0 10px;
font:12px ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-word;max-height:220px;overflow:auto;color:var(--muted)}
</style></head><body>
<h1>TRUST — ${esc(report.name)}</h1>
<div class="sub">${esc(report.target)} · profile <b>${esc(report.profile)}</b> · ${esc(report.environment)} · ${esc(report.generatedAt)} · ${report.requestCount} requests</div>
<div class="kpis">
  <div class="kpi"><b style="color:var(--ok)">${report.summary.pass}</b><span>Pass</span></div>
  <div class="kpi"><b style="color:var(--bad)">${report.summary.fail}</b><span>Fail</span></div>
  <div class="kpi"><b style="color:var(--warn)">${report.summary.warn}</b><span>Warn</span></div>
  <div class="kpi"><b style="color:var(--muted)">${report.summary.skip}</b><span>Skip</span></div>
</div>
<table><thead><tr><th>Status</th><th>Severity</th><th>ID</th><th>Test</th></tr></thead><tbody>
${rows}
</tbody></table>
</body></html>`;
}

/** Write JSON + HTML for one run. Returns the paths written. */
export async function writeRunReport(report, outDir) {
  await mkdir(outDir, { recursive: true });
  const stamp = report.generatedAt.replace(/[:.]/g, "-");
  const slug = `${report.name}-${report.profile}-${stamp}`.replace(/[^A-Za-z0-9._-]/g, "-");
  const jsonPath = path.join(outDir, `${slug}.json`);
  const htmlPath = path.join(outDir, `${slug}.html`);
  await writeFile(jsonPath, JSON.stringify(report, null, 2), { mode: 0o600 });
  await writeFile(htmlPath, buildRunHtml(report), { mode: 0o600 });
  return { jsonPath, htmlPath };
}
