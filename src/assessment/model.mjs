/**
 * TRUST — the assessment model.
 *
 * Turns raw per-profile run JSON into every value the report renders: status buckets,
 * domain scores, readiness, root causes, the row and card fragments, and the derived
 * limitations list. Sections render from this model and derive nothing themselves, so a
 * new output (SARIF, a run-over-run delta, a dashboard feed) can reuse it unchanged.
 */

import { FIX_ACTIONS, tagsFor, getTestMeta, getDomain, domainForId, ROOT_CAUSE_MAP, CATEGORY_ROOT_CAUSE_MAP, DOMAIN_ORDER, SUMMARY_RULES, CATALOG, listCatalog, matchAttackPaths } from "../catalog.mjs";
import { computeScores } from "./scoring.mjs";
import { esc, severityBadge, statusCls, ownerFor } from "./html.mjs";
import { headline } from "../finding.mjs";

/** What each sub-kind means, shown on hover where the badge appears. */
const KIND_TIP = {
  unconfigured: "Not assessed because the configuration does not say where to look — the target may well have this problem.",
  "not-applicable": "Cannot apply to this target, or cannot be verified over HTTP at all.",
  precondition: "The harness looked and could not proceed: an upstream control held, an identity was absent, or a guard refused.",
  inconclusive: "The harness could not tell — a request failed or a response was ambiguous.",
  partial: "The check ran but did not complete, so the absence of a hit proves nothing.",
  advisory: "The control is present but weaker than it should be; nothing is broken.",
};

/** Worst status wins when the same control is executed in more than one profile. */
const STATUS_RANK = { fail: 0, warn: 1, pass: 2, skip: 3 };

/**
 * Collapse executions into controls.
 *
 * The same control runs in several profiles — token hygiene runs in three — and until now the
 * model counted each execution separately. That inflated the card list, and worse, it weighted
 * the posture score and the coverage percentage by how many profiles a control happened to
 * appear in: a passing control executed three times contributed three times the weight of one
 * executed once. A team could raise its score by adding a profile.
 *
 * The control is the honest unit. Worst status wins, every profile that executed it is
 * recorded, and the differing outcomes are kept in the evidence so nothing is hidden by the
 * collapse.
 */
export function collapseToControls(executions) {
  const byId = new Map();
  for (const execution of executions) {
    const existing = byId.get(execution.id);
    if (!existing) {
      byId.set(execution.id, { ...execution, profiles: [execution.profile], executions: [{ profile: execution.profile, status: execution.status }] });
      continue;
    }
    if (!existing.profiles.includes(execution.profile)) existing.profiles.push(execution.profile);
    existing.executions.push({ profile: execution.profile, status: execution.status });
    if (STATUS_RANK[execution.status] < STATUS_RANK[existing.status]) {
      // Keep the worst outcome and the evidence that produced it — a control that failed in one
      // profile and passed in another has not held.
      Object.assign(existing, execution, { profiles: existing.profiles, executions: existing.executions });
    }
  }

  for (const control of byId.values()) {
    const outcomes = new Set(control.executions.map((e) => e.status));
    control.inconsistent = outcomes.size > 1;
    if (outcomes.size > 1) {
      // A control that behaved differently per profile is the interesting case, so it is stated
      // rather than silently reduced to its worst run.
      control.evidence = `${control.evidence}

Across profiles: ${control.executions.map((e) => `${e.profile} ${e.status}`).join(", ")}`;
    }
  }
  return [...byId.values()];
}

/**
 * Derive the model.
 *
 *   title    overrides the assessment name taken from the run
 *   scoreBy  "control" counts each control once; "execution" counts every profile run of it,
 *            which is the 1.x default because changing it changes published scores
 */
export function buildModel(reports, { title = "", scoreBy = "execution" } = {}) {
  const first = reports.values().next().value ?? {};
  const assessmentName = title || `${first.name ?? "Target"} — Security Trust Assessment`;
  const target = first.target ?? "Unknown";
  const environment = first.environment ?? "unknown";
  const dateStr = new Date().toLocaleDateString("en-GB", { year: "numeric", month: "long", day: "numeric" });

  // The run JSON already carries domain and category, set when the probe ran and its
  // catalogue entries were loaded. Re-deriving them here would discard the classification
  // of every custom probe, because merge time has no knowledge of partner catalogues.
  const domainOf = (f) => f.domain || domainForId(f.id);
  const metaOf = (f) => {
    const meta = getTestMeta(f.id);
    return f.category ? { ...meta, category: f.category } : meta;
  };

  const executions = [];
  for (const [profile, data] of reports) {
    for (const f of data.findings) executions.push({ ...f, profile });
  }
  // Every fragment below derives from allFindings, so choosing the unit here is what makes the
  // whole report — cards, scoring, coverage, remediation, retest, inventory — consistent.
  const controls = collapseToControls(executions);
  const byControl = scoreBy === "control";
  const allFindings = byControl ? controls : executions;
  const unitCounts = { controls: controls.length, executions: executions.length, unit: byControl ? "control" : "execution" };

  // The narrative sections — cards, remediation, retest — always group by control, whatever the
  // score is computed over. Deduplicating what a reader *reads* changes no verdict, so it needs
  // no flag and no major version: one control tested in three profiles is one thing to read
  // about, with the profiles that confirmed it named on the card. The inventory stays
  // per-execution, because it is the searchable ledger and already carries a profile column.
  // A control nobody configured, and a probe module that crashed, are facts about the *setup* —
  // not about the target. Leaving them in the findings list makes a reader scroll past
  // "config.api.csrf.endpoint is not defined" looking for security results, and makes the list
  // longer than the assessment actually is. They are listed separately, and still counted in
  // coverage, because an unassessed control is exactly what coverage exists to report.
  const isSetupIssue = (f) => (f.status === "skip" && f.skipKind === "unconfigured") || f.id.endsWith("-ABORTED");
  const setupIssues = controls.filter(isSetupIssue);
  const displayFindings = controls.filter((f) => !isSetupIssue(f));
  const displayFails = displayFindings.filter((f) => f.status === "fail");
  const displayWarns = displayFindings.filter((f) => f.status === "warn");
  const displaySkips = displayFindings.filter((f) => f.status === "skip");

  const fails = allFindings.filter((f) => f.status === "fail");
  const warns = allFindings.filter((f) => f.status === "warn");
  const passes = allFindings.filter((f) => f.status === "pass");
  const skips = allFindings.filter((f) => f.status === "skip");
  const totalRequests = [...reports.values()].reduce((sum, r) => sum + (r.requestCount || 0), 0);

  const { domains: domainScores, overall: overallScore } = computeScores(allFindings);

  const hasCriticalFail = fails.some((f) => f.severity === "critical");
  const hasHighFail = fails.some((f) => f.severity === "high");
  const hasMediumFail = fails.some((f) => f.severity === "medium");
  const readiness = hasCriticalFail || hasHighFail ? "not-ready" : hasMediumFail || warns.length ? "caution" : "ready";
  const readinessLabel = readiness === "not-ready" ? "Not Ready" : readiness === "caution" ? "Caution" : "Ready";

  // ── categories → finding cards ────────────────────────────────────
  const categories = new Map();
  for (const f of displayFindings) {
    const meta = metaOf(f);
    if (!categories.has(meta.category)) categories.set(meta.category, []);
    categories.get(meta.category).push({ ...f, ...meta });
  }
  const catOrder = (name) => {
    const idx = DOMAIN_ORDER.indexOf(getDomain(name));
    return idx === -1 ? 99 : idx;
  };
  const sortedCategories = [...categories.entries()].sort((a, b) => {
    const failDiff = b[1].filter((f) => f.status === "fail").length - a[1].filter((f) => f.status === "fail").length;
    return failDiff !== 0 ? failDiff : catOrder(a[0]) - catOrder(b[0]);
  });

  const findingCards = sortedCategories
    .map(([cat, findings]) => {
      const catFails = findings.filter((f) => f.status === "fail").length;
      const header = `\n<div class="cat-header"><h4>${esc(cat)}</h4><span class="cat-badge">${catFails ? `${catFails} failed` : `${findings.length} tested`}</span></div>`;
      const statusRank = { fail: 0, warn: 1, pass: 2, skip: 3 };
      const cards = [...findings]
        .sort((a, b) => statusRank[a.status] - statusRank[b.status])
        .map(
          (f) => `
<details class="finding-card f-${f.status}">
  <summary class="finding-sum">
    <span class="tag ${statusCls(f.status)}">${f.status.toUpperCase()}</span>
    ${f.skipKind || f.warnKind ? `<span class="kind-badge" title="${esc(KIND_TIP[f.skipKind || f.warnKind] ?? "")}">${esc(f.skipKind || f.warnKind)}</span>` : ""}
    ${f.inconsistent ? `<span class="kind-badge" title="This control returned different outcomes in different profiles — the worst is shown. The evidence lists each one.">inconsistent</span>` : ""}
    ${severityBadge(f.severity, f.status)}
    <span class="finding-name">${esc(headline(f))}</span>
    ${(f.profiles ?? [f.profile]).filter(Boolean).map((p) => `<span class="env-badge">${esc(p)}</span>`).join(" ")}
    <span class="finding-id-tag">${esc(f.id)}</span>
  </summary>
  <div class="finding-body">
    ${f.status === "pass" ? "" : `<span class="finding-label">Expected control</span><p>${esc(f.title)}</p>`}
    ${f.purpose ? `<span class="finding-label">Purpose</span><p>${esc(f.purpose)}</p>` : ""}
    <span class="finding-label">Evidence</span>
    <pre>${esc(f.evidence)}</pre>
    ${f.remediation ? `<span class="finding-label fix">Remediation</span><p>${esc(f.remediation)}</p>` : ""}
  </div>
</details>`,
        )
        .join("");
      return header + cards;
    })
    .join("");

  // ── executive interpretation ──────────────────────────────────────
  // Written for someone deciding whether to ship, so it leads with the decision, then the
  // compound paths, then what is exposed. Every clause is derived from a finding already in
  // this report: the paths come from set intersection over failing IDs, and the exposure
  // statements are the probes' own observed-outcome strings. Nothing here is inferred
  // beyond what the evidence supports.
  const attackPaths = matchAttackPaths(new Set(fails.map((f) => f.id)));
  const blockers = fails.filter((f) => f.severity === "critical" || f.severity === "high");
  const domainRankOf = (d) => { const i = DOMAIN_ORDER.indexOf(d); return i === -1 ? 99 : i; };
  const failDomains = [...new Set(fails.map((f) => domainOf(f)))].sort((a, b) => domainRankOf(a) - domainRankOf(b));
  // Blockers are critical/high only, so their domains are a subset. Reporting the blocker
  // count against every failing domain overstated the blast radius.
  const blockerDomains = [...new Set(blockers.map((f) => domainOf(f)))].sort((a, b) => domainRankOf(a) - domainRankOf(b));
  const nonBlockerDomains = failDomains.filter((d) => !blockerDomains.includes(d));

  // A synopsis, not a list. Assembled deterministically from findings already in this
  // report — the verdict from readiness, the chain from set intersection over failing IDs,
  // the exposure statements from the probes' own observed-outcome strings. Detail lives one
  // section below, filterable, which is where detail belongs; this is what a person reads
  // before deciding whether to ship.
  const listOf = (items) =>
    items.length <= 1 ? items.join("") : items.slice(0, -1).join(", ") + " and " + items[items.length - 1];
  const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const worstIn = (items) =>
    [...items].sort((a, b) => (SEV_RANK[a.severity] ?? 5) - (SEV_RANK[b.severity] ?? 5))[0];

  const sentences = [];
  if (fails.length === 0 && warns.length === 0) {
    sentences.push(
      `<strong>No control failed in this run.</strong> ${passes.length} control${passes.length === 1 ? "" : "s"} held across ` +
        `${[...new Set(passes.map((f) => domainOf(f)))].length} trust domain${
          [...new Set(passes.map((f) => domainOf(f)))].length === 1 ? "" : "s"
        }.`,
    );
  } else {
    // The decision, and what it rests on.
    if (readiness === "not-ready") {
      const lead = worstIn(blockers);
      sentences.push(
        `<strong>Deployment should be blocked.</strong> ${blockers.length} production blocker${blockers.length === 1 ? "" : "s"} ` +
          `across ${listOf(blockerDomains.map(esc))} — most seriously, ${esc((lead.observed || metaOf(lead).purpose).replace(/[.]$/, "").toLowerCase())}.`,
      );
    } else if (readiness === "caution") {
      sentences.push(
        `<strong>Deploy only with a documented remediation plan.</strong> No critical or high-severity control failed, ` +
          `but ${fails.length + warns.length} item${fails.length + warns.length === 1 ? "" : "s"} need attention across ${listOf(failDomains.map(esc))}.`,
      );
    } else {
      sentences.push(`<strong>No blocking failure.</strong> ${fails.length} low-severity item${fails.length === 1 ? "" : "s"} recorded.`);
    }

    // The compound story, in one sentence.
    if (attackPaths.length === 1) {
      sentences.push(`They correlate into one control-failure chain: ${esc(attackPaths[0].impact.replace(/[.]$/, "").toLowerCase())}.`);
    } else if (attackPaths.length > 1) {
      sentences.push(
        `They correlate into ${attackPaths.length} control-failure chains, the most serious being ${esc(attackPaths[0].name.toLowerCase())}.`,
      );
    }

    // Everything below the blocking line, compressed to counts.
    const secondary = [];
    if (readiness === "not-ready" && nonBlockerDomains.length) {
      secondary.push(
        `${fails.length - blockers.length} further medium or low-severity failure${fails.length - blockers.length === 1 ? "" : "s"} in ${listOf(nonBlockerDomains.map(esc))}`,
      );
    }
    if (warns.length) secondary.push(`${warns.length} advisory warning${warns.length === 1 ? "" : "s"} with no confirmed exploit path`);
    if (secondary.length) sentences.push(`Alongside: ${listOf(secondary)}.`);
  }

  // Always close on what was not established — the most common way a report misleads.
  if (skips.length) {
    sentences.push(
      `${skips.length} control${skips.length === 1 ? "" : "s"} could not run and ${skips.length === 1 ? "remains" : "remain"} <em>unvalidated</em> — untested, not proven safe.`,
    );
  }

  const execSynopsis = sentences.join(" ");
  // Kept for the section renderer's older shape; the synopsis is the value that renders.
  const execBullets = [`      <li>${execSynopsis}</li>`];

  // ── root causes ───────────────────────────────────────────────────
  const rootCauseDomains = new Map();
  for (const f of [...fails, ...warns]) {
    const domain = domainOf(f);
    if (!rootCauseDomains.has(domain)) rootCauseDomains.set(domain, { count: 0, blocking: false, categories: new Set() });
    const entry = rootCauseDomains.get(domain);
    entry.count += 1;
    entry.categories.add(metaOf(f).category);
    if (f.status === "fail" && (f.severity === "critical" || f.severity === "high")) entry.blocking = true;
  }
  const rootCauseRows =
    [...rootCauseDomains.entries()]
      .sort((a, b) => {
        const rank = (name) => {
          const i = DOMAIN_ORDER.indexOf(name);
          return i === -1 ? 99 : i;
        };
        return rank(a[0]) - rank(b[0]);
      })
      .map(
        ([domain, d]) =>
          // When every failure in a domain shares one category, describe that category rather
          // than the domain — the domain statement is too coarse to match the evidence.
          `    <tr><td><span class="rc-dot ${d.blocking ? "bad" : "warn"}"></span></td><td class="rc-domain">${esc(domain)}</td><td class="rc-cause">${esc(
            (d.categories.size === 1 && CATEGORY_ROOT_CAUSE_MAP[[...d.categories][0]]) || ROOT_CAUSE_MAP[domain] || `${domain} controls need attention`,
          )} <span style="color:var(--muted)">(${d.count} finding${d.count > 1 ? "s" : ""})</span></td></tr>`,
      )
      .join("\n") || '    <tr><td colspan="3" style="color:var(--ok);">No architectural issues detected.</td></tr>';

  // ── verified trust controls ───────────────────────────────────────
  const trustDomainPasses = new Map();
  for (const f of passes) {
    const domain = domainOf(f);
    if (!trustDomainPasses.has(domain)) trustDomainPasses.set(domain, []);
    trustDomainPasses.get(domain).push(f);
  }
  function summarizeDomain(items) {
    const out = [];
    const consumed = new Set();
    for (const rule of SUMMARY_RULES) {
      const matches = items.map((f, i) => ({ f, i })).filter(({ f, i }) => !consumed.has(i) && rule.pattern.test(f.title));
      if (matches.length > 1) {
        out.push({ title: rule.summary, count: matches.length });
        matches.forEach(({ i }) => consumed.add(i));
      }
    }
    items.forEach((item, i) => {
      if (!consumed.has(i)) out.push({ title: item.title, count: 1 });
    });
    return out;
  }
  const VISIBLE_TB = 3;
  const trustVerifiedItems =
    [...trustDomainPasses.entries()]
      .sort((a, b) => b[1].length - a[1].length)
      .map(([domain, items]) => {
        const summarized = summarizeDomain(items);
        const visible = summarized
          .slice(0, VISIBLE_TB)
          .map((s) => `      <li>${esc(s.title)}${s.count > 1 ? ` <span style="color:var(--muted)">(${s.count})</span>` : ""}</li>`)
          .join("\n");
        let overflow = "";
        if (summarized.length > VISIBLE_TB) {
          const hidden = summarized
            .slice(VISIBLE_TB)
            .map((s) => `        <li>${esc(s.title)}${s.count > 1 ? ` <span style="color:var(--muted)">(${s.count})</span>` : ""}</li>`)
            .join("\n");
          overflow = `\n    <details class="tb-card-more">\n      <summary>+ ${summarized.length - VISIBLE_TB} more verified</summary>\n      <ul class="tb-card-list">\n${hidden}\n      </ul>\n    </details>`;
        }
        return `  <div class="tb-card">\n    <div class="tb-card-hdr">\n      <span class="rc-dot ok"></span>\n      <span class="tb-card-domain">${esc(domain)}</span>\n      <span class="tb-card-count">${items.length} passed</span>\n    </div>\n    <ul class="tb-card-list">\n${visible}\n    </ul>${overflow}\n  </div>`;
      })
      .join("\n") || '  <div style="color:var(--muted);font-size:12.5px;">No passing controls recorded.</div>';

  // ── tables ────────────────────────────────────────────────────────
  const profileRows = [...reports.entries()]
    .map(
      ([profile, data]) =>
        `    <tr><td><span class="env-badge">${esc(profile)}</span></td><td>${esc(data.generatedAt)}</td><td>${data.requestCount}</td>` +
        `<td><span class="tag ok">${data.summary.pass}</span></td>` +
        `<td>${data.summary.fail ? `<span class="tag bad">${data.summary.fail}</span>` : '<span class="tag ok">0</span>'}</td>` +
        `<td>${data.summary.warn ? `<span class="tag warn">${data.summary.warn}</span>` : "0"}</td>` +
        `<td>${data.summary.skip || 0}</td></tr>`,
    )
    .join("\n");

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  // Grouped by the fix, not by the finding. Seven header controls that all close with one change
  // to the CDN configuration are one piece of work and one ticket; seven identical rows
  // misrepresent the size of the job and bury the rows that actually differ.
  // Group on the canonical action where a probe declared one, and on the remediation sentence
  // otherwise. Grouping on the sentence alone groups nothing useful: six header controls carry
  // six different sentences and close with a single change to the edge configuration, which is
  // exactly the case a partner reported as "not grouped".
  const byRemediation = new Map();
  for (const f of [...displayFails, ...displayWarns]) {
    const key = f.fix || f.remediation || "See finding evidence.";
    if (!byRemediation.has(key)) byRemediation.set(key, { action: FIX_ACTIONS[f.fix] ?? f.remediation ?? "See finding evidence.", group: [] });
    byRemediation.get(key).group.push(f);
  }
  const remediationGroups = [...byRemediation.values()]
    .map(({ action, group }) => ({ action, group: [...group].sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5)) }))
    // Worst severity first, and where two groups tie, the one that closes more controls.
    .sort((a, b) => (sevOrder[a.group[0].severity] ?? 5) - (sevOrder[b.group[0].severity] ?? 5) || b.group.length - a.group.length);

  const remediationRows = remediationGroups
    .map(({ action, group }) => {
      const worst = group[0];
      const controls = group
        .map((f) => `<div>${esc(headline(f))} <span style="font-size:11px;color:var(--muted)">${esc(f.id)}</span></div>`)
        .join("");
      const count = group.length > 1 ? `<span class="cat-badge">closes ${group.length} controls</span>` : "";
      // The shared action is the ticket; the per-control sentences are what goes in it.
      const specifics =
        group.length > 1 && group.some((f) => f.remediation && f.remediation !== action)
          ? `<ul class="rem-specifics">${group
              .filter((f) => f.remediation && f.remediation !== action)
              .map((f) => `<li>${esc(f.remediation)}</li>`)
              .join("")}</ul>`
          : "";
      return (
        `    <tr data-status="${esc(worst.status)}" data-severity="${esc(worst.severity)}">` +
        `<td>${severityBadge(worst.severity, worst.status)}</td>` +
        `<td>${controls}${count}</td>` +
        `<td>${esc(action)}${specifics}</td>` +
        `<td><span class="env-badge">${esc(ownerFor(worst, domainOf(worst)))}</span></td></tr>`
      );
    })
    .join("\n");

  // ── Remediation workstreams ───────────────────────────────────────
  // Ten rows sharing one cause is ten tickets and one fix. Grouping by trust domain gives
  // the unit of work an engineering team actually takes on, with the priority set by the
  // worst finding in the group and the closure criterion taken from the control assertions.
  const WORKSTREAM_NAMES = {
    "Assessment Integrity": "Test-harness integrity",
    "Identity Binding": "Token-bound identity",
    Authentication: "Authentication policy and session lifecycle",
    Authorization: "Owner and tenant scoping",
    "Input Handling": "Input validation and output encoding",
    "AI Runtime": "Agent boundary enforcement",
    "LLM Safety": "LLM input/output controls",
    Infrastructure: "Platform and transport hardening",
    Platform: "Platform controls",
  };
  const workstreamMap = new Map();
  for (const f of [...fails, ...warns]) {
    const domain = domainOf(f);
    if (!workstreamMap.has(domain)) workstreamMap.set(domain, []);
    workstreamMap.get(domain).push(f);
  }
  const priorityOf = (items) => {
    if (items.some((f) => f.status === "fail" && (f.severity === "critical" || f.severity === "high"))) return { label: "P0", cls: "bad" };
    if (items.some((f) => f.status === "fail" && f.severity === "medium")) return { label: "P1", cls: "warn" };
    return { label: "P2", cls: "skip" };
  };
  const workstreams = [...workstreamMap.entries()]
    .sort((a, b) => {
      const rank = { P0: 0, P1: 1, P2: 2 };
      return rank[priorityOf(a[1]).label] - rank[priorityOf(b[1]).label] || b[1].length - a[1].length;
    })
    .map(([domain, items]) => {
      const priority = priorityOf(items);
      const inPath = attackPaths.filter((p) => p.evidence.some((id) => items.some((f) => f.id === id)));
      return { domain, name: WORKSTREAM_NAMES[domain] ?? `${domain} controls`, items, priority, inPath };
    });
  const workstreamRows = workstreams
    .map(
      (w) =>
        `    <tr><td><span class="tag ${w.priority.cls}">${w.priority.label}</span></td>` +
        `<td><strong>${esc(w.name)}</strong><div class="ws-meta">${esc(w.domain)} · owners: ${esc([...new Set(w.items.map((f) => ownerFor(f, domainOf(f))))].join(", "))}` +
        `${w.inPath.length ? ` · on ${w.inPath.length} attack path${w.inPath.length > 1 ? "s" : ""}` : ""}</div></td>` +
        `<td>${w.items.length}<div class="ws-meta">${w.items.map((f) => `<code>${esc(f.id)}</code>`).join(" ")}</div></td>` +
        `<td class="ws-criteria">${w.items.map((f) => `<span class="ws-crit">${esc(f.title)}</span>`).join("")}</td></tr>`,
    )
    .join("\n");

  // ── Retest requirements ───────────────────────────────────────────
  // "Remediation deployed" is not an acceptance criterion. Each row now carries the exact
  // command that re-runs the control and the condition under which it closes — the assertion
  // itself, which is the one statement that must become true.
  const retestCommand = (f) => `trust run --config <config> --profile ${f.profile}`;
  const retestRows =
    [
      ...[...displayFails, ...displayWarns].map(
        (f) =>
          `    <tr><td><span class="tag ${statusCls(f.status)}">${f.status.toUpperCase()}</span> <code>${esc(f.id)}</code></td>` +
          `<td><strong>${esc(f.title)}</strong><div class="ws-meta">must hold before this control closes</div></td>` +
          `<td><code class="retest-cmd">${esc(retestCommand(f))}</code></td></tr>`,
      ),
      ...displaySkips
        .filter((f) => f.skipKind !== "not-applicable")
        .map(
        (f) =>
          `    <tr><td><span class="tag skip">SKIP</span> <code>${esc(f.id)}</code></td>` +
          `<td><strong>${esc(f.title)}</strong><div class="ws-meta">unblock first: ${esc(f.evidence.replace(/^Skipped:\s*/, ""))}</div></td>` +
          `<td><code class="retest-cmd">${esc(retestCommand(f))}</code></td></tr>`,
      ),
    ].join("\n") || '    <tr><td colspan="3" style="color:var(--ok)">Nothing outstanding — every control reached a verdict.</td></tr>';

  // Filtering reads these data attributes rather than scraping cell text, so a change to
  // how a status or severity is *rendered* can never silently break the filters.
  const inventoryRows = executions
    .map((f) => {
      const category = metaOf(f).category;
      return (
        `    <tr data-status="${esc(f.status)}" data-severity="${esc(f.severity)}" data-category="${esc(category)}" data-profile="${esc(f.profile)}" data-tags="${esc(tagsFor(f.id, category).join(" "))}">` +
        `<td><span class="tag ${statusCls(f.status)}">${f.status.toUpperCase()}</span></td>` +
        `<td>${severityBadge(f.severity, f.status)}</td>` +
        `<td><span class="finding-id-tag">${esc(f.id)}</span></td>` +
        `<td>${esc(category)}</td><td>${esc(headline(f))}</td>` +
        `<td><span class="env-badge">${esc(f.profile)}</span></td></tr>`
      );
    })
    .join("\n");

  // Only offer a filter value that actually occurs in this report — an empty filter is a
  // dead end, and the counts tell the reader where the weight sits before they choose.
  const countBy = (key) => {
    const counts = new Map();
    for (const f of allFindings) {
      const value = key === "category" ? metaOf(f).category : f[key];
      counts.set(value, (counts.get(value) ?? 0) + 1);
    }
    return counts;
  };
  const STATUS_ORDER = ["fail", "warn", "pass", "skip"];
  const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
  const byOrder = (order) => (a, b) => order.indexOf(a[0]) - order.indexOf(b[0]);
  const inventoryFacets = {
    statuses: [...countBy("status")].sort(byOrder(STATUS_ORDER)).map(([value, count]) => ({ value, count })),
    severities: [...countBy("severity")].sort(byOrder(SEVERITY_ORDER)).map(([value, count]) => ({ value, count })),
    categories: [...countBy("category")].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([value, count]) => ({ value, count })),
    profiles: [...countBy("profile")].map(([value, count]) => ({ value, count })),
    // Compliance filtering belongs in the report too: reading "show me OWASP API-2" should not
    // require re-running the CLI with --tag.
    tags: [...executions.reduce((acc, f) => {
      for (const tag of tagsFor(f.id, f.category)) acc.set(tag, (acc.get(tag) ?? 0) + 1);
      return acc;
    }, new Map())]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([value, count]) => ({ value, count })),
  };

  const profileScopeRows = [...reports.entries()]
    .map(
      ([profile, data]) =>
        `    <tr><td><span class="env-badge">${esc(profile)}</span></td><td>${esc([...new Set(data.findings.map((f) => metaOf(f).category))].join(", "))}</td><td>${data.findings.length}</td><td><span class="tag ok">Executed</span></td></tr>`,
    )
    .join("\n");

  const safety = first.safety ?? {};
  const limitations = [
    ...new Set([
      ...(first.limitations ?? []),
      ...(safety.allowWrites === false ? ["Writes disabled — mutation and delete paths were not exercised."] : []),
      ...(safety.allowAgentInvocations === false ? ["Agent invocations disabled — LLM safety probes did not run."] : []),
      ...(skips.length ? [`${skips.length} test(s) skipped for missing credentials or unmet preconditions — see Retest Requirements.`] : []),
      "Client-perspective testing only: server-side code review, infrastructure scanning and dependency auditing are out of scope.",
    ]),
  ];

  const profileBadges = [...reports.keys()].map((p) => `<span class="env-badge">${esc(p)}</span>`).join(" ") || "none";

  // ── Scope, derived rather than described ──────────────────────────
  // Surfaces come from the config the runs actually used, and each one is cross-referenced
  // with the findings it produced. A surface that was configured but only ever skipped is
  // reported as "configured, not exercised" — never as tested.
  const SURFACE_PREFIX = {
    web: /^WEB-/,
    api: /^API-/,
    auth: /^AUTH-/,
    storage: /^STORAGE-/,
    agent: /^AGENT-/,
    mobile: /^MOBILE-/,
  };
  // Counts are attributed per declaring run, not per prefix across the whole set: two runs
  // against different targets must not each claim the other's findings.
  const surfaces = [];
  for (const [profile, run] of reports) {
    for (const declared of run.surfaces ?? []) {
      let surface = surfaces.find((s) => s.kind === declared.kind && s.target === declared.target);
      if (!surface) {
        surface = { ...declared, profiles: [], tested: 0, skipped: 0, failed: 0, total: 0 };
        surfaces.push(surface);
      }
      if (!surface.profiles.includes(profile)) surface.profiles.push(profile);
      const pattern = SURFACE_PREFIX[surface.kind];
      const related = pattern ? run.findings.filter((f) => pattern.test(f.id)) : [];
      surface.tested += related.filter((f) => f.status !== "skip").length;
      surface.skipped += related.filter((f) => f.status === "skip").length;
      surface.failed += related.filter((f) => f.status === "fail").length;
      surface.total += related.length;
    }
  }
  const scopeRows =
    surfaces
      .map((s) => {
        const verdict =
          s.tested === 0
            ? '<span class="tag skip">Not exercised</span>'
            : s.failed > 0
              ? `<span class="tag bad">${s.failed} failed</span>`
              : '<span class="tag ok">Controls held</span>';
        return (
          `    <tr><td>${esc(s.label)}</td><td><code style="font-size:11.5px;color:var(--muted)">${esc(s.target)}</code>` +
          `${s.detail ? `<br/><span style="font-size:11px;color:var(--muted)">${esc(s.detail)}</span>` : ""}</td>` +
          `<td>${s.tested}${s.skipped ? ` <span style="color:var(--muted)">(+${s.skipped} skipped)</span>` : ""}</td><td>${verdict}</td></tr>`
        );
      })
      .join("\n") || '    <tr><td colspan="4" style="color:var(--muted)">No surfaces recorded in the run data.</td></tr>';

  // Hosts the harness was permitted to contact — the technical boundary of the engagement.
  const allowedHosts = [...new Set([...reports.values()].flatMap((r) => r.allowedHosts ?? []))];

  // ── Coverage ──────────────────────────────────────────────────────
  // A score computed only over executed controls is not a statement about the target's
  // posture. Coverage is reported alongside it, and the label changes when it is partial,
  // so a run of one passing test can never present itself as 100.
  const seenIds = new Set(allFindings.map((f) => f.id));
  // Only controls that could apply to this target count towards coverage. An API-only
  // assessment must not be marked down for mobile probes that were never configured.
  const SURFACE_OF_ID = [
    [/^TOKEN-/, ["api", "agent", "storage", "auth"]],
    [/^WEB-|^INJECT-/, ["web"]],
    [/^API-|^SESSION-/, ["api"]],
    [/^AUTH-/, ["auth", "api"]],
    [/^IDP-/, ["idp", "auth"]],
    [/^STORAGE-/, ["storage"]],
    [/^AGENT-/, ["agent"]],
    [/^MOBILE-/, ["mobile"]],
  ];
  const configuredKinds = new Set(surfaces.map((s) => s.kind));
  const applies = (id) => {
    const rule = SURFACE_OF_ID.find(([pattern]) => pattern.test(id));
    if (!rule) return true; // an unrecognised (partner) ID is assumed in scope
    return rule[1].some((kind) => configuredKinds.has(kind));
  };
  const catalogued = listCatalog().filter((e) => !e.id.endsWith("-CONFIG") && applies(e.id));
  const notRun = catalogued.filter((e) => !seenIds.has(e.id));
  const assessedCount = allFindings.filter((f) => f.status !== "skip").length;
  const unvalidatedCount = skips.length;
  const applicableCount = assessedCount + unvalidatedCount + notRun.length;
  const coveragePct = applicableCount > 0 ? Math.round((assessedCount / applicableCount) * 100) : 0;
  const partialCoverage = coveragePct < 100;
  const postureLabel = partialCoverage ? "Assessed Security Posture" : "Security Posture";

  // Domains with no verdict at all are shown as Not Assessed rather than omitted: an absent
  // domain reads as "nothing to report", which is the opposite of what it means.
  const knownDomains = [...new Set(Object.values(CATALOG).map((meta) => getDomain(meta.category)))];
  for (const domain of knownDomains) {
    if (domainScores.has(domain)) continue;
    domainScores.set(domain, { score: null, status: "skip", pass: 0, fail: 0, warn: 0, skip: 0, totalWeight: 0, passWeight: 0, notAssessed: true });
  }
  const assessedDomains = [...domainScores.values()].filter((d) => !d.notAssessed && d.totalWeight > 0).length;
  // A skip that means "nobody looked" and one that means "this cannot apply here" are
  // different facts about coverage. Counting them together is how a run reads as safer than it
  // is: the unconfigured ones are precisely the controls a team still owes itself.
  const skipsByKindCount = { unconfigured: 0, "not-applicable": 0, precondition: 0 };
  const skipsByKind = skipsByKindCount;
  // Every skipped control, including the unconfigured ones now listed under Setup. Coverage is
  // the one place they must still be counted: moving them out of the findings list changes
  // where they are *read*, never whether they count against what the run covered.
  for (const f of controls.filter((c) => c.status === "skip")) {
    skipsByKindCount[f.skipKind ?? "unconfigured"] = (skipsByKindCount[f.skipKind ?? "unconfigured"] ?? 0) + 1;
  }

  // Two numbers, because "how much of the catalogue applies here" and "how much of what this
  // configuration can reach did we assess" are different questions, and reporting only the first
  // is what the partner called conflating "not configured" with "gap". The second is the one a
  // team acts on this week; the first is the one that says how much more is possible.
  const reachableDenominator = applicableCount - skipsByKindCount.unconfigured - notRun.length;
  const reachablePct = reachableDenominator > 0 ? Math.round((assessedCount / reachableDenominator) * 100) : coveragePct;

  const coverage = {
    reachablePercent: reachablePct,
    reachableOf: reachableDenominator,
    assessed: assessedCount,
    unvalidated: unvalidatedCount,
    skipsByKind,
    notRun: notRun.length,
    applicable: applicableCount,
    percent: coveragePct,
    partial: partialCoverage,
    domainsAssessed: assessedDomains,
    domainsKnown: domainScores.size,
    notRunIds: notRun.map((e) => e.id),
  };

  // ── Attack paths ──────────────────────────────────────────────────
  // Matched above, before the executive interpretation, which narrates them.
  const attackPathRows =
    attackPaths
      .map(
        (path) =>
          `    <tr><td><span class="rc-dot bad"></span></td><td class="rc-cause"><strong>${esc(path.name)}</strong>` +
          `<div class="path-steps">${path.steps.map((step, i) => `<span class="path-step"><b>${i + 1}</b>${esc(step)}</span>`).join("")}</div>` +
          `<div class="path-impact">${esc(path.impact)}</div>` +
          `<div class="path-evidence">Corroborated by ${path.evidence.length} failing control(s): ${path.evidence.map((id) => `<code>${esc(id)}</code>`).join(" ")}</div></td>` +
          `<td>${path.blocker ? '<span class="tag bad">Blocker</span>' : '<span class="tag warn">Review</span>'}</td></tr>`,
      )
      .join("\n");

  return {
    first,
    assessmentName,
    target,
    environment,
    dateStr,
    allFindings,
    fails,
    warns,
    passes,
    skips,
    totalRequests,
    domainScores,
    overallScore,
    hasCriticalFail,
    hasHighFail,
    hasMediumFail,
    readiness,
    readinessLabel,
    categories,
    sortedCategories,
    findingCards,
    execBullets,
    execSynopsis,
    rootCauseRows,
    trustVerifiedItems,
    provenance: {
      runIds: [...reports.values()].map((r) => r.runId).filter(Boolean),
      generatedAt: first.generatedAt ?? null,
      timezone: first.timezone ?? null,
      commit: first.commit ?? null,
      branch: first.branch ?? null,
      ci: first.ci ?? false,
      toolVersion: first.toolVersion ?? null,
      configHash: first.configHash ?? null,
      catalogHash: first.catalogHash ?? null,
      catalogSize: first.catalogSize ?? null,
      credentials: first.credentials ?? [],
    },
    unitCounts,
    executions,
    controls,
    setupIssues,
    setupRows: setupIssues
      .map(
        (f) =>
          `    <tr data-status="${esc(f.status)}"><td><span class="tag ${statusCls(f.status)}">${f.status.toUpperCase()}</span> <code>${esc(f.id)}</code></td>` +
          `<td>${esc(f.title)}</td><td>${esc(String(f.evidence).replace(/^Skipped:\s*/, ""))}</td></tr>`,
      )
      .join("\n"),
    displayFindings,
    remediationGroups,
    profileRows,
    profileScopeRows,
    remediationRows,
    retestRows,
    inventoryRows,
    inventoryFacets,
    safety,
    limitations,
    profileBadges,
    surfaces,
    scopeRows,
    allowedHosts,
    coverage,
    postureLabel,
    attackPaths,
    attackPathRows,
    workstreams,
    workstreamRows,
  };
}
