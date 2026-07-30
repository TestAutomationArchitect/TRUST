/**
 * TRUST — the assessment model.
 *
 * Turns raw per-profile run JSON into every value the report renders: status buckets,
 * domain scores, readiness, root causes, the row and card fragments, and the derived
 * limitations list. Sections render from this model and derive nothing themselves, so a
 * new output (SARIF, a run-over-run delta, a dashboard feed) can reuse it unchanged.
 */

import { getTestMeta, getDomain, domainForId, ROOT_CAUSE_MAP, DOMAIN_ORDER, SUMMARY_RULES, CATALOG, listCatalog, matchAttackPaths } from "../catalog.mjs";
import { computeScores } from "./scoring.mjs";
import { esc, severityBadge, statusCls, ownerFor } from "./html.mjs";
import { headline } from "../finding.mjs";

/** Derive the model. `title` overrides the assessment name taken from the run. */
export function buildModel(reports, { title = "" } = {}) {
  const first = reports.values().next().value ?? {};
  const assessmentName = title || `${first.name ?? "Target"} — Security Trust Assessment`;
  const target = first.target ?? "Unknown";
  const environment = first.environment ?? "unknown";
  const dateStr = new Date().toLocaleDateString("en-GB", { year: "numeric", month: "long", day: "numeric" });

  const allFindings = [];
  for (const [profile, data] of reports) {
    for (const f of data.findings) allFindings.push({ ...f, profile });
  }

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
  for (const f of allFindings) {
    const meta = getTestMeta(f.id);
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
    ${severityBadge(f.severity, f.status)}
    <span class="finding-name">${esc(headline(f))}</span>
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
  const failDomains = [...new Set(fails.map((f) => domainForId(f.id)))].sort((a, b) => domainRankOf(a) - domainRankOf(b));
  // Blockers are critical/high only, so their domains are a subset. Reporting the blocker
  // count against every failing domain overstated the blast radius.
  const blockerDomains = [...new Set(blockers.map((f) => domainForId(f.id)))].sort((a, b) => domainRankOf(a) - domainRankOf(b));
  const nonBlockerDomains = failDomains.filter((d) => !blockerDomains.includes(d));

  const execBullets = [];
  if (fails.length === 0 && warns.length === 0) {
    execBullets.push(
      `      <li><strong>No control failed in this run.</strong> ${passes.length} control(s) were validated across ` +
        `${[...new Set(passes.map((f) => domainForId(f.id)))].length} trust domain(s). Read this alongside the coverage figure below — it is a statement about what was tested.</li>`,
    );
  } else {
    // 1. The decision.
    const verdict =
      readiness === "not-ready"
        ? `<strong>Deployment should be blocked.</strong> ${blockers.length} production blocker(s) confirmed across ${blockerDomains.length} trust domain(s)`
        : readiness === "caution"
          ? `<strong>Deploy only with a documented remediation plan.</strong> No critical or high-severity control failed, but ${fails.length + warns.length} item(s) need attention`
          : `<strong>No blocking failure.</strong> ${fails.length} low-severity item(s) recorded`;
    const verdictDomains = readiness === "not-ready" ? blockerDomains : failDomains;
    const alsoAffected =
      readiness === "not-ready" && nonBlockerDomains.length
        ? ` ${fails.length - blockers.length} further medium or low-severity failure(s) affect ${esc(nonBlockerDomains.join(" and "))}.`
        : "";
    execBullets.push(`      <li>${verdict}: ${esc(verdictDomains.join(", "))}.${alsoAffected}</li>`);

    // 2. The compound story, where the evidence supports one.
    if (attackPaths.length) {
      const paths = attackPaths
        .map((p) => `        <li><strong>${esc(p.name)}</strong> — ${esc(p.impact)}</li>`)
        .join("\n");
      execBullets.push(
        `      <li>${attackPaths.length} corroborated attack path${attackPaths.length > 1 ? "s" : ""}, each depending only on controls that failed in this run:\n` +
          `        <ul class="exec-sub">\n${paths}\n        </ul>\n      </li>`,
      );
    }

    // 3. What is exposed, in the probes' own words, grouped by domain and worst-first.
    const byDomain = new Map();
    for (const f of fails) {
      const domain = domainForId(f.id);
      if (!byDomain.has(domain)) byDomain.set(domain, []);
      byDomain.get(domain).push(f);
    }
    for (const [domain, items] of [...byDomain.entries()].sort((a, b) => domainRankOf(a[0]) - domainRankOf(b[0]))) {
      const statements = [...new Set(items.map((f) => (f.observed || getTestMeta(f.id).purpose).replace(/.$/, "")))];
      if (statements.length === 1) {
        execBullets.push(`      <li><strong>${esc(domain)}</strong>: ${esc(statements[0])}.</li>`);
      } else {
        const subs = statements.map((line) => `        <li>${esc(line)}</li>`).join("\n");
        execBullets.push(
          `      <li><strong>${esc(domain)}</strong> — ${items.length} control(s) not upheld:\n        <ul class="exec-sub">\n${subs}\n        </ul>\n      </li>`,
        );
      }
    }

    if (warns.length) {
      const warnCats = new Map();
      for (const f of warns) {
        const cat = getTestMeta(f.id).category;
        warnCats.set(cat, (warnCats.get(cat) ?? 0) + 1);
      }
      const parts = [...warnCats.entries()].map(([c, n]) => `${c} (${n})`).join(", ");
      execBullets.push(
        `      <li>${warns.length} advisory warning${warns.length > 1 ? "s" : ""} in: ${esc(parts)}. Review recommended; no confirmed exploit path.</li>`,
      );
    }
  }
  if (skips.length) {
    const skipCats = new Map();
    for (const f of skips) {
      const cat = getTestMeta(f.id).category;
      skipCats.set(cat, (skipCats.get(cat) ?? 0) + 1);
    }
    const parts = [...skipCats.entries()].map(([c, n]) => `${c} (${n})`).join(", ");
    execBullets.push(
      `      <li>${skips.length} test${skips.length > 1 ? "s were" : " was"} skipped for missing credentials or unmet preconditions: ${esc(parts)}. These controls remain <em>unvalidated</em>, not proven safe.</li>`,
    );
  }

  // ── root causes ───────────────────────────────────────────────────
  const rootCauseDomains = new Map();
  for (const f of [...fails, ...warns]) {
    const domain = domainForId(f.id);
    if (!rootCauseDomains.has(domain)) rootCauseDomains.set(domain, { count: 0, blocking: false });
    const entry = rootCauseDomains.get(domain);
    entry.count += 1;
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
          `    <tr><td><span class="rc-dot ${d.blocking ? "bad" : "warn"}"></span></td><td class="rc-domain">${esc(domain)}</td><td class="rc-cause">${esc(ROOT_CAUSE_MAP[domain] ?? `${domain} controls need attention`)} <span style="color:var(--muted)">(${d.count} finding${d.count > 1 ? "s" : ""})</span></td></tr>`,
      )
      .join("\n") || '    <tr><td colspan="3" style="color:var(--ok);">No architectural issues detected.</td></tr>';

  // ── verified trust controls ───────────────────────────────────────
  const trustDomainPasses = new Map();
  for (const f of passes) {
    const domain = domainForId(f.id);
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
  const remediationRows = [...fails, ...warns]
    .sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5))
    .map(
      (f) =>
        `    <tr><td>${severityBadge(f.severity, f.status)}</td><td>${esc(headline(f))}<br/><span style="font-size:11px;color:var(--muted)">${esc(f.id)}</span></td><td>${esc(f.remediation || "See finding evidence.")}</td><td><span class="env-badge">${esc(ownerFor(f.id))}</span></td></tr>`,
    )
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
    const domain = domainForId(f.id);
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
        `<td><strong>${esc(w.name)}</strong><div class="ws-meta">${esc(w.domain)} · owners: ${esc([...new Set(w.items.map((f) => ownerFor(f.id)))].join(", "))}` +
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
      ...[...fails, ...warns].map(
        (f) =>
          `    <tr><td><span class="tag ${statusCls(f.status)}">${f.status.toUpperCase()}</span> <code>${esc(f.id)}</code></td>` +
          `<td><strong>${esc(f.title)}</strong><div class="ws-meta">must hold before this control closes</div></td>` +
          `<td><code class="retest-cmd">${esc(retestCommand(f))}</code></td></tr>`,
      ),
      ...skips.map(
        (f) =>
          `    <tr><td><span class="tag skip">SKIP</span> <code>${esc(f.id)}</code></td>` +
          `<td><strong>${esc(f.title)}</strong><div class="ws-meta">unblock first: ${esc(f.evidence.replace(/^Skipped:\s*/, ""))}</div></td>` +
          `<td><code class="retest-cmd">${esc(retestCommand(f))}</code></td></tr>`,
      ),
    ].join("\n") || '    <tr><td colspan="3" style="color:var(--ok)">Nothing outstanding — every control reached a verdict.</td></tr>';

  // Filtering reads these data attributes rather than scraping cell text, so a change to
  // how a status or severity is *rendered* can never silently break the filters.
  const inventoryRows = allFindings
    .map((f) => {
      const category = getTestMeta(f.id).category;
      return (
        `    <tr data-status="${esc(f.status)}" data-severity="${esc(f.severity)}" data-category="${esc(category)}" data-profile="${esc(f.profile)}">` +
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
      const value = key === "category" ? getTestMeta(f.id).category : f[key];
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
  };

  const profileScopeRows = [...reports.entries()]
    .map(
      ([profile, data]) =>
        `    <tr><td><span class="env-badge">${esc(profile)}</span></td><td>${esc([...new Set(data.findings.map((f) => getTestMeta(f.id).category))].join(", "))}</td><td>${data.findings.length}</td><td><span class="tag ok">Executed</span></td></tr>`,
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
  const catalogued = listCatalog().filter((e) => !e.id.endsWith("-CONFIG"));
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
  const coverage = {
    assessed: assessedCount,
    unvalidated: unvalidatedCount,
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
    rootCauseRows,
    trustVerifiedItems,
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
