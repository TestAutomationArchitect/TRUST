/**
 * Trends — how posture, coverage, blockers and each trust domain have moved across runs.
 *
 * Renders nothing on a first run: there is no trend in a single point, and drawing one would
 * imply a history that does not exist. When the previous run measured something different —
 * changed config, changed catalogue, different profiles — the delta is still shown but marked
 * as not comparable, because a score moving because the denominator moved is not an
 * improvement.
 *
 * Charts are inline SVG with no library and no external request, so the report stays a single
 * self-contained file.
 */

import { esc, sectionCard } from "../html.mjs";

/**
 * A smooth sparkline.
 *
 * A polyline through a handful of runs looks jagged and reads as more volatile than the data
 * is. This interpolates with Catmull-Rom converted to cubic Bézier, which passes through every
 * point (so no value is misrepresented) while curving between them. Control points are clamped
 * to the plot band so an overshoot cannot draw outside the chart.
 */
function smoothPath(values, width, height, pad = 4) {
  const n = values.length;
  const step = n > 1 ? width / (n - 1) : width;
  const clamp = (v) => Math.max(pad, Math.min(height - pad, v));
  const y = (v) => clamp(height - pad - (Math.max(0, Math.min(100, v)) / 100) * (height - pad * 2));
  const pts = values.map((v, i) => ({ x: i * step, y: y(v) }));
  if (pts.length < 2) return "";

  let d = `M${pts[0].x.toFixed(1)},${pts[0].y.toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] ?? pts[i];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[i + 2] ?? p2;
    // Catmull-Rom → Bézier, tension 1/6 for a gentle curve that stays close to the data.
    const c1 = { x: p1.x + (p2.x - p0.x) / 6, y: clamp(p1.y + (p2.y - p0.y) / 6) };
    const c2 = { x: p2.x - (p3.x - p1.x) / 6, y: clamp(p2.y - (p3.y - p1.y) / 6) };
    d += ` C${c1.x.toFixed(1)},${c1.y.toFixed(1)} ${c2.x.toFixed(1)},${c2.y.toFixed(1)} ${p2.x.toFixed(1)},${p2.y.toFixed(1)}`;
  }
  return { d, pts };
}

function sparkline(values, { width = 300, height = 48, colour = "var(--accent)", fill = true, id = "" } = {}) {
  const usable = values.filter((v) => typeof v === "number" && Number.isFinite(v));
  if (usable.length < 2) return '<div class="spark-empty">not enough history yet</div>';
  const { d, pts } = smoothPath(usable, width, height);
  const gradId = `g-${id || Math.abs(usable.join("").length)}-${usable.length}`;
  const area = fill ? `${d} L${pts[pts.length - 1].x.toFixed(1)},${height} L${pts[0].x.toFixed(1)},${height} Z` : "";
  const last = pts[pts.length - 1];
  return `<svg class="spark" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="trend over the last ${usable.length} runs">
  <defs><linearGradient id="${gradId}" x1="0" x2="0" y1="0" y2="1">
    <stop offset="0%" stop-color="${colour}" stop-opacity=".28"/><stop offset="100%" stop-color="${colour}" stop-opacity="0"/>
  </linearGradient></defs>
  ${fill ? `<path d="${area}" fill="url(#${gradId})" stroke="none"/>` : ""}
  <path d="${d}" fill="none" stroke="${colour}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
  <circle cx="${last.x.toFixed(1)}" cy="${last.y.toFixed(1)}" r="3" fill="${colour}"/>
</svg>`;
}

/** A tiny inline bar for a domain row — enough to show direction without a second chart. */
function microline(values, colour) {
  const usable = values.filter((v) => typeof v === "number" && Number.isFinite(v));
  if (usable.length < 2) return '<span class="micro-empty">—</span>';
  const { d } = smoothPath(usable, 90, 22, 3);
  return `<svg class="micro" viewBox="0 0 90 22" preserveAspectRatio="none" aria-hidden="true"><path d="${d}" fill="none" stroke="${colour}" stroke-width="1.75" stroke-linecap="round" vector-effect="non-scaling-stroke"/></svg>`;
}

const delta = (n, { invert = false, suffix = "" } = {}) => {
  if (n === null || n === undefined) return '<span class="delta flat">—</span>';
  if (n === 0) return '<span class="delta flat">no change</span>';
  const good = invert ? n < 0 : n > 0;
  return `<span class="delta ${good ? "good" : "bad"}">${n > 0 ? "▲" : "▼"} ${Math.abs(n)}${suffix}</span>`;
};

const shortDate = (iso) => {
  try {
    return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
  } catch {
    return String(iso ?? "");
  }
};

export function renderTrends(model) {
  const { trends } = model;
  if (!trends || !trends.delta) return "";
  const { delta: d, points, entry, history } = trends;

  const idList = (ids, cls, empty = "none") =>
    ids.length
      ? `<div class="trend-ids">${ids.slice(0, 16).map((id) => `<code class="trend-id ${cls}">${esc(id)}</code>`).join("")}${
          ids.length > 16 ? `<span class="trend-more">+${ids.length - 16} more</span>` : ""
        }</div>`
      : `<div class="trend-ids trend-none">${empty}</div>`;

  const domainRows = d.domains
    .map((dom) => {
      const colour = dom.now === null ? "var(--muted)" : dom.now >= 90 ? "var(--ok)" : dom.now >= 50 ? "var(--warn)" : "var(--bad)";
      return `    <tr>
      <td>${esc(dom.name)}${dom.state ? `<div class="ws-meta">${esc(dom.state)}</div>` : ""}</td>
      <td class="num">${dom.before ?? "—"}</td>
      <td class="num"><strong>${dom.now ?? "—"}</strong></td>
      <td>${delta(dom.delta)}</td>
      <td class="micro-cell">${microline(trends.domainSeries[dom.name] ?? [], colour)}</td>
    </tr>`;
    })
    .join("\n");

  const historyRows = [...(history ?? [])]
    .slice(-12)
    .reverse()
    .map(
      (r) => `    <tr${r.runId === entry.runId ? ' class="is-current"' : ""}>
      <td>${esc(shortDate(r.at))}${r.runId === entry.runId ? ' <span class="sc-chip">this run</span>' : ""}</td>
      <td><code>${esc((r.runId ?? "").slice(0, 8))}</code></td>
      <td><code>${esc((r.commit ?? "—").slice(0, 8))}</code>${r.branch ? `<div class="ws-meta">${esc(r.branch)}</div>` : ""}</td>
      <td>${esc((r.profiles ?? []).join(", "))}</td>
      <td class="num">${r.score}</td>
      <td class="num">${r.coverage?.percent ?? "—"}%</td>
      <td class="num">${r.counts?.blockers ?? "—"}</td>
      <td><span class="tag ${r.readiness === "ready" ? "ok" : r.readiness === "caution" ? "warn" : "bad"}">${esc(r.readiness ?? "")}</span></td>
    </tr>`,
    )
    .join("\n");

  return sectionCard({
    id: "section-trends",
    title: `Trends`,
    badge:
      `<span class="sc-chip ${d.scoreDelta >= 0 ? "sc-chip-ready" : "sc-chip-bad"}">${d.scoreDelta >= 0 ? "+" : ""}${d.scoreDelta} score</span>` +
      `${d.introduced.length ? `<span class="sc-chip sc-chip-bad">${d.introduced.length} new</span>` : ""}` +
      `${d.fixed.length ? `<span class="sc-chip sc-chip-ready">${d.fixed.length} fixed</span>` : ""}` +
      `<span class="sc-chip">${d.runsRecorded} runs</span>`,
    open: false,
    body: `${
      d.comparable
        ? ""
        : `<div class="callout callout-warn"><strong>Not directly comparable.</strong> ${esc(d.caveats.join("; "))}. The figures below are shown for continuity, but a change here does not necessarily mean the target changed.</div>`
    }

<div class="trend-grid">
  <div class="trend-card">
    <div class="trend-label">Assessed posture</div>
    <div class="trend-value">${entry.score}<span class="trend-delta">${delta(d.scoreDelta)}</span></div>
    ${sparkline(points.map((p) => p.score), { id: "score" })}
    <div class="trend-foot">previous ${d.previous.score} · ${d.runsRecorded} run(s) since ${esc(shortDate(d.firstSeen))}</div>
  </div>
  <div class="trend-card">
    <div class="trend-label">Coverage</div>
    <div class="trend-value">${entry.coverage.percent}%<span class="trend-delta">${delta(d.coverageDelta, { suffix: "%" })}</span></div>
    ${sparkline(points.map((p) => p.coverage), { colour: "var(--ok)", id: "cov" })}
    <div class="trend-foot">${entry.coverage.assessed} of ${entry.coverage.applicable} applicable controls</div>
  </div>
  <div class="trend-card">
    <div class="trend-label">Production blockers</div>
    <div class="trend-value">${entry.counts.blockers}<span class="trend-delta">${delta(d.blockerDelta, { invert: true })}</span></div>
    ${sparkline(points.map((p) => (p.blockers === null ? null : Math.min(100, p.blockers * 10))), { colour: "var(--bad)", id: "blk" })}
    <div class="trend-foot">${d.readinessChanged ? `readiness moved <strong>${esc(d.previous.readiness)}</strong> → <strong>${esc(entry.readiness)}</strong>` : `readiness unchanged (${esc(entry.readiness)})`}</div>
  </div>
  <div class="trend-card">
    <div class="trend-label">Controls validated</div>
    <div class="trend-value">${entry.counts.pass}<span class="trend-delta">${delta(d.passDelta)}</span></div>
    <div class="trend-foot">
      ${entry.counts.fail} failing · ${entry.counts.warn} warn · ${entry.counts.skip} unvalidated ${delta(d.skipDelta, { invert: true })}
    </div>
  </div>
</div>

<div class="cat-header"><h4>Movement by trust domain</h4><span class="cat-badge">${d.domains.length} domains</span></div>
<div class="table-card"><div class="table-wrap">
<table>
  <thead><tr><th>Domain</th><th class="num">Previous</th><th class="num">Now</th><th>Change</th><th>History</th></tr></thead>
  <tbody>
${domainRows}
  </tbody>
</table>
</div></div>

<div class="cat-header"><h4>Newly introduced</h4><span class="cat-badge">${d.introduced.length}</span></div>
<p class="scope-note">Failing now, but passing or absent in the previous run — the regressions this change set is responsible for.</p>
${idList(d.introduced, "bad")}

<div class="cat-header"><h4>Fixed since the previous run</h4><span class="cat-badge">${d.fixed.length}</span></div>
${idList(d.fixed, "ok")}

<div class="cat-header"><h4>Still failing</h4><span class="cat-badge">${d.persisting.length}</span></div>
<p class="scope-note">Present in both runs. If these have been triaged and accepted, they belong in a suppression list rather than a report — until then they remain outstanding.</p>
${idList(d.persisting, "warn")}

${
  d.chainsIntroduced.length || d.chainsResolved.length
    ? `<div class="cat-header"><h4>Correlated chains</h4><span class="cat-badge">${d.chainsIntroduced.length} new · ${d.chainsResolved.length} resolved</span></div>
<p class="scope-note">A chain resolves as soon as any one of its component controls starts holding, which is why breaking a single link is often the cheapest fix.</p>
${idList(d.chainsIntroduced, "bad", "no new chains")}
${idList(d.chainsResolved, "ok", "none resolved")}`
    : ""
}

<div class="cat-header"><h4>Run history</h4><span class="cat-badge">last ${Math.min(12, (history ?? []).length)} of ${d.runsRecorded}</span></div>
<div class="table-card"><div class="table-wrap">
<table>
  <thead><tr><th>When</th><th>Run</th><th>Commit</th><th>Profiles</th><th class="num">Score</th><th class="num">Coverage</th><th class="num">Blockers</th><th>Readiness</th></tr></thead>
  <tbody>
${historyRows}
  </tbody>
</table>
</div></div>

<div class="trend-provenance">
  History is kept in <code>trends.json</code> alongside the reports: identity, counts and failing IDs only — never evidence, so it cannot become a second unredacted copy of the findings.
  Entries are appended, never rewritten, and a comparison across a changed config or catalogue is flagged rather than silently drawn.
</div>`,
  });
}
