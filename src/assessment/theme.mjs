/**
 * TRUST — assessment theme: COMPASS Dark tokens, stylesheet and icons.
 *
 * Colour, spacing and typography live here and nowhere else, so re-theming the report
 * for a partner's brand means editing the token block at the top of STYLE. No section
 * module names a colour directly.
 */

export const SUN_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
export const PRINT_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>';

// ─── CSS (COMPASS Dark) ─────────────────────────────────────────────
export const STYLE = `<style>
:root {
  /* Native widgets — select popups, scrollbars, date pickers — follow this, so the
     dropdown list is not rendered light-on-white by the OS in dark mode. */
  color-scheme: dark;
  --bg: #0a0a12; --panel: #111120; --ink: #f1f5f9; --muted: #94a3b8;
  --line: rgba(255,255,255,.08); --accent: #2563eb;
  --ok: #16a34a; --warn: #d97706; --bad: #dc2626;
  --radius: 12px; --chip-bg: #1a1a2e;
  --box-shadow: 0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.06);
}
body.light-mode {
  color-scheme: light;
  --bg: #f1f5f9; --panel: #ffffff; --ink: #1e293b; --muted: #64748b;
  --line: #e2e8f0; --chip-bg: #f8fafc;
}
* { box-sizing: border-box; margin: 0; padding: 0; scrollbar-width: thin;
    scrollbar-color: rgba(255,255,255,.12) transparent; }
body.light-mode * { scrollbar-color: rgba(100,116,139,.3) transparent; }
html, body { background: var(--bg); color: var(--ink);
  font-family: 'Inter', system-ui, -apple-system, sans-serif; letter-spacing: -.01em; }
button:focus-visible, a:focus-visible, [tabindex]:focus-visible {
  outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }

header { position: sticky; top: 0; z-index: 5;
  background: var(--panel);
  background: linear-gradient(var(--panel), color-mix(in srgb, var(--panel) 90%, transparent));
  -webkit-backdrop-filter: saturate(140%) blur(6px);
  backdrop-filter: saturate(140%) blur(6px); border-bottom: 1px solid var(--line); }
.header-inner { margin: 0 auto; padding: 14px 20px; display: flex; gap: 16px;
  align-items: center; flex-wrap: wrap; }
.report-title { font-size: 20px; font-weight: 700; }
.report-title .brand { color: var(--accent); }
.report-sub { color: var(--muted); font-size: 13px; }
.header-controls { display: flex; gap: 8px; margin-left: auto; }
.control-btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px;
  border: 1px solid var(--line); border-radius: 8px; background: var(--panel);
  color: var(--ink); font-size: .875rem; font-weight: 500; cursor: pointer;
  transition: all .2s; box-shadow: 0 1px 3px rgba(0,0,0,.1); font-family: inherit; }
.control-btn:hover { background: var(--bg); transform: translateY(-1px); }

.report-nav { display: flex; gap: 6px; align-items: center; flex-wrap: wrap;
  justify-content: center; padding: 8px 20px; border-top: 1px solid var(--line); }
.nav-pill { display: inline-flex; align-items: center; padding: 6px 16px;
  border: 1px solid var(--line); border-radius: 10px; background: var(--chip-bg);
  color: var(--muted); font-family: inherit; font-size: 12px; font-weight: 600;
  letter-spacing: .03em; cursor: pointer; transition: all .2s; white-space: nowrap;
  user-select: none; text-decoration: none; }
.nav-pill:hover { background: rgba(37,99,235,.12); color: var(--ink); border-color: var(--accent); }
.nav-pill.active { background: var(--accent); color: #fff; border-color: var(--accent);
  box-shadow: 0 2px 8px rgba(37,99,235,.4); }

main { margin: 0 auto; padding: 24px 20px; }
.section { margin: 48px 0 40px; scroll-margin-top: var(--nav-offset, 140px); }
.section-title { font-size: 14px; text-transform: uppercase; letter-spacing: .1em;
  color: var(--muted); margin: 0 0 16px 2px; font-weight: 600; scroll-margin-top: var(--nav-offset, 140px); }

.rag-badge { display: inline-block; font-size: 14px; font-weight: 700; letter-spacing: .04em;
  padding: 10px 24px; border-radius: 10px; color: #fff; }
.rag-badge.ok { background: var(--ok); } .rag-badge.warn { background: var(--warn); }
.rag-badge.bad { background: var(--bad); }

.table-card { background: var(--panel); border: 1px solid var(--line);
  border-radius: var(--radius); box-shadow: var(--box-shadow); overflow: hidden; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: separate; border-spacing: 0; background: var(--panel); }
thead th { background: var(--chip-bg); text-align: left; color: var(--ink); font-weight: 600;
  padding: 10px 14px; border-bottom: 1px solid var(--line); font-size: 11px;
  text-transform: uppercase; letter-spacing: .04em; position: sticky; top: 0; }
tbody td { padding: 10px 14px; border-bottom: 1px solid var(--line); font-size: 13px; vertical-align: middle; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: rgba(37,99,235,.04); }

.badge { display: inline-block; padding: 2px 10px; border-radius: 6px; font-size: 11px;
  font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
.sev-critical { background: rgba(220,38,38,.2); color: var(--bad); border: 1px solid rgba(220,38,38,.35); }
.sev-high { background: rgba(220,38,38,.1); color: var(--bad); border: 1px solid rgba(220,38,38,.2); }
.sev-med { background: rgba(217,119,6,.1); color: var(--warn); border: 1px solid rgba(217,119,6,.2); }
.sev-low { background: rgba(22,163,74,.1); color: var(--ok); border: 1px solid rgba(22,163,74,.2); }
.sev-info { background: rgba(148,163,184,.1); color: var(--muted); border: 1px solid rgba(148,163,184,.2); }
/* Latent impact: the control held, so the level is hypothetical and must not read as alarm. */
.sev-latent { background: transparent; color: var(--muted); border: 1px dashed var(--line); }
.badge-qualifier { font-weight: 500; text-transform: lowercase; letter-spacing: 0; opacity: .75; }

.tag { display: inline-block; padding: 3px 10px; border-radius: 6px; font-size: 12px;
  font-weight: 600; min-width: 50px; text-align: center; }
.tag.ok { background: rgba(22,163,74,.12); color: var(--ok); }
.tag.warn { background: rgba(217,119,6,.12); color: var(--warn); }
.tag.bad { background: rgba(220,38,38,.12); color: var(--bad); }
.tag.skip { background: rgba(148,163,184,.1); color: var(--muted); }

.finding-card { background: var(--panel); border: 1px solid var(--line);
  border-radius: var(--radius); box-shadow: var(--box-shadow); margin-bottom: 10px; }
.finding-card.f-fail { border-left: 4px solid var(--bad); }
.finding-card.f-warn { border-left: 4px solid var(--warn); }
.finding-card.f-pass { border-left: 4px solid var(--ok); }
.finding-card.f-skip { border-left: 4px solid var(--muted); }
.finding-sum { list-style: none; cursor: pointer; display: flex; align-items: center;
  gap: 12px; flex-wrap: wrap; padding: 14px 18px; }
.finding-sum::-webkit-details-marker { display: none; }
.finding-sum::before { content: '\\25B8'; color: var(--muted); font-size: 11px;
  transition: transform .15s; flex-shrink: 0; }
.finding-card[open] > .finding-sum::before { transform: rotate(90deg); }
.finding-card[open] > .finding-sum { border-bottom: 1px solid var(--line); }
.finding-name { font-weight: 600; font-size: 13.5px; flex: 1; min-width: 200px; }
.finding-id-tag { font-family: 'SF Mono', Consolas, monospace; font-size: 11px;
  color: var(--muted); background: var(--chip-bg); padding: 2px 8px; border-radius: 4px; }
.finding-body { padding: 16px 18px; }
.finding-body p { margin-bottom: 10px; font-size: 13px; line-height: 1.6; }
.finding-label { font-weight: 700; font-size: 10px; text-transform: uppercase;
  letter-spacing: .05em; color: var(--accent); margin-bottom: 4px; display: block; }
.finding-label.fix { color: var(--ok); }
pre { background: var(--chip-bg); padding: 12px 14px; border-radius: 8px; font-size: 12px;
  line-height: 1.5; white-space: pre-wrap; word-break: break-word; max-height: 200px;
  overflow-y: auto; margin: 6px 0 14px; font-family: 'SF Mono', Consolas, monospace;
  color: var(--muted); border: 1px solid var(--line); }

.arch-box { background: var(--chip-bg); padding: 20px; border-radius: var(--radius);
  font-family: 'SF Mono', Consolas, monospace; font-size: 13px; line-height: 1.7;
  margin: 1rem 0; white-space: pre; overflow-x: auto; border: 1px solid var(--line); color: var(--ink); }

.callout { background: rgba(37,99,235,.06); border-left: 4px solid var(--accent);
  padding: 14px 18px; margin: 1rem 0; font-size: 13px; line-height: 1.6; border-radius: 0 8px 8px 0; }
.callout-warn { background: rgba(217,119,6,.06); border-left-color: var(--warn); }
.callout-bad { background: rgba(220,38,38,.06); border-left-color: var(--bad); }

.cover { text-align: center; padding: 1.5rem 0; margin-bottom: 1.5rem; scroll-margin-top: var(--nav-offset, 140px); }
.cover-meta { display: inline-block; text-align: left; background: var(--panel);
  border: 1px solid var(--line); border-radius: var(--radius); padding: 4px 8px; }
.cover-meta td { padding: 5px 10px; font-size: 13px; color: var(--muted); border-bottom: none; }
.cover-meta td:first-child { font-weight: 600; color: var(--ink); text-align: right; white-space: nowrap; }
.env-badge { font-size: 11px; font-weight: 600; padding: 2px 10px; border-radius: 999px;
  background: rgba(37,99,235,.12); border: 1px solid rgba(37,99,235,.25); color: var(--accent);
  text-transform: uppercase; letter-spacing: .04em; }

.cat-header { display: flex; align-items: center; gap: 10px; margin: 1.5rem 0 .8rem;
  padding-bottom: 8px; border-bottom: 2px solid var(--accent); }
.cat-header h4 { font-size: 13px; text-transform: uppercase; letter-spacing: .08em;
  color: var(--accent); margin: 0; font-weight: 700; }
.cat-badge { font-size: 11px; background: var(--chip-bg); border: 1px solid var(--line);
  padding: 2px 8px; border-radius: 999px; color: var(--muted); }

/* Sub-kind of a skip or a warning. Deliberately quiet: it qualifies the status badge beside
   it rather than competing with it. */
.rem-specifics { margin: 6px 0 0 0; padding-left: 18px; color: var(--muted); font-size: 12px; }
.rem-specifics li { margin: 2px 0; }

.cat-header { scroll-margin-top: var(--nav-offset, 150px); }
.finding-card { scroll-margin-top: var(--nav-offset, 150px); }

/* Sticks under the header while you read the cards: jumping to another group should not mean
   scrolling back to the top of the section to find the index again. */
.cat-index { display: flex; flex-wrap: wrap; gap: 6px; margin: 0 0 14px 0;
  position: sticky; top: var(--nav-offset, 150px); z-index: 3;
  padding: 8px 2px; background: var(--panel);
  border-bottom: 1px solid var(--line); }
.cat-jump { font-size: 11px; padding: 3px 9px; border-radius: 999px; border: 1px solid var(--line);
  color: var(--muted); text-decoration: none; background: var(--chip-bg); white-space: nowrap; }
.cat-jump:hover { color: var(--ink); border-color: var(--muted); }
.cat-jump.current { color: var(--ink); border-color: var(--accent); background: var(--panel); }
.cat-jump strong { color: var(--bad); }
.cat-jump-fail { border-color: color-mix(in srgb, var(--bad) 45%, var(--line)); }

.copy-link { margin-left: 6px; border: 1px solid transparent; background: transparent; color: var(--muted);
  font-size: 12px; font-weight: 700; cursor: pointer; border-radius: 6px; padding: 0 5px; line-height: 1.6; opacity: 0; }
.finding-sum:hover .copy-link, .copy-link:focus { opacity: 1; border-color: var(--line); }

/* A linked control marks itself, so the eye lands on the right one among a hundred. */
.control-flash { outline: 2px solid var(--accent); outline-offset: 3px; }

.kind-badge { font-size: 9px; text-transform: uppercase; letter-spacing: .06em; font-weight: 700;
  padding: 2px 6px; border-radius: 4px; border: 1px dashed var(--line); color: var(--muted);
  background: transparent; white-space: nowrap; cursor: help; }

.footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
  font-size: 11px; color: var(--muted); text-align: center; line-height: 1.8; }

.inv-toolbar { display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end;
  padding: 14px 16px; border-bottom: 1px solid var(--line); }
.inv-field { display: flex; flex-direction: column; gap: 5px; min-width: 150px; }
.inv-field-grow { flex: 1; min-width: 220px; }
.inv-field-actions { flex-direction: row; align-items: center; gap: 10px; margin-left: auto; }
.inv-label { font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .07em; color: var(--muted); }
.inv-search, .inv-select { padding: 8px 12px; border: 1px solid var(--line); border-radius: 8px;
  background: var(--chip-bg); color: var(--ink); font-family: inherit; font-size: 13px;
  outline: none; width: 100%; }
.inv-select { cursor: pointer; appearance: none; padding-right: 30px;
  /* chevron drawn in CSS so the report stays a single file with no image requests */
  background-image: linear-gradient(45deg, transparent 50%, var(--muted) 50%),
                    linear-gradient(135deg, var(--muted) 50%, transparent 50%);
  background-position: calc(100% - 16px) calc(50% + 1px), calc(100% - 11px) calc(50% + 1px);
  background-size: 5px 5px, 5px 5px; background-repeat: no-repeat; }
.inv-search:focus, .inv-select:focus { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(37,99,235,.25); }
/* Belt and braces alongside color-scheme: the popup list must be legible in both themes. */
.inv-select option { background-color: #16162b; color: #f1f5f9; }
body.light-mode .inv-select option { background-color: #ffffff; color: #1e293b; }
.inv-select option:disabled { color: var(--muted); }
.inv-search::placeholder { color: var(--muted); }
/* A dropdown holding a filter reads as active, so it stops looking like an empty control. */
.inv-select.is-active { border-color: var(--accent); color: var(--ink); background-color: rgba(37,99,235,.1); }
.inv-clear { padding: 7px 14px; border: 1px solid var(--line); border-radius: 8px;
  background: var(--chip-bg); color: var(--ink); font-family: inherit; font-size: 12px;
  font-weight: 600; cursor: pointer; transition: all .15s; white-space: nowrap; }
.inv-clear:hover:not(:disabled) { border-color: var(--bad); color: var(--bad); }
.inv-clear:disabled { opacity: .4; cursor: default; }
.inv-clear-inline { margin-left: 8px; padding: 4px 10px; font-size: 11px; }
.inv-empty { text-align: center; color: var(--muted); font-size: 13px; padding: 24px 14px !important; }
.inv-count { font-size: 12px; color: var(--muted); white-space: nowrap; }
.inv-toggle { padding: 4px 10px; border: 1px dashed var(--line); border-radius: 8px;
  background: transparent; color: var(--muted); font-size: 10px; font-weight: 600;
  cursor: pointer; text-transform: uppercase; letter-spacing: .04em; font-family: inherit;
  transition: all .15s; user-select: none; }
.inv-toggle:hover { border-color: var(--accent); color: var(--ink); }

.posture-hero { display: flex; gap: 24px; align-items: center; flex-wrap: wrap;
  background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 24px; box-shadow: var(--box-shadow); margin-bottom: 16px; }
.posture-score { display: flex; flex-direction: column; align-items: center; min-width: 150px;
  padding-right: 24px; border-right: 2px solid var(--line); }
.posture-score .score-num { font-size: 48px; font-weight: 800; }
.posture-score .score-label { font-size: 11px; text-transform: uppercase; letter-spacing: .08em;
  color: var(--muted); font-weight: 600; margin-top: 4px; }
.posture-domains { flex: 1; display: grid; gap: 8px;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); }
.domain-card { display: flex; align-items: center; gap: 10px; padding: 10px 14px;
  border-radius: 8px; border: 1px solid var(--line); background: var(--chip-bg); transition: transform .15s; }
.domain-card:hover { transform: translateY(-1px); }
.domain-card .domain-status { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.domain-card .domain-status.s-pass { background: var(--ok); box-shadow: 0 0 6px rgba(22,163,74,.4); }
.domain-card .domain-status.s-warn { background: var(--warn); box-shadow: 0 0 6px rgba(217,119,6,.4); }
.domain-card .domain-status.s-fail { background: var(--bad); box-shadow: 0 0 6px rgba(220,38,38,.4); }
.domain-card .domain-status.s-skip { background: var(--muted); }
.domain-card .domain-name { font-size: 12px; font-weight: 600; flex: 1; }
.domain-card .domain-score { font-size: 14px; font-weight: 700; }
.domain-card .domain-score.ok { color: var(--ok); }
.domain-card .domain-score.warn { color: var(--warn); }
.domain-card .domain-score.bad { color: var(--bad); }
.domain-card .domain-score.na { color: var(--muted); }
.readiness-badge { font-size: 12px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .06em; padding: 4px 14px; border-radius: 6px; margin-top: 8px; }
.readiness-badge.ready { background: rgba(22,163,74,.15); color: var(--ok); border: 1px solid rgba(22,163,74,.3); }
.readiness-badge.not-ready { background: rgba(220,38,38,.15); color: var(--bad); border: 1px solid rgba(220,38,38,.3); }
.readiness-badge.caution { background: rgba(217,119,6,.15); color: var(--warn); border: 1px solid rgba(217,119,6,.3); }
.impact-summary { display: grid; gap: 8px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin-top: 12px; }
.impact-tile { padding: 12px 16px; border-radius: 8px; border: 1px solid var(--line); background: var(--chip-bg); }
.impact-tile .impact-count { font-size: 24px; font-weight: 700; }
.impact-tile .impact-label { font-size: 11px; color: var(--muted); font-weight: 600;
  text-transform: uppercase; letter-spacing: .04em; margin-top: 2px; }

[data-tip] { position: relative; cursor: default; }
[data-tip]::after { content: attr(data-tip); position: absolute; bottom: calc(100% + 8px);
  left: 50%; transform: translateX(-50%) scale(.95); opacity: 0; pointer-events: none;
  transition: opacity .15s, transform .15s; background: var(--ink); color: var(--bg);
  font-size: 11px; font-weight: 500; padding: 6px 10px; border-radius: 6px; white-space: nowrap;
  z-index: 10; box-shadow: 0 4px 12px rgba(0,0,0,.3); letter-spacing: 0; text-transform: none; }
[data-tip]::before { content: ''; position: absolute; bottom: calc(100% + 2px); left: 50%;
  transform: translateX(-50%); opacity: 0; pointer-events: none; transition: opacity .15s;
  border: 5px solid transparent; border-top-color: var(--ink); z-index: 10; }
[data-tip]:hover::after, [data-tip]:hover::before { opacity: 1; transform: translateX(-50%) scale(1); }
[data-tip]:hover::before { transform: translateX(-50%); }

.exec-panel { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 20px; box-shadow: var(--box-shadow); margin-top: 16px; }
.exec-interp-title { font-size: 13px; font-weight: 700; margin: 0 0 10px; color: var(--accent);
  text-transform: uppercase; letter-spacing: .06em; }
.exec-bullets { list-style: disc; padding-left: 18px; margin: 0; font-size: 13px; line-height: 1.8; }
.exec-synopsis { font-size: 14px; line-height: 1.85; margin: 0; }
.exec-synopsis strong { color: var(--ink); }
.exec-sub { margin: 6px 0 2px; padding-left: 18px; list-style: disc; }
.exec-sub li { margin: 3px 0; font-size: 13px; color: var(--ink); }

.rc-tb-section { margin-top: 20px; }
.rc-tb-title { font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: .06em;
  margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
.rc-tb-table { width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden; }
.rc-tb-table td { padding: 9px 10px; border-bottom: none; font-size: 12.5px;
  line-height: 1.5; vertical-align: middle; }
.rc-tb-table td:first-child { width: 20px; padding-right: 0; text-align: center; }
.rc-tb-table tr:last-child td { border-bottom: none; }
.rc-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
.rc-dot.bad { background: var(--bad); } .rc-dot.warn { background: var(--warn); } .rc-dot.ok { background: var(--ok); }
.rc-cause { color: var(--ink); }
.ws-meta { font-size: 11px; color: var(--muted); margin-top: 3px; line-height: 1.5; }
.ws-meta code { font-family: 'SF Mono', Consolas, monospace; font-size: 10.5px; background: var(--chip-bg);
  border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px; margin-right: 3px; }
.ws-criteria { font-size: 12px; }
.ws-crit { display: block; color: var(--ink); padding-left: 15px; position: relative; line-height: 1.65; }
.ws-crit::before { content: '\\2713'; position: absolute; left: 0; color: var(--ok); opacity: .6; font-size: 11px; }
.retest-cmd { font-family: 'SF Mono', Consolas, monospace; font-size: 11px; color: var(--accent);
  background: var(--chip-bg); border: 1px solid var(--line); border-radius: 6px; padding: 3px 8px; display: inline-block; }
/* ── Trends ── */
.trend-grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); margin-bottom: 18px; }
.trend-card { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 14px 16px; }
.trend-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
.trend-value { font-size: 28px; font-weight: 700; margin: 4px 0 2px; display: flex; align-items: baseline; gap: 10px; }
.trend-delta { font-size: 12px; font-weight: 600; }
.trend-foot { font-size: 11.5px; color: var(--muted); line-height: 1.6; margin-top: 6px; }
.spark { width: 100%; height: 48px; display: block; margin: 6px 0 2px; }
.spark-empty { font-size: 11px; color: var(--muted); padding: 16px 0 6px; }
.micro { width: 90px; height: 22px; display: block; }
.micro-empty { color: var(--muted); }
.micro-cell { width: 100px; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.delta { font-size: 12px; font-weight: 600; white-space: nowrap; }
.delta.good { color: var(--ok); } .delta.bad { color: var(--bad); } .delta.flat { color: var(--muted); font-weight: 500; }
.trend-ids { display: flex; flex-wrap: wrap; gap: 6px; margin: 4px 0 14px; }
.trend-id { font-family: 'SF Mono', Consolas, monospace; font-size: 11px; padding: 3px 8px;
  border-radius: 6px; border: 1px solid var(--line); background: var(--chip-bg); }
.trend-id.bad { color: var(--bad); border-color: rgba(220,38,38,.3); }
.trend-id.ok { color: var(--ok); border-color: rgba(22,163,74,.3); }
.trend-id.warn { color: var(--warn); border-color: rgba(217,119,6,.3); }
.trend-none { color: var(--muted); font-size: 12px; }
.trend-more { font-size: 11px; color: var(--muted); align-self: center; }
.trend-provenance { font-size: 11.5px; color: var(--muted); line-height: 1.7; margin-top: 16px;
  padding-top: 12px; border-top: 1px solid var(--line); }
.trend-provenance code { font-family: 'SF Mono', Consolas, monospace; background: var(--chip-bg);
  border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px; }
tr.is-current td { background: rgba(37,99,235,.06); }

/* ── Filter bars on long lists ── */
.flt-bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 12px; }
.flt-search { flex: 1; min-width: 200px; padding: 7px 12px; border: 1px solid var(--line);
  border-radius: 8px; background: var(--chip-bg); color: var(--ink); font-family: inherit;
  font-size: 13px; outline: none; }
.flt-search:focus { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(37,99,235,.25); }
.flt-chips { display: flex; gap: 6px; flex-wrap: wrap; }
.flt-chip { padding: 5px 12px; border: 1px solid var(--line); border-radius: 8px;
  background: var(--chip-bg); color: var(--muted); font-family: inherit; font-size: 11px;
  font-weight: 600; text-transform: uppercase; letter-spacing: .03em; cursor: pointer; transition: all .15s; }
.flt-chip:hover { border-color: var(--accent); color: var(--ink); }
.flt-chip.active { color: #fff; }
.flt-chip.active.c-bad { background: var(--bad); border-color: var(--bad); }
.flt-chip.active.c-warn { background: var(--warn); border-color: var(--warn); }
.flt-chip.active.c-ok { background: var(--ok); border-color: var(--ok); }
.flt-chip.active.c-skip { background: #64748b; border-color: #64748b; }
.flt-clear { padding: 6px 12px; border: 1px solid var(--line); border-radius: 8px;
  background: var(--chip-bg); color: var(--ink); font-family: inherit; font-size: 12px;
  font-weight: 600; cursor: pointer; transition: all .15s; }
.flt-clear:hover:not(:disabled) { border-color: var(--bad); color: var(--bad); }
.flt-clear:disabled { opacity: .4; cursor: default; }
.flt-count { font-size: 12px; color: var(--muted); white-space: nowrap; margin-left: auto; }

/* ── Executive dashboard (not a collapsible card) ── */
.dashboard { margin: 0 0 28px; scroll-margin-top: var(--nav-offset, 150px); }
.dashboard-head { display: flex; align-items: center; justify-content: space-between;
  gap: 16px; flex-wrap: wrap; margin-bottom: 14px; }
.dashboard-title { margin: 0; font-size: 13px; font-weight: 600; text-transform: uppercase;
  letter-spacing: .1em; color: var(--muted); }
.dashboard-meta { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

/* ── Verified controls: a matrix that stays balanced as the count changes ── */
/* auto-fit collapses empty tracks, so 6 cards give 3x2, 8 give 4x2, 10 give 5x2, and a
   larger set simply wraps to a further row rather than producing one orphan column. */
.tb-grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
@media (min-width: 1500px) { .tb-grid { grid-template-columns: repeat(5, 1fr); } }
@media (max-width: 1100px) { .tb-grid { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); } }
@media (max-width: 640px)  { .tb-grid { grid-template-columns: 1fr; } }

/* ── Remediation: chips were taking the width that closure criteria needed ── */
.ws-table { table-layout: fixed; }
.ws-col-priority { width: 92px; }
.ws-col-workstream { width: 22%; }
.ws-col-findings { width: 26%; }
.ws-col-criteria { width: auto; }  /* the remainder, ~45% at full width */
.ws-table td { padding: 12px 14px; vertical-align: top; }
.ws-table .ws-crit { padding-left: 16px; }
.ws-meta code { display: inline-block; margin: 1px 3px 1px 0; }

.coverage-note { margin-top: 14px; }
.path-steps { display: flex; flex-direction: column; gap: 3px; margin: 8px 0 6px; }
.path-step { font-size: 12px; color: var(--muted); display: flex; gap: 8px; align-items: baseline; }
.path-step b { display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0;
  width: 16px; height: 16px; border-radius: 50%; background: rgba(220,38,38,.15); color: var(--bad);
  font-size: 10px; font-weight: 700; }
.path-impact { font-size: 12.5px; color: var(--ink); margin: 6px 0; }
.path-evidence { font-size: 11px; color: var(--muted); }
.path-evidence code { font-family: 'SF Mono', Consolas, monospace; font-size: 10.5px;
  background: var(--chip-bg); border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px; }
.rc-domain { color: var(--muted); font-size: 11px; white-space: nowrap; width: 130px; padding-right: 4px; }

.tb-card { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 14px 16px; overflow: hidden; }
.tb-card-hdr { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.tb-card-domain { font-size: 13px; font-weight: 600; color: var(--ok); }
.tb-card-count { font-size: 11px; color: var(--muted); margin-left: auto; }
.tb-card-list { list-style: none; padding: 0; margin: 0; }
.tb-card-list li { font-size: 12px; color: var(--ink); padding: 3px 0 3px 16px; line-height: 1.5; position: relative; }
.tb-card-list li::before { content: ''; position: absolute; left: 2px; top: 10px; width: 6px;
  height: 6px; border-radius: 50%; background: var(--ok); opacity: .5; }
.tb-card-more { margin-top: 6px; }
.tb-card-more summary { font-size: 11px; color: var(--accent); cursor: pointer; list-style: none; padding-left: 16px; }
.tb-card-more summary::-webkit-details-marker { display: none; }
.tb-card-more summary::before { content: '\\25B8'; margin-right: 4px; font-size: 9px;
  display: inline-block; transition: transform .15s; }
.tb-card-more[open] summary::before { transform: rotate(90deg); }


/* ── Collapsible section cards ── */
.panel-card { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius);
  box-shadow: var(--box-shadow); overflow: hidden; margin: 0 0 14px; scroll-margin-top: var(--nav-offset, 150px); }
.panel-toggle { display: flex; align-items: center; justify-content: space-between; gap: 16px;
  padding: 16px 22px; cursor: pointer; user-select: none;
  border-bottom: 1px solid transparent; transition: background .2s, border-color .2s; }
.panel-toggle:hover { background: var(--chip-bg); }
.panel-toggle:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
.panel-toggle.open { border-bottom-color: var(--line); }
.panel-title { margin: 0; font-size: 13px; font-weight: 600; text-transform: uppercase;
  letter-spacing: .1em; color: var(--ink); display: flex; align-items: center; gap: 10px; }
.panel-meta { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.panel-chevron { width: 18px; height: 18px; color: var(--muted); transition: transform .3s ease; }
.panel-toggle.open .panel-chevron { transform: rotate(180deg); }
.panel-body { display: none; padding: 20px 22px 22px; }
.panel-body.show { display: block; }
.panel-body > .section:first-child, .panel-body > .rc-tb-section:first-child { margin-top: 0; }

.sc-chip { font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 999px;
  background: var(--chip-bg); border: 1px solid var(--line); color: var(--muted);
  text-transform: uppercase; letter-spacing: .04em; white-space: nowrap; }
.sc-chip-score { background: rgba(37,99,235,.12); border-color: rgba(37,99,235,.3); color: var(--accent); }
.sc-chip-bad { background: rgba(220,38,38,.12); border-color: rgba(220,38,38,.3); color: var(--bad); }
.sc-chip-warn { background: rgba(217,119,6,.12); border-color: rgba(217,119,6,.3); color: var(--warn); }
.sc-chip-ready { background: rgba(22,163,74,.12); border-color: rgba(22,163,74,.3); color: var(--ok); }
.sc-chip-caution { background: rgba(217,119,6,.12); border-color: rgba(217,119,6,.3); color: var(--warn); }
.sc-chip-not-ready { background: rgba(220,38,38,.12); border-color: rgba(220,38,38,.3); color: var(--bad); }

.panel-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px;
  flex-wrap: wrap; margin-bottom: 12px; }
.panel-hint { font-size: 12px; color: var(--muted); }

/* ── Scope ── */
.scope-lede { font-size: 13px; line-height: 1.75; margin-bottom: 4px; }
.scope-note { font-size: 12.5px; line-height: 1.65; color: var(--muted); margin: 0 0 10px; }
.host-list { display: flex; flex-wrap: wrap; gap: 6px; }
.host-list code { font-family: 'SF Mono', Consolas, monospace; font-size: 11.5px;
  background: var(--chip-bg); border: 1px solid var(--line); border-radius: 6px;
  padding: 3px 9px; color: var(--ink); }

/* ── Definitions: glossary grid ── */
.glossary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 28px; }
@media (max-width: 900px) { .glossary-grid { grid-template-columns: 1fr 1fr; } }
@media (max-width: 600px) { .glossary-grid { grid-template-columns: 1fr; } }
.glossary-section h4 { font-size: 12px; text-transform: uppercase; letter-spacing: .08em;
  color: var(--accent); margin: 0 0 12px; font-weight: 700; padding-bottom: 6px;
  border-bottom: 2px solid var(--accent); }
.glossary-section dl { margin: 0; }
.glossary-section dt { font-weight: 600; font-size: 13px; color: var(--ink); margin-top: 12px; }
.glossary-section dt:first-of-type { margin-top: 0; }
.glossary-section dd { margin: 3px 0 0; font-size: 12px; color: var(--muted); line-height: 1.55; }
.score-scale { display: flex; gap: 6px; margin-top: 8px; flex-wrap: wrap; }
.score-scale span { font-size: 11px; font-weight: 600; padding: 2px 10px; border-radius: 6px; }

@media print {
  header { position: static; }
  .header-controls, .report-nav, .inv-toolbar, .cat-index { display: none; }
  /* Nothing may be hidden in a PDF that is filed as evidence. */
  .panel-body { display: block !important; }
  .panel-chevron { display: none; }
  .panel-card { break-inside: auto; }
  .finding-card > .finding-body { display: block !important; }
  .finding-card, tr { break-inside: avoid; }
  body, body.light-mode { --bg: #fff; --panel: #fff; --ink: #1e293b; --muted: #64748b;
    --line: #e2e8f0; --chip-bg: #f8fafc; }
}
@media (max-width: 700px) {
  .header-inner, main { padding-left: 16px; padding-right: 16px; }
  .posture-hero { flex-direction: column; }
  .posture-score { border-right: none; border-bottom: 2px solid var(--line);
    padding-right: 0; padding-bottom: 16px; width: 100%; }
}
</style>`;
