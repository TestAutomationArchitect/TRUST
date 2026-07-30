/**
 * TRUST — the report's inline client script.
 *
 * Sections are collapsed cards; the nav pills are the primary way to open them, and
 * opening one closes the others so the reader always has a single subject in view.
 * Everything degrades safely: printing forces every panel open, and a deep link
 * (#section-findings) opens its target on load.
 *
 * Inlined so an assessment stays a single self-contained file that survives being
 * emailed as an attachment.
 */

export const REPORT_SCRIPT = `<script>
function toggleTheme() { document.body.classList.toggle('light-mode'); }

// ── Collapsible panels ──────────────────────────────────────────────
function panelParts(el) {
  var toggle = el.classList.contains('panel-toggle') ? el : el.querySelector('.panel-toggle');
  var section = toggle && toggle.closest('.panel-card');
  return { toggle: toggle, body: section && section.querySelector('.panel-body'), section: section };
}
function setPanel(el, open) {
  var p = panelParts(el);
  if (!p.toggle || !p.body) return;
  p.toggle.classList.toggle('open', open);
  p.toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  p.body.classList.toggle('show', open);
}
function togglePanel(el) {
  var p = panelParts(el);
  if (!p.body) return;
  setPanel(el, !p.body.classList.contains('show'));
}
function panelKey(event, el) {
  if (event.key === 'Enter' || event.key === ' ' || event.key === 'Spacebar') {
    event.preventDefault();
    togglePanel(el);
  }
}
function collapseAllPanels(except) {
  document.querySelectorAll('.panel-card').forEach(function (card) {
    if (card !== except) setPanel(card, false);
  });
}

// ── Navigation pills ────────────────────────────────────────────────
// A pill opens its section, closes the rest, and scrolls it under the sticky header.
function navTo(el) {
  var id = (el.getAttribute('href') || '').replace('#', '');
  var section = document.getElementById(id);
  document.querySelectorAll('.nav-pill').forEach(function (p) { p.classList.remove('active'); });
  el.classList.add('active');
  if (!section) return true;
  collapseAllPanels(section);
  setPanel(section, true);
  // Let the panel lay out before scrolling to it.
  requestAnimationFrame(function () { section.scrollIntoView({ behavior: 'smooth', block: 'start' }); });
  return true;
}

// Scroll-spy: reflect the section in view on the pills, without opening anything.
var observer = new IntersectionObserver(function (entries) {
  entries.forEach(function (e) {
    if (!e.isIntersecting) return;
    var id = e.target.id;
    document.querySelectorAll('.nav-pill').forEach(function (p) {
      p.classList.toggle('active', p.getAttribute('href') === '#' + id);
    });
  });
}, { rootMargin: '-150px 0px -55% 0px' });
document.querySelectorAll('section[id]').forEach(function (s) { observer.observe(s); });

// Deep link: #section-findings opens that panel on load.
(function () {
  var id = (location.hash || '').replace('#', '');
  if (!id) return;
  var section = document.getElementById(id);
  if (!section || !section.classList.contains('panel-card')) return;
  collapseAllPanels(section);
  setPanel(section, true);
  setTimeout(function () { section.scrollIntoView({ block: 'start' }); }, 0);
})();

// ── Findings: expand or collapse every card at once ──────────────────
function toggleAllFindings(btn) {
  var container = btn.closest('.panel-body') || document;
  var cards = container.querySelectorAll('details.finding-card');
  var anyOpen = container.querySelector('details.finding-card[open]');
  cards.forEach(function (c) { c.open = !anyOpen; });
  btn.textContent = anyOpen ? 'Expand all' : 'Collapse all';
}

// ── Printing: a filed PDF must never hide evidence ───────────────────
var printState = [];
window.addEventListener('beforeprint', function () {
  printState = [];
  document.querySelectorAll('.panel-card').forEach(function (card) {
    var body = card.querySelector('.panel-body');
    printState.push([card, body ? body.classList.contains('show') : false]);
    setPanel(card, true);
  });
  document.querySelectorAll('details.finding-card').forEach(function (d) {
    printState.push([d, d.open]);
    d.open = true;
  });
});
window.addEventListener('afterprint', function () {
  printState.forEach(function (entry) {
    if (entry[0].classList.contains('panel-card')) setPanel(entry[0], entry[1]);
    else entry[0].open = entry[1];
  });
  printState = [];
});

// ── Inventory filters ───────────────────────────────────────────────
// Each dropdown holds either "" (no filter) or one or more pipe-separated values, so a
// combined option like "fail|warn" needs no special case. Rows carry data-status /
// data-severity / data-category attributes, so filtering never parses rendered cell text.
var INV_SELECTS = [
  { id: 'invStatus', attr: 'status' },
  { id: 'invSeverity', attr: 'severity' },
  { id: 'invCategory', attr: 'category' },
];

function clearInventoryFilters() {
  var search = document.getElementById('invSearch');
  if (search) search.value = '';
  INV_SELECTS.forEach(function (f) {
    var el = document.getElementById(f.id);
    if (el) el.value = '';
  });
  filterInventory();
}

function filterInventory() {
  var search = document.getElementById('invSearch');
  var q = ((search && search.value) || '').trim().toLowerCase();
  var active = 0;

  var filters = [];
  INV_SELECTS.forEach(function (f) {
    var el = document.getElementById(f.id);
    if (!el) return;
    var raw = el.value;
    el.classList.toggle('is-active', raw !== '');
    if (raw === '') return;
    active++;
    filters.push({ attr: f.attr, values: raw.split('|') });
  });
  if (q) active++;

  var rows = document.querySelectorAll('#invTable tbody:first-of-type tr');
  var shown = 0;
  rows.forEach(function (row) {
    var visible = filters.every(function (f) {
      return f.values.indexOf(row.getAttribute('data-' + f.attr)) !== -1;
    }) && (!q || row.textContent.toLowerCase().indexOf(q) !== -1);
    row.style.display = visible ? '' : 'none';
    if (visible) shown++;
  });

  var count = document.getElementById('invCount');
  if (count) {
    count.textContent = shown === rows.length
      ? rows.length + ' tests'
      : shown + ' of ' + rows.length + (active ? ' · ' + active + ' filter' + (active === 1 ? '' : 's') : '');
  }
  var clear = document.getElementById('invClear');
  if (clear) clear.disabled = active === 0;
  var empty = document.getElementById('invEmpty');
  if (empty) empty.hidden = shown !== 0;
}
` + "</" + "script>";
