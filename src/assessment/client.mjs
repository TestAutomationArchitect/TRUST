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

// ── Scrolling under a sticky header ─────────────────────────────────
//
// Three things made a click land in the wrong place, and all three had to be fixed together.
//
//   1. The header is sticky and wraps at narrow widths, so a fixed scroll-margin was a guess.
//      Its real height is measured and published as --nav-offset.
//   2. Opening one panel while collapsing the others changes the height of the document *above*
//      the target. A scroll computed before that settles overshoots, which is the "it scrolls
//      too far" everyone sees. The position is now computed after layout, and corrected once
//      the animation ends.
//   3. The scroll-spy fires continuously during a smooth scroll and re-highlights whatever it
//      passes, so the pill you clicked did not stay lit. It is suspended while a programmatic
//      scroll is in flight.
var navScrolling = false;
var navScrollTimer = null;

function headerOffset() {
  var header = document.querySelector('header');
  var h = header ? Math.ceil(header.getBoundingClientRect().height) : 120;
  return h + 12;
}

function publishNavOffset() {
  document.documentElement.style.setProperty('--nav-offset', headerOffset() + 'px');
}
publishNavOffset();
window.addEventListener('resize', publishNavOffset);

/** Scroll an element under the header, after layout has settled, and hold it there. */
function scrollToElement(el) {
  if (!el) return;
  publishNavOffset();
  navScrolling = true;
  if (navScrollTimer) clearTimeout(navScrollTimer);

  var settle = function (behavior) {
    var top = el.getBoundingClientRect().top + window.pageYOffset - headerOffset();
    window.scrollTo({ top: Math.max(0, top), behavior: behavior });
  };

  // Two frames: one for the panel that just opened, one for the reflow that follows it.
  requestAnimationFrame(function () {
    requestAnimationFrame(function () {
      settle('smooth');
      // The correction is what makes it stick. Collapsing panels above the target keeps moving
      // it while the animation runs, so the final position is re-measured and snapped.
      navScrollTimer = setTimeout(function () {
        var drift = el.getBoundingClientRect().top - headerOffset();
        if (Math.abs(drift) > 4) settle('auto');
        navScrolling = false;
      }, 420);
    });
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
  scrollToElement(section);
  return true;
}

// Scroll-spy: reflect the section in view on the pills, without opening anything.
var observer = new IntersectionObserver(function (entries) {
  // A programmatic scroll passes over every section between here and there; letting the spy
  // react means the pill you clicked does not stay lit.
  if (navScrolling) return;
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
  // A control link is the common case now that findings are addressable.
  if (id.indexOf('control-') === 0 && openControl(id.slice('control-'.length))) return;
  var section = document.getElementById(id);
  if (!section || !section.classList.contains('panel-card')) return;
  collapseAllPanels(section);
  setPanel(section, true);
  setTimeout(function () { scrollToElement(section); }, 0);
})();

// Jump to a category heading inside the section already open, without collapsing anything.
function jumpWithin(event, id) {
  if (event) event.preventDefault();
  var target = document.getElementById(id);
  if (!target) return;
  scrollToElement(target);
  history.replaceState(null, '', '#' + id);
}

// A link to one control. Sharing a finding should not mean "scroll to Authorization and look
// for it" — the card opens, highlights, and the URL in the clipboard reproduces exactly that.
function copyControlLink(event, id) {
  if (event) { event.preventDefault(); event.stopPropagation(); }
  var url = location.href.split('#')[0] + '#control-' + id;
  var done = function () {
    var btn = event && event.currentTarget;
    if (!btn) return;
    var was = btn.textContent;
    btn.textContent = '✓';
    setTimeout(function () { btn.textContent = was; }, 1200);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(url).then(done, done);
  else done();
  history.replaceState(null, '', '#control-' + id);
}

// Opening a control link: open the section that holds it, open the card, and mark it briefly so
// the eye lands on the right one among a hundred.
function openControl(id) {
  var card = document.getElementById('control-' + id);
  if (!card) return false;
  var section = card.closest('section[id]');
  if (section) {
    collapseAllPanels(section);
    setPanel(section, true);
    document.querySelectorAll('.nav-pill').forEach(function (p) {
      p.classList.toggle('active', p.getAttribute('href') === '#' + section.id);
    });
  }
  card.open = true;
  scrollToElement(card);
  card.classList.add('control-flash');
  setTimeout(function () { card.classList.remove('control-flash'); }, 1600);
  return true;
}

// The category index tracks what you are reading, so the sticky bar answers "where am I" as
// well as "where can I go".
var catObserver = new IntersectionObserver(function (entries) {
  if (navScrolling) return;
  entries.forEach(function (e) {
    if (!e.isIntersecting) return;
    document.querySelectorAll('.cat-jump').forEach(function (j) {
      j.classList.toggle('current', j.getAttribute('href') === '#' + e.target.id);
    });
  });
}, { rootMargin: '-160px 0px -70% 0px' });
document.querySelectorAll('.cat-header[id]').forEach(function (h) { catObserver.observe(h); });

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

// ── Generic list filters (findings, remediation, retest) ────────────
// Two shapes share one implementation. A table list hides rows; a card list hides cards AND
// the category header above them, because a heading with nothing under it reads as an empty
// category rather than a filtered one. Finding cards also carry their status in a class.
function filterState(scope) {
  var bar = document.querySelector('.flt-bar[data-scope="' + scope + '"]');
  if (!bar) return null;
  var search = document.getElementById(scope + '-search');
  var active = [];
  bar.querySelectorAll('.flt-chip.active').forEach(function (c) { active.push(c.dataset.status); });
  return { bar: bar, q: ((search && search.value) || '').trim().toLowerCase(), active: active };
}

function applyFilter(scope) {
  var state = filterState(scope);
  if (!state) return;
  var container = state.bar.parentElement;
  var shown = 0;

  // Card lists: each <details class="finding-card f-STATUS"> under a category header.
  var cards = container.querySelectorAll('details.finding-card');
  if (cards.length) {
    cards.forEach(function (card) {
      var status = (card.className.match(/f-(fail|warn|pass|skip)/) || [])[1] || '';
      var matchStatus = state.active.length === 0 || state.active.indexOf(status) !== -1;
      var matchText = !state.q || card.textContent.toLowerCase().indexOf(state.q) !== -1;
      var visible = matchStatus && matchText;
      card.style.display = visible ? '' : 'none';
      if (visible) shown++;
    });
    // A header owns every card until the next header.
    container.querySelectorAll('.cat-header').forEach(function (header) {
      var any = false;
      var node = header.nextElementSibling;
      while (node && !node.classList.contains('cat-header')) {
        if (node.classList.contains('finding-card') && node.style.display !== 'none') { any = true; break; }
        node = node.nextElementSibling;
      }
      header.style.display = any ? '' : 'none';
    });
  }

  // Table lists.
  var rows = container.querySelectorAll('table tbody tr');
  rows.forEach(function (row) {
    if (row.querySelector('td[colspan]')) return; // empty-state row
    var text = row.textContent.toLowerCase();
    var status = (row.querySelector('.tag') || {}).textContent || '';
    var matchStatus = state.active.length === 0 || state.active.indexOf(status.trim().toLowerCase()) !== -1;
    var visible = matchStatus && (!state.q || text.indexOf(state.q) !== -1);
    row.style.display = visible ? '' : 'none';
    if (visible) shown++;
  });

  var count = document.getElementById(scope + '-count');
  if (count) count.textContent = shown + ' shown';
  var clear = document.getElementById(scope + '-clear');
  if (clear) clear.disabled = !state.q && state.active.length === 0;
}

function toggleFilterChip(el) {
  el.classList.toggle('active');
  applyFilter(el.dataset.scope);
}

function clearFilter(scope) {
  var state = filterState(scope);
  if (!state) return;
  var search = document.getElementById(scope + '-search');
  if (search) search.value = '';
  state.bar.querySelectorAll('.flt-chip.active').forEach(function (c) { c.classList.remove('active'); });
  applyFilter(scope);
}

// ── Inventory filters ───────────────────────────────────────────────
// Each dropdown holds either "" (no filter) or one or more pipe-separated values, so a
// combined option like "fail|warn" needs no special case. Rows carry data-status /
// data-severity / data-category attributes, so filtering never parses rendered cell text.
var INV_SELECTS = [
  { id: 'invStatus', attr: 'status' },
  { id: 'invSeverity', attr: 'severity' },
  { id: 'invCategory', attr: 'category' },
  // A control carries several tags, so this one matches by containment while the others match
  // the whole attribute.
  { id: 'invTag', attr: 'tags', multi: true },
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
    filters.push({ attr: f.attr, values: raw.split('|'), multi: f.multi === true });
  });
  if (q) active++;

  var rows = document.querySelectorAll('#invTable tbody:first-of-type tr');
  var shown = 0;
  rows.forEach(function (row) {
    var visible = filters.every(function (f) {
      var value = row.getAttribute('data-' + f.attr) || '';
      if (!f.multi) return f.values.indexOf(value) !== -1;
      var owned = value.split(' ');
      return f.values.some(function (wanted) { return owned.indexOf(wanted) !== -1; });
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
