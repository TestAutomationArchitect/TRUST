/**
 * The complete test inventory, filterable by status, severity, category and free text.
 *
 * Dropdowns rather than chip rows: eleven always-visible chips compete for attention and
 * give no hint of what is selected, and they had no room for category. Each option carries
 * its own count, so the reader can see where the weight sits before choosing. Only values
 * that actually occur in this report are offered — an empty filter is a dead end.
 *
 * Status and severity include a combined option ("Failed or warning", "Critical or high")
 * because that is the one multi-select the chips were genuinely useful for.
 */

import { esc, sectionCard } from "../html.mjs";

const STATUS_LABEL = { fail: "Failed", warn: "Warning", pass: "Passed", skip: "Skipped" };
const SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

function options(facet, labels, { all, combined }) {
  const total = facet.reduce((sum, f) => sum + f.count, 0);
  const present = new Set(facet.map((f) => f.value));
  const rows = [`      <option value="">${all} (${total})</option>`];

  // A combined option only earns its place when more than one of its members occurs.
  if (combined && combined.values.filter((v) => present.has(v)).length > 1) {
    const count = facet.filter((f) => combined.values.includes(f.value)).reduce((sum, f) => sum + f.count, 0);
    rows.push(`      <option value="${combined.values.join("|")}">${combined.label} (${count})</option>`);
  }
  for (const { value, count } of facet) {
    rows.push(`      <option value="${esc(value)}">${esc(labels[value] ?? value)} (${count})</option>`);
  }
  return rows.join("\n");
}

export function renderInventory(model) {
  const { allFindings, inventoryRows, inventoryFacets } = model;
  const { statuses, severities, categories } = inventoryFacets;

  return sectionCard({
    id: "section-inventory",
    title: `Complete Test Inventory`,
    badge: `<span class="sc-chip">${allFindings.length} tests</span>`,
    open: false,
    body: `<div class="table-card">
<div class="inv-toolbar">
  <div class="inv-field inv-field-grow">
    <label class="inv-label" for="invSearch">Search</label>
    <input class="inv-search" type="search" placeholder="ID, test name or category…" oninput="filterInventory()" id="invSearch"/>
  </div>
  <div class="inv-field">
    <label class="inv-label" for="invStatus">Status</label>
    <select class="inv-select" id="invStatus" onchange="filterInventory()">
${options(statuses, STATUS_LABEL, { all: "All statuses", combined: { label: "Failed or warning", values: ["fail", "warn"] } })}
    </select>
  </div>
  <div class="inv-field">
    <label class="inv-label" for="invSeverity">Severity</label>
    <select class="inv-select" id="invSeverity" onchange="filterInventory()">
${options(severities, SEVERITY_LABEL, { all: "All severities", combined: { label: "Critical or high", values: ["critical", "high"] } })}
    </select>
  </div>
  <div class="inv-field">
    <label class="inv-label" for="invCategory">Category</label>
    <select class="inv-select" id="invCategory" onchange="filterInventory()">
${options(categories, {}, { all: "All categories" })}
    </select>
  </div>
  <div class="inv-field inv-field-actions">
    <button class="inv-clear" id="invClear" onclick="clearInventoryFilters()" disabled>Clear filters</button>
    <span class="inv-count" id="invCount">${allFindings.length} tests</span>
  </div>
</div>
<div class="table-wrap">
<table id="invTable">
  <thead><tr><th>Status</th><th>Severity</th><th>ID</th><th>Category</th><th>Test</th><th>Profile</th></tr></thead>
  <tbody>
${inventoryRows}
  </tbody>
  <tbody id="invEmpty" hidden>
    <tr><td colspan="6" class="inv-empty">No tests match these filters. <button class="inv-clear inv-clear-inline" onclick="clearInventoryFilters()">Clear filters</button></td></tr>
  </tbody>
</table>
</div></div>`,
  });
}
