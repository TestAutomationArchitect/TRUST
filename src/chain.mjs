/**
 * TRUST — conditional execution.
 *
 * Probes fire independently, but real attack paths are sequential: whether a sub-agent
 * enforces its own authorisation only matters if it can be reached at all. Running the
 * downstream test unconditionally produces two kinds of noise — a finding about a path
 * nobody can take, and request budget spent proving it.
 *
 * A test declares what it depends on:
 *
 *   { "id": "ACL-BYPASS", "dependsOn": "HIERARCHY-BYPASS", "condition": "failed" }
 *
 * and the gate returns one of two things: permission to run, naming the upstream failure that
 * made this reachable, or a skip whose reason is the upstream control *holding*. The second is
 * the useful half. "Skipped — the hierarchy boundary held, so this path is not reachable" is a
 * statement about the system; "skipped" alone reads like a gap in the assessment.
 */

/** A dependency with no condition means "run me when the upstream broke". */
export const DEFAULT_CONDITION = "failed";
const CONDITIONS = ["failed", "passed", "any"];

/** id → status, from the findings produced so far in this run. */
export function statusIndex(findings = []) {
  const index = new Map();
  for (const f of findings) index.set(f.id, f.status);
  return index;
}

const met = (status, condition) => {
  if (status === undefined) return false;
  if (condition === "any") return true;
  if (condition === "passed") return status === "pass";
  return status === "fail";
};

/**
 * Decide whether a dependent test should run.
 *
 * Returns { run: true, activatedBy } or { run: false, reason }. An unknown upstream ID is a
 * configuration mistake, so it is reported as such rather than silently satisfying the gate —
 * a typo that quietly disables a test is worse than one that fails loudly.
 */
export function chainGate(spec, statuses) {
  const dependsOn = spec?.dependsOn;
  if (!dependsOn) return { run: true, activatedBy: null };

  const upstream = Array.isArray(dependsOn) ? dependsOn : [dependsOn];
  const condition = spec.condition ?? DEFAULT_CONDITION;
  if (!CONDITIONS.includes(condition)) {
    return { run: false, reason: `condition "${condition}" is not one of ${CONDITIONS.join(", ")}` };
  }

  const unknown = upstream.filter((id) => !statuses.has(id));
  if (unknown.length) {
    return { run: false, reason: `depends on ${unknown.join(", ")}, which did not run in this profile — check the ID and that its probe is enabled` };
  }

  const unmet = upstream.filter((id) => !met(statuses.get(id), condition));
  if (unmet.length) {
    const held = unmet.map((id) => `${id} ${statuses.get(id)}ed`).join(", ");
    return {
      run: false,
      reason:
        condition === "failed"
          ? `not reachable — upstream control held (${held})`
          : `precondition not met — expected ${upstream.join(", ")} to have ${condition} (${held})`,
    };
  }
  return { run: true, activatedBy: upstream.join(", ") };
}

/**
 * The sentence a chained finding carries. The report's value is in the narrative — "because
 * the hierarchy boundary was breached, this was exploitable" — so the reachability is recorded
 * on the finding itself rather than left for a reader to reconstruct.
 */
export const activationNote = (activatedBy) => (activatedBy ? `Reachable because ${activatedBy} failed.` : "");
