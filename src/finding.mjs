/**
 * TRUST — finding factory.
 *
 * Every probe emits findings through finding(). The factory enforces a single
 * shape and redacts secrets before anything reaches disk.
 */

import crypto from "node:crypto";

export const STATUSES = ["pass", "fail", "warn", "skip"];
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const SEV_WEIGHT = { critical: 10, high: 5, medium: 3, low: 1, info: 0.5 };

const MAX_EVIDENCE = 4000;

const REDACTIONS = [
  [/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+/g, "[REDACTED_JWT]"],
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, "$1 [REDACTED]"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_KEY_ID]"],
  [/\bASIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_STS_KEY_ID]"],
  [/\b(gh[pousr]_[A-Za-z0-9]{20,})\b/g, "[REDACTED_GITHUB_TOKEN]"],
  [/\bsk-[A-Za-z0-9_-]{16,}\b/g, "[REDACTED_API_KEY]"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, "[REDACTED_SLACK_TOKEN]"],
  // key/value pairs: password=…, "api_key": "…", DB_PASSWORD=…, secret: …
  // The key may carry a prefix/suffix (DB_PASSWORD) and may be quoted ("password": …),
  // so the closing quote belongs to the separator group.
  [
    /([A-Za-z0-9_.-]*(?:pass(?:word|wd)?|secret|api[_-]?key|access[_-]?key|client[_-]?secret|token|authorization|credential)[A-Za-z0-9_.-]*)("?\s*[:=]\s*)("?)([^\s",;&}]{4,})\3/gi,
    (match, key, sep, quote, value) =>
      // A scheme word or an already-redacted value is left alone — the Bearer rule above owns it.
      /^(Bearer|Basic|Digest|\[REDACTED)/i.test(value) ? match : `${key}${sep}${quote}[REDACTED]${quote}`,
  ],
  // Signed-URL credentials
  [/([?&](?:X-Amz-Signature|X-Amz-Credential|Signature|AWSAccessKeyId|sig|sv)=)[^&\s]+/gi, "$1[REDACTED]"],
  // PEM blocks
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]"],
];

/** Strip credentials from any value and clamp its length. */
export function redact(value) {
  let text = typeof value === "string" ? value : stringify(value);
  for (const [pattern, replacement] of REDACTIONS) {
    text = text.replace(pattern, replacement);
  }
  if (text.length > MAX_EVIDENCE) {
    text = `${text.slice(0, MAX_EVIDENCE)}\n… [truncated ${text.length - MAX_EVIDENCE} chars]`;
  }
  return text;
}

function stringify(value) {
  if (value == null) return "";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

/**
 * Build a finding. Throws on an invalid status/severity so a malformed probe
 * fails loudly at development time rather than producing a silent bad report.
 */
/**
 * Build a finding.
 *
 *   title     the control assertion, always phrased positively ("User B cannot read …").
 *   observed  what was actually seen when the control did NOT hold ("Cross-user read is
 *             permitted"). Reports headline this on a fail, and keep `title` as the
 *             expected control — otherwise a FAIL row reads as though the control held.
 *   severity  the impact IF this control fails. It is a property of the control, not of
 *             the outcome, which is why a passing test can legitimately be `critical`.
 */
export function finding({ id, title, status, severity = "info", evidence = "", remediation = "", observed = "" }) {
  if (!id) throw new TypeError("finding.id is required");
  if (!title) throw new TypeError(`finding.title is required (id=${id})`);
  if (!STATUSES.includes(status)) {
    throw new TypeError(`finding.status must be one of ${STATUSES.join("|")} (id=${id}, got ${status})`);
  }
  if (!SEVERITIES.includes(severity)) {
    throw new TypeError(`finding.severity must be one of ${SEVERITIES.join("|")} (id=${id}, got ${severity})`);
  }
  return {
    id,
    title,
    status,
    severity,
    // Only meaningful when the control did not hold; a pass has nothing adverse to report.
    observed: status === "fail" || status === "warn" ? String(observed ?? "") : "",
    evidence: redact(evidence),
    remediation: status === "pass" ? "" : String(remediation ?? ""),
  };
}

/**
 * The headline a report should use for a finding.
 *
 * A failing control must never be headlined with its positive assertion — "FAIL: User B
 * cannot read User A's record" reads to a non-tester as though the boundary held. Where a
 * probe supplied `observed`, use it; otherwise fall back to explicit negation rather than
 * inventing a claim about what happened.
 */
export function headline(f) {
  if (f.status === "fail") return f.observed || `Control not upheld — ${f.title}`;
  if (f.status === "warn") return f.observed || `Not fully verified — ${f.title}`;
  if (f.status === "skip") return `Not assessed — ${f.title}`;
  return f.title;
}

/** A test that could not run. Severity is always info — a skip is not a verdict. */
export function skipped(id, title, reason) {
  return finding({ id, title, status: "skip", severity: "info", evidence: `Skipped: ${reason}` });
}

/** A test that could not reach a verdict (network error, ambiguous response). */
export function inconclusive(id, title, reason, remediation = "Re-run once the precondition is met, or verify manually.") {
  return finding({ id, title, status: "warn", severity: "low", evidence: reason, remediation });
}

/** Unique marker used by injection and leak probes. */
export function canary(label = "CANARY") {
  return `${label}-${crypto.randomUUID().replace(/-/g, "").slice(0, 16).toUpperCase()}`;
}

/** Tally findings by status. */
export function summarize(findings) {
  const summary = { pass: 0, fail: 0, warn: 0, skip: 0, total: findings.length };
  for (const f of findings) summary[f.status] += 1;
  return summary;
}

/** Exit code contract: 2 when a critical/high/medium control failed, else 0. */
export function exitCodeFor(findings) {
  const blocking = new Set(["critical", "high", "medium"]);
  return findings.some((f) => f.status === "fail" && blocking.has(f.severity)) ? 2 : 0;
}
