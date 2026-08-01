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
  [/\bsk-ant-[A-Za-z0-9_-]{16,}\b/g, "[REDACTED_ANTHROPIC_KEY]"],
  [/\bsk-[A-Za-z0-9_-]{16,}\b/g, "[REDACTED_API_KEY]"],
  [/\bhf_[A-Za-z0-9]{16,}\b/g, "[REDACTED_HUGGINGFACE_TOKEN]"],
  [/\bco-[A-Za-z0-9]{32,}\b/g, "[REDACTED_COHERE_KEY]"],
  // Azure SAS: the signature and its companions appear in headers and bodies too, not only
  // after a ? or & in a URL, so match the parameter wherever it occurs.
  [/\b(sig|se|sp|sv|skoid|sktid|skt|ske|sks|srt|ss)=([A-Za-z0-9%+/=_-]{8,})/gi, "$1=[REDACTED]"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, "[REDACTED_SLACK_TOKEN]"],
  // Correlation data rather than credentials, but an evidence file is shared with people who
  // should not be able to resolve it back to a person or an account. A Cognito identity ID maps
  // to a real user in the identity pool; an account ID in an ARN is not secret, but partners
  // consistently ask for it not to travel in a document they forward.
  //
  // Deliberately *not* redacted: bare UUIDs. TRUST plants canaries and session identifiers in
  // its own evidence, and they are how a reader verifies a leak finding — blanket-redacting
  // every UUID would erase the proof along with the correlation risk.
  [/\b[a-z]{2}-[a-z]+-\d:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "[REDACTED_IDENTITY_ID]"],
  [/(arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:)(\d{12})(:)/gi, "$1[REDACTED_ACCOUNT]$3"],
  // JSON-quoted secrets, whose values may contain spaces and so are missed by the
  // whitespace-delimited rule below. A service-account key is the canonical case:
  //   "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE…"
  [
    /"([A-Za-z0-9_.-]*(?:pass(?:word|wd)?|secret|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret|token|credential)[A-Za-z0-9_.-]*)"(\s*:\s*)"[^"]{4,}"/gi,
    '"$1"$2"[REDACTED]"',
  ],
  // key/value pairs: password=…, "api_key": "…", DB_PASSWORD=…, secret: …
  // The key may carry a prefix/suffix (DB_PASSWORD) and may be quoted ("password": …),
  // so the closing quote belongs to the separator group.
  [
    /([A-Za-z0-9_.-]*(?:pass(?:word|wd)?|secret|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|token|authorization|credential)[A-Za-z0-9_.-]*)("?\s*[:=]\s*)("?)([^\s",;&}]{4,})\3/gi,
    (match, key, sep, quote, value) =>
      // A scheme word or an already-redacted value is left alone — the Bearer rule above owns it.
      /^(Bearer|Basic|Digest|\[REDACTED)/i.test(value) ? match : `${key}${sep}${quote}[REDACTED]${quote}`,
  ],
  // Signed-URL credentials
  [/([?&](?:X-Amz-Signature|X-Amz-Credential|Signature|AWSAccessKeyId|sig|sv)=)[^&\s]+/gi, "$1[REDACTED]"],
  // PEM blocks
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]"],
];

/** Clamp free text to a length every output format can carry. */
function truncate(text) {
  return text.length > MAX_EVIDENCE ? `${text.slice(0, MAX_EVIDENCE)}
… [truncated ${text.length - MAX_EVIDENCE} chars]` : text;
}

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
export function finding({ id, title, status, severity = "info", evidence = "", remediation = "", observed = "", domain = "", category = "", activatedBy = "", skipKind = "", warnKind = "" }) {
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
    // Redacted like evidence: a probe author will eventually put a response fragment here.
    observed: status === "fail" || status === "warn" ? redact(observed) : "",
    evidence: redact(evidence),
    // Bounded like evidence: remediation is rendered into HTML, XML and JSON, and an
    // unbounded string from a probe that interpolated a response body would bloat every one
    // of them.
    remediation: status === "pass" ? "" : truncate(String(remediation ?? "")),
    // A probe may classify an individual finding, overriding the catalogue lookup. This is
    // what lets one probe report into two domains, and it is what survives into the run JSON
    // so the combined report does not have to re-derive it from a catalogue it cannot see.
    ...(domain ? { domain } : {}),
    ...(category ? { category } : {}),
    // The upstream failure that made this test reachable, for a chained probe. It survives
    // into the run JSON so the report can narrate an executed attack path rather than
    // presenting two findings that happen to be adjacent.
    ...(activatedBy ? { activatedBy } : {}),
    // Why this control was not assessed, or could not be confirmed. A skip that means "nobody
    // looked" and one that means "this cannot apply here" are different facts about coverage,
    // and collapsing them is how a run reads as safer than it is.
    ...(status === "skip" ? { skipKind: SKIP_KINDS.includes(skipKind) ? skipKind : classifySkip(evidence) } : {}),
    ...(status === "warn" ? { warnKind: WARN_KINDS.includes(warnKind) ? warnKind : "advisory" } : {}),
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

/**
 * Why a control was not assessed. The distinction is the whole point:
 *
 *   unconfigured    the target may well have this problem — nobody looked, because the config
 *                   does not say where to look. This is the one that produces false confidence,
 *                   and the reason it is counted and surfaced separately.
 *   not-applicable  the control cannot apply here, or cannot be verified over HTTP at all
 *                   (certificate pinning needs a device). Excluding it is honest.
 *   precondition    the harness looked and could not proceed — an upstream control held, a
 *                   second identity was absent, a guard refused. A statement about the run.
 */
export const SKIP_KINDS = ["unconfigured", "not-applicable", "precondition"];

const SKIP_PATTERNS = [
  [/\b(is not configured|is not defined|not set in the environment|is not set|is empty|no .* configured)\b/i, "unconfigured"],
  [/\b(requires a browser|requires an instrumented device|cannot be verified|manual|out of scope)\b/i, "not-applicable"],
  [/\b(held|not reachable|needs a second identity|disabled|refused|budget|already covered|did not resolve|could not be discovered)\b/i, "precondition"],
];

/**
 * Classify a skip from its reason when a probe did not say.
 *
 * Inference rather than a mandatory argument, because a hundred call sites forced to restate
 * something their own wording already carries would drift out of step with it. A probe that
 * cares passes the kind explicitly; the default is `unconfigured`, which is the cautious end —
 * it counts against coverage and is surfaced rather than quietly excused.
 */
export function classifySkip(reason) {
  for (const [pattern, kind] of SKIP_PATTERNS) if (pattern.test(reason)) return kind;
  return "unconfigured";
}

/** A test that could not run. Severity is always info — a skip is not a verdict. */
export function skipped(id, title, reason, kind = "") {
  const skipKind = SKIP_KINDS.includes(kind) ? kind : classifySkip(String(reason));
  return finding({ id, title, status: "skip", severity: "info", evidence: `Skipped: ${reason}`, skipKind });
}

/**
 * Why a control could not be confirmed. Three different things wore one badge:
 *
 *   inconclusive  the harness could not tell — a request failed, a response was ambiguous
 *   partial       the check ran but did not complete, so absence of a hit proves nothing
 *   advisory      the control is present but weaker than it should be; nothing is broken
 */
export const WARN_KINDS = ["inconclusive", "partial", "advisory"];

/** A test that could not reach a verdict (network error, ambiguous response). */
export function inconclusive(id, title, reason, remediation = "Re-run once the precondition is met, or verify manually.") {
  return finding({ id, title, status: "warn", severity: "low", evidence: reason, remediation, warnKind: "inconclusive" });
}

/**
 * The verdict for a sweep that may not have completed.
 *
 * Loop-based probes stop early when the request budget runs low and swallow per-request
 * errors so one bad path cannot abort a suite. Both make "nothing found" indistinguishable
 * from "nothing checked", and the probe then reports a PASS for work it never did — the exact
 * failure mode that let an exhausted budget look like a clean bill of health.
 *
 * A sweep that performed no checks is not a pass; it is a skip. A partial sweep can still
 * report a positive finding (a hit is a hit) but must say how far it got.
 */
export function sweepVerdict({ hits, performed, planned }) {
  if (hits > 0) return "found";
  if (performed === 0) return "not-run";
  return performed < planned ? "partial" : "complete";
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
