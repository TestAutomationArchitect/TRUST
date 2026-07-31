/**
 * TRUST — stable finding identity.
 *
 * Baselines, SARIF de-duplication and any external issue tracker all need the same thing: a
 * name for "this finding" that survives across runs. The identity deliberately excludes
 * evidence, status and timing. An identity that changed when the evidence changed would make
 * every run look entirely new, which is precisely what makes baselines useless — and a team
 * that cannot trust a baseline goes back to reading every finding every time.
 *
 * Test plus target is what a reviewer means by "the same finding". Nothing else belongs in it.
 */

import crypto from "node:crypto";

const hostOf = (target) => {
  try {
    return new URL(target).host;
  } catch {
    return String(target ?? "");
  }
};

/** `API-CROSS-USER@api.dev.example.com` — readable, so a diff can be eyeballed. */
export function findingKey(finding, { target = "" } = {}) {
  const host = hostOf(target);
  return host ? `${finding.id}@${host}` : finding.id;
}

/** A short hash of the key, for formats that want an opaque fingerprint. */
export const fingerprint = (key) => crypto.createHash("sha256").update(key).digest("hex").slice(0, 32);
