/**
 * TRUST — storage isolation probes.
 *
 * Works against any HTTP-addressable object store (S3, GCS, Azure Blob, or a
 * signed-URL gateway). Access is exercised with the identity token the app itself
 * uses; SigV4 signing is deliberately out of scope so the harness never needs
 * long-lived cloud credentials.
 *
 * Verdict logic: 403/401 → PASS (isolation holds). 200 with content → FAIL.
 */

import { finding, skipped, inconclusive } from "../finding.mjs";

function authHeaders(storage, token) {
  const scheme = storage.authScheme ?? "Bearer";
  const header = storage.authHeader ?? "authorization";
  return {
    [header]: scheme ? `${scheme} ${token}` : token,
    ...(storage.headers ?? {}),
  };
}

function objectUrl(storage, target) {
  if (target.url) return target.url;
  if (!storage.baseUrl) throw new Error("storage.baseUrl is required when a target has no explicit url");
  return new URL(target.key ?? target.prefix ?? "", storage.baseUrl).href;
}

/** Was the object or listing actually returned? */
function readable(status, text) {
  if (status !== 200 && status !== 206) return false;
  if (/<Error>|AccessDenied|InvalidAccessKeyId|SignatureDoesNotMatch/i.test(text)) return false;
  return text.length > 0;
}

export async function runStorageProbes(config, client) {
  const storage = config.storage;
  if (!storage || (!storage.baseUrl && !storage.targets)) {
    return [skipped("STORAGE-CONFIG", "Storage isolation probe suite", "config.storage is not configured")];
  }

  const tokenA = storage.tokenAEnv ? process.env[storage.tokenAEnv] : undefined;
  const tokenB = storage.tokenBEnv ? process.env[storage.tokenBEnv] : undefined;
  const out = [];

  // ── Unauthenticated listing / read ────────────────────────────────
  if (storage.publicListingUrl ?? storage.baseUrl) {
    const url = storage.publicListingUrl ?? storage.baseUrl;
    try {
      const response = await client.request(url);
      const text = (await response.text()).slice(0, 800);
      const open = readable(response.status, text);
      out.push(
        finding({
          id: "STORAGE-PUBLIC-LISTING",
          observed: "The storage container is readable without credentials",
          title: "Storage container cannot be listed or read anonymously",
          status: open ? "fail" : "pass",
          severity: "critical",
          evidence: `Unauthenticated GET ${url} → HTTP ${response.status}\n${text}`,
          remediation: open
            ? "Enable the account-level public-access block, remove any public bucket policy or ACL, and serve objects through short-lived signed URLs."
            : "",
        }),
      );
    } catch (error) {
      out.push(inconclusive("STORAGE-PUBLIC-LISTING", "Storage container cannot be listed or read anonymously", `Request failed: ${error.message}`));
    }
  }

  if (!tokenA) {
    out.push(
      skipped(
        "STORAGE-CONFIG",
        "Authenticated storage isolation probes",
        `${storage.tokenAEnv ?? "storage.tokenAEnv"} is not set — authenticated isolation tests need a real identity`,
      ),
    );
    return out;
  }

  // ── Cross-tenant and cross-user access ────────────────────────────
  // Each target declares who owns it and who is attempting access.
  const targets = storage.targets ?? [];
  if (targets.length === 0) {
    out.push(skipped("STORAGE-CROSS-TENANT", "Cross-tenant storage isolation", "config.storage.targets is empty"));
    return out;
  }

  for (const target of targets) {
    const scope = target.scope === "user" ? "CROSS-USER" : "CROSS-TENANT";
    const asIdentity = target.as === "B" ? "B" : "A";
    const token = asIdentity === "B" ? tokenB : tokenA;
    const suffix = target.name ? `-${String(target.name).toUpperCase().replace(/[^A-Z0-9]+/g, "-")}` : `-USER-${asIdentity}`;
    const id = `STORAGE-${scope}${suffix}`;
    const title =
      target.title ??
      (scope === "CROSS-USER"
        ? `User ${asIdentity} cannot access another user's files`
        : `User ${asIdentity} cannot access another tenant's prefix`);

    if (!token) {
      out.push(skipped(id, title, `token for identity ${asIdentity} is not set`));
      continue;
    }

    let url;
    try {
      url = objectUrl(storage, target);
    } catch (error) {
      out.push(skipped(id, title, error.message));
      continue;
    }

    try {
      const response = await client.request(url, { headers: authHeaders(storage, token) });
      const text = (await response.text()).slice(0, 800);
      const accessible = readable(response.status, text);
      out.push(
        finding({
          id,
          title,
          observed: scope === "CROSS-TENANT" ? "Another tenant’s prefix is readable" : "Another user’s file is readable",
          status: accessible ? "fail" : "pass",
          severity: scope === "CROSS-TENANT" ? "critical" : "high",
          evidence: `GET ${url} as identity ${asIdentity} → HTTP ${response.status}\n${text}`,
          remediation: accessible
            ? "Scope the storage IAM/access policy to the caller's identity or tenant prefix (e.g. a condition on the token's sub or tenant claim) instead of granting the whole bucket."
            : "",
        }),
      );
    } catch (error) {
      out.push(inconclusive(id, title, `Request failed: ${error.message}`));
    }
  }

  // Two identities in genuinely different tenants is a precondition for meaning.
  if (targets.some((t) => t.scope !== "user") && !tokenB) {
    out.push(
      skipped(
        "STORAGE-CROSS-TENANT",
        "Cross-tenant isolation confirmed from both directions",
        `${storage.tokenBEnv ?? "storage.tokenBEnv"} is not set — only one direction of isolation was tested`,
      ),
    );
  }

  return out;
}
