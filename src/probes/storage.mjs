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
import { section } from "../config.mjs";
import { authInit, credentialFor } from "../auth/index.mjs";

/**
 * Request init for one identity. A bearer credential becomes a header; a SigV4 credential is
 * signed by the client after its guards pass — which is what lets these probes run against a
 * bucket that only accepts signed requests, without the harness holding long-lived keys.
 */
function asIdentityInit(storage, credential) {
  return authInit(credential, {
    header: storage.authHeader ?? "authorization",
    scheme: storage.authScheme ?? "Bearer",
    headers: { ...(storage.headers ?? {}) },
  });
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
  // The canonical section, resolved through conventional spellings — an app that calls it
  // "s3" should not have to duplicate it under "storage".
  const { value: storage, key: storageKey } = section(config, "storage");
  if (!storage || (!storage.baseUrl && !storage.targets)) {
    return [skipped("STORAGE-CONFIG", "Storage isolation probe suite", "config.storage is not configured")];
  }

  const { credential: tokenA, reason: reasonA } = credentialFor(client, storage, "tokenA");
  const { credential: tokenB, reason: reasonB } = credentialFor(client, storage, "tokenB");
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
        `authenticated isolation tests need a real identity: ${reasonA}`,
      ),
    );
    return out;
  }

  // ── Cross-tenant and cross-user access ────────────────────────────
  // Each target declares who owns it and who is attempting access.
  const targets = storage.targets ?? [];
  if (targets.length === 0) {
    out.push(skipped("STORAGE-CROSS-TENANT", "Cross-tenant storage isolation", "config.storage.targets is empty"));
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
      const response = await client.request(url, asIdentityInit(storage, token));
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
        `only one direction of isolation was tested: ${reasonB}`,
      ),
    );
  }

  // ── Path traversal out of the caller's prefix ─────────────────────
  //
  // Isolation is usually enforced by a prefix, and a prefix is a string comparison. If the key
  // is not normalised before that comparison, "user-a/../user-b/secret.pdf" satisfies it and
  // reads someone else's object. The encodings matter: a gateway may normalise one form and
  // pass another through unchanged.
  if (!storage.baseUrl || !tokenA) {
    out.push(
      skipped(
        "STORAGE-PATH-TRAVERSAL",
        "Object keys cannot escape the caller's prefix",
        storage.baseUrl ? `authenticated traversal needs an identity: ${reasonA}` : "config.storage.baseUrl is not configured",
      ),
    );
  } else {
    const ownPrefix = storage.ownPrefix ?? storage.prefix ?? "protected/";
    const escapes = [
      { name: "dot-dot", key: `${ownPrefix}../` },
      { name: "encoded", key: `${ownPrefix}%2e%2e%2f` },
      { name: "double-encoded", key: `${ownPrefix}%252e%252e%252f` },
      { name: "backslash", key: `${ownPrefix}..%5c` },
    ];
    const escaped = [];
    let attempted = 0;
    for (const escape of escapes) {
      if (client.remainingRequests < 2) break;
      attempted += 1;
      try {
        const url = new URL(escape.key, storage.baseUrl).href;
        const response = await client.request(url, asIdentityInit(storage, tokenA));
        const text = (await response.text()).slice(0, 400);
        // A listing or an object body from outside the prefix is the finding; a 403, a 404 or
        // an S3 <Error> document is the control holding.
        if (readable(response.status, text) && !/AccessDenied|NoSuchKey/i.test(text)) {
          escaped.push({ ...escape, status: response.status, snippet: text.slice(0, 200) });
        }
      } catch (error) {
        /* a refused or failed request is not evidence of traversal */
      }
    }

    out.push(
      finding({
        id: "STORAGE-PATH-TRAVERSAL",
        title: "Object keys cannot escape the caller's prefix",
        observed: "A traversal sequence in the object key reached outside the caller's prefix",
        status: escaped.length ? "fail" : attempted === 0 ? "warn" : "pass",
        warnKind: "partial",
        severity: "critical",
        evidence: escaped.length
          ? escaped.map((e) => [`${e.name}: ${e.key} → HTTP ${e.status}`, e.snippet].join("\n")).join("\n\n")
          : `Tried ${attempted} traversal encoding(s) against ${ownPrefix}; every one was refused or returned nothing.`,
        remediation: escaped.length
          ? "Normalise and canonicalise the key before the prefix check, and reject any key containing a traversal sequence in any encoding. A prefix comparison against an un-normalised key is not an authorisation boundary."
          : "",
      }),
    );
  }

  // ── Signed URL integrity ──────────────────────────────────────────
  //
  // A signed URL is a bearer credential with the scope written into it. Two questions decide
  // whether it holds: does altering the signature invalidate it, and does altering the expiry
  // extend it? Both are answered by sending a URL the caller already has, changed by one field.
  const signedUrl = storage.signedUrl;
  if (!signedUrl) {
    out.push(skipped("STORAGE-SIGNED-URL", "A signed URL cannot be altered or extended", "config.storage.signedUrl is not defined (a currently valid signed URL to test)"));
  } else {
    try {
      const original = new URL(signedUrl);
      const tampered = new URL(signedUrl);
      const signatureParam = ["X-Amz-Signature", "Signature", "sig", "sv"].find((p) => tampered.searchParams.has(p));
      const expiryParam = ["X-Amz-Expires", "Expires", "se"].find((p) => tampered.searchParams.has(p));

      if (!signatureParam) {
        out.push(
          skipped(
            "STORAGE-SIGNED-URL",
            "A signed URL cannot be altered or extended",
            "the configured URL carries no recognisable signature parameter, so there is nothing to tamper with",
            "not-applicable",
          ),
        );
      } else {
        const signature = tampered.searchParams.get(signatureParam);
        tampered.searchParams.set(signatureParam, signature.slice(0, -4) + (signature.slice(-4) === "aaaa" ? "bbbb" : "aaaa"));
        if (expiryParam) tampered.searchParams.set(expiryParam, "604800");

        const response = await client.request(tampered.href);
        const text = (await response.text()).slice(0, 300);
        const rejected = !readable(response.status, text) || /SignatureDoesNotMatch|AccessDenied|AuthenticationFailed/i.test(text);

        out.push(
          finding({
            id: "STORAGE-SIGNED-URL",
            title: "A signed URL cannot be altered or extended",
            observed: "An altered signed URL was still honoured",
            status: rejected ? "pass" : "fail",
            severity: "critical",
            evidence:
              `Altered ${signatureParam}${expiryParam ? ` and ${expiryParam}` : ""} on a signed URL for ${original.pathname} → HTTP ${response.status}
${text}
` +
              `Verdict basis: ${rejected ? "the store rejected the altered signature" : "the store served the object despite the signature not matching"}`,
            remediation: rejected
              ? ""
              : "The signature is not being verified, which makes every signed URL forgeable. Check the store or gateway is validating signatures rather than only parsing the query string, and that expiry is part of the signed payload.",
          }),
        );
      }
    } catch (error) {
      out.push(inconclusive("STORAGE-SIGNED-URL", "A signed URL cannot be altered or extended", `Request failed: ${error.message}`));
    }
  }

  return out;
}
