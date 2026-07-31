/**
 * TRUST — AWS Signature Version 4.
 *
 * Signing is a *credential kind*, not a transport: the signature is computed over a request
 * that SafeHttpClient has already approved, and applied immediately before fetch. Nothing here
 * opens a socket, so signing can never route around a guard.
 *
 * Roughly fifty lines of node:crypto, which is why this is not a dependency.
 */

import crypto from "node:crypto";

const ALGORITHM = "AWS4-HMAC-SHA256";
const UNSIGNED_HEADERS = new Set(["authorization", "content-length", "user-agent", "connection", "expect", "transfer-encoding"]);

const sha256 = (data) => crypto.createHash("sha256").update(data).digest("hex");
const hmac = (key, data) => crypto.createHmac("sha256", key).update(data, "utf8").digest();

/** RFC 3986 — encodeURIComponent leaves !'()* unescaped, which AWS does not. */
const rfc3986 = (value) => encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** 20240131T120000Z */
export function amzDate(date) {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, "");
}

/**
 * S3 requires the path double-encoded rule *disabled*; every other service encodes each
 * segment. URL.pathname is already percent-encoded, so decode a segment before re-encoding it
 * rather than encoding the escapes themselves.
 */
function canonicalPath(pathname, service) {
  if (!pathname || pathname === "/") return "/";
  if (service === "s3") return pathname;
  return pathname
    .split("/")
    .map((segment) => {
      try {
        return rfc3986(decodeURIComponent(segment));
      } catch {
        return rfc3986(segment);
      }
    })
    .join("/");
}

function canonicalQuery(searchParams) {
  const pairs = [];
  for (const [key, value] of searchParams) pairs.push([rfc3986(key), rfc3986(value)]);
  pairs.sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : 1) : a[0] < b[0] ? -1 : 1));
  return pairs.map(([k, v]) => `${k}=${v}`).join("&");
}

/**
 * Sign a request. Returns the headers to add — the caller merges them, so an unsigned
 * request and a signed one take the identical code path up to that point.
 *
 *   credentials  { accessKeyId, secretAccessKey, sessionToken?, region, service }
 */
export function signRequest({ method = "GET", url, headers = {}, body = "", credentials, date = new Date() }) {
  const { accessKeyId, secretAccessKey, sessionToken, region, service } = credentials;
  if (!accessKeyId || !secretAccessKey) throw new Error("SigV4 requires accessKeyId and secretAccessKey");
  if (!region || !service) throw new Error("SigV4 requires region and service");

  const parsed = url instanceof URL ? url : new URL(url);
  const stamp = amzDate(date);
  const day = stamp.slice(0, 8);
  const payloadHash = sha256(body ?? "");

  // The signed set is assembled first so the canonical headers and the Authorization header
  // can never disagree about what was covered.
  const signed = {
    host: parsed.host,
    "x-amz-date": stamp,
    "x-amz-content-sha256": payloadHash,
    ...(sessionToken ? { "x-amz-security-token": sessionToken } : {}),
  };
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (!UNSIGNED_HEADERS.has(lower) && value != null) signed[lower] = String(value);
  }

  const names = Object.keys(signed).sort();
  const canonicalHeaders = names.map((n) => `${n}:${signed[n].trim().replace(/\s+/g, " ")}\n`).join("");
  const signedHeaders = names.join(";");

  const canonicalRequest = [
    method.toUpperCase(),
    canonicalPath(parsed.pathname, service),
    canonicalQuery(parsed.searchParams),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const scope = `${day}/${region}/${service}/aws4_request`;
  const stringToSign = [ALGORITHM, stamp, scope, sha256(canonicalRequest)].join("\n");

  const signingKey = hmac(hmac(hmac(hmac(`AWS4${secretAccessKey}`, day), region), service), "aws4_request");
  const signature = crypto.createHmac("sha256", signingKey).update(stringToSign, "utf8").digest("hex");

  return {
    ...(sessionToken ? { "x-amz-security-token": sessionToken } : {}),
    "x-amz-date": stamp,
    "x-amz-content-sha256": payloadHash,
    authorization: `${ALGORITHM} Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}
