/**
 * TRUST — Secure Remote Password (SRP), as Cognito's USER_SRP_AUTH flow uses it.
 *
 * SRP exists so a password never crosses the wire, which is exactly why TRUST implements it
 * rather than falling back to USER_PASSWORD_AUTH: the alternative would have every partner
 * enable a plaintext-password grant on their user pool purely to run a security assessment.
 *
 * The maths is RFC 5054 over the 3072-bit MODP group, with Cognito's own key-derivation on
 * top (HKDF into an HMAC over the pool's secret block). BigInt and node:crypto cover all of it.
 */

import crypto from "node:crypto";

/** RFC 3526 group 15 — the 3072-bit prime Cognito uses. */
const N_HEX = [
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
  "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
  "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183",
  "995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A",
  "85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7A",
  "BF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D",
  "87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E20",
  "8E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
].join("");

// Transcribed from the RFC. A typo would fail late and confusingly, so the group is checked in
// the test suite the way its own definition guarantees: N is a safe prime with g=2 generating
// the large subgroup, which no mistyped digit survives.
const N = BigInt(`0x${N_HEX}`);
const g = 2n;
const INFO = "Caldera Derived Key";
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

const hexHash = (hex) => crypto.createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");
const strHash = (text) => crypto.createHash("sha256").update(text, "utf8").digest("hex");

/**
 * Pad to an even number of hex digits, and prefix 00 when the leading bit is set — a hex
 * string is read as a signed big integer at the other end, so an unpadded value that happens
 * to start with 8-F is a different number.
 */
export function padHex(value) {
  let hex = typeof value === "bigint" ? value.toString(16) : String(value);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  else if ("89abcdefABCDEF".includes(hex[0])) hex = `00${hex}`;
  return hex;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let b = ((base % modulus) + modulus) % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

/**
 * Cognito's timestamp for the signed blob: "Thu Jan 1 00:00:00 UTC 1970". The day of month is
 * not zero-padded and the names are English regardless of locale, so it is built by hand
 * rather than with toLocaleString.
 */
export function cognitoTimestamp(date = new Date()) {
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${DAYS[date.getUTCDay()]} ${MONTHS[date.getUTCMonth()]} ${date.getUTCDate()} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC ${date.getUTCFullYear()}`
  );
}

/** The pool name is the portion after the region prefix — us-east-1_AbC123 → AbC123. */
export const poolNameOf = (userPoolId) => String(userPoolId).split("_").slice(1).join("_");

/** Start the exchange: a random secret a, and the public A = g^a mod N. */
export function createSrpClient(randomBytes = (n) => crypto.randomBytes(n)) {
  let a;
  let A;
  do {
    a = BigInt(`0x${randomBytes(128).toString("hex")}`) % N;
    A = modPow(g, a, N);
  } while (A % N === 0n); // A ≡ 0 would let a server accept any password
  return { a, A, srpA: A.toString(16) };
}

/**
 * Answer the PASSWORD_VERIFIER challenge.
 *
 *   srpB / salt / secretBlock come from the InitiateAuth response
 *   returns { signature, timestamp } for RespondToAuthChallenge
 */
export function passwordVerifier({ a, A, srpB, salt, secretBlock, poolName, username, password, date = new Date() }) {
  const B = BigInt(`0x${srpB}`);
  if (B % N === 0n) throw new Error("SRP: server returned B ≡ 0 mod N — refusing to continue");

  const k = BigInt(`0x${hexHash(`${padHex(N)}${padHex(g)}`)}`);
  const u = BigInt(`0x${hexHash(`${padHex(A)}${padHex(B)}`)}`);
  if (u === 0n) throw new Error("SRP: u is zero — refusing to continue");

  const x = BigInt(`0x${hexHash(`${padHex(salt)}${strHash(`${poolName}${username}:${password}`)}`)}`);
  const exponent = a + u * x;
  const base = ((B - k * modPow(g, x, N)) % N + N) % N;
  const S = modPow(base, exponent, N);

  const key = crypto.hkdfSync("sha256", Buffer.from(padHex(S), "hex"), Buffer.from(padHex(u), "hex"), Buffer.from(INFO, "utf8"), 16);
  const timestamp = cognitoTimestamp(date);
  const message = Buffer.concat([
    Buffer.from(poolName, "utf8"),
    Buffer.from(username, "utf8"),
    Buffer.from(secretBlock, "base64"),
    Buffer.from(timestamp, "utf8"),
  ]);
  const signature = crypto.createHmac("sha256", Buffer.from(key)).update(message).digest("base64");
  return { signature, timestamp };
}

/** Cognito's SECRET_HASH, required when the app client was created with a secret. */
export const secretHash = (username, clientId, clientSecret) =>
  crypto.createHmac("sha256", clientSecret).update(`${username}${clientId}`).digest("base64");

export const SRP_N = N;
export const SRP_G = g;
