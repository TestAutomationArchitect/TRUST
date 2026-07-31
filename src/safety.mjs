/**
 * TRUST — safety module.
 *
 * Every HTTP request in the platform flows through SafeHttpClient. The client is
 * designed so that the harness is *incapable* of harming the target:
 *
 *   HTTPS-only            no plaintext transport
 *   Host allowlist        no SSRF, no accidental scanning of third parties
 *   Request counter       hard cap on total requests
 *   Minimum delay         no request floods
 *   Per-request timeout   no hung sockets
 *   Production block      prod hostnames/environments refused without override
 *   redirect: "manual"    redirects are observed, never followed
 *   Write guard           PUT/PATCH/DELETE (and POSTs marked write) need allowWrites
 *   Agent guard           LLM/agent invocations need allowAgentInvocations
 */

import { readFile } from "node:fs/promises";
import tls from "node:tls";
import { applyCredential } from "./auth/index.mjs";

export const DEFAULT_SAFETY = {
  maxRequests: 100,
  minimumDelayMs: 150,
  requestTimeoutMs: 30000,
  allowWrites: false,
  allowAgentInvocations: false,
  allowDenialTests: false,
  productionOverride: false,
};

const PROD_ENVIRONMENTS = new Set(["prod", "production", "live"]);
const PROD_HOST_PATTERN = /(^|[.\-])(prod|production|live)([.\-]|$)/i;
const WRITE_METHODS = new Set(["PUT", "PATCH", "DELETE"]);

export class SafetyError extends Error {
  constructor(message) {
    super(message);
    this.name = "SafetyError";
  }
}

export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = "ConfigError";
  }
}

/** Read and parse a config file, applying safety defaults. */
export async function loadConfig(configPath) {
  // resolveExtends handles reading and parsing, including an inheritance chain.
  const { resolveExtends } = await import("./config.mjs");
  const parsed = await resolveExtends(configPath);
  parsed.safety = { ...DEFAULT_SAFETY, ...(parsed.safety ?? {}) };
  return parsed;
}

/** Allow // and /* *\/ comments in config files (jsonc-lite). */
export function stripJsonComments(text) {
  let out = "";
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const next = text[i + 1];
    if (inString) {
      out += c;
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      out += c;
      continue;
    }
    if (c === "/" && next === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
      continue;
    }
    if (c === "/" && next === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i++;
      continue;
    }
    out += c;
  }
  return out;
}

/**
 * Validate a config before any request is made. Throws ConfigError / SafetyError.
 * Returns the list of non-fatal advisories.
 */
export function validateConfig(config) {
  const advisories = [];
  if (!config || typeof config !== "object") throw new ConfigError("Config must be an object");
  if (!config.name) throw new ConfigError("config.name is required");
  if (!config.environment) throw new ConfigError("config.environment is required");

  const targets = config.targets ?? {};
  if (!targets.web) throw new ConfigError("config.targets.web is required");
  if (!Array.isArray(targets.allowedHosts) || targets.allowedHosts.length === 0) {
    throw new ConfigError("config.targets.allowedHosts must be a non-empty array");
  }

  const s = config.safety;
  // A number caps the whole run; a map caps per profile, so a long web sweep cannot exhaust
  // the budget before the storage and agent suites execute.
  const caps = typeof s.maxRequests === "object" && s.maxRequests !== null ? Object.values(s.maxRequests) : [s.maxRequests];
  if (caps.length === 0) throw new ConfigError("safety.maxRequests must not be an empty object");
  for (const cap of caps) {
    if (!Number.isInteger(cap) || cap < 1 || cap > 5000) {
      throw new ConfigError("every safety.maxRequests value must be an integer between 1 and 5000");
    }
  }
  for (const [suite, budget] of Object.entries(s.budgets ?? {})) {
    if (!Number.isInteger(budget) || budget < 1) throw new ConfigError(`safety.budgets.${suite} must be a positive integer`);
  }
  if (typeof s.minimumDelayMs !== "number" || s.minimumDelayMs < 50) {
    throw new ConfigError("safety.minimumDelayMs must be >= 50");
  }
  if (typeof s.requestTimeoutMs !== "number" || s.requestTimeoutMs < 1000) {
    throw new ConfigError("safety.requestTimeoutMs must be >= 1000");
  }

  const isProdEnv = PROD_ENVIRONMENTS.has(String(config.environment).toLowerCase());
  const prodHosts = targets.allowedHosts.filter((h) => PROD_HOST_PATTERN.test(h));
  if ((isProdEnv || prodHosts.length > 0) && s.productionOverride !== true) {
    throw new SafetyError(
      `Production target refused (environment="${config.environment}"` +
        (prodHosts.length ? `, hosts=${prodHosts.join(", ")}` : "") +
        "). Set safety.productionOverride=true only with written authorisation.",
    );
  }
  if (s.productionOverride === true) {
    advisories.push("safety.productionOverride is enabled — production targets are reachable.");
  }
  if (s.allowWrites === true) advisories.push("safety.allowWrites is enabled — mutating requests are permitted.");
  if (s.allowAgentInvocations === true) advisories.push("safety.allowAgentInvocations is enabled — the harness will invoke LLM agents.");
  if (s.allowDenialTests === true) {
    advisories.push("safety.allowDenialTests is enabled — mutations that are expected to be refused will be attempted.");
  }

  for (const host of targets.allowedHosts) {
    if (/^https?:\/\//i.test(host)) {
      throw new ConfigError(`allowedHosts entries must be bare hostnames, got "${host}"`);
    }
  }
  const webHost = safeHostname(targets.web);
  if (!webHost) throw new ConfigError(`config.targets.web is not a valid URL: ${targets.web}`);
  if (!targets.allowedHosts.includes(webHost)) {
    throw new ConfigError(`config.targets.web host "${webHost}" is not in targets.allowedHosts`);
  }
  return advisories;
}

function safeHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

export class SafeHttpClient {
  #count = 0;
  #lastRequestAt = 0;
  #blocked = [];

  #suite = null;
  #suiteCounts = new Map();
  #refreshed = new Set();

  constructor(config, { budget = null, credentials = new Map() } = {}) {
    this.config = config;
    /** Resolved auth strategies, by name. Probes look credentials up here; see auth/index.mjs. */
    this.credentials = credentials;
    this.safety = config.safety ?? { ...DEFAULT_SAFETY };
    this.allowedHosts = new Set(config.targets?.allowedHosts ?? []);
    // A resolved budget from config.mjs; falling back to the scalar keeps direct library use
    // working without one.
    this.budget = budget ?? { total: typeof this.safety.maxRequests === "number" ? this.safety.maxRequests : 100, suites: null };
  }

  /** Probe suites announce themselves so a per-suite budget can be enforced and reported. */
  beginSuite(name) {
    this.#suite = name;
    if (!this.#suiteCounts.has(name)) this.#suiteCounts.set(name, 0);
  }

  /** Requests spent per suite — surfaced in the run so an exhausted budget is explainable. */
  get suiteSpend() {
    return Object.fromEntries(this.#suiteCounts);
  }

  get requestCount() {
    return this.#count;
  }

  get remainingRequests() {
    const overall = Math.max(0, this.budget.total - this.#count);
    const suiteCap = this.budget.suites?.[this.#suite];
    if (!suiteCap) return overall;
    return Math.max(0, Math.min(overall, suiteCap - (this.#suiteCounts.get(this.#suite) ?? 0)));
  }

  /** Requests refused by a guard, for reporting. */
  get blocked() {
    return [...this.#blocked];
  }

  /** Assert a URL is safe to contact. Throws SafetyError. Used by probes for pre-flight checks. */
  assertUrlAllowed(url) {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      throw new SafetyError(`Invalid URL: ${url}`);
    }
    if (parsed.protocol !== "https:") {
      throw new SafetyError(`Refusing non-HTTPS request to ${parsed.protocol}//${parsed.host}`);
    }
    if (!this.allowedHosts.has(parsed.hostname)) {
      throw new SafetyError(`Host "${parsed.hostname}" is not in targets.allowedHosts`);
    }
    if (PROD_HOST_PATTERN.test(parsed.hostname) && this.safety.productionOverride !== true) {
      throw new SafetyError(`Host "${parsed.hostname}" looks like production; productionOverride is not set`);
    }
    return parsed;
  }

  /**
   * Perform a guarded fetch.
   *
   * Extra init options understood by TRUST (not passed to fetch):
   *   write: true            this request mutates state → requires safety.allowWrites
   *   denialTest: true       this request is expected to be REFUSED by the target. Allowed
   *                          under safety.allowDenialTests without enabling writes generally,
   *                          because the whole point is that nothing should be written. If the
   *                          target accepts it, that acceptance is the finding.
   *   agentInvocation: true  this request invokes an LLM/agent → requires allowAgentInvocations
   *   auth: credential       a resolved credential. A bearer token is already a header by the
   *                          time it arrives; a SigV4 credential signs the request here, after
   *                          every guard has passed, so signing can never route around one.
   */
  async request(url, init = {}) {
    const { write = false, agentInvocation = false, denialTest = false, auth = null, authHeader = "authorization", ...fetchInit } = init;
    const method = (fetchInit.method ?? "GET").toUpperCase();
    const parsed = this.assertUrlAllowed(url);

    const mutating = write === true || WRITE_METHODS.has(method);
    // A denial test asserts the target refuses a mutation. Requiring allowWrites for it forced
    // teams to enable every destructive path just to prove one control holds, so it has its
    // own switch — narrower, and the request is expected to change nothing.
    const denialAllowed = denialTest === true && this.safety.allowDenialTests === true;
    if (mutating && this.safety.allowWrites !== true && !denialAllowed) {
      this.#refuse(
        `${method} ${parsed.pathname}`,
        denialTest === true
          ? "denial tests are disabled (set safety.allowDenialTests, or safety.allowWrites)"
          : "writes are disabled (safety.allowWrites=false)",
      );
    }
    if (agentInvocation && this.safety.allowAgentInvocations !== true) {
      this.#refuse(`${method} ${parsed.pathname}`, "agent invocations are disabled (safety.allowAgentInvocations=false)");
    }
    if (this.#count >= this.budget.total) {
      this.#refuse(`${method} ${parsed.pathname}`, `run request cap reached (${this.budget.total})`);
    }
    const suiteCap = this.budget.suites?.[this.#suite];
    if (suiteCap && (this.#suiteCounts.get(this.#suite) ?? 0) >= suiteCap) {
      this.#refuse(`${method} ${parsed.pathname}`, `budget for the "${this.#suite}" suite exhausted (${suiteCap})`);
    }

    await this.#throttle();
    this.#count += 1;
    if (this.#suite) this.#suiteCounts.set(this.#suite, (this.#suiteCounts.get(this.#suite) ?? 0) + 1);
    this.#lastRequestAt = Date.now();

    const signal = AbortSignal.timeout(this.safety.requestTimeoutMs);
    const headers = applyCredential(auth, { method, url: parsed, headers: fetchInit.headers ?? {}, body: fetchInit.body });
    const response = await fetch(parsed.href, { ...fetchInit, headers, method, redirect: "manual", signal });

    // A long agent run outlives a fifteen-minute token, and every probe after expiry would
    // otherwise report the target rejecting valid requests. Refresh once, then believe the 401:
    // a second failure is a finding about the target, not about the harness.
    if (response.status === 401 && typeof auth?.reacquire === "function" && !this.#refreshed.has(auth)) {
      this.#refreshed.add(auth);
      const fresh = await auth.reacquire();
      if (!fresh.error) {
        // Mutated in place so probes holding this credential pick up the new token.
        Object.assign(auth, fresh);
        return this.request(url, auth.kind === "bearer" ? this.#reauthorize(init, authHeader, auth) : init);
      }
    }
    return response;
  }

  /**
   * Replace the stale bearer header after a refresh. The header name travels with the request
   * (authInit sets it) rather than being guessed, so a section using x-api-key refreshes too.
   */
  #reauthorize(init, headerName, credential) {
    const headers = { ...(init.headers ?? {}) };
    const existing = Object.keys(headers).find((n) => n.toLowerCase() === headerName.toLowerCase()) ?? headerName;
    headers[existing] = credential.scheme === "" ? credential.token : `${credential.scheme ?? "Bearer"} ${credential.token}`;
    return { ...init, headers };
  }

  #refuse(what, why) {
    this.#blocked.push({ what, why });
    throw new SafetyError(`Blocked ${what}: ${why}`);
  }

  async #throttle() {
    const elapsed = Date.now() - this.#lastRequestAt;
    const wait = this.safety.minimumDelayMs - elapsed;
    if (this.#lastRequestAt > 0 && wait > 0) {
      await new Promise((resolve) => setTimeout(resolve, wait));
    }
  }

  /**
   * Inspect the negotiated TLS version for a host. Counts against the request cap
   * because it opens a socket, but does not send an HTTP request.
   */
  async tlsInfo(hostname, port = 443) {
    if (!this.allowedHosts.has(hostname)) {
      throw new SafetyError(`Host "${hostname}" is not in targets.allowedHosts`);
    }
    if (this.#count >= this.budget.total) {
      this.#refuse(`TLS ${hostname}`, `run request cap reached (${this.budget.total})`);
    }
    await this.#throttle();
    this.#count += 1;
    if (this.#suite) this.#suiteCounts.set(this.#suite, (this.#suiteCounts.get(this.#suite) ?? 0) + 1);
    this.#lastRequestAt = Date.now();

    return new Promise((resolve, reject) => {
      const socket = tls.connect(
        { host: hostname, port, servername: hostname, minVersion: "TLSv1.2", ALPNProtocols: ["http/1.1"] },
        () => {
          const cert = socket.getPeerCertificate();
          const info = {
            protocol: socket.getProtocol(),
            cipher: socket.getCipher()?.name ?? null,
            authorized: socket.authorized,
            authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
            issuer: cert?.issuer?.O ?? null,
            validTo: cert?.valid_to ?? null,
          };
          socket.end();
          resolve(info);
        },
      );
      socket.setTimeout(this.safety.requestTimeoutMs, () => {
        socket.destroy();
        reject(new Error(`TLS handshake to ${hostname} timed out`));
      });
      socket.on("error", (error) => reject(error));
    });
  }
}
