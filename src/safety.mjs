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

export const DEFAULT_SAFETY = {
  maxRequests: 100,
  minimumDelayMs: 150,
  requestTimeoutMs: 30000,
  allowWrites: false,
  allowAgentInvocations: false,
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
  let raw;
  try {
    raw = await readFile(configPath, "utf8");
  } catch (error) {
    throw new ConfigError(`Cannot read config ${configPath}: ${error.message}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(stripJsonComments(raw));
  } catch (error) {
    throw new ConfigError(`Config ${configPath} is not valid JSON: ${error.message}`);
  }
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
  if (!Number.isInteger(s.maxRequests) || s.maxRequests < 1 || s.maxRequests > 5000) {
    throw new ConfigError("safety.maxRequests must be an integer between 1 and 5000");
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

  constructor(config) {
    this.config = config;
    this.safety = config.safety ?? { ...DEFAULT_SAFETY };
    this.allowedHosts = new Set(config.targets?.allowedHosts ?? []);
  }

  get requestCount() {
    return this.#count;
  }

  get remainingRequests() {
    return Math.max(0, this.safety.maxRequests - this.#count);
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
   *   agentInvocation: true  this request invokes an LLM/agent → requires allowAgentInvocations
   */
  async request(url, init = {}) {
    const { write = false, agentInvocation = false, ...fetchInit } = init;
    const method = (fetchInit.method ?? "GET").toUpperCase();
    const parsed = this.assertUrlAllowed(url);

    const mutating = write === true || WRITE_METHODS.has(method);
    if (mutating && this.safety.allowWrites !== true) {
      this.#refuse(`${method} ${parsed.pathname}`, "writes are disabled (safety.allowWrites=false)");
    }
    if (agentInvocation && this.safety.allowAgentInvocations !== true) {
      this.#refuse(`${method} ${parsed.pathname}`, "agent invocations are disabled (safety.allowAgentInvocations=false)");
    }
    if (this.#count >= this.safety.maxRequests) {
      this.#refuse(`${method} ${parsed.pathname}`, `request cap reached (${this.safety.maxRequests})`);
    }

    await this.#throttle();
    this.#count += 1;
    this.#lastRequestAt = Date.now();

    const signal = AbortSignal.timeout(this.safety.requestTimeoutMs);
    return fetch(parsed.href, { ...fetchInit, method, redirect: "manual", signal });
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
    if (this.#count >= this.safety.maxRequests) {
      this.#refuse(`TLS ${hostname}`, `request cap reached (${this.safety.maxRequests})`);
    }
    await this.#throttle();
    this.#count += 1;
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
