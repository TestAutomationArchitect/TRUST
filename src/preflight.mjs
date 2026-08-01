/**
 * TRUST — `trust preflight`.
 *
 * Answers "will this run work?" before it spends the request budget. Every failure it catches
 * is one that would otherwise surface as a wall of SKIPs half an hour into a pipeline, where
 * it reads as a finding about the target rather than a mistake in the setup.
 *
 * It is deliberately cheap: config and token checks cost nothing, and reachability is one TLS
 * handshake per allowlisted host — no HTTP request, no probe payload, nothing the target will
 * log as a security test.
 *
 * Statuses mirror the report's own scale, so the output reads the same way:
 *   ok    the precondition holds
 *   warn  the run will proceed but something will be skipped or is worth knowing
 *   fail  the run cannot produce a meaningful result
 */

import { validateConfig, SafeHttpClient, SafetyError } from "./safety.mjs";
import { section, resolveBudget, resolvedSections } from "./config.mjs";
import { decodeJwt, subjectOf } from "./probes/token.mjs";
import { STRATEGY_TYPES, exportNameFor } from "./auth/index.mjs";
import { ISOLATION_TYPES } from "./probes/isolation.mjs";
import { getTestMeta } from "./catalog.mjs";
import { PROFILES } from "./runner.mjs";

/** Roughly how many requests each suite spends, for a budget sanity check. */
const TYPICAL_SPEND = { auth: 2, token: 0, web: 40, injection: 30, idp: 3, api: 14, storage: 5, agent: 16, mobile: 5 };

const check = (name, status, detail) => ({ name, status, detail });

/** Every endpoint the config points at, with the section that declared it. */
function configuredEndpoints(config) {
  const out = [];
  const add = (label, url) => {
    if (typeof url === "string" && url) out.push({ label, url });
  };
  add("targets.web", config.targets?.web);
  const api = section(config, "api");
  add(`${api.key ?? "api"}.endpoint`, api.value?.endpoint);
  add(`${api.key ?? "api"}.passwordAuth.endpoint`, api.value?.passwordAuth?.endpoint);
  const storage = section(config, "storage");
  add(`${storage.key ?? "storage"}.baseUrl`, storage.value?.baseUrl);
  for (const target of storage.value?.targets ?? []) add(`${storage.key ?? "storage"}.targets[].url`, target.url);
  const agent = section(config, "agent");
  add(`${agent.key ?? "agent"}.runtimeEndpoint`, agent.value?.runtimeEndpoint);
  const mobile = section(config, "mobile");
  add(`${mobile.key ?? "mobile"}.apiEndpoint`, mobile.value?.apiEndpoint);
  add(`${mobile.key ?? "mobile"}.deepLinkEndpoint`, mobile.value?.deepLinkEndpoint);
  const idp = section(config, "idp").value;
  add("idp.discoveryUrl", idp?.discoveryUrl);
  add("idp.loginUrl", idp?.loginUrl);
  for (const spec of config.isolation ?? []) {
    add(`isolation[${spec.id ?? "?"}].endpoint`, spec.endpoint);
    add(`isolation[${spec.id ?? "?"}].baseUrl`, spec.baseUrl);
  }
  return out;
}

/** Token env vars the config references, and whether they are usable. */
function tokenChecks(config) {
  const refs = [];
  const push = (label, envName) => envName && refs.push({ label, envName });
  const api = section(config, "api").value;
  const storage = section(config, "storage").value;
  const agent = section(config, "agent").value;
  const mobile = section(config, "mobile").value;
  push("api identity A", api?.tokenAEnv);
  push("api identity B", api?.tokenBEnv);
  push("storage identity A", storage?.tokenAEnv);
  push("storage identity B", storage?.tokenBEnv);
  push("agent identity A", agent?.accessTokenAEnv);
  push("agent identity B", agent?.accessTokenBEnv);
  push("mobile identity", mobile?.tokenEnv);

  const now = Math.floor(Date.now() / 1000);
  const results = [];
  const subjects = [];
  for (const { label, envName } of refs) {
    const value = process.env[envName];
    if (!value) {
      results.push(check(`token ${envName}`, "warn", `${label}: not set — every control needing it will skip`));
      continue;
    }
    const jwt = decodeJwt(value);
    if (!jwt) {
      results.push(check(`token ${envName}`, "ok", `${label}: present (opaque, not a JWT — claim checks will not apply)`));
      continue;
    }
    const { exp } = jwt.payload;
    const subject = subjectOf(jwt.payload);
    if (subject) subjects.push({ envName, value: subject.value });
    if (exp && exp < now) {
      results.push(
        check(`token ${envName}`, "fail", `${label}: expired ${Math.round((now - exp) / 60)} min ago — authenticated results would reflect rejected credentials`),
      );
    } else if (exp && exp - now < 300) {
      results.push(check(`token ${envName}`, "warn", `${label}: expires in ${Math.round((exp - now) / 60)} min — it may lapse mid-run`));
    } else {
      results.push(check(`token ${envName}`, "ok", `${label}: valid${exp ? ` for ${Math.round((exp - now) / 60)} more min` : " (no exp claim)"}`));
    }
  }

  // The expired-token fixture is judged by the opposite rule: it exists to be rejected, so an
  // expired one is correct and a *valid* one is the problem. Checking it like a real identity
  // failed preflight on a token whose entire purpose is to have lapsed.
  const fixtureEnv = api?.session?.expiredTokenEnv;
  if (fixtureEnv) {
    const fixture = process.env[fixtureEnv];
    const claims = fixture ? decodeJwt(fixture)?.payload : null;
    if (!fixture) {
      results.push(check(`token ${fixtureEnv}`, "warn", "expired-token fixture: not set — SESSION-EXPIRED-TOKEN will skip"));
    } else if (fixture && !claims) {
      // Nothing here can tell whether an opaque fixture has lapsed; say so rather than imply
      // the check passed.
      results.push(check(`token ${fixtureEnv}`, "ok", "expired-token fixture: present (opaque, so expiry cannot be confirmed from here)"));
    } else if (claims?.exp && claims.exp >= now) {
      results.push(check(`token ${fixtureEnv}`, "warn", `expired-token fixture: still valid for ${Math.round((claims.exp - now) / 60)} min — it cannot demonstrate that expiry is enforced until it lapses`));
    } else {
      results.push(check(`token ${fixtureEnv}`, "ok", "expired-token fixture: expired, which is what this one is for"));
    }
  }

  // Two identities that are the same principal make every isolation result vacuous, so this
  // is worth knowing before the run rather than after it.
  const distinct = new Set(subjects.map((s) => s.value));
  if (subjects.length > 1 && distinct.size === 1) {
    results.push(check("identity distinctness", "fail", `every supplied token resolves to the same principal (${[...distinct][0]}) — cross-user isolation cannot be tested`));
  } else if (subjects.length > 1) {
    results.push(check("identity distinctness", "ok", `${distinct.size} distinct principals across ${subjects.length} tokens`));
  }
  return results;
}

/** What each strategy type cannot work without, and where it will send credentials. */
const STRATEGY_REQUIREMENTS = {
  static: { fields: [], envFields: ["tokenEnv"] },
  "client-credentials": { fields: ["tokenUrl", "clientId"], envFields: [], urlFields: ["tokenUrl"] },
  "okta-ropc": { fields: ["clientId", "username"], envFields: ["passwordEnv"], urlFields: ["tokenUrl", "issuer"] },
  "cognito-srp": { fields: ["userPoolId", "clientId", "username"], envFields: ["passwordEnv"] },
  "cognito-identity-pool": { fields: ["identityPoolId", "providerName"], envFields: [] },
  sigv4: { fields: ["region"], envFields: [] },
};

/** The IdP host a strategy will contact, which must be allowlisted like any other host. */
function authHost(strategy) {
  const type = strategy.type ?? "static";
  const region = strategy.region ?? String(strategy.userPoolId ?? strategy.identityPoolId ?? "").split(/[_:]/)[0];
  if (strategy.endpoint) return safeHost(strategy.endpoint);
  if (type === "cognito-srp") return region ? `cognito-idp.${region}.amazonaws.com` : null;
  if (type === "cognito-identity-pool") return region ? `cognito-identity.${region}.amazonaws.com` : null;
  return safeHost(strategy.tokenUrl ?? strategy.issuer);
}

const safeHost = (url) => {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
};

/**
 * Auth strategies, checked declaratively. Preflight deliberately does not *acquire* anything:
 * a sign-in has side effects at the IdP — rate limits, lockout counters, audit entries — and a
 * check that costs a login is a check teams stop running. `trust tokens` does the real thing.
 */
function authChecks(config) {
  const strategies = config.auth?.strategies ?? {};
  const results = [];
  const allowed = new Set(config.targets?.allowedHosts ?? []);

  for (const [name, strategy] of Object.entries(strategies)) {
    const type = strategy.type ?? "static";
    const requirements = STRATEGY_REQUIREMENTS[type];
    if (!requirements) {
      results.push(check(`auth ${name}`, "fail", `unknown strategy type "${type}" (expected one of: ${STRATEGY_TYPES.join(", ")})`));
      continue;
    }
    const missing = requirements.fields.filter((field) => !strategy[field]);
    if (type === "okta-ropc" && !strategy.tokenUrl && !strategy.issuer) missing.push("tokenUrl or issuer");
    if (type === "cognito-identity-pool" && !strategy.idTokenFrom && !strategy.idTokenEnv) missing.push("idTokenFrom or idTokenEnv");
    if (missing.length) {
      results.push(check(`auth ${name}`, "fail", `${type}: missing ${missing.join(", ")}`));
      continue;
    }
    if (strategy.idTokenFrom && !strategies[strategy.idTokenFrom]) {
      results.push(check(`auth ${name}`, "fail", `${type}: idTokenFrom "${strategy.idTokenFrom}" is not a declared strategy`));
      continue;
    }

    const unset = [
      ...requirements.envFields.map((field) => strategy[field]).filter(Boolean),
      ...(type === "sigv4" ? [strategy.accessKeyIdEnv ?? "AWS_ACCESS_KEY_ID", strategy.secretAccessKeyEnv ?? "AWS_SECRET_ACCESS_KEY"] : []),
      ...(strategy.clientSecretEnv ? [strategy.clientSecretEnv] : []),
    ].filter((envName) => !process.env[envName]);
    const cached = type !== "sigv4" && process.env[exportNameFor(name, strategy)];

    if (unset.length && !cached) {
      results.push(check(`auth ${name}`, "fail", `${type}: ${unset.join(", ")} not set in the environment`));
      continue;
    }

    const host = authHost(strategy);
    if (host && !allowed.has(host)) {
      // Acquisition goes through the same guarded client as everything else, so an IdP outside
      // the allowlist fails at sign-in rather than at the probe that needed the token.
      results.push(check(`auth ${name}`, "fail", `${type}: ${host} is NOT in targets.allowedHosts — acquisition will be refused`));
      continue;
    }
    results.push(check(`auth ${name}`, "ok", cached ? `${type}: reusing ${exportNameFor(name, strategy)} from the environment` : `${type}: inputs present${host ? `, ${host} allowlisted` : ""}`));
  }

  // A section may name a strategy instead of an env var; a typo there would surface as a skip
  // in the middle of the run.
  for (const [canonical, keys] of Object.entries({ api: ["tokenA", "tokenB"], storage: ["tokenA", "tokenB"], agent: ["accessTokenA", "accessTokenB"], mobile: ["token"] })) {
    const { value, key } = section(config, canonical);
    for (const field of keys) {
      const reference = value?.[field];
      if (typeof reference !== "string" || !reference) continue;
      results.push(
        strategies[reference]
          ? check(`${key}.${field}`, "ok", `uses auth strategy "${reference}"`)
          : check(`${key}.${field}`, "fail", `names strategy "${reference}", which is not declared in auth.strategies`),
      );
    }
  }
  return results;
}

/**
 * Declared isolation boundaries, checked without issuing a request. A boundary that cannot
 * produce a verdict is worth knowing about before the run: an unknown type, a chain pointing at
 * an ID nothing produces, or a mutation guard with denial tests switched off — all of which
 * would otherwise surface as a skip in the middle of the output.
 */
function isolationChecks(config) {
  const specs = config.isolation ?? [];
  const results = [];
  const declaredIds = new Set(specs.map((spec) => spec.id).filter(Boolean));
  const twoIdentities = new Set(["record-ownership", "prefix-scoped-storage"]);

  for (const spec of specs) {
    const name = `isolation ${spec.id ?? "(no id)"}`;
    if (!spec.id) {
      results.push(check(name, "fail", "a spec has no id, so its result could not be attributed to a finding"));
      continue;
    }
    if (!ISOLATION_TYPES.includes(spec.type)) {
      results.push(check(name, "fail", `type "${spec.type ?? "(none)"}" is not one of: ${ISOLATION_TYPES.join(", ")}`));
      continue;
    }
    if (twoIdentities.has(spec.type) && !spec.tokenB && !spec.tokenBEnv) {
      // One identity cannot demonstrate a boundary, so this would skip rather than pass.
      results.push(check(name, "warn", `${spec.type} needs a second identity (tokenB or tokenBEnv) — it will skip`));
      continue;
    }
    if (spec.type === "mutation-guard" && config.safety?.allowDenialTests !== true && config.safety?.allowWrites !== true) {
      results.push(check(name, "warn", "mutation-guard attempts a mutation expected to be refused — set safety.allowDenialTests, or it will be blocked"));
      continue;
    }
    if (spec.type === "identity-injection" && !(spec.successIndicators ?? []).length) {
      results.push(check(name, "warn", "identity-injection has no successIndicators, so acceptance of the injected identity cannot be detected"));
      continue;
    }
    // A dependsOn typo silently disables a test, which is worse than one that fails loudly.
    const upstream = [spec.dependsOn].flat().filter(Boolean);
    const unknown = upstream.filter((id) => !declaredIds.has(id) && !getTestMeta(id).purpose);
    if (unknown.length) {
      results.push(check(name, "warn", `depends on ${unknown.join(", ")}, which is neither a known test nor another declared boundary`));
      continue;
    }
    results.push(check(name, "ok", `${spec.type}${upstream.length ? `, runs only when ${upstream.join(", ")} ${spec.condition ?? "failed"}` : ""}`));
  }
  return results;
}

/**
 * Run the preflight. `reach` performs one TLS handshake per allowlisted host; set it false
 * for a fully offline check.
 */
export async function runPreflight(config, { profile = "all", reach = true } = {}) {
  const checks = [];

  // 1. Config validity — a hard stop, since nothing else is meaningful without it.
  try {
    const advisories = validateConfig(config);
    checks.push(check("config", "ok", `${config.name} (${config.environment}) is valid`));
    for (const advisory of advisories) checks.push(check("safety", "warn", advisory));
  } catch (error) {
    checks.push(check("config", "fail", error.message));
    return { checks, ok: false };
  }

  if (config.extendsChain) checks.push(check("config inheritance", "ok", `${config.extendsChain.length} files merged`));
  const aliases = resolvedSections(config);
  for (const [canonical, key] of Object.entries(aliases)) {
    checks.push(check("config section", "ok", `${canonical} resolved from "${key}"`));
  }

  // 2. Every configured endpoint must be inside the allowlist, or its probes die mid-run.
  const allowed = new Set(config.targets?.allowedHosts ?? []);
  for (const { label, url } of configuredEndpoints(config)) {
    let host;
    try {
      const parsed = new URL(url);
      host = parsed.hostname;
      if (parsed.protocol !== "https:") {
        checks.push(check(label, "fail", `${url} is not HTTPS — the client refuses plaintext`));
        continue;
      }
    } catch {
      checks.push(check(label, "fail", `${url} is not a valid URL`));
      continue;
    }
    checks.push(
      allowed.has(host)
        ? check(label, "ok", `${host} is allowlisted`)
        : check(label, "fail", `${host} is NOT in targets.allowedHosts — every request to it will be refused`),
    );
  }

  // 3. Tokens and auth strategies.
  checks.push(...authChecks(config));
  checks.push(...tokenChecks(config));
  checks.push(...isolationChecks(config));

  // 4. Budget sanity: will the profile's cap cover the suites it runs?
  const budget = resolveBudget(config, profile);
  // Acquisition spends from the same budget as the probes, so it belongs in the estimate.
  const modules = [...(Object.keys(config.auth?.strategies ?? {}).length ? ["auth"] : []), ...(PROFILES[profile]?.modules ?? [])];
  // A declared boundary spends two requests at most (discover as A, attempt as B), which is
  // knowable exactly rather than by estimate.
  const estimate = modules.reduce((sum, name) => sum + (name === "isolation" ? (config.isolation ?? []).length * 2 : (TYPICAL_SPEND[name] ?? 10)), 0);
  checks.push(
    estimate > budget.total
      ? check(
          "request budget",
          "warn",
          `profile "${profile}" typically spends about ${estimate} requests but the cap is ${budget.total} — later suites will skip. Raise safety.maxRequests, or set per-suite budgets`,
        )
      : check("request budget", "ok", `cap ${budget.total} covers an estimated ${estimate} requests for profile "${profile}"`),
  );

  // 5. Reachability — a TLS handshake, not a probe. Cheapest possible proof of life.
  if (reach) {
    const client = new SafeHttpClient(config, { budget: { total: allowed.size + 2, suites: null } });
    for (const host of allowed) {
      try {
        const info = await client.tlsInfo(host, 443);
        checks.push(
          check(
            `reach ${host}`,
            info.authorized ? "ok" : "warn",
            `${info.protocol}${info.authorized ? "" : ` — certificate not trusted: ${info.authorizationError}`}`,
          ),
        );
      } catch (error) {
        const why = error instanceof SafetyError ? error.message : error.message.split("\n")[0];
        checks.push(check(`reach ${host}`, "fail", why));
      }
    }
  }

  return { checks, ok: !checks.some((c) => c.status === "fail") };
}
