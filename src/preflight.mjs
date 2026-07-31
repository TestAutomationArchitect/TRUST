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
import { PROFILES } from "./runner.mjs";

/** Roughly how many requests each suite spends, for a budget sanity check. */
const TYPICAL_SPEND = { token: 0, web: 40, injection: 30, api: 14, storage: 5, agent: 16, mobile: 5 };

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
  push("expired-token fixture", api?.session?.expiredTokenEnv);

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

  // 3. Tokens.
  checks.push(...tokenChecks(config));

  // 4. Budget sanity: will the profile's cap cover the suites it runs?
  const budget = resolveBudget(config, profile);
  const modules = PROFILES[profile]?.modules ?? [];
  const estimate = modules.reduce((sum, name) => sum + (TYPICAL_SPEND[name] ?? 10), 0);
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
