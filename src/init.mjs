/**
 * TRUST — `trust init`.
 *
 * Scaffolds a config, a .env template and an example custom probe into the consumer's
 * repository. TRUST is config-driven, so an install without this step leaves a partner
 * with a binary and nothing to point it at.
 */

import { mkdir, writeFile, access } from "node:fs/promises";
import path from "node:path";

const exists = async (p) => {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
};

export function configTemplate({ name, target, environment }) {
  const host = (() => {
    try {
      return new URL(target).hostname;
    } catch {
      return "dev.example.com";
    }
  })();
  const apex = host.split(".").slice(-2).join(".");

  return `{
  // TRUST config — targets, safety limits and probe definitions.
  // Rule: this file stores env var NAMES, never secret values. Secrets go in .env.
  "name": ${JSON.stringify(name)},
  "environment": ${JSON.stringify(environment)},

  "targets": {
    "web": ${JSON.stringify(target)},
    // Requests to any host not listed here are refused before they leave the process.
    "allowedHosts": [${JSON.stringify(host)}${host !== `api.${apex}` ? `, ${JSON.stringify(`api.${apex}`)}` : ""}]
  },

  "safety": {
    "maxRequests": 120,          // hard cap; blocked requests do not consume it
    "minimumDelayMs": 150,       // floor between requests (minimum 50)
    "requestTimeoutMs": 30000,
    "allowWrites": false,        // PUT/PATCH/DELETE and write-marked POSTs
    "allowAgentInvocations": false, // live LLM calls
    "productionOverride": false  // requires written authorisation
  },

  // Optional: rendered verbatim in the report's "Architecture Under Test" box.
  "architecture": "Browser → IdP (OIDC) → API → storage",

  "web": {
    "sensitivePaths": ["/.env", "/.git/config", "/config.json"],
    "redirectParams": ["redirect", "next", "returnUrl", "url"],
    "rateLimitBurst": 8
    // "expectedFrameAncestors": ["https://portal.${apex}"]
  }

  // ── Uncomment and fill in as you cover more surface. ──
  // "api":     worked examples for every section: https://github.com/TestAutomationArchitect/TRUST/blob/main/config/dev.json
  // "storage": …
  // "agent":   …
  // "mobile":  …

  // Org-specific probes. Paths resolve against this file's directory first, then the
  // working directory — so both of these work from a repo root:
  // "probes": ["../trust-probes/example.mjs"]
}
`;
}

export const ENV_TEMPLATE = `# TRUST — secrets live here only. Config stores env var NAMES.
# Never commit this file.

# API / GraphQL identities — two users, different scopes, for isolation testing
AUTH_TOKEN_A=
AUTH_TOKEN_B=

# Storage identities
STORAGE_TOKEN_A=
STORAGE_TOKEN_B=

# AI agent runtime identities
AGENT_TOKEN_A=
AGENT_TOKEN_B=
`;

export const EXAMPLE_PROBE = `/**
 * Example org-specific TRUST probe.
 *
 * Register it in your config:  "probes": ["./trust-probes/example.mjs"]
 * Run it:                      trust run --config config/dev.json --profile passive
 *
 * Rules that keep a probe well-behaved:
 *   - Missing config or token → skipped(), never a throw and never a fail.
 *   - Verdicts are pattern matches on status/headers/body. Never ask a model.
 *   - Any isolation claim needs two identities; any leak claim needs a canary().
 */
import { defineProbe, finding, skipped, canary } from "trust-verify";

export default defineProbe({
  name: "example",
  label: "example org controls",
  profiles: ["passive"],

  // Metadata for the report: category → trust domain → score → root cause.
  catalog: {
    "ACME-HEADER-REQUEST-ID": {
      category: "Web Hardening",
      purpose: "Verify the edge stamps a correlation ID on every response so security events are traceable.",
    },
  },

  async run(config, client) {
    const marker = canary("PROBE");
    const url = new URL(\`/?trust=\${marker}\`, config.targets.web).href;

    let response;
    try {
      response = await client.request(url);
    } catch (error) {
      return [skipped("ACME-HEADER-REQUEST-ID", "Edge stamps a correlation ID", error.message)];
    }

    const requestId = response.headers.get("x-request-id");
    return [
      finding({
        id: "ACME-HEADER-REQUEST-ID",
        title: "Edge stamps a correlation ID on responses",
        status: requestId ? "pass" : "fail",
        severity: "low",
        evidence: requestId ? \`x-request-id: \${requestId}\` : \`HTTP \${response.status} — x-request-id absent\`,
        remediation: requestId ? "" : "Have the CDN or gateway generate x-request-id and propagate it to application logs.",
      }),
    ];
  },
});
`;

/** Entries only — the "# TRUST" header is written around them, never compared against. */
const GITIGNORE_ENTRIES = [".env", "reports/"];

/**
 * Write the scaffold. Returns { written, skipped } paths.
 * Existing files are never overwritten unless force is set.
 */
export async function scaffold({ dir = ".", name = "", target = "https://dev.example.com", environment = "dev", force = false, withProbe = true } = {}) {
  const resolvedName = name || `${new URL(target).hostname.split(".")[0]}-${environment}`;
  const written = [];
  const untouched = [];

  const files = [
    [path.join(dir, "config", `${environment}.json`), configTemplate({ name: resolvedName, target, environment })],
    [path.join(dir, ".env.example"), ENV_TEMPLATE],
  ];
  if (withProbe) files.push([path.join(dir, "trust-probes", "example.mjs"), EXAMPLE_PROBE]);

  for (const [file, content] of files) {
    if (!force && (await exists(file))) {
      untouched.push(file);
      continue;
    }
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, content, { mode: file.endsWith(".env.example") ? 0o600 : 0o644 });
    written.push(file);
  }

  // Append to .gitignore rather than replacing it — the consumer owns that file.
  const gitignore = path.join(dir, ".gitignore");
  if (await exists(gitignore)) {
    const { readFile, appendFile } = await import("node:fs/promises");
    const current = await readFile(gitignore, "utf8");
    const present = new Set(current.split(/\r?\n/).map((line) => line.trim()));
    const missing = GITIGNORE_ENTRIES.filter((entry) => !present.has(entry));
    if (missing.length) {
      await appendFile(gitignore, `${current.endsWith("\n") ? "" : "\n"}\n# TRUST\n${missing.join("\n")}\n`);
      written.push(gitignore);
    } else {
      untouched.push(gitignore);
    }
  } else {
    await writeFile(gitignore, `# TRUST\n${GITIGNORE_ENTRIES.join("\n")}\n`);
    written.push(gitignore);
  }

  return { written, skipped: untouched, name: resolvedName, configPath: path.join(dir, "config", `${environment}.json`) };
}
