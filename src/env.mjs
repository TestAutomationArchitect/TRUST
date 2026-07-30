/**
 * TRUST — .env loading for the CLI.
 *
 * Why this exists: `trust init` tells the user to copy `.env.example` to `.env`, and the
 * config refers to tokens by env var name. Without this, following those instructions
 * produced a run where every authenticated probe skipped for "token not set" — a silent,
 * confusing failure that looked like a configuration problem in the target.
 *
 * Node's own `--env-file` cannot help here: an installed `trust` binary gives the user no
 * place to pass a node flag. So the CLI reads the file itself.
 *
 * Deliberate rules:
 *   - The real environment always wins. CI injects secrets as env vars, and a stale local
 *     `.env` must never override them.
 *   - Library callers get nothing automatic. `runProfile()` never touches the filesystem
 *     looking for secrets; an embedder owns its own configuration.
 *   - Values are never logged. Only names, and only on request.
 */

import { readFile } from "node:fs/promises";

/**
 * Parse dotenv-style text. Supports `export KEY=value`, `#` comments, quoted values with
 * escapes, and blank lines. Returns a plain object; malformed lines are skipped.
 */
export function parseEnv(text) {
  const out = {};
  for (const rawLine of String(text ?? "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    const [, key] = match;
    let value = match[2];

    // Strip a trailing comment only when the value is unquoted — a `#` inside quotes is data.
    if (!/^["']/.test(value)) {
      value = value.replace(/\s+#.*$/, "").trim();
    } else {
      const quote = value[0];
      const end = value.indexOf(quote, 1);
      if (end === -1) continue; // unterminated quote: skip rather than guess
      value = value.slice(1, end);
      if (quote === '"') value = value.replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t").replace(/\\"/g, '"');
    }
    out[key] = value;
  }
  return out;
}

/**
 * Load a .env file into process.env without overriding anything already set.
 * Returns { path, loaded: [names], skipped: [names already in the environment] }.
 * A missing file is not an error — it is the normal case in CI.
 */
export async function loadEnv(path = ".env", env = process.env) {
  let text;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return { path, loaded: [], skipped: [], present: false };
  }
  const parsed = parseEnv(text);
  const loaded = [];
  const skipped = [];
  for (const [key, value] of Object.entries(parsed)) {
    if (env[key] !== undefined && env[key] !== "") {
      skipped.push(key);
      continue;
    }
    env[key] = value;
    loaded.push(key);
  }
  return { path, loaded, skipped, present: true };
}
