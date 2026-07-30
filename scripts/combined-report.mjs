#!/usr/bin/env node
/**
 * Back-compatible shim. The report builder now lives in src/combined.mjs and is
 * reachable as `trust report` or as buildCombinedReport() from the package root.
 * Kept so existing pipelines calling this path keep working.
 */

import { writeCombinedReport } from "../src/assessment/index.mjs";

const argv = process.argv.slice(2);
const read = (flag, fallback) => {
  const i = argv.indexOf(flag);
  return i === -1 ? fallback : argv[i + 1];
};

console.error("note: scripts/combined-report.mjs is deprecated — use `trust report --dir reports`");

try {
  const { outPath, profiles } = await writeCombinedReport({
    dir: read("--dir", "reports"),
    out: read("--out", ""),
    title: read("--title", ""),
  });
  console.error(`Merged ${profiles.length} profile(s): ${profiles.join(", ")}`);
  console.log(outPath);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
