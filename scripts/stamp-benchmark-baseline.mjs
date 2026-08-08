#!/usr/bin/env node
/**
 * Normalize a Vitest --outputJson report for committing as a baseline:
 * - rewrite filepaths to repo-relative
 * - attach meta.runner for environment gating
 */
import fs from "node:fs";
import path from "node:path";

const [inputPath, runner = "local"] = process.argv.slice(2);
if (!inputPath) {
  console.error(
    "Usage: node scripts/stamp-benchmark-baseline.mjs <report.json> [runner]"
  );
  process.exit(2);
}

const root = process.cwd();
const report = JSON.parse(fs.readFileSync(inputPath, "utf8"));

report.meta = {
  runner,
  generatedAt: new Date().toISOString(),
  toleranceNote: "compare-benchmarks.mjs allows 40% hz regression",
};

for (const file of report.files ?? []) {
  if (file.filepath?.startsWith(root)) {
    file.filepath = path.relative(root, file.filepath);
  }
  // Drop volatile Vitest task ids from the committed artifact; compare keys by name.
  for (const group of file.groups ?? []) {
    for (const b of group.benchmarks ?? []) {
      delete b.id;
      delete b.samples;
    }
  }
}

fs.writeFileSync(inputPath, JSON.stringify(report, null, 2) + "\n");
console.log(`Stamped baseline runner=${runner} → ${inputPath}`);
