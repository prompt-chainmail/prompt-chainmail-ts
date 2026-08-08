#!/usr/bin/env node
/**
 * Compare a Vitest bench --outputJson report against a committed baseline.
 * Fails if any matching bench's hz drops by more than TOLERANCE.
 *
 * Keys are stable names (not Vitest task ids):
 *   basename(filepath) | suiteFullName | benchName
 */
import fs from "node:fs";
import path from "node:path";

const TOLERANCE = 0.25; // allow 25% slower (lower hz)

const [baselinePath, currentPath] = process.argv.slice(2);
if (!baselinePath || !currentPath) {
  console.error(
    "Usage: node scripts/compare-benchmarks.mjs <baseline.json> <current.json>"
  );
  process.exit(2);
}

function load(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function indexReport(report) {
  const map = new Map();
  for (const file of report.files ?? []) {
    const base = path.basename(file.filepath);
    for (const group of file.groups ?? []) {
      for (const b of group.benchmarks ?? []) {
        const key = `${base} | ${group.fullName} | ${b.name}`;
        map.set(key, b);
      }
    }
  }
  return map;
}

const baselineReport = load(baselinePath);
const currentReport = load(currentPath);
const baseline = indexReport(baselineReport);
const current = indexReport(currentReport);

const baselineRunner = baselineReport.meta?.runner ?? "unknown";
const onCI = process.env.CI === "true" || process.env.GITHUB_ACTIONS === "true";

if (baseline.size === 0 || baselineRunner === "unseeded") {
  console.error(
    `Baseline is empty/unseeded (${baselinePath}).\n` +
      `Add the PR label "update-benchmark-baseline" (CI) or run: make benchmark-baseline`
  );
  process.exit(1);
}

if (onCI && baselineRunner !== "ubuntu-latest") {
  console.error(
    `Baseline runner is "${baselineRunner}", but CI requires "ubuntu-latest".\n` +
      `Add the PR label "update-benchmark-baseline" to rewrite the baseline on GitHub Actions.`
  );
  process.exit(1);
}

const regressions = [];
const missing = [];
const rows = [];

for (const [key, base] of baseline) {
  const cur = current.get(key);
  if (!cur) {
    missing.push(key);
    continue;
  }
  const baseHz = Number(base.hz) || 0;
  const curHz = Number(cur.hz) || 0;
  const minHz = baseHz * (1 - TOLERANCE);
  const ratio = baseHz > 0 ? curHz / baseHz : 0;
  const ok = curHz >= minHz;
  rows.push({ key, baseHz, curHz, ratio, ok });
  if (!ok) {
    regressions.push({ key, baseHz, curHz, ratio, minHz });
  }
}

const extras = [...current.keys()].filter((k) => !baseline.has(k));

console.log(
  `Benchmark compare (tolerance ${(TOLERANCE * 100).toFixed(0)}% slower)`
);
console.log(`baseline: ${baselinePath}`);
console.log(`current:  ${currentPath}\n`);

for (const r of rows.sort((a, b) => a.key.localeCompare(b.key))) {
  const mark = r.ok ? "OK" : "FAIL";
  console.log(
    `${mark.padEnd(4)} ${r.ratio.toFixed(2)}x  ${r.curHz.toFixed(1)} hz vs ${r.baseHz.toFixed(1)} hz  ${r.key}`
  );
}

if (extras.length) {
  console.log(`\nNew benches (not in baseline yet):`);
  for (const k of extras) console.log(`  + ${k}`);
}

if (missing.length || regressions.length) {
  if (missing.length) {
    console.error(`\nMissing from current run (${missing.length}):`);
    for (const k of missing) console.error(`  - ${k}`);
  }
  if (regressions.length) {
    console.error(`\nRegressions (${regressions.length}):`);
    for (const r of regressions) {
      console.error(
        `  - ${r.key}: ${r.curHz.toFixed(1)} hz < min ${r.minHz.toFixed(1)} hz (${r.ratio.toFixed(2)}x of baseline ${r.baseHz.toFixed(1)})`
      );
    }
  }
  process.exit(1);
}

console.log(`\nAll ${rows.length} benches within tolerance.`);
process.exit(0);
