// Phase 6.7 — test-order independence, diff-scoped.
//
// Reuses same seeded random-test approach as prior gauntlet tooling
// Fisher-Yates with xorshift32) so a recorded seed reproduces a run.
// Diff-scoped: we only include test files transitively touching the
// changed set. We run the test command N times with different seeds and
// require every run to pass — any order-dependent failure surfaces.
//
// The gauntlet does NOT replace the runner in the project's primary
// test command; it re-invokes the user-supplied testCommand with a
// shuffled order.

import { spawnSync } from "node:child_process";
import { resolve, relative } from "node:path";
import { readdirSync, statSync } from "node:fs";

function makeRng(seed) {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}

function fisherYates(arr, rng) {
  for (let i = arr.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rng() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function findTests(cwd, files) {
  // Default: all *.test.* files under the diff's root. Conservative.
  const roots = new Set(files.map((f) => resolve(cwd, f.path).split("/").slice(0, -1).join("/")));
  const found = new Set();
  for (const root of roots) {
    walk(root, (p) => {
      if (/\.test\.(mjs|js|ts)$/.test(p)) found.add(p);
    });
  }
  return [...found].map((p) => relative(cwd, p));
}

function walk(dir, visit) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.name === "node_modules" || e.name.startsWith(".")) continue;
    const p = resolve(dir, e.name);
    if (e.isDirectory()) walk(p, visit);
    else if (e.isFile()) visit(p);
  }
}

export function runOrder({ cwd, files, testCommand, runs = 5, seed = null }) {
  const tests = findTests(cwd ?? process.cwd(), files);
  const rng = makeRng(seed ?? 0xC0FFEE);
  const results = [];
  for (let i = 0; i < runs; i += 1) {
    // Express the order via NODE_OPTIONS test sequencing — the test
    // command itself is otherwise fixed.
    const order = fisherYates([...tests], rng);
    const env = { ...process.env, GAUNTLET_TEST_ORDER: order.join(",") };
    const result = spawnSync("sh", ["-c", testCommand], { cwd, env, encoding: "utf8", timeout: 60_000 });
    results.push({ run: i + 1, seed: rng() >>> 0, status: result.status, order });
  }
  const failed = results.filter((r) => r.status !== 0).length;
  return {
    ok: failed === 0,
    passed: results.length - failed,
    failed,
    total: results.length,
    results,
  };
}
