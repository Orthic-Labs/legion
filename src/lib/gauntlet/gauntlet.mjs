#!/usr/bin/env node
// Phase 6.7 — evidence gauntlet, entry point.
//
// Usage:
//   node src/lib/gauntlet/gauntlet.mjs [--base REF] [--diff FILE] [--test CMD]
//                                    [--cwd DIR] [--no-mutation] [--no-coverage]
//                                    [--no-order] [--order-runs N]
//
// Default test command (when --test omitted): `node --test --test-concurrency=1`
// against the test files reachable from the changed set.
//
// Output: a single JSON check object on stdout matching Arcane's
//         check shape. Exit code 0 on pass, 1 on any layer failure.

import { parseArgs } from "node:util";
import { loadDiff, summarise } from "./lib/diff.mjs";
import { runMutation } from "./lib/mutation.mjs";
import { runCoverage } from "./lib/coverage.mjs";
import { runOrder } from "./lib/order.mjs";
import { buildReceipt, buildCheck } from "./lib/arcaneshape.mjs";

const { values } = parseArgs({
  options: {
    base: { type: "string" },
    diff: { type: "string" },
    test: { type: "string" },
    cwd: { type: "string" },
    "no-mutation": { type: "boolean", default: false },
    "no-coverage": { type: "boolean", default: false },
    "no-order": { type: "boolean", default: false },
    "order-runs": { type: "string", default: "5" },
  },
  allowPositionals: false,
});

const cwd = values.cwd ?? process.cwd();
const testCommand = values.test ?? "node --test --test-concurrency=1";
const orderRuns = Number(values["order-runs"]) || 5;
const startedAt = new Date().toISOString();
const command = `gauntlet --base ${values.base ?? "HEAD"} --test "${testCommand}"`;

const files = loadDiff({ cwd, base: values.base, diffFile: values.diff });
if (files.length === 0) {
  const completedAt = new Date().toISOString();
  const receipt = buildReceipt({
    startedAt, completedAt, command,
    summary: { ok: false, error: "no_diff" },
    layers: {
      mutation: { passed: 0, failed: 0, total: 0, skipped: 0, ok: false, results: [] },
      coverage: { passed: 0, failed: 0, total: 0, percent: 0, ok: false, results: [] },
      order: { passed: 0, failed: 0, total: 0, ok: false, results: [] },
    },
  });
  process.stdout.write(JSON.stringify(buildCheck(receipt), null, 2) + "\n");
  process.exit(1);
}

const layers = {
  mutation: values["no-mutation"]
    ? { passed: 0, failed: 0, total: 0, skipped: 0, ok: true, results: [] }
    : runMutation({ cwd, files, testCommand }),
  coverage: values["no-coverage"]
    ? { passed: 0, failed: 0, total: 0, percent: 0, ok: true, results: [] }
    : runCoverage({ cwd, files, testCommand }),
  order: values["no-order"]
    ? { passed: 0, failed: 0, total: 0, ok: true, results: [] }
    : runOrder({ cwd, files, testCommand, runs: orderRuns }),
};

const summary = {
  ok: layers.mutation.ok && layers.coverage.ok && layers.order.ok,
  diff: summarise(files),
  layers: {
    mutation: pickMetrics(layers.mutation),
    coverage: pickMetrics(layers.coverage),
    order: pickMetrics(layers.order),
  },
};

const completedAt = new Date().toISOString();
const receipt = buildReceipt({ startedAt, completedAt, command, summary, layers });
process.stdout.write(JSON.stringify(buildCheck(receipt), null, 2) + "\n");
process.exit(receipt.exit_code);

function pickMetrics(layer) {
  return {
    passed: layer.passed ?? 0,
    failed: layer.failed ?? 0,
    total: layer.total ?? 0,
    percent: layer.percent ?? null,
    ok: layer.ok,
    error: layer.error ?? null,
  };
}
