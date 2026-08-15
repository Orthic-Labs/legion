import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { executeArchitectureRuntimeCases, runtimePolicyIds } from '../packages/arcane/lib/s11-runtime-executor.mjs';

const root = join(import.meta.dirname, '..');
const corpus = join(root, 'evals', 'architecture');
function runtimeRows() {
  const rows = [];
  for (const name of readdirSync(corpus).filter((entry) => entry.endsWith('.jsonl')).sort()) {
    for (const line of readFileSync(join(corpus, name), 'utf8').split(/\r?\n/).filter(Boolean)) {
      const row = JSON.parse(line);
      if (row.execution === 'runtime') rows.push(row);
    }
  }
  return rows;
}

test('S11 executes each runtime scenario through an exact ingress and consumer', async () => {
  const rows = runtimeRows();
  assert.equal(rows.length, 95);
  assert.ok(runtimePolicyIds().includes('AE-CONVERGENCE-004'));
  assert.ok(runtimePolicyIds().includes('AE-AUTHORITY-001'));
  assert.equal(new Set(runtimePolicyIds()).size, runtimePolicyIds().length, 'duplicate binding IDs must fail before dispatch');
  const results = await executeArchitectureRuntimeCases(rows);
  assert.equal(results.length, 95);
  assert.equal(results.filter((row) => row.status === 'PASS').length, 95);
  assert.equal(results.filter((row) => row.status === 'PENDING').length, 0);
  assert.ok(results.every((row) => row.reason.includes('binding') || row.reason.includes('observation') || row.reason.includes('capability') || row.reason.includes('semantics')));
});

test('S11 runtime outcome is independent from scenario expected prose', async () => {
  const [row] = runtimeRows();
  const changed = structuredClone(row);
  changed.expect.must_include.push('impossible changed expectation');
  const [result] = await executeArchitectureRuntimeCases([changed]);
  assert.equal(result.status, 'PASS');
  assert.doesNotMatch(result.reason, /impossible changed expectation/);
});
