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

test('S11 runtime policy covers every runtime case exactly once', () => {
  const rows = runtimeRows();
  assert.equal(rows.length, 62);
  assert.deepEqual(runtimePolicyIds(), rows.map((row) => row.id).sort());
  const results = executeArchitectureRuntimeCases(rows);
  assert.equal(results.length, 62);
  assert.equal(results.filter((row) => row.status === 'PASS').length, 62);
  assert.equal(results.filter((row) => row.status !== 'PASS').length, 0);
});

test('S11 runtime policy fails changed expectations instead of echoing corpus', () => {
  const [row] = runtimeRows();
  const changed = structuredClone(row);
  changed.expect.must_include.push('impossible changed expectation');
  const [result] = executeArchitectureRuntimeCases([changed]);
  assert.equal(result.status, 'FAIL');
  assert.match(result.reason, /missing required decision phrase/);
});
