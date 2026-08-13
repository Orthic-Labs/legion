import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { validateSchema } from '../lib/qualification/schema-validator.mjs';

const root = join(import.meta.dirname, '..');
const corpus = join(root, 'evals', 'architecture');
const run = () => JSON.parse(execFileSync(process.execPath, ['scripts/run-architecture-evals.mjs', '--json'], { cwd: root, encoding: 'utf8' }));

test('S11 corpus JSONL parses with stable unique identifiers & positive/negative expectations', () => {
  const ids = new Set();
  let positives = 0; let negatives = 0;
  for (const name of readdirSync(corpus).filter((entry) => entry.endsWith('.jsonl')).sort()) {
    for (const line of readFileSync(join(corpus, name), 'utf8').split(/\r?\n/).filter(Boolean)) {
      const row = JSON.parse(line);
      assert.match(row.id, /^AE-[A-Z][A-Z-]*-\d{3}$/);
      assert.equal(ids.has(row.id), false, row.id); ids.add(row.id);
      assert.ok(row.expect.outcome && row.expect.must_include.length && Array.isArray(row.expect.must_not_include));
      if (row.polarity === 'positive') positives += 1; else if (row.polarity === 'negative') negatives += 1;
      if (row.execution === 'runtime') assert.equal(row.status, 'pending');
    }
  }
  assert.ok(ids.size >= 96); assert.ok(positives && negatives);
});

test('S11 runner is deterministic & emits schema-valid machine result', () => {
  const first = run(); const second = run();
  assert.deepEqual(first, second);
  assert.deepEqual(validateSchema(JSON.parse(readFileSync(join(root, 'doctrine/architecture/schemas/architecture-eval-result.schema.json'), 'utf8')), first), []);
  assert.equal(first.failed, 0); assert.equal(first.total_cases, first.passed + first.pending);
  assert.equal(first.families.length, 37); assert.equal(first.state, 'PASS_WITH_PENDING');
});
