import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { validateBookReceipt } from '../../lib/qualification/book-receipt.mjs';
import { currentSourceRevision } from '../../lib/qualification/source-revision.mjs';

const root = fileURLToPath(new URL('../..', import.meta.url));
const receipt = JSON.parse(readFileSync(new URL('../../qualification/book-3.json', import.meta.url), 'utf8'));

test('B3 receipt binds exact 30-task DAG to task-owned tests and implementations', () => {
  const result = validateBookReceipt(receipt, { root, sourceRevision: currentSourceRevision(root) });
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.sourceAccounting, { implemented: 30, mapped: 0, sourceBlocked: 0 });
});

test('B3 receipt keeps unavailable provider tools external and non-green', () => {
  assert.ok(receipt.blockers.some(({ kind, state }) =>
    kind === 'tool-availability' && state === 'external-evidence-required'));
  assert.equal(receipt.claimLevel, 'source');
});
