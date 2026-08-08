import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { validateBookReceipt } from '../../lib/qualification/book-receipt.mjs';

const root = fileURLToPath(new URL('../..', import.meta.url));
const receipt = JSON.parse(readFileSync(new URL('../../qualification/book-1.json', import.meta.url), 'utf8'));
const clone = () => structuredClone(receipt);

test('B1 receipt binds every task to a behavioral assertion and owned implementation symbol', () => {
  const result = validateBookReceipt(receipt, { root, sourceRevision: receipt.sourceRevision });
  assert.deepEqual(result.issues, []);
  assert.equal(result.taskCount, 28);
  assert.equal(receipt.tasks.every(({ evidence }) => evidence.test.assertion && evidence.implementation.length > 0), true);
});

test('B1 receipt rejects stale revision, changed evidence bytes, and undeclared fields', () => {
  const staleReceipt=clone();staleReceipt.sourceRevision='0'.repeat(40);
  const stale = validateBookReceipt(staleReceipt, { root, sourceRevision: '0'.repeat(40) });
  assert.ok(stale.issues.includes('source-revision-mismatch'));

  const changed = clone();
  changed.tasks[0].evidence.test.digest = `sha256:${'0'.repeat(64)}`;
  assert.ok(validateBookReceipt(changed, { root, sourceRevision: changed.sourceRevision }).issues.some((issue) => issue.includes('digest-mismatch')));

  const extra = clone();
  extra.undeclared = true;
  assert.ok(validateBookReceipt(extra, { root, sourceRevision: extra.sourceRevision }).issues.some((issue) => issue.includes('additional-property')));
});

test('B1 receipt rejects dependency reordering and assertions absent from named test bytes', () => {
  const reordered = clone();
  reordered.tasks[1].dependsOn = ['B1-028'];
  assert.ok(validateBookReceipt(reordered, { root, sourceRevision: reordered.sourceRevision }).issues.some((issue) => issue.includes('forward-dependency')));

  const absent = clone();
  absent.tasks[0].evidence.test.assertion = 'not present in contract test';
  assert.ok(validateBookReceipt(absent, { root, sourceRevision: absent.sourceRevision }).issues.some((issue) => issue.includes('assertion-absent')));
});
