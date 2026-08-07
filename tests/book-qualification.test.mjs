import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { validateBookReceipt } from '../lib/qualification/book-receipt.mjs';

for (const book of [1, 2, 3, 4, 5, 6, 7, 8]) {
  test(`Book ${book} receipt accounts for every task and evidence path`, () => {
    const receipt = JSON.parse(readFileSync(new URL(`../qualification/book-${book}.json`, import.meta.url), 'utf8'));
    const result = validateBookReceipt(receipt, { root: fileURLToPath(new URL('..', import.meta.url)) });
    assert.deepEqual(result.issues, []);
    assert.equal(result.taskCount, receipt.expectedTaskCount);
  });
}
