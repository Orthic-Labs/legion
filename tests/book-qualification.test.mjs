import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { validateBookReceipt } from '../lib/qualification/book-receipt.mjs';
import { committedSourceRevision, currentSourceRevision } from '../lib/qualification/source-revision.mjs';

for (const book of [1, 2, 3, 4, 5, 6, 7, 8]) {
  test(`Book ${book} receipt accounts for every task and evidence path`, () => {
    const receipt = JSON.parse(readFileSync(new URL(`../qualification/book-${book}.json`, import.meta.url), 'utf8'));
    const result = validateBookReceipt(receipt, { root: fileURLToPath(new URL('..', import.meta.url)) });
    assert.deepEqual(result.issues, []);
    assert.equal(result.taskCount, receipt.expectedTaskCount);
  });
}

test('committed qualification revision ignores dirty working bytes while live revision detects them', () => {
  const root = mkdtempSync(join(tmpdir(), 'legion-source-revision-'));
  execFileSync('git', ['init', '-q'], { cwd: root });
  writeFileSync(join(root, 'source.txt'), 'committed\n');
  execFileSync('git', ['add', 'source.txt'], { cwd: root });
  execFileSync('git', ['-c', 'user.name=Legion Test', '-c', 'user.email=legion@example.invalid', 'commit', '-qm', 'fixture'], { cwd: root });
  const committed = committedSourceRevision(root);
  assert.equal(currentSourceRevision(root), committed);
  writeFileSync(join(root, 'source.txt'), 'dirty\n');
  assert.equal(committedSourceRevision(root), committed);
  assert.notEqual(currentSourceRevision(root), committed);
  assert.match(currentSourceRevision(root), /\+dirty$/);
});
