// The minimize commit gate, now Arcane's. These pin the four properties that
// were each earned by a real production failure, plus the receipt binding that
// makes it a gate rather than a suggestion.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { after } from 'node:test';

import {
  MinimizeError,
  buildReceipt,
  buildReview,
  languageFamily,
  ownerRoot,
  validateReview,
  verifyReceipt,
  writeJson,
} from '../lib/minimize.mjs';

const POLICY = new URL('../policy/minimize-policy.md', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const VALIDATOR = new URL('../lib/minimize.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const PATHS = { policyPath: POLICY, validatorPath: VALIDATOR };

const roots = [];
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }); });

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', windowsHide: true });
}

/** A two-package repo: pkg-a (JS) and pkg-b (Python), each with its own manifest. */
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'arcane-minimize-'));
  roots.push(root);
  git(root, 'init', '-q');
  git(root, 'config', 'user.email', 't@t');
  git(root, 'config', 'user.name', 't');
  for (const pkg of ['pkg-a', 'pkg-b']) {
    mkdirSync(join(root, pkg, 'src'), { recursive: true });
    writeFileSync(join(root, pkg, 'package.json'), `{"name":"${pkg}"}\n`);
  }
  writeFileSync(join(root, 'pkg-a/src/one.mjs'), 'export function computeChecksum(x) { return x; }\n');
  writeFileSync(join(root, 'pkg-b/src/two.py'), 'def compute_checksum(x):\n    return x\n');
  git(root, 'add', '-A');
  git(root, 'commit', '-qm', 'base');
  return root;
}

function inRepo(root, fn) {
  const previous = process.cwd();
  process.chdir(root);
  try { return fn(); } finally { process.chdir(previous); }
}

test('a duplicate inside the same package and language is caught', () => {
  const root = fixture();
  writeFileSync(join(root, 'pkg-a/src/dup.mjs'), 'export function computeChecksum(y) { return y; }\n');
  git(root, 'add', 'pkg-a/src/dup.mjs');
  const review = inRepo(root, buildReview);
  assert.equal(review.findings.length, 1, JSON.stringify(review.findings));
  assert.equal(review.findings[0].symbol, 'computeChecksum');
});

test('the same name in another package is not a duplicate anyone could have reused', () => {
  const root = fixture();
  writeFileSync(join(root, 'pkg-b/src/dup.mjs'), 'export function computeChecksum(z) { return z; }\n');
  git(root, 'add', 'pkg-b/src/dup.mjs');
  assert.deepEqual(inRepo(root, buildReview).findings, []);
});

test('a Python def and a JS function sharing a name are never compared', () => {
  const root = fixture();
  writeFileSync(join(root, 'pkg-b/src/three.py'), 'def computeChecksum(x):\n    return x\n');
  git(root, 'add', 'pkg-b/src/three.py');
  assert.deepEqual(inRepo(root, buildReview).findings, []);
});

test('underscore-private names are skipped — they cannot be reused by convention', () => {
  const root = fixture();
  writeFileSync(join(root, 'pkg-a/src/priv.mjs'), 'export function _normalizePath(a) { return a; }\n');
  writeFileSync(join(root, 'pkg-a/src/priv2.mjs'), 'export function _normalizePath(b) { return b; }\n');
  git(root, 'add', 'pkg-a/src/priv.mjs', 'pkg-a/src/priv2.mjs');
  assert.deepEqual(inRepo(root, buildReview).findings, []);
});

test('the HEAD search uses POSIX classes, so it is not a silent no-op on macOS', () => {
  const source = readFileSync(VALIDATOR, 'utf8');
  const declSearch = source.slice(source.indexOf('const DECL_SEARCH'), source.indexOf('\n', source.indexOf('const DECL_SEARCH')));
  assert.ok(declSearch.includes('[[:space:]]'), declSearch);
  assert.ok(!/\\\\s|\\\\b/.test(declSearch), `GNU-only escapes would match nothing on BSD libc: ${declSearch}`);
});

test('an open finding blocks the receipt', () => {
  const root = fixture();
  writeFileSync(join(root, 'pkg-a/src/dup.mjs'), 'export function computeChecksum(y) { return y; }\n');
  git(root, 'add', 'pkg-a/src/dup.mjs');
  inRepo(root, () => {
    const path = join(root, 'review.json');
    writeJson(path, buildReview());
    assert.throws(() => buildReceipt(path, PATHS), /open finding blocks commit receipt/);
  });
});

test('a waiver without a stated reason is refused', () => {
  const root = fixture();
  writeFileSync(join(root, 'pkg-a/src/dup.mjs'), 'export function computeChecksum(y) { return y; }\n');
  git(root, 'add', 'pkg-a/src/dup.mjs');
  inRepo(root, () => {
    const review = buildReview();
    review.findings[0].status = 'waived';
    assert.throws(() => validateReview(review), /waived finding needs a waiver_reason/);
    review.findings[0].waiver_reason = 'deliberate: separate runtime';
    assert.equal(validateReview(review).verdict, 'CLEAN');
  });
});

test('a waiver is carried into the receipt, so a waived CLEAN is distinguishable', () => {
  const root = fixture();
  writeFileSync(join(root, 'pkg-a/src/dup.mjs'), 'export function computeChecksum(y) { return y; }\n');
  git(root, 'add', 'pkg-a/src/dup.mjs');
  inRepo(root, () => {
    const path = join(root, 'review.json');
    const review = buildReview();
    review.findings[0].status = 'waived';
    review.findings[0].waiver_reason = 'deliberate: fixture';
    writeJson(path, review);
    const receipt = buildReceipt(path, PATHS);
    assert.deepEqual(receipt.waivers, [{ symbol: 'computeChecksum', reason: 'deliberate: fixture' }]);
  });
});

test('a receipt is bound to the staged tree and goes stale when the index moves', () => {
  const root = fixture();
  writeFileSync(join(root, 'pkg-a/src/clean.mjs'), 'export function uniqueSymbolHere(a) { return a; }\n');
  git(root, 'add', 'pkg-a/src/clean.mjs');
  inRepo(root, () => {
    const reviewPath = join(root, 'review.json');
    writeJson(reviewPath, buildReview());
    const receipt = buildReceipt(reviewPath, PATHS);
    assert.equal(verifyReceipt(receipt, PATHS).verdict, 'CLEAN');

    writeFileSync(join(root, 'pkg-a/src/extra.mjs'), 'export function laterAddition(q) { return q; }\n');
    git(root, 'add', 'pkg-a/src/extra.mjs');
    assert.throws(() => verifyReceipt(receipt, PATHS), /stale commit receipt: candidate_tree mismatch/);
  });
});

test('ownerRoot stops at the nearest manifest and languageFamily groups runtimes', () => {
  const root = fixture();
  inRepo(root, () => {
    assert.equal(ownerRoot('pkg-a/src/one.mjs'), 'pkg-a');
    assert.equal(ownerRoot('pkg-b/src/two.py'), 'pkg-b');
  });
  assert.ok(languageFamily('x.ts').includes('*.mjs'));
  assert.deepEqual(languageFamily('x.py'), ['*.py']);
  assert.deepEqual(languageFamily('x.txt'), []);
});

test('MinimizeError is the failure type callers can catch', () => {
  assert.ok(new MinimizeError('x') instanceof Error);
});
