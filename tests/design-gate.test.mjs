import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { BREAKPOINTS, loadBannedWords, runDesignGate } from '../src/lib/design-gate.mjs';

const ROOT = resolve(import.meta.dirname, '..');

function surface({ html = '<html><body><p>Plain honest copy.</p></body></html>', motion = 'pass' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'legion-design-gate-'));
  writeFileSync(join(dir, 'index.html'), html);
  writeFileSync(join(dir, 'motion-plan.md'), '# motion\n');
  if (motion) writeFileSync(join(dir, 'motion-gate.json'), JSON.stringify({ verdict: motion }));
  return dir;
}
const byId = (report, id) => report.checks.find((c) => c.id === id);

test('banned vocabulary is read from the documented source, not duplicated in code', () => {
  const banned = loadBannedWords(ROOT);
  assert.equal(banned.available, true);
  assert.ok(banned.vocabulary.includes('leverage'), 'parses the vocabulary table');
  assert.ok(banned.vocabulary.length >= 10, `expected a real term list, got ${banned.vocabulary.length}`);
  assert.ok(banned.structural.length >= 3, 'parses the structural table');
});

test('banned words and em dashes in built HTML fail the gate', () => {
  const dir = surface({ html: '<p>We leverage synergy to unlock value — truly revolutionary.</p>' });
  try {
    const report = runDesignGate({ root: ROOT, surface: dir });
    assert.equal(report.verdict, 'fail');
    const words = byId(report, 'banned-words');
    assert.equal(words.status, 'fail');
    assert.deepEqual(words.hits.map((h) => h.term).sort(), ['leverage', 'revolutionary', 'synergy', 'unlock']);
    assert.equal(byId(report, 'typography').status, 'fail', 'em dash is caught');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('clean copy passes the text checks without flagging ASCII as smart quotes', () => {
  // banned-words.md carries a malformed escape for U+2019 that decodes to a
  // space; a naive decoder flags every space in the build.
  const dir = surface({ html: "<p>It's plain ASCII copy with 'quotes' and no tells.</p>" });
  try {
    const report = runDesignGate({ root: ROOT, surface: dir });
    assert.equal(byId(report, 'banned-words').status, 'pass');
    assert.equal(byId(report, 'typography').status, 'pass', 'ASCII apostrophes are not smart quotes');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a missing motion gate blocks, and a failed motion verdict blocks', () => {
  const missing = surface({ motion: null });
  try {
    const report = runDesignGate({ root: ROOT, surface: missing });
    assert.equal(byId(report, 'motion-gate-verdict').status, 'fail');
    assert.ok(report.blocking.includes('motion-gate-verdict'));
  } finally { rmSync(missing, { recursive: true, force: true }); }

  const failed = surface({ motion: 'fail' });
  try {
    assert.equal(byId(runDesignGate({ root: ROOT, surface: failed }), 'motion-gate-verdict').status, 'fail');
  } finally { rmSync(failed, { recursive: true, force: true }); }
});

test('a check that cannot run reports unavailable and blocks — never a silent pass', () => {
  const dir = mkdtempSync(join(tmpdir(), 'legion-design-gate-empty-'));
  try {
    const report = runDesignGate({ root: ROOT, surface: dir });
    assert.equal(byId(report, 'banned-words').status, 'unavailable', 'no text to scan is not a pass');
    assert.equal(byId(report, 'lighthouse').status, 'unavailable');
    assert.equal(report.verdict, 'fail', 'unavailable required checks block the gate');
    assert.ok(report.counts.pass < report.counts.total);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a waiver clears a check only when it carries a reason', () => {
  const dir = surface({ html: '<p>We leverage synergy.</p>' });
  try {
    mkdirSync(join(dir, 'artifacts', 'qa'), { recursive: true });
    writeFileSync(join(dir, 'artifacts/qa/gate-waivers.json'), JSON.stringify({ 'banned-words': '', lighthouse: 'no CI browser' }));
    const report = runDesignGate({ root: ROOT, surface: dir });
    assert.equal(byId(report, 'banned-words').waived, undefined, 'empty reason does not waive');
    assert.equal(byId(report, 'lighthouse').waived, true, 'reasoned waiver clears the check');
    assert.ok(report.blocking.includes('banned-words'));
    assert.ok(!report.blocking.includes('lighthouse'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the gate reports the five specified breakpoints', () => {
  assert.deepEqual([...BREAKPOINTS], [360, 768, 1024, 1440, 1920]);
});
