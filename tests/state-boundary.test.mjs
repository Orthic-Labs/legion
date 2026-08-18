// `legion state snapshot|verify` — the mechanical machine-state boundary.
// Pins the SampleApp escape: a test wrote a fake route into the app's real
// app-data directory; source was clean, tests were green, the audit passed,
// and the machine stayed poisoned. verify must catch created, modified, and
// deleted files under a snapshotted surface, and pass untouched surfaces.

import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { runState } from '../src/lib/cli/commands/state.mjs';

function scenario() {
  const root = mkdtempSync(join(tmpdir(), 'legion-state-'));
  const appData = join(root, 'SampleAppNext');
  mkdirSync(appData, { recursive: true });
  writeFileSync(join(appData, 'recognition-route.json'), '{"id":"dml-0","provider":"dml"}\n');
  writeFileSync(join(appData, 'settings.json'), '{"theme":"dark"}\n');
  const out = [];
  const errs = [];
  return {
    root,
    appData,
    snap: join(root, 'before.json'),
    ctx: { stdout: { write: (c) => out.push(c) }, stderr: { write: (c) => errs.push(c) }, env: {}, cwd: root },
    out,
    errs,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

test('untouched state verifies clean', async () => {
  const s = scenario();
  try {
    await runState(['snapshot', '--path', s.appData, '--out', s.snap], s.ctx);
    const result = await runState(['verify', '--snapshot', s.snap], s.ctx);
    assert.equal(result.exitCode, 0);
    assert.match(s.out.join(''), /"verdict":"clean"/);
  } finally { s.cleanup(); }
});

test('the SampleApp contamination is caught: a test rewrites production state', async () => {
  const s = scenario();
  try {
    await runState(['snapshot', '--path', s.appData, '--out', s.snap], s.ctx);
    // What the intermediate calibration test actually did:
    writeFileSync(join(s.appData, 'recognition-route.json'), '{"id":"two","provider":"cpu_only"}\n');
    const result = await runState(['verify', '--snapshot', s.snap], s.ctx);
    assert.equal(result.exitCode, 1);
    assert.match(s.errs.join(''), /STATE BOUNDARY BREACH/);
    assert.match(s.out.join(''), /"change":"modified"/);
    assert.match(s.out.join(''), /recognition-route\.json/);
  } finally { s.cleanup(); }
});

test('created and deleted files under the surface are both deltas', async () => {
  const s = scenario();
  try {
    await runState(['snapshot', '--path', s.appData, '--out', s.snap], s.ctx);
    writeFileSync(join(s.appData, 'calibration-log.jsonl'), '{"utterance":"one"}\n');
    rmSync(join(s.appData, 'settings.json'));
    const result = await runState(['verify', '--snapshot', s.snap], s.ctx);
    assert.equal(result.exitCode, 1);
    const payload = s.out.join('');
    assert.match(payload, /"change":"created"/);
    assert.match(payload, /"change":"deleted"/);
  } finally { s.cleanup(); }
});

test('a surface absent at snapshot time that appears later is a breach', async () => {
  const s = scenario();
  const ghost = join(s.root, 'not-yet-existing');
  try {
    await runState(['snapshot', '--path', ghost, '--out', s.snap], s.ctx);
    mkdirSync(ghost, { recursive: true });
    writeFileSync(join(ghost, 'sneaky.json'), '{}\n');
    const result = await runState(['verify', '--snapshot', s.snap], s.ctx);
    assert.equal(result.exitCode, 1);
    assert.match(s.out.join(''), /sneaky\.json/);
  } finally { s.cleanup(); }
});
