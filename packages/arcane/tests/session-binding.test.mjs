// EC-5 item 1 — lib/session-binding.mjs (SessionBindingStore)
//
// Mandatory coverage (task dispatch):
//   round-trip; ensureBinding idempotent on repeat; simulated EEXIST race —
//   two ensureBinding calls on one fresh root return the SAME runId; corrupt
//   file degrades to null without throwing; unwritable root degrades to null
//   without throwing.
//
// The race test reproduces the real production scenario (two separate hook
// subprocesses racing SessionStart for the same session — see the module
// header in lib/session-binding.mjs) with two real, concurrently-spawned
// Node processes rather than an in-process approximation, so it proves the
// filesystem-level `wx` exclusivity actually holds, not just that the catch
// branch is reachable.

import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SessionBindingStore } from '../lib/session-binding.mjs';

const RACE_WORKER = fileURLToPath(new URL('./fixtures/session-binding-race-worker.mjs', import.meta.url));

function freshRoot() {
  return mkdtempSync(join(tmpdir(), 'arcane-session-binding-'));
}

function runWorker(root, sessionId, outFile) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [RACE_WORKER, root, sessionId, outFile], { stdio: 'inherit' });
    child.on('error', reject);
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`race worker exited ${code}`))));
  });
}

test('SessionBindingStore: round-trip — ensureBinding mints, getBinding reads it back, putBinding upgrades', () => {
  const store = new SessionBindingStore({ root: freshRoot() });

  assert.equal(store.getBinding('sess-1'), null, 'nothing minted yet');

  const minted = store.ensureBinding('sess-1');
  assert.match(minted.runId, /^run_[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.equal(minted.taskId, null);
  assert.equal(minted.contractId, null);
  assert.deepEqual(store.getBinding('sess-1'), minted);

  const upgraded = store.putBinding('sess-1', { runId: minted.runId, taskId: 'T-1', contractId: 'EC-5' });
  assert.deepEqual(upgraded, { runId: minted.runId, taskId: 'T-1', contractId: 'EC-5' });
  assert.deepEqual(store.getBinding('sess-1'), upgraded, 'getBinding reflects the putBinding upgrade');
});

test('SessionBindingStore: ensureBinding is idempotent on repeat calls', () => {
  const store = new SessionBindingStore({ root: freshRoot() });
  const first = store.ensureBinding('sess-1');
  const second = store.ensureBinding('sess-1');
  const third = store.ensureBinding('sess-1');
  assert.equal(first.runId, second.runId);
  assert.equal(second.runId, third.runId);
});

test('SessionBindingStore: two sessions on the same store never share a runId', () => {
  const store = new SessionBindingStore({ root: freshRoot() });
  const a = store.ensureBinding('sess-a');
  const b = store.ensureBinding('sess-b');
  assert.notEqual(a.runId, b.runId);
});

test('SessionBindingStore: binding filename is a sha256 hex digest of the session id, not the raw id (no path-injection surface)', () => {
  const root = freshRoot();
  const store = new SessionBindingStore({ root });
  const trickySessionId = '../../../etc/passwd';
  const binding = store.ensureBinding(trickySessionId);
  assert.ok(binding, 'a session id containing path-traversal characters still binds normally');

  const expectedFile = `${createHash('sha256').update(trickySessionId, 'utf8').digest('hex')}.json`;
  const onDisk = JSON.parse(readFileSync(join(root, expectedFile), 'utf8'));
  assert.equal(onDisk.runId, binding.runId, 'the record lives at the hashed filename, confined to root');
});

test('SessionBindingStore: corrupt binding file degrades to null without throwing', () => {
  const root = freshRoot();
  const store = new SessionBindingStore({ root });
  const minted = store.ensureBinding('sess-1');
  assert.ok(minted);

  const file = join(root, `${createHash('sha256').update('sess-1', 'utf8').digest('hex')}.json`);
  writeFileSync(file, '{not valid json', 'utf8');

  assert.doesNotThrow(() => {
    assert.equal(store.getBinding('sess-1'), null);
  });
});

test('SessionBindingStore: unwritable root (a file occupying the root path) degrades ensureBinding/putBinding to null without throwing', () => {
  const parent = freshRoot();
  const blockerFile = join(parent, 'blocker-file');
  writeFileSync(blockerFile, 'not a directory', 'utf8');
  // Use a path THROUGH a file as the "root" — mkdirSync(recursive) cannot
  // create a directory through an existing regular file (ENOTDIR/EEXIST),
  // so every write path in the store must degrade rather than throw.
  const unwritableRoot = join(blockerFile, 'session-bindings');
  const store = new SessionBindingStore({ root: unwritableRoot });

  assert.doesNotThrow(() => {
    assert.equal(store.ensureBinding('sess-1'), null);
  });
  assert.doesNotThrow(() => {
    assert.equal(store.putBinding('sess-1', { runId: 'run_00000000000000000000000000' }), null);
  });
  assert.doesNotThrow(() => {
    assert.equal(store.getBinding('sess-1'), null);
  });
});

test('SessionBindingStore: getBinding/ensureBinding/putBinding degrade to null on non-string/empty session ids, never throw', () => {
  const store = new SessionBindingStore({ root: freshRoot() });
  for (const bad of [null, undefined, '', 42, {}]) {
    assert.doesNotThrow(() => assert.equal(store.getBinding(bad), null));
    assert.doesNotThrow(() => assert.equal(store.ensureBinding(bad), null));
  }
  assert.doesNotThrow(() => assert.equal(store.putBinding('', { runId: 'run_x' }), null));
});

test('SessionBindingStore: constructor requires a root path, matching ReceiptStore\'s constructor-time validation shape', () => {
  assert.throws(() => new SessionBindingStore({}), /requires a root directory path/);
  assert.throws(() => new SessionBindingStore({ root: 42 }), /requires a root directory path/);
});

test('SessionBindingStore: simulated EEXIST race — two concurrently-spawned ensureBinding calls on one fresh root converge on the SAME runId', async () => {
  const root = freshRoot();
  mkdirSync(root, { recursive: true });
  const sessionId = 'race-session';
  const outA = join(root, 'out-a.json');
  const outB = join(root, 'out-b.json');

  // Launched together (spawn, not spawnSync) so both processes race to
  // create the same `<root>/<hash>.json` with the exclusive `wx` flag —
  // exactly the two-concurrent-SessionStart-handlers scenario the module
  // header documents. Whichever loses gets EEXIST and must read back the
  // winner's record rather than minting its own.
  await Promise.all([
    runWorker(root, sessionId, outA),
    runWorker(root, sessionId, outB),
  ]);

  const resultA = JSON.parse(readFileSync(outA, 'utf8'));
  const resultB = JSON.parse(readFileSync(outB, 'utf8'));
  assert.ok(resultA, 'process A produced a binding');
  assert.ok(resultB, 'process B produced a binding');
  assert.equal(resultA.runId, resultB.runId, 'both concurrent handlers converge on exactly one runId');

  // And the store's own on-disk state agrees with both.
  const store = new SessionBindingStore({ root });
  assert.equal(store.getBinding(sessionId).runId, resultA.runId);
});
