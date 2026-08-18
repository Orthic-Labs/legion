// EC-5 item 5 — lib/preeffect-correlation.mjs (PreEffectCorrelationStore)
//
// Mirrors session-binding.test.mjs's coverage shape (same primitive, same
// race argument) — round-trip; ensureRequestId idempotent on repeat;
// concurrent race converges on one requestId; corrupt file degrades to null;
// unwritable root degrades to null. See lib/preeffect-correlation.mjs's
// header for why this needs its own store rather than reusing
// SessionBindingStore (different key: tool_use_id, not sessionId; different
// value shape: one requestId string, not a {runId,taskId,contractId} record).

import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { PreEffectCorrelationStore } from '../lib/preeffect-correlation.mjs';

const RACE_WORKER = fileURLToPath(new URL('./fixtures/preeffect-correlation-race-worker.mjs', import.meta.url));

function freshRoot() {
  return mkdtempSync(join(tmpdir(), 'arcane-preeffect-correlation-'));
}

function runWorker(root, toolUseId, outFile) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [RACE_WORKER, root, toolUseId, outFile], { stdio: 'inherit' });
    child.on('error', reject);
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`race worker exited ${code}`))));
  });
}

test('PreEffectCorrelationStore: round-trip — ensureRequestId mints, getRequestId reads it back', () => {
  const store = new PreEffectCorrelationStore({ root: freshRoot() });
  assert.equal(store.getRequestId('tu-1'), null);
  const minted = store.ensureRequestId('tu-1');
  assert.match(minted, /^req_[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.equal(store.getRequestId('tu-1'), minted);
});

test('PreEffectCorrelationStore: ensureRequestId is idempotent on repeat calls', () => {
  const store = new PreEffectCorrelationStore({ root: freshRoot() });
  const first = store.ensureRequestId('tu-1');
  const second = store.ensureRequestId('tu-1');
  assert.equal(first, second);
});

test('PreEffectCorrelationStore: reserve returns exactly one winner & compatibility keeps its id', () => {
  const store = new PreEffectCorrelationStore({ root: freshRoot() });
  const first = store.reserve('tu-reserve');
  const duplicate = store.reserve('tu-reserve');
  assert.equal(first.created, true);
  assert.equal(duplicate.created, false);
  assert.equal(first.requestId, duplicate.requestId);
  assert.equal(store.ensureRequestId('tu-reserve'), first.requestId);
});

test('PreEffectCorrelationStore: finalization is immutable & idempotent', () => {
  const store = new PreEffectCorrelationStore({ root: freshRoot() });
  const reservation = store.reserve('tu-final');
  const record = { requestId: reservation.requestId, capabilityId: 'cap-1', requestedEffect: { effectClass: 'FILE_WRITE', target: 'a.mjs', operation: 'write' }, authorizedEffect: { effectClass: 'FILE_WRITE', target: 'a.mjs', operation: 'write' } };
  assert.deepEqual(store.finalize('tu-final', record), record);
  assert.deepEqual(store.finalize('tu-final', record), record);
  assert.equal(store.finalize('tu-final', { ...record, capabilityId: 'cap-2' }), null);
  assert.deepEqual(store.getFinalized('tu-final'), record);
});

test('PreEffectCorrelationStore: corrupt & reservation-mismatched finalization fail closed', () => {
  const root = freshRoot();
  const store = new PreEffectCorrelationStore({ root });
  const reservation = store.reserve('tu-finalized-corrupt');
  const record = { requestId: reservation.requestId, capabilityId: 'cap-1', requestedEffect: { effectClass: 'FILE_WRITE', target: 'a.mjs', operation: 'write' }, authorizedEffect: { effectClass: 'FILE_WRITE', target: 'a.mjs', operation: 'write' } };
  assert.equal(store.finalize('tu-finalized-corrupt', { ...record, requestId: 'req_wrong' }), null);
  assert.deepEqual(store.finalize('tu-finalized-corrupt', record), record);
  const file = join(root, `${createHash('sha256').update('tu-finalized-corrupt', 'utf8').digest('hex')}.finalized.json`);
  writeFileSync(file, '{not valid json', 'utf8');
  assert.equal(store.getFinalized('tu-finalized-corrupt'), null);
});

test('PreEffectCorrelationStore: two different tool_use_ids never share a requestId', () => {
  const store = new PreEffectCorrelationStore({ root: freshRoot() });
  const a = store.ensureRequestId('tu-a');
  const b = store.ensureRequestId('tu-b');
  assert.notEqual(a, b);
});

test('PreEffectCorrelationStore: corrupt correlation file degrades to null without throwing', () => {
  const root = freshRoot();
  const store = new PreEffectCorrelationStore({ root });
  store.ensureRequestId('tu-1');
  const file = join(root, `${createHash('sha256').update('tu-1', 'utf8').digest('hex')}.json`);
  writeFileSync(file, '{not valid json', 'utf8');
  assert.doesNotThrow(() => {
    assert.equal(store.getRequestId('tu-1'), null);
  });
});

test('PreEffectCorrelationStore: unwritable root degrades ensureRequestId to null without throwing', () => {
  const parent = freshRoot();
  const blockerFile = join(parent, 'blocker-file');
  writeFileSync(blockerFile, 'not a directory', 'utf8');
  const store = new PreEffectCorrelationStore({ root: join(blockerFile, 'preeffect-correlation') });
  assert.doesNotThrow(() => {
    assert.equal(store.ensureRequestId('tu-1'), null);
  });
});

test('PreEffectCorrelationStore: getRequestId/ensureRequestId degrade to null on non-string/empty ids, never throw', () => {
  const store = new PreEffectCorrelationStore({ root: freshRoot() });
  for (const bad of [null, undefined, '', 42, {}]) {
    assert.doesNotThrow(() => assert.equal(store.getRequestId(bad), null));
    assert.doesNotThrow(() => assert.equal(store.ensureRequestId(bad), null));
  }
});

test('PreEffectCorrelationStore: constructor requires a root path', () => {
  assert.throws(() => new PreEffectCorrelationStore({}), /requires a root directory path/);
});

test('PreEffectCorrelationStore: EC-5 I-1 — two concurrently-spawned ensureRequestId calls for the same tool_use_id converge on the SAME requestId', async () => {
  const root = freshRoot();
  const toolUseId = 'race-tool-use-id';
  const outA = join(root, 'out-a.json');
  const outB = join(root, 'out-b.json');

  await Promise.all([
    runWorker(root, toolUseId, outA),
    runWorker(root, toolUseId, outB),
  ]);

  const a = JSON.parse(readFileSync(outA, 'utf8'));
  const b = JSON.parse(readFileSync(outB, 'utf8'));
  assert.ok(a.requestId);
  assert.ok(b.requestId);
  assert.equal(a.requestId, b.requestId, 'at most one in-flight pre-effect per tool_use_id — both converge on one requestId');
});
