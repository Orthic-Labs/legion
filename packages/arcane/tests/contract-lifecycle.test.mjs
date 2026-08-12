import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ContractLifecycle } from '../lib/contract-lifecycle.mjs';
import { generateTestKeyRing } from '../lib/keys.mjs';
import { SessionBindingStore } from '../lib/session-binding.mjs';
import { runRun } from '../../../lib/cli/commands/run.mjs';

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'arcane-lifecycle-'));
  const bindings = new SessionBindingStore({ root: join(root, 'bindings') });
  const delivery = { repositories: [{ root: 'D:/repo', commonDir: 'D:/repo/.git', primaryRoot: 'D:/repo', canonicalRef: 'refs/heads/main', head: 'a'.repeat(40), snapshotTree: 'b'.repeat(40), mode: 'write', leaseToken: 'lease-1' }] };
  const initial = { runId: 'run_lifecycle', taskId: 'T-5', contractId: 'EC-603', contractVersion: 7, contractDigest: `sha256:${'a'.repeat(64)}`, delivery, work: { queue: ['preserve-me'], cursor: 3 } };
  bindings.putBinding('session-lifecycle', initial);
  const args = { root: join(root, 'transitions'), bindingStore: bindings, sealStore: { get: (contractId, version) => contractId === 'EC-604' && version === 1 ? { contractId, version, contractDigest: `sha256:${'b'.repeat(64)}` } : null }, keyRing: generateTestKeyRing(['lifecycle-key']), keyId: 'lifecycle-key', clock: () => '2026-08-12T00:00:00.000Z' };
  return { root, bindings, initial, args, dispose: () => rmSync(root, { recursive: true, force: true }) };
}

test('suspend writes signed receipt & preserves delivery, work, leases, and binding lineage', () => {
  const f = fixture();
  try {
    const receipt = new ContractLifecycle(f.args).transition({ action: 'suspend', sessionId: 'session-lifecycle', transactionId: 'transition-suspend-01' });
    assert.equal(receipt.state, 'COMMITTED'); assert.equal(receipt.authentication.keyId, 'lifecycle-key');
    const binding = f.bindings.getBinding('session-lifecycle');
    assert.deepEqual(binding.delivery, f.initial.delivery); assert.deepEqual(binding.work, f.initial.work);
    assert.equal(binding.runId, f.initial.runId); assert.equal(binding.contractId, 'EC-603'); assert.equal(binding.lifecycle.state, 'suspended');
  } finally { f.dispose(); }
});

test('supersede preserves run, delivery, work & uses sealed target identity', () => {
  const f = fixture();
  try {
    new ContractLifecycle(f.args).transition({ action: 'supersede', sessionId: 'session-lifecycle', transactionId: 'transition-supersede-01', target: { contractId: 'EC-604', version: 1, taskId: 'T-9' } });
    const binding = f.bindings.getBinding('session-lifecycle');
    assert.equal(binding.runId, f.initial.runId); assert.equal(binding.taskId, 'T-9'); assert.equal(binding.contractId, 'EC-604'); assert.equal(binding.contractVersion, 1); assert.equal(binding.contractDigest, `sha256:${'b'.repeat(64)}`);
    assert.deepEqual(binding.delivery, f.initial.delivery); assert.deepEqual(binding.work, f.initial.work);
  } finally { f.dispose(); }
});

test('forged journal & changed replay reject without changing binding', () => {
  const f = fixture();
  try {
    const lifecycle = new ContractLifecycle(f.args); lifecycle.transition({ action: 'suspend', sessionId: 'session-lifecycle', transactionId: 'transition-replay-01' });
    const before = f.bindings.getBinding('session-lifecycle');
    assert.throws(() => lifecycle.transition({ action: 'suspend', sessionId: 'session-lifecycle', transactionId: 'transition-replay-01' }), { code: 'ARC_REPLAY_NONCE_SEEN' });
    assert.throws(() => lifecycle.transition({ action: 'supersede', sessionId: 'session-lifecycle', transactionId: 'transition-replay-01', target: { contractId: 'EC-604', version: 1 } }), { code: 'ARC_REPLAY_NONCE_SEEN' });
    assert.deepEqual(f.bindings.getBinding('session-lifecycle'), before);
    const path = join(f.args.root, `${(awaitDigest('session-lifecycle'))}.jsonl`); const text = readFileSync(path, 'utf8'); writeFileSync(path, text.replace('suspended', 'forged-state'));
    assert.throws(() => lifecycle.repair({ sessionId: 'session-lifecycle' }), { code: 'ARC_AUTH_FORGED' });
    assert.deepEqual(f.bindings.getBinding('session-lifecycle'), before);
  } finally { f.dispose(); }
});

test('repair completes both pre-CAS & post-CAS crashes from exact signed predecessor', () => {
  for (const crashPoint of ['after-prepare', 'after-cas']) {
    const f = fixture();
    try {
      assert.throws(() => new ContractLifecycle({ ...f.args, failpoint: crashPoint }).transition({ action: 'suspend', sessionId: 'session-lifecycle', transactionId: `transition-crash-${crashPoint}` }));
      const beforeRepair = f.bindings.getBinding('session-lifecycle');
      if (crashPoint === 'after-prepare') assert.deepEqual(beforeRepair, f.initial); else assert.equal(beforeRepair.lifecycle.state, 'suspended');
      const receipt = new ContractLifecycle(f.args).repair({ sessionId: 'session-lifecycle' });
      assert.equal(receipt.state, 'COMMITTED');
      const repaired = f.bindings.getBinding('session-lifecycle'); assert.equal(repaired.lifecycle.state, 'suspended'); assert.deepEqual(repaired.delivery, f.initial.delivery); assert.deepEqual(repaired.work, f.initial.work);
    } finally { f.dispose(); }
  }
});

test('reachable CLI lifecycle command requires host key & emits signed transition receipt', async () => {
  const f = fixture();
  try {
    const keyDir = join(f.root, 'host-keys');
    const { mkdirSync } = await import('node:fs'); mkdirSync(keyDir); writeFileSync(join(keyDir, 'cli-key.key'), '11'.repeat(32));
    const cliBindings = new SessionBindingStore({ root: join(f.root, '.audit', 'arcane', 'session-bindings') }); cliBindings.putBinding('session-lifecycle', f.initial);
    const stdout = { text: '', write(value) { this.text += value; } };
    const result = await runRun(['suspend', '--session', 'session-lifecycle', '--transaction', 'transition-cli-01'], { stdout, stderr: { write() {} }, env: { ARCANE_KEY_DIR: keyDir, ARCANE_KEY_ID: 'cli-key' }, cwd: f.root });
    assert.equal(result.exitCode, 0); const output = JSON.parse(stdout.text); assert.equal(output.receipt.authentication.keyId, 'cli-key'); assert.equal(cliBindings.getBinding('session-lifecycle').lifecycle.state, 'suspended');
  } finally { f.dispose(); }
});

function awaitDigest(sessionId) {
  // ContractLifecycle keys journal paths with this stable SHA-256 projection.
  // Keep this independent from private implementation by deriving same value
  // through Node's standard hash used by canonical digest input shape.
  return createHash('sha256').update(`{\"domain\":\"arcane.contract-transition.v1\",\"sessionId\":${JSON.stringify(sessionId)}}`).digest('hex');
}
