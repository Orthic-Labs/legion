// S03 — lib/receipt-store.mjs (ReceiptStore + CapabilityStore)
//
// Mandatory coverage (task dispatch + INTERFACES.md §S03):
//   ReceiptStore   — append/get/list round-trip; verifyChain() green on a
//                     clean store; hand-tampered line -> verifyChain() ok:
//                     false with the exact corruptAt; quarantine() preserves
//                     earlier records as readable; a receipt written through
//                     the store still satisfies assertValid('effect-receipt-v1', ...).
//   CapabilityStore — expired, max-used, revoked, unknown, and each binding
//                     mismatch (run/workspace/operation/effectClass/target).
//
// Every ReceiptStore in this file gets a fresh temp directory so tests never
// interact through shared state.

import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ReceiptStore, CapabilityStore } from '../lib/receipt-store.mjs';
import { assertValid } from '../lib/validate.mjs';
import { mintId } from '../lib/ids.mjs';
import { digestValue } from '../lib/canonical.mjs';

function freshRoot() {
  return mkdtempSync(join(tmpdir(), 'arcane-receipt-store-'));
}

function sampleReceipt(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'legion-effect-receipt',
    receiptId: mintId('effectReceipt'),
    requestId: 'req_01ARZ3NDEKTSV4RRFFQ69G5FAV',
    runId: 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV',
    contractId: 'EC-1',
    taskId: 'T-1',
    requested: { effectClass: 'FILE_WRITE', target: 'a.txt', operation: 'write' },
    authorized: { effectClass: 'FILE_WRITE', target: 'a.txt', operation: 'write', capabilityId: 'cap_1' },
    observed: { effectClass: 'FILE_WRITE', target: 'a.txt', operation: 'write' },
    match: true,
    sourceRevision: '0123abcd',
    replayOf: null,
    idempotencyKey: 'idem-1',
    observedAt: new Date().toISOString(),
    authentication: { issuerIdentity: 'key:k1', verificationMethod: 'capability-signature', perMessage: true, verifiedAt: new Date().toISOString() },
    replayDefense: { nonce: 'n-1', sequence: 1, freshnessWindowSeconds: 300, freshAt: new Date().toISOString() },
    ...overrides,
  };
}

// ---------------------------------------------------------------- ReceiptStore

test('ReceiptStore: append then get/list round-trip', () => {
  const store = new ReceiptStore({ root: freshRoot() });
  const r1 = sampleReceipt();
  const r2 = sampleReceipt({ receiptId: mintId('effectReceipt'), idempotencyKey: 'idem-2' });

  const a1 = store.append(r1);
  const a2 = store.append(r2);
  assert.equal(a1.sequence, 1);
  assert.equal(a2.sequence, 2);
  assert.equal(a1.prevDigest, null, 'first entry in the store has no predecessor');
  assert.notEqual(a2.prevDigest, null, 'second entry chains to the first (digest of the full stored entry, not just recordDigest)');
  assert.match(a1.recordDigest, /^sha256:[0-9a-f]{64}$/);

  assert.deepEqual(store.get(r1.receiptId), r1);
  assert.deepEqual(store.get(r2.receiptId), r2);
  assert.equal(store.get('eff_does-not-exist'), null);

  const all = store.list();
  assert.equal(all.length, 2);
  assert.deepEqual(all.map((r) => r.receiptId), [r1.receiptId, r2.receiptId]);

  const filtered = store.list({ runId: r1.runId });
  assert.equal(filtered.length, 2, 'both fixtures share the same runId');
});

test('ReceiptStore: list({runId}) filters correctly when runIds differ', () => {
  const store = new ReceiptStore({ root: freshRoot() });
  const other = mintId('run');
  const r1 = sampleReceipt();
  const r2 = sampleReceipt({ receiptId: mintId('effectReceipt'), runId: other, idempotencyKey: 'idem-2' });
  store.append(r1);
  store.append(r2);

  assert.deepEqual(store.list({ runId: other }).map((r) => r.receiptId), [r2.receiptId]);
});

test('ReceiptStore: verifyChain() is green on a clean store', () => {
  const store = new ReceiptStore({ root: freshRoot() });
  store.append(sampleReceipt());
  store.append(sampleReceipt({ receiptId: mintId('effectReceipt'), idempotencyKey: 'idem-2' }));
  store.append(sampleReceipt({ receiptId: mintId('effectReceipt'), idempotencyKey: 'idem-3' }));

  const result = store.verifyChain();
  assert.equal(result.ok, true);
  assert.equal(result.length, 3);
  assert.equal(result.corruptAt, null);
});

test('ReceiptStore: a hand-tampered JSONL line makes verifyChain() report ok:false with the exact corruptAt', () => {
  const root = freshRoot();
  const store = new ReceiptStore({ root });
  store.append(sampleReceipt());
  store.append(sampleReceipt({ receiptId: mintId('effectReceipt'), idempotencyKey: 'idem-2' }));
  store.append(sampleReceipt({ receiptId: mintId('effectReceipt'), idempotencyKey: 'idem-3' }));

  const receiptsPath = join(root, 'receipts.jsonl');
  const lines = readFileSync(receiptsPath, 'utf8').split('\n').filter(Boolean);
  const tampered = JSON.parse(lines[1]); // sequence 2
  tampered.record.idempotencyKey = 'HAND-TAMPERED';
  lines[1] = JSON.stringify(tampered);
  writeFileSync(receiptsPath, lines.join('\n') + '\n', 'utf8');

  const result = store.verifyChain();
  assert.equal(result.ok, false);
  assert.equal(result.corruptAt, 2);
  assert.ok(result.reason.length > 0);
});

test('ReceiptStore: quarantine() preserves earlier records as readable and never truncates the file', () => {
  const root = freshRoot();
  const store = new ReceiptStore({ root });
  const r1 = sampleReceipt();
  const r2 = sampleReceipt({ receiptId: mintId('effectReceipt'), idempotencyKey: 'idem-2' });
  const r3 = sampleReceipt({ receiptId: mintId('effectReceipt'), idempotencyKey: 'idem-3' });
  store.append(r1);
  store.append(r2);
  store.append(r3);

  const receiptsPath = join(root, 'receipts.jsonl');
  const lines = readFileSync(receiptsPath, 'utf8').split('\n').filter(Boolean);
  const tampered = JSON.parse(lines[1]);
  tampered.record.idempotencyKey = 'HAND-TAMPERED';
  lines[1] = JSON.stringify(tampered);
  writeFileSync(receiptsPath, lines.join('\n') + '\n', 'utf8');

  assert.equal(store.verifyChain().corruptAt, 2);

  const qEntry = store.quarantine(2, 'hand-tamper test');
  assert.equal(qEntry.sequence, 2);
  assert.equal(qEntry.reason, 'hand-tamper test');

  // History is preserved, never truncated: 3 lines still on disk.
  const linesAfter = readFileSync(receiptsPath, 'utf8').split('\n').filter(Boolean);
  assert.equal(linesAfter.length, 3);

  // Earlier record is still readable.
  assert.deepEqual(store.get(r1.receiptId), r1);
  // Quarantined record is excluded from get()/list() (it is a tombstone now).
  assert.equal(store.get(r2.receiptId), null);
  // Record after the quarantined one is still individually readable.
  assert.deepEqual(store.get(r3.receiptId), r3);

  const listed = store.list();
  assert.deepEqual(listed.map((r) => r.receiptId), [r1.receiptId, r3.receiptId]);

  const quarantined = store.quarantined();
  assert.equal(quarantined.length, 1);
  assert.equal(quarantined[0].sequence, 2);
  assert.ok(quarantined[0].raw.includes('HAND-TAMPERED'), 'original tampered bytes preserved for forensics');
});

test('ReceiptStore: a receipt written through the store still satisfies assertValid(effect-receipt-v1)', () => {
  const store = new ReceiptStore({ root: freshRoot() });
  const receipt = sampleReceipt();
  store.append(receipt);
  const roundTripped = store.get(receipt.receiptId);
  assertValid('effect-receipt-v1', roundTripped);
});

// ------------------------------------------------------------- CapabilityStore

function baseCap(overrides = {}) {
  return {
    capabilityId: 'cap_1',
    runId: 'run-1',
    taskId: 'T-1',
    workspace: 'ws-1',
    operation: 'FILE_WRITE',
    effectClass: 'FILE_WRITE',
    targets: ['a.txt', 'b.txt'],
    policyDigest: 'sha256:' + '0'.repeat(64),
    expiresAt: null,
    maxUses: null,
    ...overrides,
  };
}

function baseCheckCtx(overrides = {}) {
  return {
    runId: 'run-1',
    taskId: 'T-1',
    workspace: 'ws-1',
    operation: 'FILE_WRITE',
    effectClass: 'FILE_WRITE',
    target: 'a.txt',
    ...overrides,
  };
}

test('CapabilityStore: positive check() on a freshly issued capability', () => {
  const store = new CapabilityStore();
  store.issue(baseCap());
  const result = store.check('cap_1', baseCheckCtx());
  assert.equal(result.allowed, true);
});

test('CapabilityStore: unknown capability -> ARC_CAPABILITY_UNKNOWN', () => {
  const store = new CapabilityStore();
  const result = store.check('cap_ghost', baseCheckCtx());
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_CAPABILITY_UNKNOWN');
});

test('CapabilityStore: expired capability -> ARC_CAPABILITY_EXPIRED', () => {
  const store = new CapabilityStore();
  store.issue(baseCap({ expiresAt: '2020-01-01T00:00:00.000Z' }));
  const result = store.check('cap_1', baseCheckCtx({ now: '2026-01-01T00:00:00.000Z' }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_CAPABILITY_EXPIRED');
});

test('CapabilityStore: max-used capability -> ARC_CAPABILITY_EXHAUSTED', () => {
  const store = new CapabilityStore();
  store.issue(baseCap({ maxUses: 1 }));
  const consumed = store.consume('cap_1');
  assert.equal(consumed.usedCount, 1);

  const result = store.check('cap_1', baseCheckCtx());
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_CAPABILITY_EXHAUSTED');
});

test('CapabilityStore: revoked capability -> ARC_CAPABILITY_REVOKED', () => {
  const store = new CapabilityStore();
  store.issue(baseCap());
  store.revoke('cap_1', 'compromised key');
  const result = store.check('cap_1', baseCheckCtx());
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_CAPABILITY_REVOKED');
});

test('CapabilityStore: wrong run -> ARC_BINDING_MISMATCH', () => {
  const store = new CapabilityStore();
  store.issue(baseCap());
  const result = store.check('cap_1', baseCheckCtx({ runId: 'run-other' }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_BINDING_MISMATCH');
  assert.equal(result.detail.field, 'runId');
});

test('CapabilityStore: wrong workspace -> ARC_BINDING_MISMATCH', () => {
  const store = new CapabilityStore();
  store.issue(baseCap());
  const result = store.check('cap_1', baseCheckCtx({ workspace: 'ws-other' }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_BINDING_MISMATCH');
  assert.equal(result.detail.field, 'workspace');
});

test('CapabilityStore: wrong operation -> ARC_BINDING_MISMATCH', () => {
  const store = new CapabilityStore();
  store.issue(baseCap());
  const result = store.check('cap_1', baseCheckCtx({ operation: 'FILE_DELETE' }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_BINDING_MISMATCH');
  assert.equal(result.detail.field, 'operation');
});

test('CapabilityStore: wrong effectClass -> ARC_BINDING_MISMATCH', () => {
  const store = new CapabilityStore();
  store.issue(baseCap());
  const result = store.check('cap_1', baseCheckCtx({ effectClass: 'NETWORK_EGRESS' }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_BINDING_MISMATCH');
  assert.equal(result.detail.field, 'effectClass');
});

test('CapabilityStore: target not in the granted set -> ARC_BINDING_MISMATCH', () => {
  const store = new CapabilityStore();
  store.issue(baseCap());
  const result = store.check('cap_1', baseCheckCtx({ target: 'c.txt' }));
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_BINDING_MISMATCH');
  assert.equal(result.detail.field, 'target');
});

test('CapabilityStore: consume()/revoke() on an unknown capability throw ARC_CAPABILITY_UNKNOWN', () => {
  const store = new CapabilityStore();
  assert.throws(() => store.consume('cap_ghost'), (err) => err.code === 'ARC_CAPABILITY_UNKNOWN');
  assert.throws(() => store.revoke('cap_ghost'), (err) => err.code === 'ARC_CAPABILITY_UNKNOWN');
});

// ── Head-anchor coverage (added at lane review) ────────────────────────────
// A forward-only hash chain cannot detect anything done to its NEWEST entry,
// because nothing links to it. Rewriting the tail (recomputing its own
// recordDigest) and truncating the tail both produced ok:true before the head
// anchor existed — and silent truncation is precisely what detailed plan §5.3
// forbids. These lock that shut.

test('verifyChain detects a rewritten tail entry whose own digest was recomputed', () => {
  const root = freshRoot();
  try {
    const store = new ReceiptStore({ root });
    for (let i = 1; i <= 3; i += 1) store.append({ receiptId: `eff_${i}`, runId: 'run_x', n: i });
    assert.equal(store.verifyChain().ok, true);

    const jsonl = join(root, 'receipts.jsonl');
    const lines = readFileSync(jsonl, 'utf8').trimEnd().split('\n');
    const entry = JSON.parse(lines[2]);
    entry.record.n = 999;
    entry.recordDigest = digestValue(entry.record); // attacker repairs the obvious check
    lines[2] = JSON.stringify(entry);
    writeFileSync(jsonl, `${lines.join('\n')}\n`, 'utf8');

    const chain = new ReceiptStore({ root }).verifyChain();
    assert.equal(chain.ok, false);
    assert.equal(chain.corruptAt, 3);
    assert.match(chain.reason, /head anchor/);
  } finally { /* temp dir left to the OS, as elsewhere in this file */ }
});

test('verifyChain detects truncated history — never a silent shorter chain', () => {
  const root = freshRoot();
  try {
    const store = new ReceiptStore({ root });
    for (let i = 1; i <= 3; i += 1) store.append({ receiptId: `eff_${i}`, runId: 'run_x', n: i });

    const jsonl = join(root, 'receipts.jsonl');
    const lines = readFileSync(jsonl, 'utf8').trimEnd().split('\n');
    writeFileSync(jsonl, `${lines.slice(0, 2).join('\n')}\n`, 'utf8');

    const chain = new ReceiptStore({ root }).verifyChain();
    assert.equal(chain.ok, false);
    assert.equal(chain.corruptAt, 3);
    assert.match(chain.reason, /truncated/);
  } finally { /* temp dir left to the OS, as elsewhere in this file */ }
});

test('a legitimate quarantine of the newest entry still verifies — re-anchored, not flagged', () => {
  const root = freshRoot();
  try {
    const store = new ReceiptStore({ root });
    for (let i = 1; i <= 3; i += 1) store.append({ receiptId: `eff_${i}`, runId: 'run_x', n: i });
    store.quarantine(3, 'corrupt unit');
    assert.equal(new ReceiptStore({ root }).verifyChain().ok, true);
    assert.equal(store.quarantined().length, 1);
  } finally { /* temp dir left to the OS, as elsewhere in this file */ }
});
