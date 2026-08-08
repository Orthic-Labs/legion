// GATE 2 — the pre-effect gate and the receipt store working end-to-end.
//
// DISPATCH-11: "The pre-effect gate + receipt store working end-to-end = Gate 2."
//
// Everything here uses the REAL modules — real PolicyEngine over the shipped
// bundle, real CapabilityStore, real ReceiptStore on a temp dir, real HMAC
// signing, real replay guard. No test doubles: a gate proven only against
// stubs is not a gate.
//
// The end-to-end shape being proven:
//
//   authority asserted (kernel)
//     -> capability issued, policy-bound
//       -> PRE-EFFECT GATE authorizes
//         -> effect happens (simulated host observation)
//           -> receipt signed, replay-checked, appended to the chain
//             -> chain independently verifies
//
// and the negative half, which matters more: every step refuses when it should.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { PreEffectGate } from '../lib/preeffect-gate.mjs';
import { loadPolicy, PolicyEngine, DEFAULT_POLICY_PATH } from '../lib/policy.mjs';
import { AuthorityLedger } from '../lib/authority.mjs';
import { ReceiptStore, CapabilityStore } from '../lib/receipt-store.mjs';
import { ReplayGuard } from '../lib/replay.mjs';
import { generateTestKeyRing } from '../lib/keys.mjs';
import { signRecord, verifyRecord, authenticationBlock, EFFECT_RECEIPT_BOUND_FIELDS } from '../lib/receipt-auth.mjs';
import { assertValid } from '../lib/validate.mjs';
import { mintId } from '../lib/ids.mjs';

const NOW = Date.parse('2026-08-08T12:00:00.000Z');
const ISO = (ms = NOW) => new Date(ms).toISOString();

const RUN_ID = 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV';
const REQUEST_ID = 'req_01ARZ3NDEKTSV4RRFFQ69G5FAV';

function tempRoot() {
  const root = mkdtempSync(path.join(tmpdir(), 'arcane-gate2-'));
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

function contract() {
  return {
    schemaVersion: 1,
    kind: 'legion-execution-contract',
    contractId: 'EC-44',
    version: 2,
    sourceRevision: '0123abcdef',
    objective: 'ship',
    currentState: 'a',
    desiredState: 'b',
    requirements: [],
    decisions: [],
    invariants: [],
    nonGoals: [],
    scope: { own: ['src/**'], read: ['docs/**'], forbidden: ['src/secrets/**'] },
    artifacts: {
      exact: [{ id: 'a1', path: 'src/exact.ts', latitude: 'EXACT', content: 'x' }],
      bounded: [],
    },
    tasks: ['T-1'],
    dependencies: [],
    acceptanceCriteria: [],
    declaredChecks: [],
    evidenceRequirements: [],
    authorizedEffectClasses: ['FILE_WRITE'],
    repairLatitude: [],
    stopConditions: [],
    escalationConditions: [],
    rollback: [],
    openQuestions: [],
  };
}

function request(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'legion-effect-request',
    requestId: REQUEST_ID,
    runId: RUN_ID,
    contractId: 'EC-44',
    taskId: 'T-1',
    requestedBy: 'alchemist',
    effectClass: 'FILE_WRITE',
    target: 'src/exact.ts',
    operation: 'write',
    latitude: 'EXACT',
    sourceRevision: '0123abcdef',
    requestedAt: ISO(),
    ...overrides,
  };
}

/** Full live wiring: policy + capabilities + receipts + authority + keys. */
function wire({ root, now = NOW, expiresAt = ISO(NOW + 900_000) }) {
  const policy = new PolicyEngine(loadPolicy({ path: DEFAULT_POLICY_PATH }));
  const capabilityStore = new CapabilityStore();
  const receiptStore = new ReceiptStore({ root });
  const authorityLedger = new AuthorityLedger({ clock: () => now });
  const keyRing = generateTestKeyRing(['k1']);
  const replay = new ReplayGuard({
    freshnessWindowSeconds: policy.replayLimits().freshnessWindowSeconds,
    maxSkewSeconds: policy.replayLimits().maxSkewSeconds,
    clock: () => now,
  });

  authorityLedger.assertForTurn({
    turnId: 'turn-1',
    authority: 'alchemist',
    assertedBy: 'kernel:proc-1',
    verificationMethod: 'capability-signature',
    perMessage: true,
    source: 'kernel',
  });

  const capabilityId = 'cap_gate2_1';
  capabilityStore.issue(policy.bindPolicy({
    capabilityId,
    runId: RUN_ID,
    taskId: 'T-1',
    operation: 'write',
    effectClass: 'FILE_WRITE',
    targets: ['src/exact.ts'],
    policyDigest: policy.digest,
    expiresAt,
    maxUses: policy.capabilityLimits().maxUses,
  }));

  const gate = new PreEffectGate({ policy, capabilityStore, authorityLedger, clock: () => now });
  return { policy, capabilityStore, receiptStore, authorityLedger, keyRing, replay, gate, capabilityId };
}

/** Build + sign + replay-check + persist the post-effect receipt. */
function recordEffect(w, { observedTarget = 'src/exact.ts', now = NOW } = {}) {
  const receipt = {
    schemaVersion: 1,
    kind: 'legion-effect-receipt',
    receiptId: mintId('effectReceipt'),
    requestId: REQUEST_ID,
    runId: RUN_ID,
    contractId: 'EC-44',
    taskId: 'T-1',
    requested: { effectClass: 'FILE_WRITE', target: 'src/exact.ts', operation: 'write' },
    authorized: { effectClass: 'FILE_WRITE', target: 'src/exact.ts', operation: 'write', capabilityId: w.capabilityId },
    observed: { effectClass: 'FILE_WRITE', target: observedTarget, operation: 'write' },
    match: observedTarget === 'src/exact.ts',
    sourceRevision: '0123abcdef',
    replayOf: null,
    idempotencyKey: 'idem-1',
    observedAt: ISO(now),
  };
  const auth = signRecord(receipt, { keyRing: w.keyRing, keyId: 'k1', boundFields: EFFECT_RECEIPT_BOUND_FIELDS });
  const verified = verifyRecord(receipt, auth, { keyRing: w.keyRing, boundFields: EFFECT_RECEIPT_BOUND_FIELDS });
  const nonce = `nonce-${receipt.receiptId}`;
  const fresh = w.replay.check({
    scope: { issuerId: 'k1', sessionId: 'sess-1', runId: RUN_ID, workspaceId: 'ws-main' },
    nonce,
    sequence: 1,
    timestamp: ISO(now),
  });
  const final = {
    ...receipt,
    authentication: authenticationBlock({ keyId: 'k1', verifiedAt: ISO(now) }),
    replayDefense: {
      nonce,
      sequence: 1,
      freshnessWindowSeconds: w.policy.replayLimits().freshnessWindowSeconds,
      freshAt: ISO(now),
    },
  };
  assertValid('effect-receipt-v1', final);
  const appended = w.receiptStore.append(final);
  return { receipt: final, auth, verified, fresh, appended };
}

// ─────────────────────────────────────────────────────────── the live path

test('GATE 2: authorize -> effect -> authenticated receipt -> verified chain', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });

    const gateCall = w.gate.evaluate(request(), {
      contract: contract(), turnId: 'turn-1', capabilityId: w.capabilityId,
    });
    assert.equal(gateCall.allowed, true, gateCall.message);
    assert.equal(gateCall.enforcementHealth, 'strong');
    assert.equal(gateCall.detail.policyDigest, w.policy.digest);

    const { receipt, verified, fresh, appended } = recordEffect(w);
    assert.equal(verified.allowed, true, 'receipt must authenticate');
    assert.equal(fresh.allowed, true, 'receipt must pass replay defense');
    assert.equal(receipt.authentication.perMessage, true);
    assert.equal(receipt.authentication.verificationMethod, 'capability-signature');
    assert.ok(Number.isInteger(appended.sequence));

    const chain = w.receiptStore.verifyChain();
    assert.equal(chain.ok, true, chain.reason);
    assert.equal(chain.corruptAt, null);

    const readBack = w.receiptStore.get(receipt.receiptId);
    assert.equal(readBack.receiptId, receipt.receiptId);
    assert.equal(w.receiptStore.list({ runId: RUN_ID }).length, 1);
  } finally {
    cleanup();
  }
});

test('GATE 2: gate health reports strong only when every capability is actually present', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    assert.deepEqual(w.gate.health(), {
      policy: 'strong', capability: 'strong', authority: 'strong', overall: 'strong',
    });
    const noCaps = new PreEffectGate({ policy: w.policy, capabilityStore: null, authorityLedger: w.authorityLedger });
    assert.equal(noCaps.health().overall, 'unsupported');
    assert.equal(noCaps.health().capability, 'unsupported');
  } finally {
    cleanup();
  }
});

// ────────────────────────────────────────────── the negative half (the point)

test('GATE 2: an EXPIRED capability is refused through the gate', () => {
  // Regression: the gate used to pass `now` as epoch millis while
  // CapabilityStore compares it against an ISO `expiresAt` with `>=`. A
  // number-vs-string comparison is always false, so expiry silently never
  // fired. This test exists to keep that seam honest.
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root, expiresAt: ISO(NOW - 1000) });
    const d = w.gate.evaluate(request(), { contract: contract(), turnId: 'turn-1', capabilityId: w.capabilityId });
    assert.equal(d.allowed, false);
    assert.equal(d.code, 'ARC_CAPABILITY_EXPIRED');
  } finally {
    cleanup();
  }
});

test('GATE 2: a capability bound to a different target does not authorize this effect', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const d = w.gate.evaluate(request({ target: 'src/other.ts', latitude: 'BOUNDED' }), {
      contract: contract(), turnId: 'turn-1', capabilityId: w.capabilityId,
    });
    assert.equal(d.allowed, false);
    assert.equal(d.code, 'ARC_BINDING_MISMATCH');
  } finally {
    cleanup();
  }
});

test('GATE 2: a single-use capability cannot authorize a second effect', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const first = w.gate.evaluate(request(), { contract: contract(), turnId: 'turn-1', capabilityId: w.capabilityId });
    assert.equal(first.allowed, true);
    w.capabilityStore.consume(w.capabilityId, { now: ISO() });
    const second = w.gate.evaluate(request(), { contract: contract(), turnId: 'turn-1', capabilityId: w.capabilityId });
    assert.equal(second.allowed, false);
    assert.equal(second.code, 'ARC_CAPABILITY_EXHAUSTED');
  } finally {
    cleanup();
  }
});

test('GATE 2: a revoked capability is refused, and revocation is not retroactively forgotten', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    w.capabilityStore.revoke(w.capabilityId, 'operator revoked');
    const d = w.gate.evaluate(request(), { contract: contract(), turnId: 'turn-1', capabilityId: w.capabilityId });
    assert.equal(d.allowed, false);
    assert.equal(d.code, 'ARC_CAPABILITY_REVOKED');
  } finally {
    cleanup();
  }
});

test('GATE 2: a replayed receipt is refused even though its signature is genuine', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const scope = { issuerId: 'k1', sessionId: 'sess-1', runId: RUN_ID, workspaceId: 'ws-main' };
    const first = w.replay.check({ scope, nonce: 'n-1', sequence: 1, timestamp: ISO() });
    assert.equal(first.allowed, true);
    const replayed = w.replay.check({ scope, nonce: 'n-1', sequence: 2, timestamp: ISO() });
    assert.equal(replayed.allowed, false);
    assert.equal(replayed.code, 'ARC_REPLAY_NONCE_SEEN');
  } finally {
    cleanup();
  }
});

test('GATE 2: a tampered receipt chain is detected by independent verification', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    recordEffect(w);
    assert.equal(w.receiptStore.verifyChain().ok, true);

    // Tamper with the persisted line the way an attacker with disk access would.
    const jsonl = path.join(root, 'receipts.jsonl');
    const lines = readFileSync(jsonl, 'utf8').trimEnd().split('\n');
    const entry = JSON.parse(lines[0]);
    entry.record.observed.target = 'src/somewhere-else.ts';
    lines[0] = JSON.stringify(entry);
    writeFileSync(jsonl, `${lines.join('\n')}\n`, 'utf8');

    const chain = w.receiptStore.verifyChain();
    assert.equal(chain.ok, false);
    assert.equal(chain.corruptAt, entry.sequence);
  } finally {
    cleanup();
  }
});

test('GATE 2: a model self-report never becomes a receipt — no signature, no entry', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    // A model claiming it wrote the file: correct shape, zero authentication.
    const selfReport = {
      schemaVersion: 1,
      kind: 'legion-effect-receipt',
      receiptId: mintId('effectReceipt'),
      requestId: REQUEST_ID,
      runId: RUN_ID,
      contractId: 'EC-44',
      taskId: 'T-1',
      requested: { effectClass: 'FILE_WRITE', target: 'src/exact.ts', operation: 'write' },
      authorized: { effectClass: 'FILE_WRITE', target: 'src/exact.ts', operation: 'write' },
      observed: { effectClass: 'FILE_WRITE', target: 'src/exact.ts', operation: 'write' },
      match: true,
      sourceRevision: '0123abcdef',
      replayOf: null,
      idempotencyKey: 'idem-model',
      observedAt: ISO(),
    };
    const v = verifyRecord(selfReport, null, { keyRing: w.keyRing, boundFields: EFFECT_RECEIPT_BOUND_FIELDS });
    assert.equal(v.allowed, false);
    assert.equal(v.code, 'ARC_AUTH_UNAUTHENTICATED');
    assert.equal(w.receiptStore.list({ runId: RUN_ID }).length, 0, 'nothing unauthenticated reached the store');
  } finally {
    cleanup();
  }
});

test('GATE 2: a legacy Forge signature_or_mac cannot stand in for authentication', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const v = verifyRecord(
      { runId: RUN_ID, taskId: 'T-1' },
      { signature_or_mac: `hook:${'a'.repeat(64)}` },
      { keyRing: w.keyRing, boundFields: ['runId', 'taskId'] },
    );
    assert.equal(v.allowed, false);
    assert.equal(v.code, 'ARC_AUTH_LEGACY_DIGEST');
  } finally {
    cleanup();
  }
});

test('GATE 2: with the gate down, the mutation is refused and nothing is written', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const down = new PreEffectGate({ policy: w.policy, capabilityStore: null, authorityLedger: w.authorityLedger });
    const d = down.evaluate(request(), { contract: contract(), turnId: 'turn-1', capabilityId: w.capabilityId });
    assert.equal(d.allowed, false);
    assert.equal(d.code, 'ARC_GATE_UNAVAILABLE');
    assert.equal(d.failClosed, true);
    assert.equal(w.receiptStore.list().length, 0);
  } finally {
    cleanup();
  }
});
