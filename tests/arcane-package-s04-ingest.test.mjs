// S04 — HostIngestor: trusted host activity flows into Arcane without model
// re-entry and without confusing success with proof (WP4 §"Objective").
//
// This is the module that closes S00 finding 5: `lib/core.js:493-494,536-539`
// let `authority='host'` plus a non-empty `receipt` string mint unconditional
// tool-trust with zero structural validation. Here, authority='host' is
// necessary but never sufficient — the receipt must validate structurally
// AND verify under S03's real `verifyRecord`, or ingestion refuses with
// ARC_HOST_EVENT_UNTRUSTED.
//
// Real modules throughout, no test doubles: real PolicyEngine over the
// shipped bundle, real ReceiptStore on a temp dir, real ReplayGuard, real
// HMAC signing via S03's receipt-auth.mjs, real DependencyLedger — a lane
// proven only against stubs is not a lane, per tests/s07-gate2-integration's
// established pattern.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { HostIngestor } from '../src/lib/verification/arcane/ingest.mjs';
import { HOST_EVENT_BOUND_FIELDS } from '../src/lib/host/arcane/host-event.mjs';
import { loadPolicy, PolicyEngine, DEFAULT_POLICY_PATH } from '../src/lib/guard/compat/policy/policy.mjs';
import { ReceiptStore, CapabilityStore } from '../src/lib/guard/compat/audit/receipt-store.mjs';
import { ReplayGuard } from '../src/lib/guard/compat/effects/replay.mjs';
import { generateTestKeyRing } from '../src/lib/guard/compat/host/keys.mjs';
import { signRecord } from '../src/lib/guard/compat/audit/receipt-auth.mjs';
import { digest } from '../src/lib/contracts/arcane/canonical.mjs';
import { DependencyLedger } from '../src/lib/verification/arcane/invalidation.mjs';

const NOW = Date.parse('2026-08-08T12:00:00.000Z');
const ISO = (ms = NOW) => new Date(ms).toISOString();

const RUN_ID = 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV';
const REQUEST_ID = 'req_01ARZ3NDEKTSV4RRFFQ69G5FAV';
const EVENT_ID = 'hev_01ARZ3NDEKTSV4RRFFQ69G5FAV';

function tempRoot() {
  const root = mkdtempSync(path.join(tmpdir(), 'arcane-s04-'));
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

function baseEvent(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'arcane-host-event',
    eventId: EVENT_ID,
    eventType: 'post-effect',
    time: ISO(),
    adapter: { name: 'claude-code', version: '1.2.3' },
    client: { name: 'claude-code', version: '1.2.3' },
    host: { platform: 'darwin', version: '24.0' },
    runId: RUN_ID,
    taskId: 'T-1',
    sessionId: 'sess-1',
    requestId: REQUEST_ID,
    contractId: 'EC-44',
    workspace: 'ws-main',
    subject: null,
    actor: { issuerId: 'host-process:1', processIdentity: 'pid:123' },
    operation: { toolId: 'Write', operationId: 'write', argumentDigest: digest('args') },
    sourceRevision: '0123abcdef',
    effect: { effectClass: 'FILE_WRITE', target: 'src/exact.ts', operation: 'write' },
    result: { outcome: 'success', exitCode: 0, terminal: true, observedDigest: digest('content') },
    pathMeta: null,
    processMeta: null,
    networkMeta: null,
    priorCorrelation: {
      requestId: REQUEST_ID,
      capabilityId: 'cap_1',
      priorReceiptId: null,
      requestedEffect: { effectClass: 'FILE_WRITE', target: 'src/exact.ts', operation: 'write' },
      authorizedEffect: { effectClass: 'FILE_WRITE', target: 'src/exact.ts', operation: 'write' },
    },
    checkCorrelation: null,
    hostEnforcement: { capabilities: ['preToolUse-intercept', 'postToolUse-observe'], knownBypasses: [] },
    replayNonce: 'nonce-1',
    replaySequence: 1,
    idempotencyKey: 'idem-1',
    ...overrides,
  };
}

/** Full live wiring: policy + receipts + replay + keys. */
function wire({ root, dependencyLedger = null }) {
  const policy = new PolicyEngine(loadPolicy({ path: DEFAULT_POLICY_PATH }));
  const receiptStore = new ReceiptStore({ root });
  const capabilityStore = new CapabilityStore();
  const keyRing = generateTestKeyRing(['k1']);
  const replayGuard = new ReplayGuard({
    freshnessWindowSeconds: policy.replayLimits().freshnessWindowSeconds,
    maxSkewSeconds: policy.replayLimits().maxSkewSeconds,
    clock: () => NOW,
  });
  const ingestor = new HostIngestor({
    receiptStore, capabilityStore, replayGuard, keyRing, policy, clock: () => NOW, dependencyLedger,
  });
  return { policy, receiptStore, capabilityStore, keyRing, replayGuard, ingestor };
}

function hostAuthority(w, event) {
  const receipt = signRecord(event, { keyRing: w.keyRing, keyId: 'k1', boundFields: HOST_EVENT_BOUND_FIELDS });
  return { assertedBy: 'host', receipt, connectionTrust: null };
}
function connectionTrustAuthority(issuerIdentity, verifiedAt) {
  return { assertedBy: 'host', receipt: null, connectionTrust: { issuerIdentity, verifiedAt } };
}
function modelAuthority() {
  return { assertedBy: 'model', receipt: null, connectionTrust: null };
}

// ───────────────────────────────────────────────────────── mandatory test 1

test('S04: a model self-report never becomes a receipt (mandatory test 1)', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const result = w.ingestor.ingest(baseEvent(), { authorityAssertion: modelAuthority() });
    assert.equal(result.accepted, false);
    assert.equal(result.receipt, null);
    assert.equal(result.decision.code, 'ARC_MODEL_SELF_REPORT');
    assert.equal(w.receiptStore.list().length, 0);
  } finally {
    cleanup();
  }
});

// ───────────────────────────────────────────────────────── mandatory test 2

test('S04: S00 finding 5 — the legacy attack. authority=host plus a non-empty receipt string is not authentication', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const event = baseEvent();

    // (a) exactly S00 finding 5's shape: authority='host', receipt is any non-empty string.
    const bareStringAttack = w.ingestor.ingest(event, {
      authorityAssertion: { assertedBy: 'host', receipt: `hook:${'a'.repeat(64)}`, connectionTrust: null },
    });
    assert.equal(bareStringAttack.accepted, false);
    assert.equal(bareStringAttack.decision.code, 'ARC_HOST_EVENT_UNTRUSTED');

    // (b) structurally receipt-shaped but forged — fails verifyRecord, not just the string check.
    const genuineAuth = signRecord(event, { keyRing: w.keyRing, keyId: 'k1', boundFields: HOST_EVENT_BOUND_FIELDS });
    const forged = { ...genuineAuth, mac: genuineAuth.mac.slice(0, -1) + (genuineAuth.mac.endsWith('0') ? '1' : '0') };
    const forgedAttack = w.ingestor.ingest(event, {
      authorityAssertion: { assertedBy: 'host', receipt: forged, connectionTrust: null },
    });
    assert.equal(forgedAttack.accepted, false);
    assert.equal(forgedAttack.decision.code, 'ARC_HOST_EVENT_UNTRUSTED');

    assert.equal(w.receiptStore.list().length, 0, 'neither attack produced a receipt');

    // (c) control: the identical event with a genuine, verifying receipt succeeds.
    const genuine = w.ingestor.ingest(event, {
      authorityAssertion: { assertedBy: 'host', receipt: genuineAuth, connectionTrust: null },
    });
    assert.equal(genuine.accepted, true, genuine.decision.message);
    assert.equal(w.receiptStore.list().length, 1);
  } finally {
    cleanup();
  }
});

// ───────────────────────────────────────────────────────── mandatory test 4

test('S04: duplicate delivery of the same idempotencyKey returns the original receipt and appends nothing new', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const event = baseEvent({ idempotencyKey: 'dup-1' });
    const auth = hostAuthority(w, event);

    const first = w.ingestor.ingest(event, { authorityAssertion: auth });
    assert.equal(first.accepted, true, first.decision.message);
    assert.equal(w.receiptStore.list().length, 1);

    const second = w.ingestor.ingest(event, { authorityAssertion: auth });
    assert.equal(second.accepted, true);
    assert.equal(second.receipt.receiptId, first.receipt.receiptId);
    assert.equal(w.receiptStore.list().length, 1, 'nothing new appended on duplicate delivery');
  } finally {
    cleanup();
  }
});

// ───────────────────────────────────────────────────────── mandatory test 5

test('S04: a post-effect event with no correlated pre-effect request is refused (ARC_INGEST_CORRELATION_MISSING)', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const event = baseEvent({
      priorCorrelation: { requestId: null, capabilityId: null, priorReceiptId: null, requestedEffect: null, authorizedEffect: null },
    });
    const result = w.ingestor.ingest(event, { authorityAssertion: hostAuthority(w, event) });
    assert.equal(result.accepted, false);
    assert.equal(result.decision.code, 'ARC_INGEST_CORRELATION_MISSING');
    assert.equal(w.receiptStore.list().length, 0);
  } finally {
    cleanup();
  }
});

// ───────────────────────────────────────────────────────── mandatory test 8

test('S04: a trusted host check event can satisfy a criterion — the identical payload from a model cannot', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const event = baseEvent({
      effect: { effectClass: 'COMMAND_EXEC', target: 'npm test', operation: 'exec' },
      checkCorrelation: { declaredCheckId: 'AC-1', method: 'npm-test-exit-code' },
      priorCorrelation: {
        requestId: REQUEST_ID,
        capabilityId: 'cap_1',
        priorReceiptId: null,
        requestedEffect: { effectClass: 'COMMAND_EXEC', target: 'npm test', operation: 'exec' },
        authorizedEffect: { effectClass: 'COMMAND_EXEC', target: 'npm test', operation: 'exec' },
      },
      result: { outcome: 'success', exitCode: 0, terminal: true, observedDigest: null },
    });

    // Host-observed, host-authenticated: satisfies the criterion without the
    // model retyping any output.
    const trusted = w.ingestor.ingest(event, { authorityAssertion: hostAuthority(w, event) });
    assert.equal(trusted.accepted, true, trusted.decision.message);
    assert.equal(trusted.observationClass, 'deterministic-check-candidate');
    assert.equal(trusted.receipt.authentication.perMessage, true);
    assert.equal(w.receiptStore.list().length, 1);

    // The IDENTICAL payload, this time asserted by the model — never a receipt.
    const modelAttempt = w.ingestor.ingest(event, { authorityAssertion: modelAuthority() });
    assert.equal(modelAttempt.accepted, false);
    assert.equal(modelAttempt.decision.code, 'ARC_MODEL_SELF_REPORT');
    assert.equal(w.receiptStore.list().length, 1, 'the model-supplied duplicate produced nothing new');
  } finally {
    cleanup();
  }
});

// ───────────────────────────────────────────────────────── mandatory test 9

test('S04: failed and successful effects both correlate exactly to their pre-effect request', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const successEvent = baseEvent({ idempotencyKey: 'succ-1', replayNonce: 'n-succ', replaySequence: 1 });
    const failEvent = baseEvent({
      idempotencyKey: 'fail-1',
      replayNonce: 'n-fail',
      replaySequence: 2,
      eventType: 'post-effect-failure',
      result: { outcome: 'failure', exitCode: 1, terminal: true, observedDigest: null },
    });

    const successResult = w.ingestor.ingest(successEvent, { authorityAssertion: hostAuthority(w, successEvent) });
    const failResult = w.ingestor.ingest(failEvent, { authorityAssertion: hostAuthority(w, failEvent) });

    assert.equal(successResult.accepted, true, successResult.decision.message);
    assert.equal(failResult.accepted, true, failResult.decision.message);
    assert.equal(successResult.observationClass, 'mutation-observation');
    assert.equal(failResult.observationClass, 'failure');
    assert.equal(successResult.receipt.requestId, REQUEST_ID);
    assert.equal(failResult.receipt.requestId, REQUEST_ID);
    assert.equal(successResult.receipt.result, 'applied');
    assert.equal(failResult.receipt.result, 'failed');
    assert.equal(w.receiptStore.list().length, 2);
  } finally {
    cleanup();
  }
});

// ──────────────────────────────────────────────────────── mandatory test 10

test('S04: an observed mutation invalidates affected evidence (DependencyLedger integration, WP4 action 10)', () => {
  const { root, cleanup } = tempRoot();
  try {
    const ledger = new DependencyLedger({ clock: () => ISO() });
    const originalDigest = digest('original-content');
    ledger.register('ev_1', [{ dimension: 'source-digest', ref: 'src/exact.ts', digest: originalDigest }]);
    ledger.link('ev_1', { criterionId: 'AC-1' });
    assert.equal(ledger.proofEligibility('AC-1').status, 'proven');

    const w = wire({ root, dependencyLedger: ledger });
    const newDigest = digest('mutated-content');
    const event = baseEvent({ result: { outcome: 'success', exitCode: 0, terminal: true, observedDigest: newDigest } });

    const result = w.ingestor.ingest(event, { authorityAssertion: hostAuthority(w, event) });
    assert.equal(result.accepted, true, result.decision.message);
    assert.equal(result.observationClass, 'mutation-observation');

    assert.equal(ledger.isStale('ev_1'), true);
    assert.equal(ledger.proofEligibility('AC-1').status, 'unproven');
  } finally {
    cleanup();
  }
});

// ──────────────────────────────────────────────────────── mandatory test 11

test('S04: honest downgrade — connection-level trust records host-connection-trust, never a strength it lacks', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const event = baseEvent({ idempotencyKey: 'conn-1' });
    const result = w.ingestor.ingest(event, {
      authorityAssertion: connectionTrustAuthority('host-process:mcp-1', ISO()),
    });
    assert.equal(result.accepted, true, result.decision.message);
    assert.equal(result.receipt.authentication.verificationMethod, 'host-connection-trust');
    assert.equal(result.receipt.authentication.perMessage, false);
    assert.equal(result.receipt.authentication.issuerIdentity, 'host-process:mcp-1');
  } finally {
    cleanup();
  }
});

// ───────────────────────────────────────────────────── supporting coverage

test('S04: authority=host with neither a receipt nor connection-trust proof is untrusted', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const event = baseEvent({ idempotencyKey: 'none-1' });
    const result = w.ingestor.ingest(event, { authorityAssertion: { assertedBy: 'host', receipt: null, connectionTrust: null } });
    assert.equal(result.accepted, false);
    assert.equal(result.decision.code, 'ARC_HOST_EVENT_UNTRUSTED');
    assert.equal(w.receiptStore.list().length, 0);
  } finally {
    cleanup();
  }
});

test('S04: pre-effect and lifecycle events are accepted and classified but never become a receipt', () => {
  const { root, cleanup } = tempRoot();
  try {
    const w = wire({ root });
    const event = baseEvent({ eventType: 'pre-effect', idempotencyKey: 'pre-1', priorCorrelation: null });
    const result = w.ingestor.ingest(event, { authorityAssertion: hostAuthority(w, event) });
    assert.equal(result.accepted, true, result.decision.message);
    assert.equal(result.receipt, null);
    assert.equal(w.receiptStore.list().length, 0);
  } finally {
    cleanup();
  }
});
