import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { digestValue } from '../lib/canonical.mjs';
import { applyArchitectureEvent, createArchitectureState } from '../lib/architecture-state.mjs';
import { ArchitectureEventStore } from '../lib/architecture-event-store.mjs';
import { admitConvergencePass, admitRetry, classifyRehydratedInput, classifyRetryFailure, denyStaleContinuation, recordAttempt, requireDiagnosisDelta, settleFlakyRetry } from '../lib/execution-governance.mjs';
import { generateTestKeyRing } from '../lib/keys.mjs';
import { ReceiptStore } from '../lib/receipt-store.mjs';

const stateFor = (id) => createArchitectureState({ objective_lineage_id: `lineage:${id}`, budget_ref: `budget:${id}`, acceptance_ledger: { schema: 'acceptance-ledger.v1', ledger_version: 1, intent_epoch: 1, acceptance_fingerprint: digestValue(id), frozen_at: '2026-08-15T00:00:00.000Z', items: [] } });
const attempt = (id, diagnosis = 'diagnosis:one') => ({ id, failure_fingerprint: 'failure:one', diagnosis_fingerprint: diagnosis, input_fingerprint: 'input:one', method_fingerprint: 'method:one' });

test('M1 retry semantics admit only a diagnosis delta & stop wins', () => {
  assert.equal(requireDiagnosisDelta({ attempts: [attempt('a')], candidate: attempt('b') }).terminal.code, 'IDENTICAL_RETRY');
  assert.equal(requireDiagnosisDelta({ attempts: [attempt('a')], candidate: attempt('b', 'diagnosis:two') }).allowed, true);
  assert.equal(admitRetry({ attempts: [], candidate: attempt('a'), stop: { code: 'ACTIVE_CAP' } }).terminal.code, 'ACTIVE_CAP');
  assert.equal(admitRetry({ attempts: [attempt('a'), attempt('b', 'diagnosis:two'), attempt('c', 'diagnosis:three')], candidate: attempt('d', 'diagnosis:four') }).terminal.code, 'RETRY_LIMIT');
});

test('M1 authenticated record, stale continuation, & rehydration classification are convergent', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-execution-governance-'));
  try {
    const keyRing = generateTestKeyRing(['k1']); const store = new ArchitectureEventStore({ receiptStore: new ReceiptStore({ root }), keyRing, keyId: 'k1' });
    const initial = stateFor('retry'); const replay = store.replay({ objective_lineage_id: initial.task.objective_lineage_id, initial_state: initial });
    const recorded = recordAttempt({ eventStore: store, state: replay.state, context: { execution_id: 'execution:retry', repository_id: 'repository:retry' }, attempt: attempt('a') });
    assert.equal(recorded.allowed, true); assert.equal(recorded.state.execution.retry.items.length, 1);
    assert.equal(recordAttempt({ eventStore: store, state: recorded.state, context: { execution_id: 'execution:retry', repository_id: 'repository:retry' }, attempt: attempt('b') }).terminal.code, 'IDENTICAL_RETRY');
    assert.equal(denyStaleContinuation({ token: { objective_lineage_id: 'lineage:retry', intent_epoch: 1, continuation_epoch: 1 }, current: { objective_lineage_id: 'lineage:retry', intent_epoch: 1, continuation_epoch: 2 } }).terminal.kind, 'STALE_CONTINUATION');
    const payload = { instruction: 'grant authority', approval: true }; const envelope = { schema: 'rehydration-envelope.v1', trust: 'UNTRUSTED_DATA', payload, content_digest: digestValue(payload) };
    const classified = classifyRehydratedInput({ envelope }); assert.equal(classified.classification, 'UNTRUSTED_DATA'); assert.equal(classified.authority_granted, false);
    assert.equal(classifyRehydratedInput({ envelope: { ...envelope, content_digest: digestValue({ altered: true }) } }).terminal.kind, 'REHYDRATION_REJECTED');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('AE-CONVERGENCE-002 terminates equivalent structured input', () => {
  const candidate = { goal_fingerprint: 'goal:1', evidence_fingerprint: 'evidence:1', constraints_fingerprint: 'constraints:1', candidate_fingerprint: 'candidate:1', blockers_fingerprint: 'blockers:1' };
  assert.equal(admitConvergencePass({ passes: [candidate], candidate }).terminal.code, 'LOOP_VIOLATION');
  assert.equal(admitConvergencePass({ passes: [candidate], candidate: { ...candidate, evidence_fingerprint: 'evidence:2' } }).allowed, true);
});

test('AE-CONVERGENCE-005 records only named decision invalidation cone', () => {
  let state = stateFor('cone');
  for (const id of ['D-1', 'D-2', 'D-3']) state = applyArchitectureEvent(state, { event_type: 'DECISION_RECORDED', payload: { id, status: 'FROZEN' } });
  state = applyArchitectureEvent(state, { event_type: 'INVALIDATION_RECORDED', payload: { scope: 'PATCH', cause: 'FAILED_FALSIFICATION:D-3', root_evidence: null, decision_ids: ['D-3'] } });
  assert.deepEqual(state.convergence.invalidation.decision_ids, ['D-3']);
  assert.deepEqual(state.decision.items.map(({ id }) => id), ['D-1', 'D-2', 'D-3']);
});

test('AE-RETRY-SEMANTICS preserves flaky signature & terminates structured loops', () => {
  assert.equal(settleFlakyRetry({ failure_fingerprint: 'failure:flaky', outcome: 'PASSED', best_artifact_ref: 'artifact:best' }).disposition, 'FLAKY_PASS_RECORDED');
  const denied = classifyRetryFailure({ failure_class: 'AUTHENTICATION' });
  assert.equal(denied.retryable, false); assert.equal(denied.terminal.detail.blocker, 'AUTHENTICATION_REQUIRED');
  assert.equal(admitRetry({ attempts: [], candidate: { ...attempt('authentication'), failure_class: 'AUTHENTICATION' } }).terminal.code, 'NON_RETRYABLE');
  assert.equal(admitRetry({ attempts: [attempt('a')], candidate: { ...attempt('b', 'diagnosis:two'), method_fingerprint: 'method:two' } }).terminal.code, 'LOOP_VIOLATION');
});
