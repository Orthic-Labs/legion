import assert from 'node:assert/strict';
import test from 'node:test';

import { applyArchitectureEvent, createArchitectureState, replayArchitectureEvents } from '../lib/architecture-state.mjs';
import { createExecutionCheckpoint, verifyExecutionCheckpoint } from '../lib/continuity.mjs';
import { digestValue } from '../lib/canonical.mjs';
import { ArchitectureEventStore } from '../lib/architecture-event-store.mjs';
import { generateTestKeyRing } from '../lib/keys.mjs';
import { ReceiptStore } from '../lib/receipt-store.mjs';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const state = () => createArchitectureState({
  objective_lineage_id: 'm7:state-replay', budget_ref: 'm7:budget',
  acceptance_ledger: { schema:'acceptance-ledger.v1', ledger_version:1, intent_epoch:1, acceptance_fingerprint:digestValue({ m7:true }), frozen_at:'2026-08-15T00:00:00.000Z', items:[] },
});

test('M7 replay projects effect, denial, cancellation, recovery & supersession without authority', () => {
  const events = [
    { event_type:'EFFECT_RECORDED', payload:{ id:'effect-1', effect_id:'write-1', effect_class:'write', status:'completed' } },
    { event_type:'EFFECT_DENIED', payload:{ id:'denial-1', effect_id:'write-2', code:'ARC_PATH_FORBIDDEN', reason:'policy' } },
    { event_type:'CANCEL_RECORDED', payload:{ id:'cancel-1', intent_epoch:2, reason:'PAUSE', unverified_candidate_ids:['candidate-2','candidate-1'] } },
    { event_type:'RECOVERY_RECORDED', payload:{ id:'recovery-1', checkpoint_digest:digestValue({ checkpoint:1 }), reason:'resume denied', candidate_ids:['candidate-1'] } },
    { event_type:'SUPERSESSION_RECORDED', payload:{ id:'supersession-1', supersedes_id:'candidate-1', replacement_id:'candidate-3', reason:'new evidence' } },
  ];
  const first = replayArchitectureEvents(events, { initial_state:state() });
  const replay = replayArchitectureEvents(events, { initial_state:state() });
  assert.equal(first.state_fingerprint, replay.state_fingerprint);
  assert.equal(replay.authority_minted, false);
  assert.equal(replay.state.execution.effects.length, 1);
  assert.equal(replay.state.execution.denials.length, 1);
  assert.equal(replay.state.execution.cancellations.length, 1);
  assert.equal(replay.state.execution.recovery_refs.length, 1);
  assert.equal(replay.state.execution.supersession_refs.length, 1);
  assert.equal(replay.state.intent.intent_epoch, 2);
});

test('M7 third revision is terminal & a fourth comparison is rejected', () => {
  let current = state();
  for (const revision of [1, 2]) current = applyArchitectureEvent(current, { event_type:'ARCHITECTURE_REVISION_RECORDED', payload:{ id:`revision-${revision}`, decision_id:'D-2', revision, live_candidate_ids:['a','b'], terminal_disposition:null } });
  current = applyArchitectureEvent(current, { event_type:'ARCHITECTURE_REVISION_RECORDED', payload:{ id:'revision-3', decision_id:'D-2', revision:3, live_candidate_ids:['a','b'], terminal_disposition:'DECIDE_WITH_DEBT' } });
  assert.equal(current.convergence.terminal_disposition, 'DECIDE_WITH_DEBT');
  assert.throws(() => applyArchitectureEvent(current, { event_type:'ARCHITECTURE_REVISION_RECORDED', payload:{ id:'revision-4', decision_id:'D-2', revision:4, live_candidate_ids:['a','b'], terminal_disposition:null } }), /tripwire/);
});

test('M7 accepted design invalidations count revisions automatically', () => {
  let current = applyArchitectureEvent(state(), { event_type:'DECISION_RECORDED', payload:{ id:'D-2' } });
  current = applyArchitectureEvent(current, { event_type:'INVALIDATION_RECORDED', payload:{ scope:'DESIGN', cause:'new evidence', root_evidence:null, decision_ids:['D-2'] } });
  current = applyArchitectureEvent(current, { event_type:'INVALIDATION_RECORDED', payload:{ scope:'DESIGN', cause:'failed check', root_evidence:null, decision_ids:['D-2'] } });
  assert.deepEqual(current.convergence.revisions.map(({ decision_id, revision }) => ({ decision_id, revision })), [{ decision_id:'D-2', revision:1 }, { decision_id:'D-2', revision:2 }]);
  assert.throws(() => applyArchitectureEvent(current, { event_type:'INVALIDATION_RECORDED', payload:{ scope:'DESIGN', cause:'third pass without disposition', root_evidence:null, decision_ids:['D-2'] } }), /third revision requires/);
  current = applyArchitectureEvent(current, { event_type:'INVALIDATION_RECORDED', payload:{ scope:'DESIGN', cause:'terminal pass', root_evidence:null, decision_ids:['D-2'], terminal_disposition:'SPIKE' } });
  assert.equal(current.convergence.terminal_disposition, 'SPIKE');
  assert.throws(() => applyArchitectureEvent(current, { event_type:'INVALIDATION_RECORDED', payload:{ scope:'DESIGN', cause:'fourth pass', root_evidence:null, decision_ids:['D-2'] } }), /tripwire/);
});

test('M7 epoch mismatch keeps checkpoint candidates unverified & cannot authorize resume', () => {
  const initial = state();
  const checkpoint = createExecutionCheckpoint({ state:initial, contract_fingerprint:digestValue({ contract:1 }), repository_state:digestValue({ repository:1 }), producer_versions:{ arcane:'m7' }, event_sequence:0, event_digest:digestValue({ event:0 }), preserved_candidate_ids:['candidate-1'], created_at:'2026-08-15T00:00:00.000Z' });
  const result = verifyExecutionCheckpoint(checkpoint, { objective_lineage_id:initial.task.objective_lineage_id, intent_epoch:2, continuation_epoch:1, repository_state:checkpoint.repository_state, contract_fingerprint:checkpoint.acceptance.contract_fingerprint, event_sequence:0, event_digest:checkpoint.event_digest, producer_versions:checkpoint.producer_versions });
  assert.equal(result.valid, false);
  assert.ok(result.mismatches.includes('intent_epoch'));
  assert.deepEqual(result.unverified_candidates, ['candidate-1']);
  assert.equal(result.resume_authorized, false);
});

test('M7 authenticated event-store replay reproduces full state without authority', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-m7-replay-'));
  try {
    const keyRing = generateTestKeyRing(['k1']);
    const eventStore = new ArchitectureEventStore({ receiptStore:new ReceiptStore({ root }), keyRing, keyId:'k1', clock:() => '2026-08-15T00:00:00.000Z' });
    const initial = state();
    let replay = eventStore.replay({ objective_lineage_id:initial.task.objective_lineage_id, initial_state:initial });
    const accept = (event_type, payload) => {
      const accepted = eventStore.accept({ objective_lineage_id:initial.task.objective_lineage_id, intent_epoch:replay.state.intent.intent_epoch, execution_id:'m7:execution', repository_id:'m7:repository', actor_role:'alchemist', phase:'execute', event_type, payload, acceptance_ids:[], decision_ids:[], finding_ids:[], input_fingerprint:null, output_refs:[], checkpoint_ref:null, cost_delta:{}, retry_class:'none', terminal_reason:null, privacy_class:'metadata' }, { expected_state_fingerprint:replay.state_fingerprint });
      assert.equal(accepted.accepted, true, event_type);
      replay = accepted;
    };
    accept('ARCHITECTURE_TRANSITIONED', { from:'UNROUTED', to:'TAILORED' });
    accept('EFFECT_RECORDED', { id:'effect-1', effect_id:'write-1', effect_class:'write', status:'completed' });
    accept('EFFECT_DENIED', { id:'denial-1', effect_id:'write-2', code:'ARC_PATH_FORBIDDEN', reason:'policy' });
    accept('CANCEL_RECORDED', { id:'cancel-1', intent_epoch:2, reason:'PAUSE', unverified_candidate_ids:['candidate-1'] });
    accept('RECOVERY_RECORDED', { id:'recovery-1', checkpoint_digest:digestValue({ checkpoint:1 }), reason:'resume denied', candidate_ids:['candidate-1'] });
    accept('SUPERSESSION_RECORDED', { id:'supersession-1', supersedes_id:'candidate-1', replacement_id:'candidate-2', reason:'new evidence' });
    accept('ARCHITECTURE_REVISION_RECORDED', { id:'revision-1', decision_id:'D-2', revision:1, live_candidate_ids:['a','b'], terminal_disposition:null });
    accept('ARCHITECTURE_REVISION_RECORDED', { id:'revision-2', decision_id:'D-2', revision:2, live_candidate_ids:['a','b'], terminal_disposition:null });
    accept('ARCHITECTURE_REVISION_RECORDED', { id:'revision-3', decision_id:'D-2', revision:3, live_candidate_ids:['a','b'], terminal_disposition:'DECIDE_WITH_DEBT' });
    const restored = eventStore.replay({ objective_lineage_id:initial.task.objective_lineage_id, initial_state:initial });
    assert.equal(restored.state_fingerprint, replay.state_fingerprint);
    assert.equal(restored.authority_minted, false);
    assert.equal(restored.event_count, 9);
    assert.equal(restored.state.execution.denials.length, 1);
    assert.equal(restored.state.execution.cancellations.length, 1);
    assert.equal(restored.state.convergence.terminal_disposition, 'DECIDE_WITH_DEBT');
  } finally { rmSync(root, { recursive:true, force:true }); }
});
