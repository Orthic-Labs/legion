import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { applyArchitectureEvent, createArchitectureState } from '../architecture-state.mjs';
import { ArchitectureEventStore } from '../architecture-event-store.mjs';
import { digestValue } from '../canonical.mjs';
import { createExecutionCheckpoint, verifyExecutionCheckpoint } from '../continuity.mjs';
import { generateTestKeyRing } from '../keys.mjs';
import { ReceiptStore } from '../receipt-store.mjs';

const NOW = '2026-08-15T00:00:00.000Z';
const state = (id) => createArchitectureState({ objective_lineage_id: `s11:${id}`, budget_ref: `s11:${id}`, acceptance_ledger: { schema: 'acceptance-ledger.v1', ledger_version: 1, intent_epoch: 1, acceptance_fingerprint: digestValue(id), frozen_at: NOW, items: [] } });
const observation = (producer, consumer, value) => Object.freeze({ producer, consumer, value: Object.freeze(value) });

function fullReplay() {
  const root = mkdtempSync(join(tmpdir(), 's11-m7-replay-'));
  try {
    const initial = state('AE-STATE-TRANSITIONS-REPLAY-002');
    const store = new ArchitectureEventStore({ receiptStore: new ReceiptStore({ root }), keyRing: generateTestKeyRing(['k1']), keyId: 'k1', clock: () => NOW });
    let accepted = store.replay({ objective_lineage_id: initial.task.objective_lineage_id, initial_state: initial });
    const append = (event_type, payload) => {
      accepted = store.accept({ objective_lineage_id: initial.task.objective_lineage_id, intent_epoch: accepted.state.intent.intent_epoch, execution_id: 's11:m7', repository_id: 's11:repository', actor_role: 'alchemist', phase: 'execute', event_type, payload, acceptance_ids: [], decision_ids: [], finding_ids: [], input_fingerprint: null, output_refs: [], checkpoint_ref: null, cost_delta: {}, retry_class: 'none', terminal_reason: null, privacy_class: 'metadata' }, { expected_state_fingerprint: accepted.state_fingerprint });
      if (!accepted.accepted) throw new Error(`event rejected: ${event_type}`);
    };
    append('ARCHITECTURE_TRANSITIONED', { from: 'UNROUTED', to: 'TAILORED' });
    append('EFFECT_RECORDED', { id: 'effect-1', effect_id: 'write-1', effect_class: 'write', status: 'completed' });
    append('EFFECT_DENIED', { id: 'denial-1', effect_id: 'write-2', code: 'ARC_PATH_FORBIDDEN', reason: 'policy' });
    append('CANCEL_RECORDED', { id: 'cancel-1', intent_epoch: 2, reason: 'PAUSE', unverified_candidate_ids: ['candidate-1'] });
    append('RECOVERY_RECORDED', { id: 'recovery-1', checkpoint_digest: digestValue({ checkpoint: 1 }), reason: 'resume denied', candidate_ids: ['candidate-1'] });
    append('SUPERSESSION_RECORDED', { id: 'supersession-1', supersedes_id: 'candidate-1', replacement_id: 'candidate-2', reason: 'new evidence' });
    const restored = store.replay({ objective_lineage_id: initial.task.objective_lineage_id, initial_state: initial });
    return observation('ArchitectureEventStore.accept/replay', 'authenticated trajectory receipt store', { acceptedFingerprint: accepted.state_fingerprint, replayFingerprint: restored.state_fingerprint, authorityMinted: restored.authority_minted, eventCount: restored.event_count, effects: restored.state.execution.effects.length, denials: restored.state.execution.denials.length, cancellations: restored.state.execution.cancellations.length, recoveries: restored.state.execution.recovery_refs.length, supersessions: restored.state.execution.supersession_refs.length });
  } finally { rmSync(root, { recursive: true, force: true }); }
}

function revisionTripwire() {
  let current = state('AE-CONVERGENCE-006');
  for (const revision of [1, 2]) current = applyArchitectureEvent(current, { event_type: 'ARCHITECTURE_REVISION_RECORDED', payload: { id: `revision-${revision}`, decision_id: 'D-2', revision, live_candidate_ids: ['a', 'b'], terminal_disposition: null } });
  current = applyArchitectureEvent(current, { event_type: 'ARCHITECTURE_REVISION_RECORDED', payload: { id: 'revision-3', decision_id: 'D-2', revision: 3, live_candidate_ids: ['a', 'b'], terminal_disposition: 'DECIDE_WITH_DEBT' } });
  let fourthRejected = false;
  try { applyArchitectureEvent(current, { event_type: 'ARCHITECTURE_REVISION_RECORDED', payload: { id: 'revision-4', decision_id: 'D-2', revision: 4, live_candidate_ids: ['a', 'b'], terminal_disposition: null } }); } catch { fourthRejected = true; }
  return observation('applyArchitectureEvent', 'architecture convergence state', { revisions: current.convergence.revisions.length, terminalDisposition: current.convergence.terminal_disposition, fourthRejected });
}

function epochMismatch() {
  const initial = state('AE-TRAJECTORY-RESUME-002');
  const checkpoint = createExecutionCheckpoint({ state: initial, contract_fingerprint: digestValue({ contract: 1 }), repository_state: digestValue({ repository: 1 }), producer_versions: { arcane: 'm7' }, event_sequence: 0, event_digest: digestValue({ event: 0 }), preserved_candidate_ids: ['candidate-1'], created_at: NOW });
  const result = verifyExecutionCheckpoint(checkpoint, { objective_lineage_id: initial.task.objective_lineage_id, intent_epoch: 2, continuation_epoch: 1, repository_state: checkpoint.repository_state, contract_fingerprint: checkpoint.acceptance.contract_fingerprint, event_sequence: 0, event_digest: checkpoint.event_digest, producer_versions: checkpoint.producer_versions });
  return observation('verifyExecutionCheckpoint', 'continuity admission', result);
}

const BINDINGS = new Map([
  ['AE-STATE-TRANSITIONS-REPLAY-002', fullReplay],
  ['AE-CONVERGENCE-006', revisionTripwire],
  ['AE-TRAJECTORY-RESUME-002', epochMismatch],
]);

export function m7BindingIds() { return Object.freeze([...BINDINGS.keys()].sort()); }
export function executeM7Binding(id) { return BINDINGS.get(id)?.() ?? null; }
