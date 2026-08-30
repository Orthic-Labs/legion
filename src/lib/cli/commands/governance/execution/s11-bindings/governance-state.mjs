import { classifyEffect, routeArchitecture } from '../../../../../verification/arcane/architecture-router.mjs';
import { applyArchitectureEvent, createArchitectureState, projectArchitectureEvents, validateArchitectureState } from '../../../../../verification/arcane/architecture-state.mjs';
import { ContinuityController, cancelProcessGroup, createExecutionCheckpoint, verifyExecutionCheckpoint } from '../../../../../host/arcane/continuity.mjs';
import { digestValue } from '../../../../../contracts/arcane/canonical.mjs';
import { ReplayGuard } from '../../../../../guard/compat/effects/replay.mjs';

const NOW = '2026-08-14T00:00:00.000Z';

function stateFor(caseId) {
  return createArchitectureState({
    objective_lineage_id: `s11:${caseId}`,
    budget_ref: `s11:${caseId}`,
    acceptance_ledger: {
      schema: 'acceptance-ledger.v1', ledger_version: 1, intent_epoch: 1,
      acceptance_fingerprint: digestValue({ caseId }), frozen_at: NOW, items: [],
    },
  });
}

function observed(caseId, ingress, consumer, state = stateFor(caseId)) {
  const validation = validateArchitectureState(state);
  if (!validation.valid) throw new Error(validation.issues[0]);
  return Object.freeze({ case_id: caseId, ingress: Object.freeze(ingress), consumer: Object.freeze(consumer), state_fingerprint: state.state_fingerprint });
}

function rejected(run) {
  try { run(); return false; } catch { return true; }
}

function route(caseId, input) {
  const result = routeArchitecture({ ...input, effect: {} });
  return observed(caseId, { module: 'architecture-router', input }, result);
}

function checkpointCurrent(state, checkpoint, overrides = {}) {
  return {
    objective_lineage_id: state.task.objective_lineage_id,
    intent_epoch: state.intent.intent_epoch,
    continuation_epoch: state.intent.continuation_epoch,
    repository_state: checkpoint.repository_state,
    contract_fingerprint: checkpoint.acceptance.contract_fingerprint,
    event_sequence: checkpoint.event_sequence,
    event_digest: checkpoint.event_digest,
    producer_versions: checkpoint.producer_versions,
    ...overrides,
  };
}

function trajectoryCheckpoint(caseId) {
  const state = stateFor(caseId);
  return [state, createExecutionCheckpoint({
    state,
    contract_fingerprint: digestValue({ caseId, contract: 'current' }),
    repository_state: digestValue({ caseId, repository: 'current' }),
    producer_versions: { arcane: 's11' }, event_sequence: 4,
    event_digest: digestValue({ caseId, event: 4 }), completed_effect_ids: ['effect-1'], created_at: NOW,
  })];
}

function bindTrajectoryResume(caseId) {
  const [state, checkpoint] = trajectoryCheckpoint(caseId);
  const verification = verifyExecutionCheckpoint(checkpoint, checkpointCurrent(state, checkpoint));
  const controller = new ContinuityController({ intent_epoch: state.intent.intent_epoch, continuation_epoch: state.intent.continuation_epoch, completed_effect_ids: verification.completed_effect_ids });
  const duplicate_denied = rejected(() => controller.claimEffect(controller.bind('resume'), 'effect-1'));
  return observed(caseId, { module: 'continuity.createExecutionCheckpoint', checkpoint_digest: checkpoint.checkpoint_digest }, { verification, duplicate_denied }, state);
}

function bindTrajectoryEpochMismatch(caseId) {
  const [state, checkpoint] = trajectoryCheckpoint(caseId);
  const verification = verifyExecutionCheckpoint(checkpoint, checkpointCurrent(state, checkpoint, { intent_epoch: state.intent.intent_epoch + 1 }));
  return observed(caseId, { module: 'continuity.verifyExecutionCheckpoint', checkpoint_digest: checkpoint.checkpoint_digest }, verification, state);
}

function bindTrajectoryRepositoryDrift(caseId) {
  const [state, checkpoint] = trajectoryCheckpoint(caseId);
  const verification = verifyExecutionCheckpoint(checkpoint, checkpointCurrent(state, checkpoint, { repository_state: digestValue({ caseId, repository: 'drifted' }) }));
  return observed(caseId, { module: 'continuity.verifyExecutionCheckpoint', checkpoint_digest: checkpoint.checkpoint_digest }, verification, state);
}

function bindInvalidation(caseId, decisionIds) {
  let state = stateFor(caseId);
  for (const id of decisionIds) state = applyArchitectureEvent(state, { event_type: 'DECISION_RECORDED', payload: { id, status: 'FROZEN' } });
  state = applyArchitectureEvent(state, { event_type: 'INVALIDATION_RECORDED', payload: { scope: 'PATCH', cause: `FAILED_FALSIFICATION:${decisionIds.at(-1)}`, root_evidence: null } });
  return observed(caseId, { module: 'architecture-state.applyArchitectureEvent', event_type: 'INVALIDATION_RECORDED' }, { decisions: state.decision.items, invalidation: state.convergence.invalidation }, state);
}

function bindStateTransitionRejection(caseId) {
  const initial = stateFor(caseId);
  const rejected_transition = rejected(() => applyArchitectureEvent(initial, { event_type: 'ARCHITECTURE_TRANSITIONED', payload: { from: 'UNROUTED', to: 'VERIFIED' } }));
  return observed(caseId, { module: 'architecture-state.applyArchitectureEvent', event_type: 'ARCHITECTURE_TRANSITIONED' }, { rejected_transition, prior_fingerprint: initial.state_fingerprint }, initial);
}

function bindStateReplay(caseId) {
  const initial = stateFor(caseId);
  const events = [{ event_type: 'ARCHITECTURE_TRANSITIONED', payload: { from: 'UNROUTED', to: 'TAILORED' } }];
  const first = projectArchitectureEvents(events, { initial_state: initial });
  const replay = projectArchitectureEvents(events, { initial_state: initial });
  return observed(caseId, { module: 'architecture-state.projectArchitectureEvents', event_count: events.length }, { first_fingerprint: first.state_fingerprint, replay_fingerprint: replay.state_fingerprint, authority_minted: false }, replay);
}

function bindEffectCancellation(caseId) {
  let remaining = [101, 102];
  return cancelProcessGroup({
    group_id: `s11:${caseId}`,
    terminate: async () => { remaining = []; },
    alive: async () => remaining,
  }).then((consumer) => observed(caseId, { module: 'continuity.cancelProcessGroup', group_id: consumer.group_id }, consumer));
}

const BINDINGS = Object.freeze({
  'AE-ROUTING-001': () => route('AE-ROUTING-001', { significance: {} }),
  'AE-ROUTING-002': () => route('AE-ROUTING-002', { significance: {} }),
  'AE-ROUTING-003': () => route('AE-ROUTING-003', { significance: { durable_contract: true } }),
  'AE-ROUTING-004': () => route('AE-ROUTING-004', { optimize_axis: 'startup', significance: {} }),
  'AE-ROUTING-005': () => observed('AE-ROUTING-005', { module: 'architecture-router.routeArchitecture', prior_objective: 'sufficient', requested_objective: 'best_shape' }, { self_upgrade_rejected: rejected(() => routeArchitecture({ objective: 'best_shape', prior_route: { objective: 'sufficient' }, significance: {} })) }),
  'AE-CANDIDATE-QUALITY-003': () => route('AE-CANDIDATE-QUALITY-003', { objective: 'best_shape', significance: { responsibility_boundary: true } }),
  'AE-CONVERGENCE-002': () => {
    const guard = new ReplayGuard({ clock: () => Date.parse(NOW) });
    guard.check({ scope: 's11-convergence', nonce: 'same', sequence: 1, timestamp: NOW });
    return observed('AE-CONVERGENCE-002', { module: 'replay.ReplayGuard', scope: 's11-convergence' }, guard.check({ scope: 's11-convergence', nonce: 'same', sequence: 2, timestamp: NOW }));
  },
  'AE-CONVERGENCE-004': () => bindInvalidation('AE-CONVERGENCE-004', ['D-3']),
  'AE-CONVERGENCE-005': () => bindInvalidation('AE-CONVERGENCE-005', ['D-1', 'D-2', 'D-3']),
  'AE-EFFECT-CLASSIFICATION-001': () => observed('AE-EFFECT-CLASSIFICATION-001', { module: 'architecture-router.classifyEffect', input: {} }, classifyEffect({})),
  'AE-EFFECT-CLASSIFICATION-002': () => bindEffectCancellation('AE-EFFECT-CLASSIFICATION-002'),
  'AE-TRAJECTORY-RESUME-001': () => bindTrajectoryResume('AE-TRAJECTORY-RESUME-001'),
  'AE-TRAJECTORY-RESUME-002': () => bindTrajectoryEpochMismatch('AE-TRAJECTORY-RESUME-002'),
  'AE-TRAJECTORY-RESUME-003': () => bindTrajectoryRepositoryDrift('AE-TRAJECTORY-RESUME-003'),
  'AE-STATE-TRANSITIONS-REPLAY-001': () => bindStateTransitionRejection('AE-STATE-TRANSITIONS-REPLAY-001'),
  'AE-STATE-TRANSITIONS-REPLAY-002': () => bindStateReplay('AE-STATE-TRANSITIONS-REPLAY-002'),
});

export function governanceStateBindingIds() { return Object.freeze(Object.keys(BINDINGS).sort()); }

// Returns null only where no production ingress/consumer pair exists.  Some
// production consumers are asynchronous; callers must await promise results.
export function executeGovernanceStateBinding(caseId) {
  const binding = BINDINGS[caseId];
  return binding ? binding() : null;
}
