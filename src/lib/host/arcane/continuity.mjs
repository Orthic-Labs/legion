import { digestValue } from '../../contracts/arcane/canonical.mjs';
import { createArchitectureState } from '../../verification/arcane/architecture-state.mjs';
import { routeArchitecture } from '../../verification/arcane/architecture-router.mjs';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const clone = (value) => structuredClone(value);
const fail = (message) => { throw new Error(message); };

const acceptanceBinding = (ledger, contractFingerprint) => {
  if (!DIGEST.test(contractFingerprint ?? '')) fail('current item or stage contract fingerprint is required');
  if (ledger?.schema === 'acceptance-ledger.v2') return {
    contract_fingerprint: contractFingerprint,
    acceptance_manifest_fingerprint: ledger.acceptance_manifest_fingerprint,
    schedule_fingerprint: ledger.schedule_fingerprint,
  };
  if (ledger?.schema === 'acceptance-ledger.v1') return {
    contract_fingerprint: contractFingerprint,
    acceptance_manifest_fingerprint: ledger.acceptance_fingerprint,
    schedule_fingerprint: null,
  };
  fail('unsupported acceptance ledger');
};

export function createExecutionCheckpoint({ state, contract_fingerprint, repository_state, producer_versions, event_sequence, event_digest, completed_effect_ids = [], preserved_candidate_ids = [], created_at }) {
  if (!state?.task?.objective_lineage_id || !state?.intent) fail('canonical architecture state is required');
  if (!DIGEST.test(repository_state ?? '') || !DIGEST.test(event_digest ?? '')) fail('repository and event digests are required');
  if (!Number.isInteger(event_sequence) || event_sequence < 0) fail('event sequence must be non-negative');
  const checkpoint = {
    schema: 'execution-checkpoint.v1',
    objective_lineage_id: state.task.objective_lineage_id,
    intent_epoch: state.intent.intent_epoch,
    continuation_epoch: state.intent.continuation_epoch,
    repository_state,
    acceptance: acceptanceBinding(state.acceptance_ledger, contract_fingerprint),
    producer_versions: Object.fromEntries(Object.entries(producer_versions ?? {}).sort(([a], [b]) => a.localeCompare(b))),
    event_sequence,
    event_digest,
    completed_effect_ids: [...new Set(completed_effect_ids)].sort(),
    // Candidates survive a stop as data only. They never become an authority,
    // a continuation, or a completed effect during rehydration.
    preserved_candidate_ids: [...new Set(preserved_candidate_ids)].sort(),
    created_at,
  };
  if (!checkpoint.created_at) fail('checkpoint timestamp is required');
  return Object.freeze({ ...checkpoint, checkpoint_digest: digestValue(checkpoint) });
}

export function verifyExecutionCheckpoint(checkpoint, current) {
  const { checkpoint_digest, ...body } = checkpoint ?? {};
  const preservedCandidates = Object.freeze([...(checkpoint?.preserved_candidate_ids ?? [])].sort());
  if (!DIGEST.test(checkpoint_digest ?? '') || digestValue(body) !== checkpoint_digest) return Object.freeze({ valid: false, reason: 'checkpoint_digest_mismatch', preserved_artifacts: true, unverified_candidates: preservedCandidates, resume_authorized: false });
  const mismatches = [];
  if (checkpoint.objective_lineage_id !== current.objective_lineage_id) mismatches.push('objective_lineage');
  if (checkpoint.intent_epoch !== current.intent_epoch) mismatches.push('intent_epoch');
  if (checkpoint.continuation_epoch !== current.continuation_epoch) mismatches.push('continuation_epoch');
  if (checkpoint.repository_state !== current.repository_state) mismatches.push('repository_state');
  if (checkpoint.acceptance.contract_fingerprint !== current.contract_fingerprint) mismatches.push('acceptance_contract');
  if (checkpoint.event_sequence !== current.event_sequence || checkpoint.event_digest !== current.event_digest) mismatches.push('event_continuity');
  if (JSON.stringify(checkpoint.producer_versions) !== JSON.stringify(Object.fromEntries(Object.entries(current.producer_versions ?? {}).sort(([a], [b]) => a.localeCompare(b))))) mismatches.push('producer_versions');
  const scheduleChanged = checkpoint.acceptance.schedule_fingerprint !== (current.schedule_fingerprint ?? null);
  if (mismatches.length) return Object.freeze({
    valid: false,
    reason: 'binding_mismatch',
    mismatches: Object.freeze(mismatches),
    invalidation_scope: 'dependency_cone',
    invalidated_acceptance_ids: Object.freeze([...(current.invalidated_acceptance_ids ?? [])]),
    preserved_artifacts: true,
    unverified_candidates: preservedCandidates,
    resume_authorized: false,
  });
  return Object.freeze({
    valid: true,
    schedule_changed: scheduleChanged,
    execution_replan_required: scheduleChanged,
    invalidated_acceptance_ids: Object.freeze([]),
    completed_effect_ids: Object.freeze([...checkpoint.completed_effect_ids]),
    preserved_candidate_ids: preservedCandidates,
    resume_authorized: true,
  });
}

export function rehydrateUntrustedData(envelope) {
  if (envelope?.schema !== 'rehydration-envelope.v1' || envelope.trust !== 'UNTRUSTED_DATA') fail('rehydration envelope must be typed UNTRUSTED_DATA');
  if (!DIGEST.test(envelope.content_digest ?? '') || digestValue(envelope.payload) !== envelope.content_digest) fail('rehydration content digest mismatch');
  return Object.freeze({
    data: clone(envelope.payload),
    authority_granted: false,
    instruction_status: 'DATA_ONLY',
    preference_write_allowed: false,
    effect_downgrade_allowed: false,
  });
}

export class ContinuityController {
  #intentEpoch;
  #continuationEpoch;
  #cancelled = false;
  #completedEffects;

  constructor({ intent_epoch, continuation_epoch, completed_effect_ids = [] }) {
    if (!Number.isInteger(intent_epoch) || !Number.isInteger(continuation_epoch)) fail('epochs are required');
    this.#intentEpoch = intent_epoch;
    this.#continuationEpoch = continuation_epoch;
    this.#completedEffects = new Set(completed_effect_ids);
  }

  bind(work_id) {
    if (!work_id) fail('work id is required');
    return Object.freeze({ work_id, intent_epoch: this.#intentEpoch, continuation_epoch: this.#continuationEpoch });
  }

  cancel({ next_intent_epoch }) {
    if (!Number.isInteger(next_intent_epoch) || next_intent_epoch <= this.#intentEpoch) fail('cancellation must advance intent epoch');
    this.#intentEpoch = next_intent_epoch;
    this.#cancelled = true;
    return Object.freeze({ cancelled: true, intent_epoch: this.#intentEpoch });
  }

  resume({ intent_epoch, continuation_epoch }) {
    if (!Number.isInteger(intent_epoch) || !Number.isInteger(continuation_epoch) || intent_epoch < this.#intentEpoch || continuation_epoch <= this.#continuationEpoch) fail('resume requires current intent and newer continuation epoch');
    this.#intentEpoch = intent_epoch;
    this.#continuationEpoch = continuation_epoch;
    this.#cancelled = false;
  }

  assertCurrent(token) {
    if (this.#cancelled || token?.intent_epoch !== this.#intentEpoch || token?.continuation_epoch !== this.#continuationEpoch) fail('stale or cancelled continuation');
    return true;
  }

  claimEffect(token, effect_id) {
    this.assertCurrent(token);
    if (!effect_id) fail('effect id is required');
    if (this.#completedEffects.has(effect_id)) fail('duplicate effect denied');
    this.#completedEffects.add(effect_id);
    return Object.freeze({ effect_id, accepted: true });
  }

  completedEffectIds() { return Object.freeze([...this.#completedEffects].sort()); }
}

export async function cancelProcessGroup({ group_id, terminate, alive, max_passes = 2 }) {
  if (!group_id || typeof terminate !== 'function' || typeof alive !== 'function') fail('process-group controller is required');
  for (let pass = 1; pass <= max_passes; pass += 1) {
    await terminate(group_id);
    const survivors = await alive(group_id);
    if (!Array.isArray(survivors)) fail('alive probe must return process ids');
    if (survivors.length === 0) return Object.freeze({ group_id, process_group_quiescent: true, passes: pass });
  }
  fail('process group failed to quiesce');
}

/** Durable workflow state used by registered host ingress. */
export class WorkflowContinuityStore {
  constructor({ root, clock = () => new Date().toISOString() } = {}) {
    if (!root) fail('workflow continuity root is required');
    this.root = root;
    this.clock = clock;
  }

  _path(runId) { return join(this.root, `${encodeURIComponent(runId)}.json`); }
  _read(runId) { return existsSync(this._path(runId)) ? JSON.parse(readFileSync(this._path(runId), 'utf8')) : null; }
  _write(state) {
    mkdirSync(this.root, { recursive: true });
    const path = this._path(state.runId);
    const tmp = join(this.root, `.state-${process.pid}-${Date.now()}.tmp`);
    const body = { ...state, stateDigest: digestValue(Object.fromEntries(Object.entries(state).filter(([key]) => key !== 'stateDigest'))) };
    writeFileSync(tmp, JSON.stringify(body), { flag: 'wx' });
    renameSync(tmp, path);
    return Object.freeze(body);
  }

  checkpoint({ runId, fingerprint, nodes = [], completedEffects = [], completedOutputs = {} }) {
    if (!runId || !DIGEST.test(fingerprint ?? '')) fail('run id & fingerprint are required');
    const prior = this._read(runId);
    const nodeMap = new Map((prior?.nodes ?? []).map((node) => [node.id, node]));
    for (const node of nodes) nodeMap.set(node.id, { id: node.id, dependencies: [...(node.dependencies ?? [])], state: node.state ?? 'PENDING' });
    const state = {
      schemaVersion: 1, kind: 'legion-workflow-continuity', runId, fingerprint,
      continuationEpoch: prior?.continuationEpoch ?? 1,
      nodes: [...nodeMap.values()],
      completedEffects: [...new Set([...(prior?.completedEffects ?? []), ...completedEffects])].sort(),
      completedOutputs: { ...(prior?.completedOutputs ?? {}), ...completedOutputs },
      pause: prior?.pause ?? null,
      updatedAt: this.clock(),
    };
    return this._write(state);
  }

  resume({ runId, fingerprint }) {
    const state = this._read(runId);
    if (!state || state.fingerprint !== fingerprint) fail('workflow continuity fingerprint mismatch');
    const unfinished = state.nodes.filter((node) => !['SUCCEEDED', 'SKIPPED'].includes(node.state));
    return Object.freeze({ runId, continuationEpoch: state.continuationEpoch, unfinished: clone(unfinished), completedEffects: Object.freeze([...state.completedEffects]), completedOutputs: Object.freeze(clone(state.completedOutputs)) });
  }

  pause({ runId, decisionId, phase, choices, contextFingerprint, continuationToken }) {
    const state = this._read(runId);
    if (!state || !decisionId || !Array.isArray(choices) || choices.length < 1 || !DIGEST.test(contextFingerprint ?? '')) fail('named pause decision is invalid');
    return this._write({ ...state, pause: { decisionId, phase, choices: [...choices], contextFingerprint, continuationToken, chosen: null, responseDigest: null, pausedAt: this.clock() }, updatedAt: this.clock() });
  }

  applyDirection({ runId, decisionId, choice, response }) {
    const state = this._read(runId);
    if (!state?.pause || state.pause.decisionId !== decisionId || !state.pause.choices.includes(choice)) fail('operator direction does not bind current pause');
    return this._write({ ...state, continuationEpoch: state.continuationEpoch + 1, pause: { ...state.pause, chosen: choice, responseDigest: digestValue(response), resumedAt: this.clock() }, updatedAt: this.clock() });
  }

  replan({ runId, failure, replacementNodes }) {
    const state = this._read(runId);
    if (!state || !failure || !Array.isArray(replacementNodes)) fail('failure & replacement nodes are required');
    const completed = state.nodes.filter((node) => node.state === 'SUCCEEDED');
    const completedIds = new Set(completed.map((node) => node.id));
    if (replacementNodes.some((node) => completedIds.has(node.id))) fail('replan may not replace completed nodes');
    return this._write({ ...state, continuationEpoch: state.continuationEpoch + 1, nodes: [...completed, ...replacementNodes.map((node) => ({ ...node, dependencies: [...(node.dependencies ?? [])], state: node.state ?? 'PENDING' }))], replan: { failureDigest: digestValue(failure), preservedOutputDigest: digestValue(state.completedOutputs), at: this.clock() }, updatedAt: this.clock() });
  }
}

// Host hooks are the only production producer for this minimal lifecycle.
// They carry no model-authored architecture state: lineage, route, & phase
// are derived from authenticated host observations before persistence.
// Session identity is stable across ingress. A binding's run id can first be
// materialized during SessionStart, so including it would fork one lifecycle.
const hostLineage = ({ workspace, sessionId }) => `host:${digestValue({ workspace, sessionId: sessionId ?? null })}`;
const hostAcceptance = ({ workspace, sessionId }) => ({
  schema: 'acceptance-ledger.v1', ledger_version: 1, intent_epoch: 1,
  acceptance_fingerprint: digestValue({ workspace, sessionId: sessionId ?? null, producer: 'arcane-host-ingress-v1' }),
  frozen_at: '1970-01-01T00:00:00.000Z', items: [],
});

export function createHostArchitectureState({ workspace, sessionId = null } = {}) {
  if (typeof workspace !== 'string' || !workspace) fail('host workspace is required');
  return createArchitectureState({
    objective_lineage_id: hostLineage({ workspace, sessionId }),
    budget_ref: `host:${digestValue({ workspace, sessionId: sessionId ?? null })}`,
    acceptance_ledger: hostAcceptance({ workspace, sessionId }),
  });
}

export const executionTrajectoryPayload = (hostEvent, payload = {}) => Object.freeze({
  ...payload,
  parent_execution_id: hostEvent?.extensions?.parentExecutionId ?? null,
  work_node_id: hostEvent?.extensions?.workNodeId ?? hostEvent?.eventId ?? null,
  dependency_ids: Object.freeze([...(hostEvent?.extensions?.dependencyIds ?? [])]),
  submission_state: hostEvent?.eventType === 'stop' ? 'TERMINAL' : 'ACCEPTED',
  submitted_at: hostEvent?.time ?? null,
  terminal_state: hostEvent?.eventType === 'stop' ? (payload?.to ?? 'STOPPED') : null,
});

const proposal = ({ state, hostEvent, binding, event_type, payload, phase = 'route' }) => ({
  objective_lineage_id: state.task.objective_lineage_id,
  intent_epoch: state.intent.intent_epoch,
  execution_id: binding?.runId ?? `host:${hostEvent.sessionId ?? 'unbound'}`,
  repository_id: `workspace:${digestValue(hostEvent.workspace)}`,
  actor_role: 'host', phase, event_type, payload: event_type === 'ROUTE_CLASSIFIED' ? executionTrajectoryPayload(hostEvent, payload) : payload,
  acceptance_ids: [], decision_ids: [], finding_ids: [],
  input_fingerprint: digestValue({ eventType: hostEvent.eventType, eventId: hostEvent.eventId, effect: hostEvent.effect }),
  output_refs: [], checkpoint_ref: null, cost_delta: {}, retry_class: 'none', terminal_reason: null, privacy_class: 'metadata',
});

/**
 * Translate host ingress into only legal, replayed architecture transitions.
 * `eventStore` must be an authenticated ArchitectureEventStore sharing Arcane's
 * ReceiptStore. Callers receive projected state; no hook payload can inject it.
 */
export function consumeHostArchitectureLifecycle({ eventStore, hostEvent, binding = null, workspace, stopIntent = 'UNKNOWN' } = {}) {
  if (!eventStore || typeof eventStore.replay !== 'function' || typeof eventStore.accept !== 'function') fail('architecture event store is required');
  const initial_state = createHostArchitectureState({ workspace, sessionId: hostEvent?.sessionId ?? null });
  let replay = eventStore.replay({ objective_lineage_id: initial_state.task.objective_lineage_id, initial_state });
  const accept = (event_type, payload, phase) => {
    const accepted = eventStore.accept(proposal({ state: replay.state, hostEvent, binding, event_type, payload, phase }), { expected_state_fingerprint: replay.state_fingerprint });
    if (!accepted.accepted) fail(`host architecture lifecycle rejected: ${accepted.decision.code}`);
    replay = { state: accepted.state, state_fingerprint: accepted.state_fingerprint };
  };

  if (replay.state.task.architecture_status === 'UNROUTED') {
    const route = routeArchitecture({
      objective: 'sufficient', significance: {},
      effect: hostEvent?.effect ? { category: hostEvent.effect.effectClass } : { semantic_risk: 'ambiguous' },
    });
    accept('ROUTE_CLASSIFIED', route, 'route');
    accept('ARCHITECTURE_TRANSITIONED', { from: 'UNROUTED', to: 'TAILORED' }, 'route');
  }
  if (hostEvent?.eventType === 'pre-effect') {
    if (replay.state.execution.episode_state === 'PENDING') accept('EXECUTION_EPISODE_TRANSITIONED', { from: 'PENDING', to: 'QUEUED' }, 'execute');
    if (replay.state.execution.episode_state === 'QUEUED') accept('EXECUTION_EPISODE_TRANSITIONED', { from: 'QUEUED', to: 'RUNNING' }, 'execute');
  }
  if (hostEvent?.eventType === 'stop') {
    if (['PAUSE', 'REVOKE', 'SCOPE_NARROW'].includes(stopIntent)) accept('INTENT_EPOCH_ADVANCED', { intent_epoch: replay.state.intent.intent_epoch + 1 }, 'close');
    else if (replay.state.execution.episode_state === 'RUNNING') accept('EXECUTION_EPISODE_TRANSITIONED', { from: 'RUNNING', to: 'SUCCEEDED' }, 'close');
  }
  return Object.freeze({ state: replay.state, state_fingerprint: replay.state_fingerprint });
}
