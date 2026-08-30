// Authenticated accepted-event trajectory over Arcane's existing ReceiptStore.

import { ArcaneError, decision } from '../../contracts/arcane/errors.mjs';
import { assertId, mintId } from '../../contracts/arcane/ids.mjs';
import { signRecord, verifyRecord } from '../../guard/compat/audit/receipt-auth.mjs';
import { applyArchitectureEvent, assertArchitectureState, withStateFingerprint } from './architecture-state.mjs';
import { architectureEventFingerprint, architectureStateFingerprint } from './architecture-fingerprints.mjs';

export const ARCHITECTURE_EVENT_BOUND_FIELDS = Object.freeze([
  'schema', 'kind', 'event_id', 'sequence', 'occurred_at', 'objective_lineage_id',
  'intent_epoch', 'continuation_epoch', 'execution_id', 'repository_id', 'actor_role',
  'phase', 'event_type', 'payload', 'acceptance_status', 'acceptance_ids',
  'decision_ids', 'finding_ids', 'input_fingerprint',
  'output_refs', 'checkpoint_ref', 'cost_delta', 'retry_class', 'terminal_reason',
  'privacy_class', 'predecessor_digest', 'resulting_state_fingerprint',
]);
export const ARCHITECTURE_ACCEPTED_EVENT_BOUND_FIELDS = ARCHITECTURE_EVENT_BOUND_FIELDS;
export const ARCHITECTURE_EVENT_TYPES = Object.freeze([
  'ROUTE_CLASSIFIED', 'ARCHITECTURE_TRANSITIONED', 'DECISION_RECORDED',
  'DECISION_FROZEN', 'INVALIDATION_RECORDED', 'INTENT_EPOCH_ADVANCED',
  'CONTINUATION_EPOCH_ADVANCED', 'EXECUTION_EPISODE_TRANSITIONED',
  'BUDGET_SNAPSHOT_RECORDED', 'FINGERPRINTS_RECORDED', 'FINDING_UPSERTED',
  'RETRY_RECORDED', 'ACCEPTANCE_RESULT_RECORDED', 'DELIVERY_DEFICIT_UPSERTED',
  'DOWNSTREAM_ACKNOWLEDGEMENT_RECORDED', 'OWNERSHIP_DISPOSITION_RECORDED',
  'MIGRATION_CUTOVER_RECORDED', 'ARTIFACT_ENVELOPE_RECORDED',
  'EVIDENCE_LIFECYCLE_RECORDED', 'EFFECT_RECORDED', 'EFFECT_DENIED',
  'CANCEL_RECORDED', 'TERMINAL_STATE_RECORDED', 'RECOVERY_RECORDED',
  'SUPERSESSION_RECORDED', 'ARCHITECTURE_REVISION_RECORDED',
  'CONVERGENCE_REVISION_RECORDED',
]);

const PROPOSAL_FIELDS = new Set(['objective_lineage_id', 'intent_epoch', 'execution_id', 'repository_id', 'actor_role', 'phase', 'event_type', 'payload', 'acceptance_ids', 'decision_ids', 'finding_ids', 'input_fingerprint', 'output_refs', 'checkpoint_ref', 'cost_delta', 'retry_class', 'terminal_reason', 'privacy_class']);
const RESERVED_FIELDS = new Set(['schema', 'kind', 'event_id', 'sequence', 'occurred_at', 'continuation_epoch', 'acceptance_status', 'authentication', 'predecessor_digest', 'resulting_state_fingerprint']);
const ACTOR_ROLES = new Set(['legion', 'sage', 'alchemist', 'oracle', 'covenant', 'worker', 'host']);
const PHASES = new Set(['route', 'decide', 'dispatch', 'execute', 'verify', 'integrate', 'close']);
const RETRY_CLASSES = new Set(['none', 'mechanical', 'changed_input', 'changed_method', 'external']);
const PRIVACY_CLASSES = new Set(['content_free', 'metadata', 'sensitive', 'restricted']);
const EVENT_SCHEMA = 'execution-trajectory-event.v1';
const EVENT_KIND = 'architecture-trajectory-event';
const MAC_DOMAIN = 'arcane-architecture-event-v1';
const ACCEPTED_EVENT_FIELDS = new Set([...ARCHITECTURE_EVENT_BOUND_FIELDS, 'authentication']);

const fail = (code, message, detail = {}) => { throw new ArcaneError(code, message, detail); };
const clone = (value) => structuredClone(value);
const nonEmpty = (value, field) => { if (typeof value !== 'string' || !value) fail('ARC_SCHEMA_INVALID', `${field} is required`); };
const rejection = (error) => error instanceof ArcaneError ? decision({ allowed: false, code: error.code, message: error.message, detail: error.detail }) : (() => { throw error; })();

function acceptedEvents(receiptStore, objectiveLineageId) {
  return receiptStore.list().filter((event) => event?.schema === EVENT_SCHEMA && event?.kind === EVENT_KIND && event.objective_lineage_id === objectiveLineageId);
}
function verifyReceiptStore(receiptStore) {
  const chain = receiptStore.verifyChain();
  if (!chain.ok) fail('ARC_STORE_CORRUPT', 'ReceiptStore chain verification failed', chain);
}
function validateProposal(proposal) {
  if (!proposal || typeof proposal !== 'object' || Array.isArray(proposal)) fail('ARC_SCHEMA_INVALID', 'event proposal must be an object');
  for (const key of Object.keys(proposal)) {
    if (RESERVED_FIELDS.has(key)) fail('ARC_SCHEMA_INVALID', `proposal may not set accepted field: ${key}`);
    if (!PROPOSAL_FIELDS.has(key)) fail('ARC_SCHEMA_INVALID', `event proposal contains unknown field: ${key}`);
  }
  for (const field of ['objective_lineage_id', 'execution_id', 'repository_id', 'event_type']) nonEmpty(proposal[field], field);
  if (!Number.isInteger(proposal.intent_epoch) || proposal.intent_epoch < 1) fail('ARC_SCHEMA_INVALID', 'intent_epoch must be a positive integer');
  if (!ARCHITECTURE_EVENT_TYPES.includes(proposal.event_type) || !ACTOR_ROLES.has(proposal.actor_role) || !PHASES.has(proposal.phase) || !RETRY_CLASSES.has(proposal.retry_class) || !PRIVACY_CLASSES.has(proposal.privacy_class)) fail('ARC_SCHEMA_INVALID', 'event proposal contains an illegal closed value');
  if (!proposal.payload || typeof proposal.payload !== 'object' || Array.isArray(proposal.payload)) fail('ARC_SCHEMA_INVALID', 'payload must be an object');
  for (const field of ['acceptance_ids', 'decision_ids', 'finding_ids', 'output_refs']) if (!Array.isArray(proposal[field])) fail('ARC_SCHEMA_INVALID', `${field} must be an array`);
  if (!proposal.cost_delta || typeof proposal.cost_delta !== 'object' || Array.isArray(proposal.cost_delta)) fail('ARC_SCHEMA_INVALID', 'cost_delta must be an object');
}
function replayEvents(events, initialState, keyRing) {
  assertArchitectureState(initialState);
  let state = initialState;
  let predecessor = null;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (Object.keys(event).some((key) => !ACCEPTED_EVENT_FIELDS.has(key)) || [...ACCEPTED_EVENT_FIELDS].some((key) => !Object.hasOwn(event, key))) fail('ARC_SCHEMA_INVALID', 'stored event violates closed accepted-event fields');
    const verified = verifyRecord(event, event.authentication, { keyRing, boundFields: ARCHITECTURE_EVENT_BOUND_FIELDS, macDomain: MAC_DOMAIN });
    if (!verified.allowed) fail(verified.code, 'accepted event authentication failed', verified.detail);
    if (event.schema !== EVENT_SCHEMA || event.kind !== EVENT_KIND || event.acceptance_status !== 'ACCEPTED' || !ARCHITECTURE_EVENT_TYPES.includes(event.event_type)) fail('ARC_SCHEMA_INVALID', 'stored event violates accepted-event schema');
    if (event.sequence !== index + 1 || event.predecessor_digest !== predecessor || event.objective_lineage_id !== state.task.objective_lineage_id || event.intent_epoch !== state.intent.intent_epoch || event.continuation_epoch !== state.intent.continuation_epoch) fail('ARC_STORE_CORRUPT', 'stored trajectory lineage, sequence, predecessor, or epoch mismatch', { sequence: event.sequence });
    state = applyArchitectureEvent(state, { event_type: event.event_type, payload: event.payload });
    state = withStateFingerprint({ ...state, execution: { ...state.execution, trajectory: { ...state.execution.trajectory, last_sequence: event.sequence } } });
    predecessor = architectureEventFingerprint(event);
    state = withStateFingerprint({ ...state, execution: { ...state.execution, trajectory: { ...state.execution.trajectory, last_event_digest: predecessor, replay_state_fingerprint: state.state_fingerprint } } });
    if (event.resulting_state_fingerprint !== state.state_fingerprint) fail('ARC_STORE_CORRUPT', 'stored resulting state fingerprint mismatch', { sequence: event.sequence });
  }
  return { state, predecessor };
}

export class ArchitectureEventStore {
  #receiptStore; #keyRing; #keyId; #clock; #initialStates = new Map();
  constructor({ receiptStore, keyRing, keyId, clock = () => new Date().toISOString() } = {}) {
    if (!receiptStore || typeof receiptStore.append !== 'function' || typeof receiptStore.list !== 'function' || typeof receiptStore.verifyChain !== 'function') fail('ARC_STORE_CORRUPT', 'ArchitectureEventStore requires ReceiptStore injection');
    if (!keyRing || typeof keyRing.get !== 'function') fail('ARC_AUTH_KEY_UNAVAILABLE', 'ArchitectureEventStore requires key custody');
    nonEmpty(keyId, 'keyId'); this.#receiptStore = receiptStore; this.#keyRing = keyRing; this.#keyId = keyId; this.#clock = clock;
  }
  events({ objective_lineage_id }) {
    nonEmpty(objective_lineage_id, 'objective_lineage_id'); verifyReceiptStore(this.#receiptStore);
    return Object.freeze(acceptedEvents(this.#receiptStore, objective_lineage_id).map((event) => Object.freeze(clone(event))));
  }
  replay({ objective_lineage_id, initial_state }) {
    nonEmpty(objective_lineage_id, 'objective_lineage_id'); assertArchitectureState(initial_state);
    if (initial_state.task.objective_lineage_id !== objective_lineage_id) fail('ARC_BINDING_MISMATCH', 'initial_state lineage differs from replay request');
    verifyReceiptStore(this.#receiptStore);
    const events = acceptedEvents(this.#receiptStore, objective_lineage_id);
    const { state, predecessor } = replayEvents(events, initial_state, this.#keyRing);
    this.#initialStates.set(objective_lineage_id, clone(initial_state));
    return Object.freeze({ schema: 'architecture-replay-result.v1', state, state_fingerprint: state.state_fingerprint, last_sequence: events.length, last_event_digest: predecessor, event_count: events.length, authority_minted: false });
  }
  accept(proposal, { expected_state_fingerprint } = {}) {
    try {
      validateProposal(proposal);
      const initial_state = this.#initialStates.get(proposal.objective_lineage_id);
      if (!initial_state) fail('ARC_BINDING_MISMATCH', 'accept requires prior replay for objective lineage');
      assertArchitectureState(initial_state);
      if (initial_state.task.objective_lineage_id !== proposal.objective_lineage_id) fail('ARC_BINDING_MISMATCH', 'initial_state lineage differs from proposal');
      verifyReceiptStore(this.#receiptStore);
      const events = acceptedEvents(this.#receiptStore, proposal.objective_lineage_id);
      const { state, predecessor } = replayEvents(events, initial_state, this.#keyRing);
      if (expected_state_fingerprint !== state.state_fingerprint) fail('ARC_BINDING_MISMATCH', 'expected state fingerprint is stale', { expected: state.state_fingerprint, actual: expected_state_fingerprint ?? null });
      if (proposal.intent_epoch !== state.intent.intent_epoch) fail('ARC_BINDING_MISMATCH', 'proposal intent epoch differs from accepted projection');
      let next = applyArchitectureEvent(state, { event_type: proposal.event_type, payload: proposal.payload });
      const sequence = events.length + 1;
      next = withStateFingerprint({ ...next, execution: { ...next.execution, trajectory: { ...next.execution.trajectory, last_sequence: sequence } } });
      const event = { schema: EVENT_SCHEMA, kind: EVENT_KIND, event_id: mintId('artifact'), sequence, occurred_at: this.#clock(), objective_lineage_id: proposal.objective_lineage_id, intent_epoch: proposal.intent_epoch, continuation_epoch: state.intent.continuation_epoch, execution_id: proposal.execution_id, repository_id: proposal.repository_id, actor_role: proposal.actor_role, phase: proposal.phase, event_type: proposal.event_type, payload: clone(proposal.payload), acceptance_status: 'ACCEPTED', acceptance_ids: clone(proposal.acceptance_ids), decision_ids: clone(proposal.decision_ids), finding_ids: clone(proposal.finding_ids), input_fingerprint: proposal.input_fingerprint ?? null, output_refs: clone(proposal.output_refs), checkpoint_ref: proposal.checkpoint_ref ?? null, cost_delta: clone(proposal.cost_delta), retry_class: proposal.retry_class, terminal_reason: proposal.terminal_reason ?? null, privacy_class: proposal.privacy_class, predecessor_digest: predecessor, resulting_state_fingerprint: architectureStateFingerprint(next), };
      assertId('artifact', event.event_id, 'event_id');
      event.authentication = signRecord(event, { keyRing: this.#keyRing, keyId: this.#keyId, boundFields: ARCHITECTURE_EVENT_BOUND_FIELDS, macDomain: MAC_DOMAIN });
      this.#receiptStore.append(event);
      const lastEventDigest = architectureEventFingerprint(event);
      const acceptedState = withStateFingerprint({ ...next, execution: { ...next.execution, trajectory: { ...next.execution.trajectory, last_event_digest: lastEventDigest, replay_state_fingerprint: next.state_fingerprint } } });
      if (acceptedState.state_fingerprint !== event.resulting_state_fingerprint) fail('ARC_STORE_CORRUPT', 'accepted state fingerprint mismatch');
      return Object.freeze({ accepted: true, event: Object.freeze(event), state: acceptedState, state_fingerprint: acceptedState.state_fingerprint, last_sequence: event.sequence, last_event_digest: lastEventDigest });
    } catch (error) { return Object.freeze({ accepted: false, event: null, decision: rejection(error) }); }
  }
}
