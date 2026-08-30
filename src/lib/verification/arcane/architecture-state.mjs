import { ArcaneError } from '../../contracts/arcane/errors.mjs';
import { digestValue } from '../../contracts/arcane/canonical.mjs';

export const ARCHITECTURE_STATE_SCHEMA_ID = 'architecture-state.v4';
export const ARCHITECTURE_STATUS = Object.freeze(['UNROUTED','TAILORED','FRAMED','DRIVERS_READY','CANDIDATES_READY','EVALUATED','MINIMIZED','DECIDED','CHALLENGED','FROZEN','EVIDENCE_TASK','EXECUTING','VERIFIED','FAILED','BLOCKED']);
export const EXECUTION_EPISODE_STATE = Object.freeze(['PENDING','QUEUED','RUNNING','SUCCEEDED','FAILED','CANCELLED','TIMEOUT','BUDGET_STOP','COMPLETE_WITH_DEBT']);
export const INVALIDATION_TARGET = Object.freeze({ PATCH: 'same', PLAN: 'FROZEN', DESIGN: 'CANDIDATES_READY', ROOT: 'TAILORED' });
export const ARCHITECTURE_TRANSITIONS = Object.freeze({ UNROUTED:['TAILORED'], TAILORED:['FRAMED'], FRAMED:['DRIVERS_READY'], DRIVERS_READY:['CANDIDATES_READY'], CANDIDATES_READY:['EVALUATED'], EVALUATED:['MINIMIZED'], MINIMIZED:['DECIDED'], DECIDED:['CHALLENGED','FROZEN'], CHALLENGED:['FROZEN'], FROZEN:['EVIDENCE_TASK','EXECUTING'], EVIDENCE_TASK:['FROZEN','EXECUTING','FAILED','BLOCKED'], EXECUTING:['VERIFIED','FAILED','BLOCKED'] });
export const EXECUTION_EPISODE_TRANSITIONS = Object.freeze({ PENDING:['QUEUED'], QUEUED:['RUNNING'], RUNNING:['SUCCEEDED','FAILED','CANCELLED','TIMEOUT','BUDGET_STOP','COMPLETE_WITH_DEBT'] });

const TOP_FIELDS = ['schema','task','mandate','intent','acceptance_ledger','context','architecture','uncertainty','decision','evidence','assurance','description','convergence','execution','integration','evidence_reachability','gate_validity','machinery_defects','state_fingerprint'];
const BUDGET_SNAPSHOT_FIELDS = ['id','budget_ref','budget_digest','observed_counters'];
const BUDGET_COUNTER_FIELDS = ['active_time_ms','excluded_wait_ms','retry_count','event_count'];
const AUTHORITY_FIELDS = ['authority','capability','capability_id','grant','grant_id','token','token_id'];
const TERMINAL_REVISION_DISPOSITIONS = new Set(['DECIDE_WITH_DEBT','SPIKE','ESCALATE']);

// Closed payloads for event kinds whose replay must never imply capability or authority creation.
export const ARCHITECTURE_EVENT_PAYLOAD_SCHEMAS = Object.freeze({
  EFFECT_RECORDED: Object.freeze(['id','effect_id','decision_id','effect_class','status','realization_status','correction_route','output_refs','unverified_candidate_ids']),
  EFFECT_DENIED: Object.freeze(['id','effect_id','decision_id','effect_class','code','reason','unverified_candidate_ids']),
  CANCEL_RECORDED: Object.freeze(['id','intent_epoch','reason','unverified_candidate_ids']),
  RECOVERY_RECORDED: Object.freeze(['id','checkpoint_digest','reason','candidate_ids','unverified_candidate_ids']),
  SUPERSESSION_RECORDED: Object.freeze(['id','supersedes_id','replacement_id','reason']),
  ARCHITECTURE_REVISION_RECORDED: Object.freeze(['id','decision_id','revision','live_candidate_ids','terminal_disposition']),
  CONVERGENCE_REVISION_RECORDED: Object.freeze(['id','decision_id','revision','live_candidate_ids','terminal_disposition']),
});

function fail(message, detail = {}) { throw new ArcaneError('ARC_SCHEMA_INVALID', message, detail); }
function clone(value) { return structuredClone(value); }
function sortStable(value) {
  if (Array.isArray(value)) return value.map(sortStable).sort((a, b) => typeof a?.id === 'string' && typeof b?.id === 'string' ? a.id.localeCompare(b.id) : 0);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sortStable(item)]));
  return value;
}
function exactKeys(value, fields, label) { if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`); for (const key of Object.keys(value)) if (!fields.includes(key)) fail(`${label} contains unknown field: ${key}`); for (const key of fields) if (!Object.hasOwn(value, key)) fail(`${label}.${key} is required`); }
function payloadKeys(payload, fields, label) { if (!payload || typeof payload !== 'object' || Array.isArray(payload)) fail(`${label} payload must be an object`); for (const key of Object.keys(payload)) if (!fields.includes(key)) fail(`${label} payload contains unknown field: ${key}`); }
function upsert(target, item) { if (!item || typeof item.id !== 'string' || !item.id) fail('stable item id is required'); const index = target.findIndex((entry) => entry.id === item.id); if (index >= 0) target[index] = sortStable(item); else target.push(sortStable(item)); target.sort((a, b) => a.id.localeCompare(b.id)); }
function checkedIds(value, label) { if (!Array.isArray(value) || value.some((id) => typeof id !== 'string' || !id)) fail(`${label} must be an array of stable ids`); return [...new Set(value)].sort(); }
function legalPayload(eventType, payload) {
  const fields = ARCHITECTURE_EVENT_PAYLOAD_SCHEMAS[eventType];
  if (!fields) return;
  payloadKeys(payload, fields, eventType);
  if (typeof payload.id !== 'string' || !payload.id) fail(`${eventType} requires id`);
  if (AUTHORITY_FIELDS.some((field) => Object.hasOwn(payload, field))) fail(`${eventType} may not mint authority`);
  for (const field of ['unverified_candidate_ids','candidate_ids','live_candidate_ids']) if (Object.hasOwn(payload, field)) checkedIds(payload[field], field);
}

export function fingerprintArchitectureState(state) { const copy = clone(state); delete copy.state_fingerprint; delete copy.execution?.trajectory?.replay_state_fingerprint; delete copy.execution?.trajectory?.last_event_digest; return digestValue(copy); }
export function createArchitectureState({ objective_lineage_id, acceptance_ledger, budget_ref } = {}) {
  if (typeof objective_lineage_id !== 'string' || !objective_lineage_id) fail('objective_lineage_id is required');
  if (!acceptance_ledger || typeof acceptance_ledger !== 'object') fail('acceptance_ledger is required');
  if (typeof budget_ref !== 'string' || !budget_ref) fail('budget_ref is required');
  const state = { schema: ARCHITECTURE_STATE_SCHEMA_ID, task:{ objective_lineage_id, architecture_status:'UNROUTED', budget_ref }, mandate:{}, intent:{ intent_epoch:1, continuation_epoch:1, outcomes:[], success_signals:[], unacceptable_losses:[] }, acceptance_ledger:sortStable(acceptance_ledger), context:{ route:null }, architecture:{}, uncertainty:{}, decision:{ items:[], fingerprints:[], refs:[] }, evidence:{ items:[], lifecycle:[], artifact_envelopes:[], fingerprints:[], refs:[] }, assurance:{ findings:[], fingerprints:[], refs:[] }, description:{}, convergence:{ revisions:[], terminal_disposition:null }, execution:{ episode_state:'PENDING', trajectory:{ last_sequence:0, last_event_digest:null, replay_state_fingerprint:null }, budget_snapshots:[], retry:{ items:[], fingerprints:[], refs:[] }, diagnosis:null, delivery_deficits:[], downstream_acknowledgements:[], effects:[], denials:[], cancellations:[], terminal_states:[], recovery_refs:[], supersession_refs:[], findings:[], evidence:[] }, integration:{ ownership_dispositions:[], migration_cutover:null }, evidence_reachability:{}, gate_validity:{}, machinery_defects:{ out_of_scope:[] }, state_fingerprint:null };
  state.state_fingerprint = fingerprintArchitectureState(state); return Object.freeze(state);
}

function recordRevision(next, payload) {
  if (!Number.isInteger(payload.revision) || payload.revision < 1) fail('revision must be a positive integer');
  const prior = next.convergence.revisions.filter((item) => item.decision_id === payload.decision_id).sort((a, b) => b.revision - a.revision)[0];
  if (prior && payload.revision !== prior.revision + 1) fail('revision must be contiguous per decision');
  if (payload.revision > 3) fail('revision tripwire is terminal; fourth comparison rejected');
  if (payload.revision === 3 && !TERMINAL_REVISION_DISPOSITIONS.has(payload.terminal_disposition)) fail('third revision requires DECIDE_WITH_DEBT, SPIKE, or ESCALATE');
  if (payload.revision < 3 && payload.terminal_disposition != null) fail('terminal disposition is only legal at revision tripwire');
  upsert(next.convergence.revisions, { ...payload, live_candidate_ids: checkedIds(payload.live_candidate_ids, 'live_candidate_ids') });
  if (payload.revision === 3) next.convergence.terminal_disposition = payload.terminal_disposition;
}

export function applyArchitectureEvent(state, event) {
  if (!state || state.schema !== ARCHITECTURE_STATE_SCHEMA_ID) fail('invalid architecture state'); if (!event || typeof event !== 'object') fail('event is required');
  const next = clone(state); const payload = event.payload ?? {}; legalPayload(event.event_type, payload);
  if (event.event_type === 'ROUTE_CLASSIFIED') next.context.route = sortStable(payload);
  else if (event.event_type === 'ARCHITECTURE_TRANSITIONED') { payloadKeys(payload,['from','to'],'ARCHITECTURE_TRANSITIONED'); if (payload.from !== next.task.architecture_status || !ARCHITECTURE_TRANSITIONS[next.task.architecture_status]?.includes(payload.to)) fail('illegal architecture transition'); next.task.architecture_status = payload.to; }
  else if (event.event_type === 'INVALIDATION_RECORDED') { payloadKeys(payload,['scope','cause','root_evidence','decision_ids','terminal_disposition'],'INVALIDATION_RECORDED'); if (!INVALIDATION_TARGET[payload.scope] || typeof payload.cause !== 'string' || !payload.cause) fail('invalidation requires cause and scope'); if (payload.scope === 'ROOT' && !payload.root_evidence) fail('root invalidation requires root evidence'); const decision_ids = payload.decision_ids == null ? [] : checkedIds(payload.decision_ids, 'decision_ids'); if (decision_ids.some((id) => !next.decision.items.some((decision) => decision.id === id))) fail('invalidation decision must exist'); if (payload.scope !== 'PATCH') { next.task.architecture_status = INVALIDATION_TARGET[payload.scope]; for (const decision_id of decision_ids) { const revision = next.convergence.revisions.filter((item) => item.decision_id === decision_id).length + 1; recordRevision(next, { id:`invalidation:${decision_id}:${revision}`, decision_id, revision, live_candidate_ids:[], terminal_disposition:payload.terminal_disposition ?? null }); } } next.convergence.invalidation = { scope:payload.scope, cause:payload.cause, root_evidence:payload.root_evidence ?? null, decision_ids }; }
  else if (event.event_type === 'EXECUTION_EPISODE_TRANSITIONED') { payloadKeys(payload,['from','to'],'EXECUTION_EPISODE_TRANSITIONED'); if (payload.from !== next.execution.episode_state || !EXECUTION_EPISODE_TRANSITIONS[next.execution.episode_state]?.includes(payload.to)) fail('illegal execution episode transition'); next.execution.episode_state = payload.to; }
  else if (event.event_type === 'INTENT_EPOCH_ADVANCED') { payloadKeys(payload,['intent_epoch'],'INTENT_EPOCH_ADVANCED'); if (payload.intent_epoch !== next.intent.intent_epoch + 1) fail('intent epoch must be contiguous'); next.intent.intent_epoch = payload.intent_epoch; next.acceptance_ledger.intent_epoch = payload.intent_epoch; }
  else if (event.event_type === 'CONTINUATION_EPOCH_ADVANCED') { payloadKeys(payload,['continuation_epoch'],'CONTINUATION_EPOCH_ADVANCED'); if (payload.continuation_epoch !== next.intent.continuation_epoch + 1) fail('continuation epoch must be contiguous'); next.intent.continuation_epoch = payload.continuation_epoch; }
  else if (event.event_type === 'BUDGET_SNAPSHOT_RECORDED') { payloadKeys(payload,BUDGET_SNAPSHOT_FIELDS,'BUDGET_SNAPSHOT_RECORDED'); exactKeys(payload.observed_counters,BUDGET_COUNTER_FIELDS,'budget observed_counters'); if (typeof payload.id !== 'string' || !payload.id || typeof payload.budget_ref !== 'string' || !payload.budget_ref || !/^sha256:[0-9a-f]{64}$/.test(payload.budget_digest) || Object.values(payload.observed_counters).some((value) => !Number.isInteger(value) || value < 0)) fail('budget snapshot requires authenticated reference, digest, and non-negative observed counters'); upsert(next.execution.budget_snapshots,payload); }
  else if (event.event_type === 'FINGERPRINTS_RECORDED') { payloadKeys(payload,['decision','evidence','finding','retry'],'FINGERPRINTS_RECORDED'); if (payload.decision) next.decision.fingerprints = sortStable(payload.decision); if (payload.evidence) next.evidence.fingerprints = sortStable(payload.evidence); if (payload.finding) next.assurance.fingerprints = sortStable(payload.finding); if (payload.retry) next.execution.retry.fingerprints = sortStable(payload.retry); }
  else if (event.event_type === 'MIGRATION_CUTOVER_RECORDED') next.integration.migration_cutover = sortStable(payload);
  else if (event.event_type === 'ACCEPTANCE_RESULT_RECORDED') {
    if (next.acceptance_ledger.items == null) next.acceptance_ledger.items = [];
    upsert(next.acceptance_ledger.items, payload);
  }
  else if (event.event_type === 'ARCHITECTURE_REVISION_RECORDED' || event.event_type === 'CONVERGENCE_REVISION_RECORDED') recordRevision(next, payload);
  else {
    const paths = { DECISION_RECORDED:['decision','items'], DECISION_FROZEN:['decision','items'], FINDING_UPSERTED:['assurance','findings'], RETRY_RECORDED:['execution','retry','items'], DELIVERY_DEFICIT_UPSERTED:['execution','delivery_deficits'], DOWNSTREAM_ACKNOWLEDGEMENT_RECORDED:['execution','downstream_acknowledgements'], OWNERSHIP_DISPOSITION_RECORDED:['integration','ownership_dispositions'], ARTIFACT_ENVELOPE_RECORDED:['evidence','artifact_envelopes'], EVIDENCE_LIFECYCLE_RECORDED:['evidence','lifecycle'], EFFECT_RECORDED:['execution','effects'], EFFECT_DENIED:['execution','denials'], CANCEL_RECORDED:['execution','cancellations'], TERMINAL_STATE_RECORDED:['execution','terminal_states'], RECOVERY_RECORDED:['execution','recovery_refs'], SUPERSESSION_RECORDED:['execution','supersession_refs'] };
    const path = paths[event.event_type]; if (!path) fail('unsupported architecture event'); let list = next; for (const key of path) list = list[key]; upsert(list, payload);
    if (event.event_type === 'CANCEL_RECORDED') { if (payload.intent_epoch !== next.intent.intent_epoch + 1) fail('cancellation must advance intent epoch'); next.intent.intent_epoch = payload.intent_epoch; next.acceptance_ledger.intent_epoch = payload.intent_epoch; if (next.execution.episode_state === 'RUNNING') next.execution.episode_state = 'CANCELLED'; }
  }
  next.state_fingerprint = fingerprintArchitectureState(next); return Object.freeze(next);
}

export function projectArchitectureEvents(events, { initial_state } = {}) { if (!initial_state) fail('initial_state is required'); if (!Array.isArray(events)) fail('events must be an array'); return events.reduce((state, event) => applyArchitectureEvent(state, event), initial_state); }
export function replayArchitectureEvents(events, { initial_state } = {}) { const state = projectArchitectureEvents(events, { initial_state }); return Object.freeze({ state, state_fingerprint:state.state_fingerprint, authority_minted:false }); }
export const stateFingerprint = fingerprintArchitectureState; export const reduceArchitectureState = applyArchitectureEvent; export const withStateFingerprint = (state) => Object.freeze({ ...clone(state), state_fingerprint:fingerprintArchitectureState(state) });

export function validateArchitectureState(state) { try {
  exactKeys(state,TOP_FIELDS,'architecture state'); exactKeys(state.task,['objective_lineage_id','architecture_status','budget_ref'],'task'); exactKeys(state.intent,['intent_epoch','continuation_epoch','outcomes','success_signals','unacceptable_losses'],'intent');
  const ledgerFields = state.acceptance_ledger.schema === 'acceptance-ledger.v2' ? ['schema','ledger_version','intent_epoch','acceptance_manifest_fingerprint','schedule_fingerprint','schedule','frozen_at','items'] : ['schema','ledger_version','intent_epoch','acceptance_fingerprint','frozen_at','items']; exactKeys(state.acceptance_ledger,ledgerFields,'acceptance_ledger');
  exactKeys(state.decision,['items','fingerprints','refs'],'decision'); exactKeys(state.evidence,['items','lifecycle','artifact_envelopes','fingerprints','refs'],'evidence'); exactKeys(state.assurance,['findings','fingerprints','refs'],'assurance'); exactKeys(state.convergence,['revisions','terminal_disposition',...(Object.hasOwn(state.convergence,'invalidation') ? ['invalidation'] : [])],'convergence');
  exactKeys(state.execution,['episode_state','trajectory','budget_snapshots','retry','diagnosis','delivery_deficits','downstream_acknowledgements','effects','denials','cancellations','terminal_states','recovery_refs','supersession_refs','findings','evidence'],'execution'); exactKeys(state.execution.trajectory,['last_sequence','last_event_digest','replay_state_fingerprint'],'execution.trajectory'); exactKeys(state.execution.retry,['items','fingerprints','refs'],'execution.retry');
  for (const snapshot of state.execution.budget_snapshots) { exactKeys(snapshot,BUDGET_SNAPSHOT_FIELDS,'budget snapshot'); exactKeys(snapshot.observed_counters,BUDGET_COUNTER_FIELDS,'budget observed_counters'); if (typeof snapshot.id !== 'string' || !snapshot.id || typeof snapshot.budget_ref !== 'string' || !snapshot.budget_ref || !/^sha256:[0-9a-f]{64}$/.test(snapshot.budget_digest) || Object.values(snapshot.observed_counters).some((value) => !Number.isInteger(value) || value < 0)) fail('invalid budget snapshot'); }
  exactKeys(state.integration,['ownership_dispositions','migration_cutover'],'integration'); if (state.schema !== ARCHITECTURE_STATE_SCHEMA_ID || !['acceptance-ledger.v1','acceptance-ledger.v2'].includes(state.acceptance_ledger.schema)) fail('invalid schema'); if (!ARCHITECTURE_STATUS.includes(state.task.architecture_status) || !EXECUTION_EPISODE_STATE.includes(state.execution.episode_state)) fail('invalid state enum'); if (!Number.isInteger(state.intent.intent_epoch) || state.intent.intent_epoch < 1 || !Number.isInteger(state.intent.continuation_epoch) || state.intent.continuation_epoch < 1 || state.acceptance_ledger.intent_epoch !== state.intent.intent_epoch) fail('invalid intent epoch'); if (!Number.isInteger(state.execution.trajectory.last_sequence) || state.execution.trajectory.last_sequence < 0) fail('invalid trajectory sequence'); if (state.state_fingerprint !== fingerprintArchitectureState(state)) fail('state fingerprint mismatch'); return Object.freeze({ valid:true, issues:Object.freeze([]) });
} catch (error) { return Object.freeze({ valid:false, issues:Object.freeze([error.message]) }); } }
export function assertArchitectureState(state) { const result = validateArchitectureState(state); if (!result.valid) fail(result.issues[0]); return state; }
