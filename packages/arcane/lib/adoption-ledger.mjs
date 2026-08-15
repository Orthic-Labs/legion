// Admission for architecture adoption ledgers. A stage may be a candidate on
// producer testimony, but VERIFIED is an Arcane-owned transition requiring
// current independent evidence for every acceptance item & exact integrated
// state identity.
import { decision } from './errors.mjs';
import { loadCompletionEvidence } from './completion-evidence.mjs';
import { digestValue } from './canonical.mjs';
import { signRecord, verifyRecord } from './receipt-auth.mjs';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { validateSchema } from '../../../lib/qualification/schema-validator.mjs';

const ADOPTION_LEDGER_SCHEMA = JSON.parse(readFileSync(new URL('../../../schemas/adoption-ledger.schema.json', import.meta.url), 'utf8'));

const deny = (code, message, detail = {}) => decision({ allowed: false, code, message, detail });
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
export const ADOPTION_VERIFICATION_BOUND_FIELDS = Object.freeze(['schemaVersion', 'kind', 'stageId', 'stageFingerprint', 'runId', 'taskId', 'contractId', 'integratedState', 'admittedAt']);
const stageFingerprint = (stage) => {
  const { verification_admission: _admission, ...unsigned } = stage;
  return digestValue(unsigned);
};

export function validateAdoptionDependencyGraph(ledger) {
  const stages = ledger?.stages ?? [];
  if (stages.length > 1 && !(ledger?.consumption_dependencies?.length > 0)) return deny('ARC_BINDING_MISMATCH', 'multi-stage adoption ledger requires an explicit dependency graph');
  const stageById = new Map(stages.map((stage) => [stage.stage_id, stage]));
  if (stageById.size !== stages.length) return deny('ARC_BINDING_MISMATCH', 'adoption ledger stage identifiers must be unique');
  const incoming = new Map(stages.map((stage) => [stage.stage_id, []]));
  for (const edge of ledger?.consumption_dependencies ?? []) {
    const producer = stageById.get(edge.producer_stage_id);
    const consumer = stageById.get(edge.consumer_stage_id);
    if (!producer || !consumer || producer.stage_id === consumer.stage_id) return deny('ARC_BINDING_MISMATCH', 'adoption dependency references an absent or identical stage', { edge });
    if (!producer.required_items?.some((item) => item.acceptance_id === edge.producer_acceptance_id) || !consumer.required_items?.some((item) => item.acceptance_id === edge.consumer_acceptance_id)) return deny('ARC_BINDING_MISMATCH', 'adoption dependency references an absent acceptance item', { edge });
    incoming.get(consumer.stage_id).push(producer.stage_id);
  }
  const visiting = new Set();
  const visited = new Set();
  const visit = (stageId) => {
    if (visiting.has(stageId)) return false;
    if (visited.has(stageId)) return true;
    visiting.add(stageId);
    for (const predecessor of incoming.get(stageId) ?? []) if (!visit(predecessor)) return false;
    visiting.delete(stageId);
    visited.add(stageId);
    return true;
  };
  if (!stages.every((stage) => visit(stage.stage_id))) return deny('ARC_BINDING_MISMATCH', 'adoption dependency graph contains a cycle');
  return decision({ allowed: true, message: 'Arcane validated adoption dependency graph' });
}

function verifyStageDependencies(ledger, stageId) {
  const graph = validateAdoptionDependencyGraph(ledger);
  if (!graph.allowed) return graph;
  for (const edge of (ledger.consumption_dependencies ?? []).filter((candidate) => candidate.consumer_stage_id === stageId && candidate.required_verification)) {
    const producer = ledger.stages.find((stage) => stage.stage_id === edge.producer_stage_id);
    const item = producer?.required_items?.find((candidate) => candidate.acceptance_id === edge.producer_acceptance_id);
    if (producer?.done_state !== 'VERIFIED' || item?.result !== 'PASS' || !item.evidence?.length) return deny('ARC_CLAIM_PREREQUISITE_UNMET', 'adoption stage requires every declared predecessor to be VERIFIED with evidence', { stageId, producerStageId: edge.producer_stage_id, producerAcceptanceId: edge.producer_acceptance_id });
  }
  return decision({ allowed: true, message: 'Arcane verified adoption predecessors' });
}

// Candidate is durable progress, never a substitute for verified evidence.
// Keep this separate from verified admission so candidate transitions cannot
// weaken its receipt-backed requirements.
export function transitionCandidateStage(ledger, stageId) {
  const stage = ledger?.stages?.find((candidate) => candidate.stage_id === stageId);
  if (!stage) return deny('ARC_BINDING_MISMATCH', 'adoption stage is absent from ledger', { stageId });
  if (stage.done_state === 'VERIFIED') return deny('ARC_CLAIM_PREREQUISITE_UNMET', 'VERIFIED adoption stage cannot regress to CANDIDATE', { stageId });
  stage.done_state = 'CANDIDATE';
  return decision({ allowed: true, message: 'Arcane retained adoption stage as CANDIDATE', detail: { stageId, doneState: stage.done_state } });
}

export function readAdoptionStage(ledger, stageId, verification = {}) {
  const stage = ledger?.stages?.find((candidate) => candidate.stage_id === stageId);
  if (!stage) return deny('ARC_BINDING_MISMATCH', 'adoption stage is absent from ledger', { stageId });
  if (stage.done_state === 'VERIFIED') {
    const verified = verifyVerifiedStageAdmission(ledger, stageId, verification);
    if (!verified.allowed) return deny(verified.code, 'VERIFIED adoption stage is invalid for status reporting', { stageId, doneState: 'CANDIDATE', terminalStateInvalid: true, verification: verified.detail });
  }
  return decision({ allowed: true, message: 'Arcane read adoption stage', detail: { stageId, doneState: stage.done_state, integratedStateIdentity: stage.integrated_state_identity ?? null, verificationAdmission: stage.verification_admission ?? null } });
}

// This is deliberately a receipt-store admission API.  Callers cannot supply a
// registry or proofs: those are reconstructed from Arcane-authenticated Oracle
// receipts, bound to the live run/task/contract & current integrated state.
export function admitVerifiedStage(ledger, stageId, { receiptStore, keyRing, authorityProofIssuer, execution, integratedState = null, latestMaterialChange = null, now = new Date() } = {}) {
  const schemaIssues = validateSchema(ADOPTION_LEDGER_SCHEMA, ledger);
  if (schemaIssues.length) return deny('ARC_SCHEMA_INVALID', 'VERIFIED transition requires a valid adoption ledger', { stageId, issues: schemaIssues });
  const stage = ledger?.stages?.find((candidate) => candidate.stage_id === stageId);
  if (!stage) return deny('ARC_BINDING_MISMATCH', 'adoption stage is absent from ledger', { stageId });
  if (!receiptStore?.list || !keyRing || !authorityProofIssuer || !execution?.runId || !execution?.taskId || !execution?.contractId) return deny('ARC_EVIDENCE_INSUFFICIENT', 'VERIFIED transition requires Arcane-authenticated Oracle proof & receipt-store evidence', { stageId });
  if (integratedState === null || integratedState === undefined || !stage.integrated_state_identity || stage.integrated_state_identity !== integratedState) return deny('ARC_EVIDENCE_INSUFFICIENT', 'VERIFIED transition requires the stage identity to exactly match current integrated state', { stageId });
  if (!latestMaterialChange || !Number.isFinite(Date.parse(latestMaterialChange))) return deny('ARC_EVIDENCE_INSUFFICIENT', 'VERIFIED transition requires latest material-change identity', { stageId });
  const dependencies = verifyStageDependencies(ledger, stageId);
  if (!dependencies.allowed) return dependencies;
  const required = stage.required_items ?? [];
  if (!required.length || required.some((item) => item.result !== 'PASS')) return deny('ARC_EVIDENCE_INSUFFICIENT', 'VERIFIED transition requires every stage acceptance item to pass', { stageId, openAcceptanceIds: required.filter((item) => item.result !== 'PASS').map((item) => item.acceptance_id) });
  const requiredIds = required.map((item) => item.acceptance_id);
  const criteria = execution.acceptanceCriteria ?? [];
  if (criteria.length !== requiredIds.length || criteria.some((criterion) => !requiredIds.includes(criterion?.id)) || new Set(requiredIds).size !== requiredIds.length) return deny('ARC_BINDING_MISMATCH', 'VERIFIED transition requires contract acceptance criteria to exactly match stage items', { stageId });
  const evidence = loadCompletionEvidence({ receiptStore, keyRing, authorityProofIssuer, execution, integratedState, latestMaterialChange, now });
  const proofs = new Map(evidence.acceptanceProofs.map((proof) => [proof?.acceptanceId, proof]));
  for (const item of required) {
    const proof = proofs.get(item.acceptance_id);
    if (!proof) return deny('ARC_EVIDENCE_INSUFFICIENT', 'VERIFIED transition requires a proof for every stage acceptance item', { stageId, acceptanceId: item.acceptance_id });
    if (!same(proof.integratedState, integratedState)) return deny('ARC_EVIDENCE_INSUFFICIENT', 'VERIFIED transition evidence does not match current integrated state', { stageId, acceptanceId: item.acceptance_id });
    const checked = evidence.evidenceRegistry.verify(item.acceptance_id, proof, { integratedState, latestMaterialChange, now });
    if (!checked.allowed) return checked;
  }
  return decision({ allowed: true, message: 'Arcane admits VERIFIED transition with fresh exact-state acceptance evidence', detail: { stageId, integratedState } });
}

// Sole production mutation path for a VERIFIED adoption stage.  It records a
// key-authenticated admission bound to the final stage projection; consumers
// can reject a hand-edited VERIFIED JSON object even when its shape is valid.
export function transitionVerifiedStage(ledger, stageId, options = {}) {
  const admitted = admitVerifiedStage(ledger, stageId, options);
  if (!admitted.allowed) return admitted;
  const stage = ledger.stages.find((candidate) => candidate.stage_id === stageId);
  const hostKeys = options.keyRing?.list?.().filter((entry) => entry.status === 'active' && !entry.keyId.includes(':authority-proof:')).sort((a, b) => a.createdAt.localeCompare(b.createdAt)) ?? [];
  const keyId = options.keyId ?? hostKeys.at(-1)?.keyId ?? options.keyRing?.activeKeyId?.();
  if (!keyId) return deny('ARC_AUTH_KEY_UNAVAILABLE', 'VERIFIED transition requires an Arcane signing key', { stageId });
  stage.done_state = 'VERIFIED';
  const admission = {
    schemaVersion: 1,
    kind: 'arcane-adoption-verification',
    stageId,
    stageFingerprint: stageFingerprint(stage),
    runId: options.execution.runId,
    taskId: options.execution.taskId,
    contractId: options.execution.contractId,
    integratedState: options.integratedState,
    admittedAt: options.now instanceof Date ? options.now.toISOString() : new Date(options.now).toISOString(),
  };
  admission.authentication = signRecord(admission, { keyRing: options.keyRing, keyId, boundFields: ADOPTION_VERIFICATION_BOUND_FIELDS, macDomain: 'arcane-adoption-verification-v1' });
  stage.verification_admission = admission;
  return decision({ allowed: true, message: 'Arcane recorded VERIFIED adoption transition', detail: { stageId, admission } });
}

export function verifyVerifiedStageAdmission(ledger, stageId, { keyRing, integratedState = null } = {}) {
  const stage = ledger?.stages?.find((candidate) => candidate.stage_id === stageId);
  const admission = stage?.verification_admission;
  if (stage?.done_state !== 'VERIFIED' || !admission) return deny('ARC_EVIDENCE_INSUFFICIENT', 'VERIFIED stage lacks Arcane admission receipt', { stageId });
  const schemaIssues = validateSchema(ADOPTION_LEDGER_SCHEMA, ledger);
  if (schemaIssues.length) return deny('ARC_SCHEMA_INVALID', 'VERIFIED stage does not satisfy adoption-ledger admission schema', { stageId, issues: schemaIssues });
  if (!keyRing) return deny('ARC_AUTH_KEY_UNAVAILABLE', 'VERIFIED admission requires Arcane verification key', { stageId });
  if (integratedState === null || integratedState === undefined) return deny('ARC_EVIDENCE_INSUFFICIENT', 'VERIFIED admission requires current integrated state for consumption', { stageId });
  const checked = verifyRecord(admission, admission.authentication, { keyRing, boundFields: ADOPTION_VERIFICATION_BOUND_FIELDS, expectedBinding: { stageId }, macDomain: 'arcane-adoption-verification-v1' });
  if (!checked.allowed || admission.stageId !== stageId || admission.stageFingerprint !== stageFingerprint(stage) || admission.integratedState !== stage.integrated_state_identity || admission.integratedState !== integratedState) return deny('ARC_BINDING_MISMATCH', 'VERIFIED admission receipt does not bind current stage state', { stageId });
  return decision({ allowed: true, message: 'VERIFIED stage has an Arcane-authenticated admission receipt', detail: { stageId } });
}

// Canonical status-file consumer. A claimed VERIFIED state is downgraded to
// CANDIDATE unless its schema, MAC & current integrated state all verify.
export function readVerifiedStageFile(ledgerPath, stageId, options = {}) {
  let ledger;
  try { ledger = JSON.parse(readFileSync(ledgerPath, 'utf8')); } catch { return deny('ARC_STORE_CORRUPT', 'adoption ledger is unreadable', { ledgerPath, stageId, doneState: 'CANDIDATE' }); }
  const read = readAdoptionStage(ledger, stageId, options);
  if (!read.allowed) return decision({ allowed: false, code: read.code, message: read.message, detail: { ...read.detail, ledgerPath, doneState: 'CANDIDATE' } });
  if (read.detail.doneState !== 'VERIFIED') return deny('ARC_EVIDENCE_INSUFFICIENT', 'adoption stage is not VERIFIED', { ledgerPath, stageId, doneState: 'CANDIDATE' });
  return decision({ allowed: true, message: 'Arcane consumed verified adoption stage', detail: { ...read.detail, ledgerPath } });
}

export function transitionVerifiedStageFile(ledgerPath, stageId, options = {}) {
  let ledger;
  try { ledger = JSON.parse(readFileSync(ledgerPath, 'utf8')); } catch { return deny('ARC_STORE_CORRUPT', 'adoption ledger is unreadable', { ledgerPath }); }
  const transitioned = transitionVerifiedStage(ledger, stageId, options);
  if (!transitioned.allowed) return transitioned;
  const temporary = `${ledgerPath}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(ledger, null, 2)}\n`, { flag: 'wx' });
  renameSync(temporary, ledgerPath);
  return decision({ allowed: true, message: 'Arcane persisted VERIFIED adoption transition', detail: { stageId, ledgerPath, admission: transitioned.detail.admission } });
}

export function transitionCandidateStageFile(ledgerPath, stageId) {
  let ledger;
  try { ledger = JSON.parse(readFileSync(ledgerPath, 'utf8')); } catch { return deny('ARC_STORE_CORRUPT', 'adoption ledger is unreadable', { ledgerPath }); }
  const transitioned = transitionCandidateStage(ledger, stageId);
  if (!transitioned.allowed) return transitioned;
  const temporary = `${ledgerPath}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(ledger, null, 2)}\n`, { flag: 'wx' });
  renameSync(temporary, ledgerPath);
  return decision({ allowed: true, message: 'Arcane persisted CANDIDATE adoption transition', detail: { stageId, ledgerPath } });
}
