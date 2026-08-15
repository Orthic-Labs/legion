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
export const ADOPTION_VERIFICATION_BOUND_FIELDS = Object.freeze(['schemaVersion', 'kind', 'stageId', 'stageFingerprint', 'runId', 'taskId', 'contractId', 'acceptanceFingerprint', 'integratedState', 'admittedAt']);
export const ADOPTION_MANIFEST_RECEIPT_BOUND_FIELDS = Object.freeze(['schemaVersion', 'kind', 'manifestDigest', 'itemSetDigest', 'runId', 'taskId', 'contractId', 'contractVersion', 'contractDigest', 'sourceRevision', 'acceptanceFingerprint', 'integratedState', 'authorityProofDigest', 'observedAt']);
export const REQUIRED_ADOPTION_EDGES = Object.freeze([
  ['S01-canon-ownership', 'S02-scope-convergence-doctrine'],
  ['S02-scope-convergence-doctrine', 'S03-router-state-trajectory'],
  ['S03-router-state-trajectory', 'S04-rehydration-cancellation-checkpoints'],
  ['S04-rehydration-cancellation-checkpoints', 'S05-seals-gates-evidence'],
  ['S02-scope-convergence-doctrine', 'S06-edaf-workflow-modules'],
  ['S06-edaf-workflow-modules', 'S07-templates-lenses'],
  ['S05-seals-gates-evidence', 'S08-execution-ownership-migration'],
  ['S07-templates-lenses', 'S08-execution-ownership-migration'],
  ['S08-execution-ownership-migration', 'S09-arcane-guards'],
  ['S08-execution-ownership-migration', 'S10-handoffs'],
  ['S09-arcane-guards', 'S11-evals'],
  ['S10-handoffs', 'S11-evals'],
  ['S11-evals', 'S12-calibration-retirement'],
]);
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

export function validateFormalAdoptionGraph(ledger) {
  const graph = validateAdoptionDependencyGraph(ledger);
  if (!graph.allowed) return graph;
  const actualEdges = (ledger.consumption_dependencies ?? []).map((edge) => `${edge.producer_stage_id}\0${edge.consumer_stage_id}`).sort();
  const required = REQUIRED_ADOPTION_EDGES.map(([producer, consumer]) => `${producer}\0${consumer}`).sort();
  if (!same(actualEdges, required)) return deny('ARC_BINDING_MISMATCH', 'formal adoption requires exact Architecture Book dependency edges', { requiredEdges: required.length, actualEdges: actualEdges.length });
  return decision({ allowed: true, message: 'Arcane validated exact formal-adoption DAG' });
}

function manifestItems(manifest) {
  return Array.isArray(manifest?.items) ? manifest.items : [];
}

function ledgerAcceptanceIds(ledger) {
  return ledger.stages.flatMap((stage) => stage.required_items.map((item) => item.acceptance_id));
}

function validateManifestShape(ledger, manifest, { execution, integratedState, now }) {
  const ids = ledgerAcceptanceIds(ledger);
  const items = manifestItems(manifest);
  const itemIds = items.map((item) => item?.acceptanceId);
  const expectedKeys = ['acceptanceId', 'acceptanceSurface', 'evidence', 'evidenceId', 'liveConsumer', 'observedAt', 'productionSymbol', 'requirementId', 'verdict'];
  if (manifest?.schemaVersion !== 1 || manifest?.kind !== 'legion-adoption-oracle-manifest'
      || manifest.runId !== execution.runId || manifest.taskId !== execution.taskId || manifest.contractId !== execution.contractId
      || manifest.contractVersion !== execution.contractVersion || manifest.contractDigest !== execution.contractDigest
      || manifest.sourceRevision !== execution.sourceRevision || manifest.acceptanceFingerprint !== ledger.acceptance_fingerprint
      || manifest.integratedState !== integratedState || !Number.isFinite(Date.parse(manifest.observedAt))
      || Date.parse(manifest.observedAt) > now.getTime()) return deny('ARC_BINDING_MISMATCH', 'Oracle adoption manifest does not bind current execution, acceptance, state, or time');
  if (ids.length !== items.length || new Set(itemIds).size !== itemIds.length || !ids.every((id) => itemIds.includes(id))) return deny('ARC_EVIDENCE_INSUFFICIENT', 'Oracle adoption manifest must cover every ledger item exactly once', { expected: ids.length, actual: items.length });
  for (const item of items) {
    const evidence = item?.evidence;
    const evidenceValid = evidence && typeof evidence === 'object' && !Array.isArray(evidence) && evidence.kind === 'oracle-adoption-item-evidence' && Array.isArray(evidence.sources) && evidence.sources.length > 0 && evidence.sources.every((source) => source && typeof source.path === 'string' && source.path && /^sha256:[0-9a-f]{64}$/.test(source.digest ?? '')) && Array.isArray(evidence.checks) && evidence.checks.length > 0 && evidence.checks.every((check) => typeof check === 'string' && check);
    if (!same(Object.keys(item).sort(), expectedKeys) || item.verdict !== 'PASS' || !item.acceptanceId || !item.requirementId || !item.productionSymbol || !item.liveConsumer || !item.acceptanceSurface || !evidenceValid || item.evidenceId !== digestValue(evidence) || !Number.isFinite(Date.parse(item.observedAt)) || Date.parse(item.observedAt) > Date.parse(manifest.observedAt)) return deny('ARC_EVIDENCE_INSUFFICIENT', 'Oracle adoption manifest contains invalid, unbound, or non-PASS item evidence', { acceptanceId: item?.acceptanceId ?? null });
  }
  return decision({ allowed: true, message: 'Arcane validated exact Oracle adoption manifest', detail: { itemCount: items.length, itemSetDigest: digestValue([...itemIds].sort()) } });
}

export function validateOracleAdoptionManifest(ledger, manifest, options = {}) {
  const graph = validateFormalAdoptionGraph(ledger);
  if (!graph.allowed) return graph;
  return validateManifestShape(ledger, manifest, options);
}

export function verifyOracleAdoptionManifest(ledger, manifest, { receiptStore, keyRing, authorityProofIssuer, execution, integratedState, now = new Date() } = {}) {
  if (!receiptStore?.list || !keyRing || !authorityProofIssuer || !execution) return deny('ARC_EVIDENCE_INSUFFICIENT', 'formal adoption requires persisted Oracle manifest authority');
  const shaped = validateOracleAdoptionManifest(ledger, manifest, { execution, integratedState, now });
  if (!shaped.allowed) return shaped;
  const manifestDigest = digestValue(manifest);
  const receipt = receiptStore.list({ runId: execution.runId }).find((record) => record?.kind === 'arcane-adoption-manifest-receipt' && record.manifestDigest === manifestDigest);
  if (!receipt || receipt.itemSetDigest !== shaped.detail.itemSetDigest || receipt.taskId !== execution.taskId || receipt.contractId !== execution.contractId || receipt.contractVersion !== execution.contractVersion || receipt.contractDigest !== execution.contractDigest || receipt.sourceRevision !== execution.sourceRevision || receipt.acceptanceFingerprint !== ledger.acceptance_fingerprint || receipt.integratedState !== integratedState || receipt.observedAt !== manifest.observedAt) return deny('ARC_EVIDENCE_INSUFFICIENT', 'persisted Oracle manifest receipt is absent or misbound');
  const authority = authorityProofIssuer.findByDigest(receipt.authorityProofDigest);
  const expected = { runId: execution.runId, taskId: execution.taskId, contractId: execution.contractId, contractVersion: execution.contractVersion, contractDigest: execution.contractDigest, sourceRevision: execution.sourceRevision };
  if (!authority || !authorityProofIssuer.verify(authority, { expected }).allowed || !verifyRecord(receipt, receipt.authentication, { keyRing, boundFields: ADOPTION_MANIFEST_RECEIPT_BOUND_FIELDS, expectedBinding: { runId: execution.runId, taskId: execution.taskId, contractId: execution.contractId }, macDomain: 'arcane-adoption-manifest-v1' }).allowed) return deny('ARC_AUTH_FORGED', 'Oracle adoption manifest receipt authentication is invalid');
  return decision({ allowed: true, message: 'Arcane verified authenticated Oracle adoption manifest', detail: { manifestDigest, receiptId: receipt.receiptId } });
}

function topologicalStageIds(ledger) {
  const incoming = new Map(ledger.stages.map((stage) => [stage.stage_id, new Set()]));
  const outgoing = new Map(ledger.stages.map((stage) => [stage.stage_id, []]));
  for (const edge of ledger.consumption_dependencies) { incoming.get(edge.consumer_stage_id).add(edge.producer_stage_id); outgoing.get(edge.producer_stage_id).push(edge.consumer_stage_id); }
  const ready = [...incoming].filter(([, predecessors]) => predecessors.size === 0).map(([id]) => id).sort();
  const order = [];
  while (ready.length) { const id = ready.shift(); order.push(id); for (const next of outgoing.get(id).sort()) { incoming.get(next).delete(id); if (incoming.get(next).size === 0) ready.push(next); } ready.sort(); }
  return order;
}

export function transitionVerifiedLedger(ledger, manifest, options = {}) {
  const admitted = verifyOracleAdoptionManifest(ledger, manifest, options);
  if (!admitted.allowed) return admitted;
  const keyId = options.keyId ?? options.keyRing?.list?.().filter((entry) => entry.status === 'active' && !entry.keyId.includes(':authority-proof:')).sort((a, b) => a.createdAt.localeCompare(b.createdAt)).at(-1)?.keyId;
  if (!keyId) return deny('ARC_AUTH_KEY_UNAVAILABLE', 'formal adoption requires Arcane signing key');
  const evidenceById = new Map(manifest.items.map((item) => [item.acceptanceId, item.evidenceId]));
  const order = topologicalStageIds(ledger);
  if (order.length !== ledger.stages.length) return deny('ARC_BINDING_MISMATCH', 'formal adoption DAG is not topologically complete');
  const admittedAt = options.now instanceof Date ? options.now.toISOString() : new Date(options.now).toISOString();
  for (const stageId of order) {
    const stage = ledger.stages.find((candidate) => candidate.stage_id === stageId);
    for (const item of stage.required_items) { item.result = 'PASS'; item.evidence = [evidenceById.get(item.acceptance_id)]; }
    stage.produce_readiness = 'PRODUCED'; stage.integrate_readiness = 'INTEGRATED'; stage.activate_readiness = 'ACTIVATED'; stage.done_state = 'VERIFIED'; stage.integrated_state_identity = options.integratedState;
    const admission = { schemaVersion: 1, kind: 'arcane-adoption-verification', stageId, stageFingerprint: stageFingerprint(stage), runId: options.execution.runId, taskId: options.execution.taskId, contractId: options.execution.contractId, acceptanceFingerprint: ledger.acceptance_fingerprint, integratedState: options.integratedState, admittedAt };
    admission.authentication = signRecord(admission, { keyRing: options.keyRing, keyId, boundFields: ADOPTION_VERIFICATION_BOUND_FIELDS, macDomain: 'arcane-adoption-verification-v1' });
    stage.verification_admission = admission;
  }
  return decision({ allowed: true, message: 'Arcane atomically admitted complete formal-adoption DAG', detail: { stageIds: order, manifestReceiptId: admitted.detail.receiptId } });
}

export function transitionVerifiedLedgerFile(ledgerPath, manifest, options = {}) {
  let ledger;
  try { ledger = JSON.parse(readFileSync(ledgerPath, 'utf8')); } catch { return deny('ARC_STORE_CORRUPT', 'adoption ledger is unreadable', { ledgerPath }); }
  const transitioned = transitionVerifiedLedger(ledger, manifest, options);
  if (!transitioned.allowed) return transitioned;
  const schemaIssues = validateSchema(ADOPTION_LEDGER_SCHEMA, ledger);
  if (schemaIssues.length) return deny('ARC_SCHEMA_INVALID', 'admitted adoption ledger is schema-invalid', { issues: schemaIssues });
  const temporary = `${ledgerPath}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(ledger, null, 2)}\n`, { flag: 'wx' });
  renameSync(temporary, ledgerPath);
  return decision({ allowed: true, message: 'Arcane persisted complete formal adoption atomically', detail: { ...transitioned.detail, ledgerPath } });
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
    acceptanceFingerprint: ledger.acceptance_fingerprint,
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
  if (!checked.allowed || admission.stageId !== stageId || admission.stageFingerprint !== stageFingerprint(stage) || admission.acceptanceFingerprint !== ledger.acceptance_fingerprint || admission.integratedState !== stage.integrated_state_identity || admission.integratedState !== integratedState) return deny('ARC_BINDING_MISMATCH', 'VERIFIED admission receipt does not bind current stage state', { stageId });
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
