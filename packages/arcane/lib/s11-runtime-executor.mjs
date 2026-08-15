import { authorityReviewBindings, authorityReviewBlockers } from './s11-bindings/authority-review.mjs';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { admitConvergencePass, admitRetry, classifyRetryFailure, settleFlakyRetry } from './execution-governance.mjs';
import { applyArchitectureEvent, createArchitectureState } from './architecture-state.mjs';
import { digestValue } from './canonical.mjs';
import { consumeForwardedWorkloadReceipt, forwardRequestedWorkload } from './dispatch-scheduler.mjs';
import { verifyCommandResult } from './command-verifier.mjs';
import { EvidenceAuthorityRegistry, classifyTechnologyRequirement, resolveLatencyTarget } from './evidence-authority.mjs';
import { generateTestKeyRing } from './keys.mjs';
import { HostEventLedger } from './host-event-ledger.mjs';
import { ReceiptStore } from './receipt-store.mjs';
import { evaluateResidualRiskCloseAdmission } from './current-user-risk-acceptance.mjs';
import { verifyCurrentUserScopeAmendment } from './current-user-scope-amendment.mjs';
import { deliveryContinuityBindings, executeDeliveryContinuityCase } from './s11-bindings/delivery-continuity.mjs';
import { evidenceClosureRuntimePolicyIds, executeEvidenceClosureRuntimeCase } from './s11-bindings/evidence-closure.mjs';
import { executeGovernanceStateBinding, governanceStateBindingIds } from './s11-bindings/governance-state.mjs';
import { executeM1M6Binding, m1M6BindingIds } from './s11-bindings/m1-m6-production.mjs';
import { executeM7Binding, m7BindingIds } from './s11-bindings/m7-production.mjs';
import { advisoryJudgmentBindings, advisoryJudgmentRuntimeIds, validateAdvisoryJudgmentObservation } from './s11-bindings/advisory-judgment.mjs';
import { adrCanonClarifyBindingIds, executeAdrCanonClarifyBinding, validateAdrCanonClarifyObservation } from './s11-bindings/eval-adr-canon-clarify.mjs';
import { adversarialBindingIds, executeAdversarialBinding, validateAdversarialObservation } from './s11-bindings/eval-adversarial.mjs';
import { candidateQualityBindingIds, executeCandidateQualityCase, validateCandidateQualityObservation } from './s11-bindings/eval-candidate-quality.mjs';
import { concurrencyConvergenceBindingIds, executeConcurrencyConvergenceCase, validateConcurrencyConvergenceObservation } from './s11-bindings/eval-concurrency-convergence.mjs';
import { handoffNegativeBindingIds, executeHandoffNegativeCase, validateHandoffNegativeObservation } from './s11-bindings/eval-handoff-negative.mjs';
import { reviewSecurityRuntimeIds, executeReviewSecurityBinding, reviewSecurityBlockers, validateReviewSecurityObservation } from './s11-bindings/eval-review-security.mjs';
import { adversarialProportionalityBindingIds, executeAdversarialProportionalityCase, validateAdversarialProportionalityObservation } from './adversarial-proportionality.mjs';
import { adversarialMigrationDistributedBindingIds, executeAdversarialMigrationDistributedCase, validateAdversarialMigrationDistributedObservation } from './adversarial-migration-distributed.mjs';
import { adversarialOwnershipEconomicsBindingIds, executeAdversarialOwnershipEconomicsCase, validateAdversarialOwnershipEconomicsObservation } from './adversarial-ownership-economics.mjs';
import { AI_RECONSTRUCTION_BINDING_IDS, executeAdversarialAiReconstructionCase, validateAdversarialAiReconstructionObservation } from './adversarial-ai-reconstruction.mjs';
import { evaluateCalibrationConvergenceCase, validateCalibrationConvergenceObservation } from './calibration-convergence-policy.mjs';
import { evaluateReviewDispositionCase, reviewDispositionPolicyIds, validateReviewDispositionDecision } from './review-disposition-policy.mjs';
import { completionIntegratedState } from './completion-state.mjs';

// One scenario has one runtime owner. Newer M1-M7 production consumers replace
// their older test-only adapters; registration rejects every remaining overlap.
const M1_M6_IDS = m1M6BindingIds();
const M7_IDS = m7BindingIds();
const M1_M6_SET = new Set(M1_M6_IDS);
const M7_SET = new Set(M7_IDS);
const LATEST_RUNTIME_IDS = Object.freeze(['AE-CONVERGENCE-002', 'AE-CONVERGENCE-005', 'AE-FORWARD-WORKLOAD-001', 'AE-RETRY-SEMANTICS-001', 'AE-RETRY-SEMANTICS-003', 'AE-RETRY-SEMANTICS-004']);
const LATEST_RUNTIME_SET = new Set(LATEST_RUNTIME_IDS);
const CURRENT_USER_IDS = Object.freeze(['AE-AUTHORITY-001', 'AE-SCOPE-AUTHORITY-001']);
const CURRENT_USER_SET = new Set(CURRENT_USER_IDS);
const COMMAND_VERIFIER_IDS = Object.freeze(['AE-REVIEW-VERDICT-SECURITY-001']);
const EVIDENCE_AUTHORITY_IDS = Object.freeze(['AE-EVIDENCE-001', 'AE-EVIDENCE-002']);
const EVIDENCE_AUTHORITY_SET = new Set(EVIDENCE_AUTHORITY_IDS);
const CASE_EVALUATOR_IDS = Object.freeze([
  ...adrCanonClarifyBindingIds(), ...adversarialBindingIds(), ...candidateQualityBindingIds(),
  ...concurrencyConvergenceBindingIds(), ...handoffNegativeBindingIds(), ...reviewSecurityRuntimeIds(),
]);
const CASE_EVALUATOR_SET = new Set(CASE_EVALUATOR_IDS);
const ADVERSARIAL_CAPABILITY_IDS = Object.freeze([
  ...adversarialProportionalityBindingIds(), ...adversarialMigrationDistributedBindingIds(),
  ...adversarialOwnershipEconomicsBindingIds(), ...AI_RECONSTRUCTION_BINDING_IDS,
]);
const ADVERSARIAL_CAPABILITY_SET = new Set(ADVERSARIAL_CAPABILITY_IDS);
const CALIBRATION_CONVERGENCE_IDS = Object.freeze(['AE-CONTROL-PLANE-BUDGETS-002', 'AE-CONVERGENCE-001', 'AE-CONVERGENCE-003']);
const CALIBRATION_CONVERGENCE_SET = new Set(CALIBRATION_CONVERGENCE_IDS);
const REVIEW_DISPOSITION_SET = new Set(reviewDispositionPolicyIds);
const SOURCE_SCOPE = Object.freeze(['packages/arcane/**', 'scripts/**', 'evals/architecture/**']);

function bindingOwners() {
  const owners = new Map();
  const sources = [
    ['m1-m6-production', M1_M6_IDS],
    ['m7-production', M7_IDS],
    ['latest-runtime', LATEST_RUNTIME_IDS],
    ['current-user-authority', CURRENT_USER_IDS],
    ['command-verifier', COMMAND_VERIFIER_IDS],
    ['evidence-authority', EVIDENCE_AUTHORITY_IDS],
    ['eval-adr-canon-clarify', adrCanonClarifyBindingIds()],
    ['adversarial-capability', ADVERSARIAL_CAPABILITY_IDS],
    ['calibration-convergence-policy', CALIBRATION_CONVERGENCE_IDS],
    ['review-disposition-policy', reviewDispositionPolicyIds],
    ['eval-adversarial', adversarialBindingIds().filter((id) => !ADVERSARIAL_CAPABILITY_SET.has(id))],
    ['eval-candidate-quality', candidateQualityBindingIds()],
    ['eval-concurrency-convergence', concurrencyConvergenceBindingIds().filter((id) => !CALIBRATION_CONVERGENCE_SET.has(id))],
    ['eval-handoff-negative', handoffNegativeBindingIds().filter((id) => !REVIEW_DISPOSITION_SET.has(id))],
    ['eval-review-security', reviewSecurityRuntimeIds().filter((id) => !REVIEW_DISPOSITION_SET.has(id))],
    ['advisory-judgment', advisoryJudgmentRuntimeIds().filter((id) => !CURRENT_USER_SET.has(id) && !CASE_EVALUATOR_SET.has(id))],
    ['authority-review', Object.keys(authorityReviewBindings)],
    ['delivery-continuity', deliveryContinuityBindings().filter((id) => !M1_M6_SET.has(id))],
    ['evidence-closure', evidenceClosureRuntimePolicyIds().filter((id) => !M1_M6_SET.has(id) && !EVIDENCE_AUTHORITY_SET.has(id))],
    ['governance-state', governanceStateBindingIds().filter((id) => !M7_SET.has(id) && !LATEST_RUNTIME_SET.has(id))],
  ];
  for (const [owner, ids] of sources) for (const id of ids) {
    if (owners.has(id)) throw new Error(`S11 duplicate binding ${id}: ${owners.get(id)} and ${owner}`);
    owners.set(id, owner);
  }
  return owners;
}

const OWNERS = bindingOwners();
export function runtimePolicyIds() { return Object.freeze([...OWNERS.keys()].sort()); }

const pending = (row, reason) => Object.freeze({ id: row.id, family: row.family, status: 'PENDING', reason });
const failed = (row, source, error) => Object.freeze({ id: row.id, family: row.family, status: 'FAIL', reason: `${source} binding failed: ${error.message}` });
const resultValue = (value) => value?.value;

function hasLiveObservation(value) {
  return typeof value?.producer === 'string' && value.producer.length > 0 && typeof value?.consumer === 'string' && value.consumer.length > 0 && value.value && typeof value.value === 'object';
}

function validateM1M6(id, value) {
  const v = resultValue(value);
  switch (id) {
    case 'AE-RETRY-SEMANTICS-002': return v?.terminal?.code === 'IDENTICAL_RETRY';
    case 'AE-NEGATIVE-TRIGGERS-002': return v?.unchanged?.terminal?.code === 'IDENTICAL_RETRY' && v?.changed?.allowed === true;
    case 'AE-STOP-PRECEDENCE-001': return v?.terminal?.code === 'EXPLICIT_STOP';
    case 'AE-REHYDRATION-INJECTION-001': case 'AE-REHYDRATION-INJECTION-002': return v?.classification === 'UNTRUSTED_DATA' && v?.authority_granted === false;
    case 'AE-CONCURRENCY-ATTENTION-001': return v?.outcome === 'CAPACITY_ADMITTED' && v?.limit === 1 && v?.deferred?.length === 2;
    case 'AE-CONCURRENCY-ATTENTION-003': return v?.outcome === 'PREPARATION_ADMITTED';
    case 'AE-CONCURRENCY-ATTENTION-004': return v?.outcome === 'ACTIVATION_DENIED' && v?.code === 'ARC_PRODUCER_PROOF_MISSING';
    case 'AE-HANDOFF-001': return v?.first?.outcome === 'PACKET_ADMITTED' && v?.second?.code === 'ARC_PACKET_DIGEST_REPLAY';
    case 'AE-HANDOFF-003': return v?.status === 'READY_WITH_ASSUMPTIONS' && v?.requiredAction === 'test_assumptions';
    case 'AE-HANDOFF-005': return v?.decisionStatus === 'frozen' && v?.realizationStatus === 'diverged' && v?.correctionRoute === 'alchemist';
    case 'AE-OWNERSHIP-DISPOSITION-001': return v?.outcome === 'LOCAL_REPAIR_PERMITTED' && v?.canonicalOwnershipRewrite === false;
    case 'AE-DEFICIT-PROPAGATION-001': return v?.detail?.claimCeiling === 'COMPLETE_WITH_DEBT';
    case 'AE-DEFICIT-PROPAGATION-002': case 'AE-DEFICIT-PROPAGATION-003': return v?.code === 'ARC_CLAIM_PREREQUISITE_UNMET';
    case 'AE-OUTCOME-CLOSURE-001': return v?.code === 'ARC_EVIDENCE_INSUFFICIENT' && v?.detail?.acceptanceSurface === 'UNOBSERVED';
    case 'AE-FINDING-LIFECYCLE-001': return v?.count === 1 && v?.second?.disposition === 'EXISTING_RECORD';
    case 'AE-FINDING-LIFECYCLE-002': return v?.code === 'ARC_SELF_CERTIFICATION';
    case 'AE-FINDING-LIFECYCLE-003': return v?.closed?.length === 1 && v?.deferred?.[0]?.disposition === 'DEFERRED_INFORMATIONAL';
    case 'AE-REVIEW-VERDICT-SECURITY-004': return v?.blocking?.length === 1 && v?.informational?.length === 1;
    case 'AE-EVIDENCE-003': return v?.eliminated?.[0]?.phase === 'HARD_GATE' && v?.ranked?.[0]?.candidate?.id === 'eligible';
    case 'AE-EVIDENCE-ARTIFACTS-001': case 'AE-EVIDENCE-ARTIFACTS-003': return v?.code === 'ARC_UNSOUND_SEAL' && v?.detail?.admission === 'INFORMATIONAL_ONLY';
    case 'AE-EVIDENCE-ARTIFACTS-002': return v?.code === 'ARC_UNSOUND_SEAL' && v?.detail?.missing?.includes('deletionOwner');
    case 'AE-EVIDENCE-FRESHNESS-002': return v?.waiver?.lifecycle === 'REFRESH_REQUIRED' && v?.waiver?.visible === true;
    case 'AE-MACHINERY-DEFECTS-002': return v?.code === 'ARC_RECOVERY_RESUMED' && v?.verification === 'PASS';
    case 'AE-MIGRATION-CUTOVER-001': return v?.code === 'ARC_MIGRATION_ABSENCE_PROOF_FAILED' && v?.ready === false;
    case 'AE-MIGRATION-CUTOVER-002': return v?.code === 'ARC_MIGRATION_READINESS_FAILED' && v?.ready === false;
    case 'AE-CONTROL-RETIREMENT-001': return v?.code === 'ARC_RETIREMENT_DENIED' && v?.status === 'ACTIVE';
    default: return false;
  }
}

function validateM7(id, value) {
  const v = resultValue(value);
  if (id === 'AE-STATE-TRANSITIONS-REPLAY-002') return v?.acceptedFingerprint === v?.replayFingerprint && v?.eventCount === 6 && v?.authorityMinted === false;
  if (id === 'AE-CONVERGENCE-006') return v?.revisions === 3 && v?.terminalDisposition === 'DECIDE_WITH_DEBT' && v?.fourthRejected === true;
  if (id === 'AE-TRAJECTORY-RESUME-002') return v?.valid === false && v?.reason === 'binding_mismatch' && v?.mismatches?.includes('intent_epoch');
  return false;
}

function validateAdvisoryJudgment(row, value) {
  return validateAdvisoryJudgmentObservation(row, value);
}

const convergenceCandidate = Object.freeze({ goal_fingerprint: 'goal:s11', evidence_fingerprint: 'evidence:s11', constraints_fingerprint: 'constraints:s11', candidate_fingerprint: 'candidate:s11', blockers_fingerprint: 'blockers:s11' });
const retryAttempt = (id, overrides = {}) => ({ id, failure_fingerprint: 'failure:s11', diagnosis_fingerprint: 'diagnosis:s11', input_fingerprint: 'input:s11', method_fingerprint: 'method:s11', ...overrides });

function executeLatestRuntimeBinding(id) {
  if (id === 'AE-CONVERGENCE-002') return { producer: 'admitConvergencePass', consumer: 'convergence terminal admission', value: admitConvergencePass({ passes: [convergenceCandidate], candidate: convergenceCandidate }) };
  if (id === 'AE-CONVERGENCE-005') {
    let state = createArchitectureState({ objective_lineage_id: 's11:convergence-cone', budget_ref: 's11', acceptance_ledger: { schema: 'acceptance-ledger.v1', ledger_version: 1, intent_epoch: 1, acceptance_fingerprint: digestValue('s11:convergence-cone'), frozen_at: '2026-08-15T00:00:00.000Z', items: [] } });
    for (const id of ['D-1', 'D-2', 'D-3']) state = applyArchitectureEvent(state, { event_type: 'DECISION_RECORDED', payload: { id, status: 'FROZEN' } });
    state = applyArchitectureEvent(state, { event_type: 'INVALIDATION_RECORDED', payload: { scope: 'PATCH', cause: 'FAILED_FALSIFICATION:D-3', root_evidence: null, decision_ids: ['D-3'] } });
    return { producer: 'architecture-state.applyArchitectureEvent', consumer: 'named decision invalidation cone', value: state.convergence.invalidation };
  }
  if (id === 'AE-RETRY-SEMANTICS-001') return { producer: 'settleFlakyRetry', consumer: 'flaky retry disposition', value: settleFlakyRetry({ failure_fingerprint: 'failure:flaky', outcome: 'PASSED', best_artifact_ref: 'artifact:best' }) };
  if (id === 'AE-RETRY-SEMANTICS-003') return { producer: 'classifyRetryFailure', consumer: 'retry eligibility admission', value: classifyRetryFailure({ failure_class: 'AUTHENTICATION' }) };
  if (id === 'AE-RETRY-SEMANTICS-004') return { producer: 'admitRetry', consumer: 'behavioral retry loop terminal', value: admitRetry({ attempts: [retryAttempt('a')], candidate: retryAttempt('b', { diagnosis_fingerprint: 'diagnosis:changed', method_fingerprint: 'method:changed' }) }) };
  if (id === 'AE-FORWARD-WORKLOAD-001') {
    const keyRing = generateTestKeyRing(['s11']); const requestedWorkflow = { id: 'representative-workload', digest: digestValue({ workflow: 'representative' }) };
    const receipt = forwardRequestedWorkload({ runId: 's11-run', taskId: id, contractId: 's11-contract', requestedWorkflow, machineryDefect: { code: 'ARC_GATE_INVALID', classification: 'OUT_OF_SCOPE_MACHINERY_DEFECT' }, executeRequestedWorkflow: ({ id: workflowId }) => ({ workflowId, executionState: 'COMPLETED', output: { artifact: 'representative-workload-output' } }), observedAt: '2026-08-15T00:00:00.000Z' }, { keyRing, keyId: 's11' });
    return { producer: 'forwardRequestedWorkload', consumer: 'consumeForwardedWorkloadReceipt', value: consumeForwardedWorkloadReceipt(receipt, { runId: 's11-run', taskId: id, contractId: 's11-contract', requestedWorkflowId: requestedWorkflow.id, requestedWorkflowDigest: requestedWorkflow.digest }, { keyRing }) };
  }
  return null;
}

function validateLatestRuntimeBinding(id, value) {
  const v = value?.value;
  if (id === 'AE-CONVERGENCE-002') return v?.terminal?.code === 'LOOP_VIOLATION';
  if (id === 'AE-CONVERGENCE-005') return v?.scope === 'PATCH' && v?.cause === 'FAILED_FALSIFICATION:D-3' && v?.decision_ids?.length === 1 && v.decision_ids[0] === 'D-3';
  if (id === 'AE-RETRY-SEMANTICS-001') return v?.disposition === 'FLAKY_PASS_RECORDED' && v?.pass_recorded === true;
  if (id === 'AE-RETRY-SEMANTICS-003') return v?.retryable === false && v?.terminal?.code === 'NON_RETRYABLE' && v?.terminal?.detail?.blocker === 'AUTHENTICATION_REQUIRED';
  if (id === 'AE-RETRY-SEMANTICS-004') return v?.terminal?.code === 'LOOP_VIOLATION';
  if (id === 'AE-FORWARD-WORKLOAD-001') return v?.allowed === true && v?.detail?.continuation === 'CONTINUED_DESPITE_MACHINERY_DEFECT' && v?.detail?.execution?.executionState === 'COMPLETED';
  return false;
}

function currentUserFixture(kind) {
  const root = mkdtempSync(join(tmpdir(), `arcane-s11-${kind}-`));
  const keyRing = generateTestKeyRing(['s11']); const now = new Date('2026-08-15T00:00:00.000Z');
  const ledgerStore = new HostEventLedger({ root: join(root, 'events'), keyRing, keyId: 's11', clock: () => now.toISOString() });
  const receiptStore = new ReceiptStore({ root: join(root, 'receipts') });
  const binding = { runId: 's11-run', taskId: kind, contractId: 's11-contract', contractVersion: 1, contractDigest: digestValue('s11-contract') };
  const payload = { prompt: `S11 ${kind} challenge` };
  const hostEvent = ledgerStore.append({ eventId: 's11-user-prompt', adapter: 'codex', eventType: 'UserPromptSubmit', sessionId: 's11-session', binding, sourceRevision: 's11', observedAuthority: 'current-user', payload });
  return { root, keyRing, ledgerStore, receiptStore, now, promptDigest: digestValue(hostEvent), challengeToken: payload.prompt };
}

function executeCurrentUserBinding(id) {
  const fixture = currentUserFixture(id);
  try {
    if (id === 'AE-AUTHORITY-001') {
      const expected = { riskId: 'R-s11', riskDigest: digestValue('risk'), acceptanceLedgerFingerprint: digestValue('ledger'), integratedStateIdentity: digestValue('state'), sourceSetDigest: digestValue('source'), userPromptEventDigest: fixture.promptDigest, challengeToken: fixture.challengeToken };
      return { producer: 'current-user-risk-acceptance host ingress', consumer: 'evaluateResidualRiskCloseAdmission', value: evaluateResidualRiskCloseAdmission(expected, { ledgerStore: fixture.ledgerStore, receiptStore: fixture.receiptStore, keyRing: fixture.keyRing, now: fixture.now }) };
    }
    const expected = { acceptanceId: 'AC-s11', oldAcceptanceFingerprint: digestValue('old'), newAcceptanceFingerprint: digestValue('new'), sourceSetDigest: digestValue('source'), integratedStateIdentity: digestValue('state'), userPromptEventDigest: fixture.promptDigest, challengeToken: fixture.challengeToken };
    return { producer: 'current-user-scope-amendment host ingress', consumer: 'verifyCurrentUserScopeAmendment', value: verifyCurrentUserScopeAmendment(expected, { ledgerStore: fixture.ledgerStore, receiptStore: fixture.receiptStore, keyRing: fixture.keyRing, now: fixture.now }) };
  } finally { rmSync(fixture.root, { recursive: true, force: true }); }
}

function validateCurrentUserBinding(id, value) {
  const v = value?.value;
  if (id === 'AE-AUTHORITY-001') return v?.allowed === false && v?.closeDisposition === 'BLOCKED' && v?.code === 'ACCEPTANCE_AUTHORITY_MISSING';
  if (id === 'AE-SCOPE-AUTHORITY-001') return v?.allowed === false && v?.code === 'ARC_APPROVAL_REQUIRED' && v?.detail?.disposition === 'OUT_OF_SCOPE';
  return false;
}

function executeCommandVerifierBinding() {
  const expectedOutput = { verdict: { status: 'PASS' }, artifact: { id: 's11-command-receipt' } };
  return { producer: 'command-verifier.verifyCommandResult', consumer: 'structured subprocess verdict admission', value: verifyCommandResult({ exitCode: 1, structuredOutput: { ...expectedOutput, stdout: 'PASS' } }, { expectedOutput }) };
}

function executeEvidenceAuthorityBinding(id) {
  const registry = new EvidenceAuthorityRegistry();
  if (id === 'AE-EVIDENCE-001') return { producer: 'evidence-authority.resolveLatencyTarget', consumer: 'authorized latency target resolution', value: resolveLatencyTarget({ scopeId: 'checkout', targetMs: null, assumption: null, authorityRequest: { id: 'ask-product', question: 'What latency target is authorized?' } }, { registry }) };
  return { producer: 'evidence-authority.classifyTechnologyRequirement', consumer: 'technology requirement classification', value: classifyTechnologyRequirement({ scopeId: 'payments', technology: 'Kubernetes', consequence: null }, { registry }) };
}

function pass(row, source, observation) {
  if (!observation) return pending(row, `${source} did not emit a structured production observation`);
  const integratedState = completionIntegratedState(process.cwd(), SOURCE_SCOPE);
  if (!integratedState) return pending(row, `current integrated source identity is unavailable for ${source}`);
  return Object.freeze({ id: row.id, family: row.family, status: 'PASS', reason: `${source} structured live ingress/consumer observation bound to ${integratedState}` });
}

function validateAuthority(row, value) {
  const observed = value?.observed;
  if (!value?.state_identity) return false;
  if (row.id === 'AE-SCOPE-AUTHORITY-002') return observed?.code === 'ARC_AUTHORITY_NOT_ASSERTED';
  if (row.id === 'AE-REVIEW-VERDICT-SECURITY-003') return observed?.verdict?.allowed === true;
  if (row.id === 'AE-OWNERSHIP-DISPOSITION-002') return observed?.code === 'ARC_INTEGRATION_OWNER_CONFLICT';
  if (row.id === 'AE-ADVERSARIAL-008') return Array.isArray(observed?.affectedClaims) && observed.affectedClaims.length === 1 && observed.affectedClaims[0] === 'decision-affected';
  return false;
}

function validateDelivery(row, value) {
  const observed = value?.observed;
  if (row.id === 'AE-INTEGRATION-OWNERSHIP-001' || row.id === 'AE-CONCURRENCY-ATTENTION-005') return observed?.code === 'ARC_INTEGRATION_OWNER_CONFLICT';
  if (row.id === 'AE-CONTROL-PLANE-BUDGETS-001' || row.id === 'AE-LINEAGE-BUDGETS-001') return observed?.terminal === 'ACTIVE_CAP';
  if (row.id === 'AE-MACHINERY-DEFECTS-001') return observed?.machinery_defect === 'OUT_OF_SCOPE_MACHINERY_DEFECT';
  return false;
}

function validateGovernance(row, value) {
  const consumer = value?.consumer;
  switch (row.id) {
    case 'AE-ROUTING-001': case 'AE-ROUTING-002': return consumer?.depth === 'D0' && consumer?.objective === 'sufficient';
    case 'AE-ROUTING-003': return consumer?.depth === 'D1' && consumer?.rigor === 'standard';
    case 'AE-ROUTING-004': return consumer?.objective === 'optimize' && consumer?.optimize_axis === 'startup';
    case 'AE-CANDIDATE-QUALITY-003': return consumer?.depth === 'D2' && consumer?.objective === 'best_shape';
    case 'AE-CONVERGENCE-004': return consumer?.invalidation?.scope === 'PATCH' && consumer?.invalidation?.cause === 'FAILED_FALSIFICATION:D-3' && consumer?.decisions?.length === 1 && consumer.decisions[0]?.id === 'D-3';
    case 'AE-EFFECT-CLASSIFICATION-001': return consumer?.matched_rule === 'safe_default' && consumer?.door === 'authority_sensitive';
    case 'AE-EFFECT-CLASSIFICATION-002': return consumer?.process_group_quiescent === true;
    case 'AE-TRAJECTORY-RESUME-001': return consumer?.verification?.valid === true && consumer?.duplicate_denied === true && consumer.verification.completed_effect_ids?.includes('effect-1');
    case 'AE-TRAJECTORY-RESUME-003': return consumer?.valid === false && consumer?.reason === 'binding_mismatch' && consumer?.mismatches?.includes('repository_state') && consumer?.invalidation_scope === 'dependency_cone';
    case 'AE-STATE-TRANSITIONS-REPLAY-001': return consumer?.rejected_transition === true && typeof consumer?.prior_fingerprint === 'string';
    case 'AE-ROUTING-005': return consumer?.self_upgrade_rejected === true;
    default: return false;
  }
}

async function execute(row) {
  const owner = OWNERS.get(row.id);
  if (owner === 'm1-m6-production') {
    const value = executeM1M6Binding(row.id);
    return hasLiveObservation(value) && validateM1M6(row.id, value) ? pass(row, owner, value) : pending(row, `m1-m6 production observation does not cover ${row.id} semantics`);
  }
  if (owner === 'm7-production') {
    const value = executeM7Binding(row.id);
    return hasLiveObservation(value) && validateM7(row.id, value) ? pass(row, owner, value) : pending(row, `m7 production observation does not cover ${row.id} semantics`);
  }
  if (owner === 'latest-runtime') {
    const value = executeLatestRuntimeBinding(row.id);
    return hasLiveObservation(value) && validateLatestRuntimeBinding(row.id, value) ? pass(row, owner, value) : pending(row, `latest production observation does not cover ${row.id} semantics`);
  }
  if (owner === 'current-user-authority') {
    const value = executeCurrentUserBinding(row.id);
    return hasLiveObservation(value) && validateCurrentUserBinding(row.id, value) ? pass(row, owner, value) : pending(row, `current-user authority observation does not cover ${row.id} semantics`);
  }
  if (owner === 'command-verifier') {
    const value = executeCommandVerifierBinding(row.id);
    return hasLiveObservation(value) && value.value?.allowed === false && value.value?.code === 'ARC_EVIDENCE_INSUFFICIENT' && value.value?.detail?.exitCode === 1 ? pass(row, owner, value) : pending(row, `command-verifier observation does not cover ${row.id} semantics`);
  }
  if (owner === 'evidence-authority') {
    const value = executeEvidenceAuthorityBinding(row.id);
    const valid = row.id === 'AE-EVIDENCE-001'
      ? value.value?.detail?.disposition === 'AUTHORITY_REQUEST'
      : value.value?.detail?.classification === 'PREFERENCE';
    return hasLiveObservation(value) && valid ? pass(row, owner, value) : pending(row, `evidence-authority observation does not cover ${row.id} semantics`);
  }
  if (owner === 'eval-adr-canon-clarify') {
    const value = executeAdrCanonClarifyBinding(row.id);
    if (value?.status === 'PENDING') return pending(row, value.missingProducer ?? `missing evaluator input for ${row.id}`);
    return validateAdrCanonClarifyObservation(row.id, value) ? pass(row, owner, value) : pending(row, `ADR/canon/clarification observation does not cover ${row.id} semantics`);
  }
  if (owner === 'adversarial-capability') {
    let value;
    if (adversarialProportionalityBindingIds().includes(row.id)) value = executeAdversarialProportionalityCase(row);
    else if (adversarialMigrationDistributedBindingIds().includes(row.id)) value = executeAdversarialMigrationDistributedCase(row);
    else if (adversarialOwnershipEconomicsBindingIds().includes(row.id)) value = executeAdversarialOwnershipEconomicsCase(row);
    else {
      const input = row.id === 'AE-ADVERSARIAL-009'
        ? { systemId: 'assistant-routing', provenance: [{ sourceRef: 'registry:model-v4', digest: 'sha256:model-v4' }], evaluation: { status: 'PASS', reportRef: 'eval:s11', evaluatedAt: '2026-08-15T00:00:00.000Z', metrics: { safety: 1 } }, fallback: { mode: 'deterministic-rules', owner: 'ops', testedAt: '2026-08-15T00:00:00.000Z' }, humanAuthority: { role: 'risk-owner', authorityRef: 'authority:risk-owner', approvedAt: '2026-08-15T00:00:00.000Z' } }
        : { asOf: '2026-08-15T00:00:00.000Z', evidence: [{ scope: 'topology', sourceRef: 'cortex:topology', observedAt: '2026-08-10T00:00:00.000Z', expiresAt: '2026-09-01T00:00:00.000Z' }, { scope: 'runtime', sourceRef: 'runtime:stale', observedAt: '2026-07-01T00:00:00.000Z', expiresAt: '2026-07-02T00:00:00.000Z' }, { scope: 'ownership', sourceRef: 'owners:map', observedAt: '2026-08-10T00:00:00.000Z', expiresAt: '2026-09-01T00:00:00.000Z' }] };
      value = executeAdversarialAiReconstructionCase(row.id, input);
    }
    const observed = value?.observed ?? value;
    const valid = adversarialProportionalityBindingIds().includes(row.id) ? validateAdversarialProportionalityObservation(row.id, observed)
      : adversarialMigrationDistributedBindingIds().includes(row.id) ? validateAdversarialMigrationDistributedObservation(row.id, observed)
      : adversarialOwnershipEconomicsBindingIds().includes(row.id) ? validateAdversarialOwnershipEconomicsObservation(row.id, observed)
      : validateAdversarialAiReconstructionObservation(row.id, observed);
    if (value?.status === 'FAIL') return failed(row, owner, new Error(value.reason));
    return valid ? pass(row, owner, observed) : pending(row, `adversarial capability observation does not cover ${row.id} semantics`);
  }
  if (owner === 'calibration-convergence-policy') {
    const value = evaluateCalibrationConvergenceCase(row.id);
    return validateCalibrationConvergenceObservation(row.id, value) ? pass(row, owner, value) : pending(row, `calibration/convergence observation does not cover ${row.id} semantics`);
  }
  if (owner === 'review-disposition-policy') {
    const evidence = row.id === 'AE-HANDOFF-004'
      ? { irreversible: true, uncertainty: true, reviewBudget: { exhausted: true }, externalBlock: false, budgetStop: false }
      : row.id === 'AE-REVIEW-VERDICT-SECURITY-002'
        ? { nodes: ['entry', 'sink'], links: [{ from: 'entry', to: 'sink', demonstrated: false, evidenceId: '' }], coverage: { claimedAreas: ['entry', 'sink', 'auth'], inspectedAreas: ['entry', 'sink'] } }
        : { reviewClosed: true, findings: [{ id: 'style-note', blocking: false, disposition: 'ADVISORY' }] };
    const value = evaluateReviewDispositionCase(row.id, evidence);
    return validateReviewDispositionDecision(row.id, value) ? pass(row, owner, value) : pending(row, `review disposition observation does not cover ${row.id} semantics`);
  }
  if (owner === 'eval-adversarial') {
    const value = executeAdversarialBinding(row.id);
    if (value?.status === 'PENDING') return pending(row, value.reason);
    return validateAdversarialObservation(row.id, value) ? pass(row, owner, value) : pending(row, `adversarial observation does not cover ${row.id} semantics`);
  }
  if (owner === 'eval-candidate-quality') {
    const value = executeCandidateQualityCase(row);
    if (value?.status === 'FAIL') return failed(row, owner, new Error(value.reason));
    return value?.status === 'PASS' && validateCandidateQualityObservation(row.id, value.observed) ? pass(row, owner, value.observed) : pending(row, `candidate-quality observation does not cover ${row.id} semantics`);
  }
  if (owner === 'eval-concurrency-convergence') {
    const value = executeConcurrencyConvergenceCase(row);
    if (value?.status === 'PENDING') return pending(row, value.reason);
    if (value?.status === 'FAIL') return failed(row, owner, new Error(value.reason));
    return value?.status === 'PASS' && validateConcurrencyConvergenceObservation(row.id, value.observed) ? pass(row, owner, value.observed) : pending(row, `concurrency/convergence observation does not cover ${row.id} semantics`);
  }
  if (owner === 'eval-handoff-negative') {
    const value = executeHandoffNegativeCase(row);
    if (value?.status === 'PENDING') return pending(row, value.reason);
    if (value?.status === 'FAIL') return failed(row, owner, new Error(value.reason));
    return value?.status === 'PASS' && validateHandoffNegativeObservation(row.id, value.observed) ? pass(row, owner, value.observed) : pending(row, `handoff/negative-trigger observation does not cover ${row.id} semantics`);
  }
  if (owner === 'eval-review-security') {
    const value = executeReviewSecurityBinding(row.id);
    if (value?.value?.status === 'PENDING') return pending(row, reviewSecurityBlockers[row.id] ?? value.value.reason);
    return validateReviewSecurityObservation(row.id, value) ? pass(row, owner, value) : pending(row, `review/security observation does not cover ${row.id} semantics`);
  }
  if (owner === 'advisory-judgment') {
    const value = advisoryJudgmentBindings[row.id](row);
    return validateAdvisoryJudgment(row, value) ? pass(row, owner, value) : pending(row, `advisory-judgment observation does not cover ${row.id} exact Sage/Oracle semantics`);
  }
  if (owner === 'authority-review') {
    const value = authorityReviewBindings[row.id]();
    return validateAuthority(row, value) ? pass(row, owner, value) : pending(row, `authority-review observation does not cover ${row.id} semantics`);
  }
  if (owner === 'delivery-continuity') {
    const value = executeDeliveryContinuityCase(row);
    if (value.status === 'FAIL') return failed(row, owner, new Error(value.reason));
    return validateDelivery(row, value) ? pass(row, owner, value) : pending(row, `delivery-continuity observation does not cover ${row.id} semantics`);
  }
  if (owner === 'evidence-closure') {
    const value = executeEvidenceClosureRuntimeCase(row);
    if (value.status === 'FAIL') return failed(row, owner, new Error(value.reason));
    if (value.status === 'PASS' && typeof value.integratedStateIdentity === 'string') return pass(row, owner, value);
    return pending(row, value.missingCapability ? `missing production capability: ${value.missingCapability}` : `evidence-closure result lacks structured semantics for ${row.id}`);
  }
  if (owner === 'governance-state') {
    const value = await executeGovernanceStateBinding(row.id);
    return validateGovernance(row, value) ? pass(row, owner, value) : pending(row, `governance-state observation does not cover ${row.id} semantics`);
  }
  if (authorityReviewBlockers[row.id]) return pending(row, `missing production capability: ${authorityReviewBlockers[row.id]}`);
  return pending(row, `missing case-specific production ingress, consumer, durable/direct output, and integrated-state binding for ${row.id} (${row.family})`);
}

export async function executeArchitectureRuntimeCases(rows) {
  return Object.freeze(await Promise.all([...rows].sort((left, right) => left.id.localeCompare(right.id)).map(async (row) => {
    try { return await execute(row); } catch (error) { return failed(row, OWNERS.get(row.id) ?? 'unbound', error); }
  })));
}
