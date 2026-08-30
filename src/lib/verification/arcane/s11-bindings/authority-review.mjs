// Case-specific S11 observations for authority and review controls.  This is
// deliberately an adapter over existing ingress points, never a policy clone.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createArchitectureState, applyArchitectureEvent, validateArchitectureState } from '../architecture-state.mjs';
import { digestValue } from '../../../contracts/arcane/canonical.mjs';
import { BudgetGovernanceStore, BUDGET_AMENDMENT_BOUND_FIELDS, BUDGET_BOUND_FIELDS, AMENDED_BUDGET_BOUND_FIELDS } from '../../../cli/commands/governance/execution/budget-governance-store.mjs';
import { generateTestKeyRing } from '../../../guard/compat/host/keys.mjs';
import { signRecord } from '../../../guard/compat/audit/receipt-auth.mjs';
import { openDelivery, finalizeClose } from '../../../cli/commands/governance/delivery/delivery-guard.mjs';
import { DependencyLedger } from '../invalidation.mjs';
import { AcceptanceEvidenceRegistry } from '../evidence-registry.mjs';
import { buildAssurancePacket } from '../assurance-packet.mjs';

const NOW = '2026-08-14T00:00:00.000Z';

function stateIdentity(caseId, ingress, observed) {
  const initial = createArchitectureState({
    objective_lineage_id: `s11:${caseId}`,
    budget_ref: 's11-observation-only',
    acceptance_ledger: { schema: 'acceptance-ledger.v1', ledger_version: 1, intent_epoch: 1, acceptance_fingerprint: digestValue(caseId), frozen_at: NOW, items: [] },
  });
  const state = applyArchitectureEvent(initial, { event_type: 'ROUTE_CLASSIFIED', payload: { ingress, observed_digest: digestValue(observed) } });
  if (!validateArchitectureState(state).valid) throw new Error('architecture state rejected live observation');
  return state.state_fingerprint;
}

function observed(caseId, ingress, result) {
  return Object.freeze({ observed: Object.freeze(result), state_identity: stateIdentity(caseId, ingress, result) });
}

function budget(id, version) {
  return { schemaVersion: 1, kind: 'arcane-budget-governance', contractId: id, version, contractDigest: digestValue({ id, version }), objectiveLineageId: 's11-scope', objectiveDigest: digestValue('s11-scope-objective'), legionBlastMapCapMs: 10, sagePlanningCapMs: 10, maxContractVersions: 2, resumeEvidence: null, amendmentEvidence: null, userScopeExpansionEvidence: null };
}

function scopeAuthority() {
  const root = mkdtempSync(join(tmpdir(), 'arcane-s11-scope-'));
  try {
    const ring = generateTestKeyRing(['s11']);
    const store = new BudgetGovernanceStore({ root, keyRing: ring });
    const first = budget('EC-611', 1);
    first.authentication = signRecord(first, { keyRing: ring, keyId: 's11', boundFields: BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' });
    store.seal(first);
    const next = budget('EC-611', 2);
    next.legionBlastMapCapMs = 11;
    next.amendmentEvidence = { schemaVersion: 1, kind: 'arcane-budget-amendment', priorContractDigest: first.contractDigest, newContractDigest: next.contractDigest, priorLegionBlastMapCapMs: 10, newLegionBlastMapCapMs: 11, priorSagePlanningCapMs: 10, newSagePlanningCapMs: 10, scopeExpanded: true, invocationProofDigest: digestValue('untrusted-reviewer-finding'), observedAt: NOW };
    next.amendmentEvidence.authentication = signRecord(next.amendmentEvidence, { keyRing: ring, keyId: 's11', boundFields: BUDGET_AMENDMENT_BOUND_FIELDS, macDomain: 'arcane-budget-amendment-v1' });
    next.authentication = signRecord(next, { keyRing: ring, keyId: 's11', boundFields: AMENDED_BUDGET_BOUND_FIELDS, macDomain: 'arcane-budget-governance-v1' });
    try { store.seal(next); throw new Error('scope amendment unexpectedly sealed'); }
    catch (error) {
      if (error.message === 'scope amendment unexpectedly sealed') throw error;
      return observed('AE-SCOPE-AUTHORITY-002', 'BudgetGovernanceStore.seal', { allowed: false, code: error.code ?? null, message: error.message, prior_contract_digest: first.contractDigest, attempted_contract_digest: next.contractDigest });
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
}

function reviewArtifactBinding() {
  const integratedState = Object.freeze({ revision: 's11-reviewed' });
  const registry = new AcceptanceEvidenceRegistry();
  const registration = registry.register({ acceptanceId: 'AC-S11', claimType: 'acceptance', producer: 'alchemist', durableStore: 'receipt', verifier: 'oracle', completionConsumer: 'legion', integratedStateBinding: true, validityPolicy: 'exact' });
  const verdict = buildAssurancePacket({ frozenContract: { id: 'EC-S11', version: 1 }, artifacts: [{ acceptanceId: 'AC-S11', authenticated: true, integratedState, producer: 'alchemist', verifier: 'oracle', completionConsumer: 'legion', producerNarrative: 'success' }], evidenceRegistry: registry, producerAuthority: 'alchemist', reviewerAuthority: 'oracle', integratedState });
  return observed('AE-REVIEW-VERDICT-SECURITY-003', 'buildAssurancePacket', { registration, verdict });
}

function writerLease() {
  const root = mkdtempSync(join(tmpdir(), 'arcane-s11-lease-'));
  const owner = { sessionId: 's11-session', runId: 's11-run', taskId: 's11-task' };
  try {
    writeFileSync(join(root, 'README.md'), 's11\n');
    for (const args of [['init', '-q'], ['config', 'user.email', 's11@example.test'], ['config', 'user.name', 's11'], ['add', 'README.md'], ['commit', '-qm', 'seed']]) execFileSync('git', args, { cwd: root });
    const lease = openDelivery({ repositories: [root], readOnly: false, owner });
    try {
      openDelivery({ repositories: [root], readOnly: false, owner: { ...owner, runId: 'second-run' } });
      throw new Error('second writer unexpectedly acquired lease');
    } catch (error) {
      if (error.message === 'second writer unexpectedly acquired lease') throw error;
      return observed('AE-OWNERSHIP-DISPOSITION-002', 'openDelivery', { allowed: false, code: error.code ?? null, message: error.message });
    } finally { finalizeClose(lease, { owner }); }
  } finally { rmSync(root, { recursive: true, force: true }); }
}

function affectedDecisionOnly() {
  const ledger = new DependencyLedger({ clock: () => NOW });
  ledger.register('incident-proof', [{ dimension: 'source', ref: 'incident', digest: 'sha256:old' }]);
  ledger.link('incident-proof', { criterionId: 'criterion-affected', claimId: 'decision-affected' });
  ledger.register('unrelated-proof', [{ dimension: 'source', ref: 'other', digest: 'sha256:still-current' }]);
  ledger.link('unrelated-proof', { criterionId: 'criterion-unaffected', claimId: 'decision-unaffected' });
  return observed('AE-ADVERSARIAL-008', 'DependencyLedger.observeChange', ledger.observeChange({ dimension: 'source', ref: 'incident', digest: 'sha256:new' }));
}

export const authorityReviewBindings = Object.freeze({
  'AE-SCOPE-AUTHORITY-002': scopeAuthority,
  'AE-REVIEW-VERDICT-SECURITY-003': reviewArtifactBinding,
  'AE-OWNERSHIP-DISPOSITION-002': writerLease,
  'AE-ADVERSARIAL-008': affectedDecisionOnly,
});

// These corpus rows intentionally stay pending: none has a production ingress
// whose structured consumer output covers its stated semantic claim.
export const authorityReviewBlockers = Object.freeze({
  'AE-AUTHORITY-001': 'residual-risk acceptance and close-admission ingress is absent',
  'AE-SCOPE-AUTHORITY-001': 'frozen-acceptance amendment disposition ingress is absent',
  'AE-REVIEW-ADMISSION-001': 'review-admission policy ingress is absent',
  'AE-REVIEW-VERDICT-SECURITY-001': 'subprocess exit-status verification ingress is absent',
  'AE-REVIEW-VERDICT-SECURITY-002': 'exploit-chain evidence and coverage-claim ingress is absent',
  'AE-REVIEW-VERDICT-SECURITY-004': 'review finding threshold/disposition ingress is absent',
  'AE-REVIEW-VERDICT-SECURITY-005': 'review reopening disposition ingress is absent',
  'AE-REVIEW-VERDICT-SECURITY-006': 'configured-scope verdict ingress is absent',
  'AE-OWNERSHIP-DISPOSITION-001': 'first-fix versus canonical ownership disposition ingress is absent',
  'AE-ADVERSARIAL-001': 'architecture proportionality assessment ingress is absent',
  'AE-ADVERSARIAL-002': 'mandatory-obligation readiness ingress is absent',
  'AE-ADVERSARIAL-003': 'critical-rigor classification ingress is absent',
  'AE-ADVERSARIAL-004': 'migration target selection ingress is absent',
  'AE-ADVERSARIAL-005': 'distributed failure-mode assessment ingress is absent',
  'AE-ADVERSARIAL-006': 'source-of-truth ownership-conflict ingress is absent',
  'AE-ADVERSARIAL-007': 'adverse-case vendor economics ingress is absent',
  'AE-ADVERSARIAL-009': 'AI readiness governance ingress is absent',
  'AE-ADVERSARIAL-010': 'architecture-reconstruction uncertainty verdict ingress is absent',
  'AE-NEGATIVE-TRIGGERS-001': 'ambient-versus-diagnosis routing ingress is absent',
  'AE-NEGATIVE-TRIGGERS-002': 'diagnosis-state delta guard ingress is absent',
  'AE-NEGATIVE-TRIGGERS-003': 'scoped-search conclusion ingress is absent',
  'AE-NEGATIVE-TRIGGERS-004': 'execution-cost routing ingress is absent',
});

export function authorityReviewRuntimeIds() { return Object.freeze(Object.keys(authorityReviewBindings).sort()); }
