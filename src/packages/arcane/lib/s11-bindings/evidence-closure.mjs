// Case-specific S11 production bindings for evidence closure.  Each supported
// case invokes its real Arcane verifier, then records exact observed state in
// Arcane's architecture-state reducer.  Unsupported cases name missing
// production capability instead of pretending corpus prose is execution.
import { digestValue } from '../canonical.mjs';
import { createArchitectureState, applyArchitectureEvent, validateArchitectureState } from '../architecture-state.mjs';
import { AcceptanceEvidenceRegistry } from '../evidence-registry.mjs';
import { verifyExternalProviderCapability } from '../provider-capability.mjs';
import { compileSealReachability } from '../seal-reachability.mjs';
import { validateGate, executeValidatedGate } from '../gate-validity.mjs';

const NOW = new Date('2026-08-14T00:00:00.000Z');

function observedState(caseId, eventType, payload) {
  const state = createArchitectureState({
    objective_lineage_id: `s11:${caseId}`,
    budget_ref: 's11-production-binding',
    acceptance_ledger: {
      schema: 'acceptance-ledger.v1', ledger_version: 1, intent_epoch: 1,
      acceptance_fingerprint: digestValue(caseId), frozen_at: NOW.toISOString(), items: [],
    },
  });
  const observed = applyArchitectureEvent(state, { event_type: eventType, payload });
  if (!validateArchitectureState(observed).valid) throw new Error('architecture-state rejected production observation');
  return observed.state_fingerprint;
}

function accepted(caseId, eventType, payload) {
  return Object.freeze({ accepted: true, integratedStateIdentity: observedState(caseId, eventType, payload) });
}

function gateContract() {
  return {
    id: 's11-evidence-closure-gate', inspectedScope: 'src/**', discoveryBreadth: 'bounded',
    blockingFilter: 'known', threshold: 1, gates: true, authority: 'oracle', failureSemantics: 'deny',
  };
}

const SUPPORTED = Object.freeze({
  'AE-EVIDENCE-ARTIFACTS-001': () => {
    const result = verifyExternalProviderCapability({ providerId: 'dashboard', machineReadable: false }, { providerId: 'dashboard' });
    if (result.code !== 'ARC_UNSOUND_SEAL') throw new Error('dashboard-only provider was admitted as closure evidence');
    return accepted('AE-EVIDENCE-ARTIFACTS-001', 'ARTIFACT_ENVELOPE_RECORDED', { id: 'dashboard', admission: 'INFORMATIONAL_ONLY', verifierCode: result.code });
  },
  'AE-EVIDENCE-ARTIFACTS-002': () => {
    const result = verifyExternalProviderCapability({
      providerId: 'sensitive-trace', machineReadable: true, gateable: true, downloadable: true,
      trustedRetrieval: true, trajectoryBindable: true, sensitivity: 'sensitive', retention: null, deletionOwner: null,
    }, { providerId: 'sensitive-trace' });
    if (result.code !== 'ARC_UNSOUND_SEAL' || !result.detail.missing.includes('deletionOwner')) throw new Error('trace without deletion owner was admitted');
    return accepted('AE-EVIDENCE-ARTIFACTS-002', 'ARTIFACT_ENVELOPE_RECORDED', { id: 'sensitive-trace', admission: 'DENIED', verifierCode: result.code, missing: result.detail.missing });
  },
  'AE-EVIDENCE-FRESHNESS-001': () => {
    const registry = new AcceptanceEvidenceRegistry();
    const integratedState = { revision: 'before-change' };
    const registered = registry.register({ acceptanceId: 'AC-freshness', claimType: 'acceptance-surface', producer: 'oracle', durableStore: 'receipt-store', verifier: 'arcane', completionConsumer: 'legion', integratedStateBinding: 'exact', validityPolicy: 'latest-material-change' });
    if (!registered.allowed) throw new Error(registered.message);
    const check = registry.verify('AC-freshness', { acceptanceId: 'AC-freshness', producer: 'oracle', verifier: 'arcane', completionConsumer: 'legion', authenticated: true, integratedState, observedAt: '2026-08-13T00:00:00.000Z', validUntil: '2026-08-15T00:00:00.000Z' }, { integratedState, latestMaterialChange: NOW.toISOString(), now: NOW });
    if (check.code !== 'ARC_EVIDENCE_STALE' || check.detail.status !== 'STALE') throw new Error('materially stale proof was accepted');
    return accepted('AE-EVIDENCE-FRESHNESS-001', 'EVIDENCE_LIFECYCLE_RECORDED', { id: 'AC-freshness', lifecycle: 'STALE', completion: 'CANDIDATE', verifierCode: check.code });
  },
  'AE-GATE-VALIDITY-001': () => {
    const contract = gateContract();
    const validity = validateGate({ contract, fixtures: { knownGood: { id: 'good', expected: 'PASS' }, knownBad: { id: 'bad', expected: 'FAIL' }, empty: { id: 'empty', expected: 'FAIL' }, malformed: { id: 'malformed', expected: 'FAIL' } }, execute: (fixture) => ({ status: fixture.expected }) });
    const result = executeValidatedGate({ contract, validity, inspected: [] });
    if (result.code !== 'ARC_EVIDENCE_INSUFFICIENT' || result.detail.gateStatus !== 'INCONCLUSIVE') throw new Error('zero-item blocking gate passed');
    return accepted('AE-GATE-VALIDITY-001', 'TERMINAL_STATE_RECORDED', { id: contract.id, status: result.detail.gateStatus, verifierCode: result.code });
  },
  'AE-GATE-VALIDITY-002': () => {
    const validity = validateGate({ contract: gateContract(), fixtures: { knownGood: { id: 'good', expected: 'PASS' } }, execute: (fixture) => ({ status: fixture.expected }) });
    if (validity.code !== 'ARC_GATE_INVALID' || validity.detail.machineryDefect !== 'OUT_OF_SCOPE_MACHINERY_DEFECT') throw new Error('incomplete gate self-test remained enabled');
    return accepted('AE-GATE-VALIDITY-002', 'TERMINAL_STATE_RECORDED', { id: 's11-evidence-closure-gate', status: 'BLOCKING_DISABLED', machineryDefect: validity.detail.machineryDefect, verifierCode: validity.code });
  },
  'AE-SEAL-REACHABILITY-001': () => {
    const result = compileSealReachability({ requirements: [{ id: 'required-schema', producer: 'oracle', durableStore: true, authenticatedPersistence: true, verifier: 'arcane', completionConsumer: 'legion', closePath: true, fixtureOnly: true }], recoveryPaths: [{ requirementId: 'required-schema', authenticated: true, closePath: true }] });
    if (result.code !== 'ARC_UNSOUND_SEAL' || result.detail.status !== 'UNSOUND_SEAL') throw new Error('fixture-only evidence reached a seal');
    return accepted('AE-SEAL-REACHABILITY-001', 'EVIDENCE_LIFECYCLE_RECORDED', { id: 'required-schema', status: result.detail.status, verifierCode: result.code });
  },
});

const UNSUPPORTED = Object.freeze({
  'AE-EVIDENCE-001': 'authority-backed candidate constraint/admission evaluator',
  'AE-EVIDENCE-002': 'authority-backed preference-versus-constraint classifier',
  'AE-EVIDENCE-003': 'candidate comparison engine with pre-score hard-gate elimination',
  'AE-EVIDENCE-ARTIFACTS-003': 'catalog capability registry with adapter-backed gateability state',
  'AE-EVIDENCE-FRESHNESS-002': 'waiver lifecycle store that exposes REFRESH_REQUIRED while retaining visible waiver state',
  'AE-FINDING-LIFECYCLE-001': 'finding store keyed by stable fingerprint with review-round identity',
  'AE-FINDING-LIFECYCLE-002': 'independent finding-closure verifier that rejects fix-author certification',
  'AE-FINDING-LIFECYCLE-003': 'scoped recheck consumer that closes blockers & defers unrelated findings',
  'AE-DEFICIT-PROPAGATION-001': 'acceptance deficit classifier & completion claim-ceiling consumer',
  'AE-DEFICIT-PROPAGATION-002': 'required correctness/safety debt-conversion guard',
  'AE-DEFICIT-PROPAGATION-003': 'dispatch admission consumer for canonical downstream deficit acknowledgement',
  'AE-OUTCOME-CLOSURE-001': 'outcome state machine with acceptance-surface observation status',
});

export function evidenceClosureRuntimePolicyIds() {
  return Object.freeze([...Object.keys(SUPPORTED), ...Object.keys(UNSUPPORTED)].sort());
}

export function executeEvidenceClosureRuntimeCase(row) {
  const binding = SUPPORTED[row?.id];
  if (binding) {
    try { return Object.freeze({ id: row.id, family: row.family, status: 'PASS', ...binding() }); }
    catch (error) { return Object.freeze({ id: row?.id ?? null, family: row?.family ?? null, status: 'FAIL', reason: `production binding failed: ${error.message}` }); }
  }
  const missingCapability = UNSUPPORTED[row?.id];
  return Object.freeze({ id: row?.id ?? null, family: row?.family ?? null, status: 'PENDING', reason: missingCapability ? `missing production capability: ${missingCapability}` : 'no evidence-closure binding is registered', missingCapability: missingCapability ?? null });
}
