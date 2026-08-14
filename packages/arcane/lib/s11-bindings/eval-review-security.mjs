// Case-specific review admission observations.  The evaluators below call
// Arcane controls with independent fixtures; they never inspect eval prose or
// manufacture receipts.  Cases requiring Sage/Oracle judgment stay pending.
import { validateGate, executeValidatedGate } from '../gate-validity.mjs';

const IDS = Object.freeze([
  'AE-REVIEW-ADMISSION-001',
  'AE-REVIEW-VERDICT-SECURITY-002',
  'AE-REVIEW-VERDICT-SECURITY-005',
  'AE-REVIEW-VERDICT-SECURITY-006',
]);

const gateContract = Object.freeze({
  id: 'review-admission-s11', inspectedScope: ['packages/arcane/**'],
  discoveryBreadth: 'configured', blockingFilter: 'security', threshold: 3,
  gates: true, authority: 'oracle', failureSemantics: 'fail-closed',
});

function gateFixtures() {
  return Object.freeze({
    knownGood: { id: 'known-good', status: 'PASS' },
    knownBad: { id: 'known-bad', status: 'FAIL' },
    empty: { id: 'empty', status: 'FAIL' },
    malformed: { id: 'malformed', status: 'FAIL' },
  });
}

function admission() {
  const validity = validateGate({
    contract: gateContract, fixtures: gateFixtures(),
    execute: (fixture) => fixture,
  });
  const result = executeValidatedGate({ contract: gateContract, validity, inspected: [] });
  return Object.freeze({ validity, result });
}

function configuredScope() {
  const validity = validateGate({
    contract: gateContract, fixtures: gateFixtures(),
    execute: (fixture) => fixture,
  });
  // This is an independently supplied observation: a claim about an area
  // outside configured scope must not produce CLEAN.
  const result = executeValidatedGate({
    contract: gateContract, validity,
    inspected: [{ subjectId: 'packages/arcane/lib/gate-validity.mjs' }],
    matches: [{ ruleId: 'UNINSPECTED_SCOPE', reason: 'outside configured scope' }],
  });
  return Object.freeze({ validity, result, configuredScope: gateContract.inspectedScope });
}

function pending(id, reason) {
  return Object.freeze({
    producer: 'advisory-judgment',
    consumer: 'review verdict security admission',
    value: Object.freeze({ status: 'PENDING', caseId: id, reason, exactProducer: 'advisory-judgment' }),
  });
}

export const reviewSecurityBindings = Object.freeze({
  'AE-REVIEW-ADMISSION-001': () => ({ producer: 'validateGate + executeValidatedGate', consumer: 'review admission gate', value: admission() }),
  'AE-REVIEW-VERDICT-SECURITY-002': () => pending('AE-REVIEW-VERDICT-SECURITY-002', 'exploit-chain and coverage claims require pre-existing Sage/Oracle judgment'),
  'AE-REVIEW-VERDICT-SECURITY-005': () => pending('AE-REVIEW-VERDICT-SECURITY-005', 'reopening disposition requires pre-existing Sage/Oracle judgment'),
  'AE-REVIEW-VERDICT-SECURITY-006': () => ({ producer: 'validateGate + executeValidatedGate', consumer: 'configured-scope verdict admission', value: configuredScope() }),
});

export const reviewSecurityBlockers = Object.freeze({
  'AE-REVIEW-VERDICT-SECURITY-002': 'requires pre-existing Sage/Oracle judgment for exploit-chain evidence and coverage claims',
  'AE-REVIEW-VERDICT-SECURITY-005': 'requires pre-existing Sage/Oracle judgment for reopening disposition',
});

export function reviewSecurityRuntimeIds() { return IDS; }
export function executeReviewSecurityBinding(id) { return reviewSecurityBindings[id]?.() ?? null; }

export function validateReviewSecurityObservation(id, observation) {
  if (!observation || typeof observation.producer !== 'string' || typeof observation.consumer !== 'string') return false;
  const value = observation.value;
  if (id === 'AE-REVIEW-ADMISSION-001') return observation.producer === 'validateGate + executeValidatedGate' && value?.result?.allowed === false && value.result.code === 'ARC_EVIDENCE_INSUFFICIENT' && value.result.detail?.inspectionCount === 0;
  if (id === 'AE-REVIEW-VERDICT-SECURITY-006') return observation.producer === 'validateGate + executeValidatedGate' && value?.result?.allowed === false && value.result.code === 'ARC_CLAIM_PREREQUISITE_UNMET' && Array.isArray(value.configuredScope);
  return value?.status === 'PENDING' && value.exactProducer === 'advisory-judgment';
}
