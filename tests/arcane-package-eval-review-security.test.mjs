import assert from 'node:assert/strict';
import test from 'node:test';
import {
  executeReviewSecurityBinding,
  reviewSecurityRuntimeIds,
  validateReviewSecurityObservation,
} from '../src/lib/verification/arcane/s11-bindings/eval-review-security.mjs';

test('review security evaluators use case-specific structured observations', () => {
  assert.deepEqual(reviewSecurityRuntimeIds(), [
    'AE-REVIEW-ADMISSION-001',
    'AE-REVIEW-VERDICT-SECURITY-002',
    'AE-REVIEW-VERDICT-SECURITY-005',
    'AE-REVIEW-VERDICT-SECURITY-006',
  ]);
  for (const id of reviewSecurityRuntimeIds()) {
    const observation = executeReviewSecurityBinding(id);
    assert.equal(validateReviewSecurityObservation(id, observation), true);
    assert.equal(typeof observation.producer, 'string');
    assert.equal(typeof observation.consumer, 'string');
    assert.equal(typeof observation.value, 'object');
  }
});

test('admission and configured-scope controls fail closed on their actual observations', () => {
  const admission = executeReviewSecurityBinding('AE-REVIEW-ADMISSION-001').value;
  assert.equal(admission.result.code, 'ARC_EVIDENCE_INSUFFICIENT');
  assert.equal(admission.result.detail.inspectionCount, 0);
  const scope = executeReviewSecurityBinding('AE-REVIEW-VERDICT-SECURITY-006').value;
  assert.equal(scope.result.code, 'ARC_CLAIM_PREREQUISITE_UNMET');
  assert.deepEqual(scope.configuredScope, ['packages/arcane/**']);
});

test('judgment-only cases remain typed pending with exact producer', () => {
  for (const id of ['AE-REVIEW-VERDICT-SECURITY-002', 'AE-REVIEW-VERDICT-SECURITY-005']) {
    const observation = executeReviewSecurityBinding(id);
    assert.equal(observation.value.status, 'PENDING');
    assert.equal(observation.value.exactProducer, 'advisory-judgment');
  }
});
