import assert from 'node:assert/strict';
import test from 'node:test';

import {
  evaluateReviewDispositionCase,
  reviewDispositionPolicyIds,
  validateReviewDispositionDecision,
} from '../src/lib/verification/arcane/review-disposition-policy.mjs';

test('irreversible uncertainty after exhausted review budget needs a spike', () => {
  const decision = evaluateReviewDispositionCase('AE-HANDOFF-004', {
    irreversible: true, uncertainty: true, reviewBudget: { exhausted: true }, externalBlock: false, budgetStop: false,
  });
  assert.equal(decision.disposition, 'NEEDS_SPIKE');
  assert.equal(validateReviewDispositionDecision('AE-HANDOFF-004', decision), true);
});

test('unsupported links deny exploit chain and downgrade coverage', () => {
  const decision = evaluateReviewDispositionCase('AE-REVIEW-VERDICT-SECURITY-002', {
    nodes: ['entry', 'sink'],
    links: [{ from: 'entry', to: 'sink', demonstrated: false, evidenceId: '' }],
    coverage: { claimedAreas: ['entry', 'sink', 'auth'], inspectedAreas: ['entry', 'sink'] },
  });
  assert.equal(decision.disposition, 'NO_EXPLOIT_CHAIN');
  assert.equal(decision.coverage.disposition, 'INCOMPLETE_COVERAGE');
  assert.equal(validateReviewDispositionDecision('AE-REVIEW-VERDICT-SECURITY-002', decision), true);
});

test('closed reviews with advisory items only never reopen', () => {
  const decision = evaluateReviewDispositionCase('AE-REVIEW-VERDICT-SECURITY-005', {
    reviewClosed: true,
    findings: [{ id: 'style-note', blocking: false, disposition: 'ADVISORY' }],
  });
  assert.equal(decision.disposition, 'NO_REOPEN');
  assert.equal(validateReviewDispositionDecision('AE-REVIEW-VERDICT-SECURITY-005', decision), true);
});

test('policy rejects malformed or contrary evidence instead of defaulting to success', () => {
  assert.equal(evaluateReviewDispositionCase('AE-HANDOFF-004', {}).status, 'DENY');
  assert.equal(evaluateReviewDispositionCase('AE-REVIEW-VERDICT-SECURITY-005', {
    reviewClosed: true,
    findings: [{ id: 'security', blocking: true, disposition: 'BLOCKING' }],
  }).disposition, 'REOPEN_REQUIRED');
  assert.deepEqual(reviewDispositionPolicyIds, [
    'AE-HANDOFF-004', 'AE-REVIEW-VERDICT-SECURITY-002', 'AE-REVIEW-VERDICT-SECURITY-005',
  ]);
});
