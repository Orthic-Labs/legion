import assert from 'node:assert/strict';
import test from 'node:test';
import {
  adversarialOwnershipEconomicsBindingIds,
  admitVendorSelection,
  assessSourceOfTruthOwnership,
  executeAdversarialOwnershipEconomicsCase,
  validateAdversarialOwnershipEconomicsObservation,
} from '../lib/adversarial-ownership-economics.mjs';

test('conflicting source ownership blocks selection from structured source claims', () => {
  const blocked = assessSourceOfTruthOwnership({
    sources: [
      { sourceId: 'event-store', owner: 'operations', authorities: ['shipment-status'] },
      { sourceId: 'vendor-console', owner: 'logistics', authorities: ['shipment-status'] },
    ],
  });
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.code, 'ARC_CLAIM_PREREQUISITE_UNMET');
  assert.equal(blocked.detail.disposition, 'BLOCK_SELECTION');
  assert.deepEqual(blocked.detail.ownershipConflicts[0], {
    authority: 'shipment-status',
    sources: [
      { sourceId: 'event-store', owner: 'operations' },
      { sourceId: 'vendor-console', owner: 'logistics' },
    ],
    owners: ['logistics', 'operations'],
  });
});

test('one owner can retain multiple source replicas without manufacturing conflict', () => {
  const admitted = assessSourceOfTruthOwnership({
    sources: [
      { sourceId: 'primary-db', owner: 'platform', authorities: ['profile'] },
      { sourceId: 'read-replica', owner: 'platform', authorities: ['profile'] },
    ],
  });
  assert.equal(admitted.allowed, true);
  assert.equal(admitted.detail.disposition, 'ELIGIBLE_FOR_SELECTION');
});

test('vendor with incomplete adverse economics is eliminated before score-based selection', () => {
  const blocked = admitVendorSelection({
    candidates: [
      { candidateId: 'cheap-but-ungrounded', score: 999, adverseCaseEconomics: { outageCost: 1, overageCost: 1 } },
      { candidateId: 'grounded', score: 1, adverseCaseEconomics: { outageCost: 100, overageCost: 20, egressCost: 30, exitCost: 400 } },
    ],
    selectedCandidateId: 'cheap-but-ungrounded',
  });
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.code, 'ARC_EVIDENCE_INSUFFICIENT');
  assert.deepEqual(blocked.detail.missingEconomicMetrics, ['egressCost', 'exitCost']);
  assert.equal(blocked.detail.comparison.eliminated[0].candidate.candidateId, 'cheap-but-ungrounded');
  assert.equal(blocked.detail.comparison.ranked[0].candidate.candidateId, 'grounded');
});

test('executor bindings run production admissions & validate independent observations', () => {
  assert.deepEqual(adversarialOwnershipEconomicsBindingIds(), ['AE-ADVERSARIAL-006', 'AE-ADVERSARIAL-007']);
  for (const id of adversarialOwnershipEconomicsBindingIds()) {
    const result = executeAdversarialOwnershipEconomicsCase({ id, family: 'adversarial' });
    assert.equal(result.status, 'PASS');
    assert.equal(validateAdversarialOwnershipEconomicsObservation(id, result.observed), true);
  }
  assert.equal(validateAdversarialOwnershipEconomicsObservation('AE-ADVERSARIAL-006', { producer: 'assessSourceOfTruthOwnership', value: { allowed: true } }), false);
});
