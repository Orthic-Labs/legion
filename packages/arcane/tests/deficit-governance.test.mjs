import assert from 'node:assert/strict';
import test from 'node:test';
import { acknowledgeDownstreamDeficits, classifyAcceptanceDeficits, convertDeficitsToDebt, evaluateOutcomeClosure } from '../lib/deficit-governance.mjs';
import { readAdoptionStage, transitionCandidateStage } from '../lib/adoption-ledger.mjs';

test('AE-DEFICIT-PROPAGATION-001: optional deficit produces COMPLETE_WITH_DEBT claim ceiling', () => {
  const result = convertDeficitsToDebt({ acceptanceItems: [{ id: 'required', obligationClass: 'CORRECTNESS', result: 'PASS' }, { id: 'optional', obligationClass: 'OPTIONAL', result: 'OPEN' }] });
  assert.equal(result.allowed, true);
  assert.equal(result.detail.claimCeiling, 'COMPLETE_WITH_DEBT');
  assert.equal(result.detail.debts[0].canonicalDeficitId, 'deficit:optional');
});

test('AE-DEFICIT-PROPAGATION-002: correctness or safety deficits cannot become debt', () => {
  for (const obligationClass of ['CORRECTNESS', 'SAFETY']) {
    const result = convertDeficitsToDebt({ acceptanceItems: [{ id: obligationClass, obligationClass, result: 'FAIL' }] });
    assert.equal(result.allowed, false);
    assert.equal(result.detail.outcomeState, 'CANDIDATE');
    assert.equal(result.detail.claimCeiling, 'CANDIDATE');
  }
});

test('AE-DEFICIT-PROPAGATION-003: downstream dispatch requires canonical acknowledgement', () => {
  const classified = classifyAcceptanceDeficits({ acceptanceItems: [{ id: 'optional', obligationClass: 'OPTIONAL', result: 'OPEN' }] });
  const [debt] = classified.detail.deficits;
  const rejected = acknowledgeDownstreamDeficits({ canonicalDeficits: [debt], acknowledgements: [] });
  assert.equal(rejected.allowed, false);
  assert.equal(rejected.detail.dispatch, 'REJECTED');
  assert.equal(acknowledgeDownstreamDeficits({ canonicalDeficits: [debt], acknowledgements: [{ canonicalDeficitId: debt.canonicalDeficitId, canonical: true, consumerId: 'child' }] }).allowed, true);
});

test('AE-OUTCOME-CLOSURE-001: an unobserved acceptance surface remains CANDIDATE', () => {
  const result = evaluateOutcomeClosure({ acceptanceSurface: { observed: false, authenticated: true, integratedState: 'tree:1' } });
  assert.equal(result.allowed, false);
  assert.equal(result.detail.outcomeState, 'CANDIDATE');
});

test('AE-ADOPTION-GOVERNANCE-001: evidence denial can durably retain CANDIDATE', () => {
  const ledger = { stages: [{ stage_id: 'S-1', done_state: 'IN_PROGRESS', integrated_state_identity: 'tree:1', required_items: [] }] };
  assert.equal(transitionCandidateStage(ledger, 'S-1').allowed, true);
  const read = readAdoptionStage(ledger, 'S-1');
  assert.equal(read.allowed, true);
  assert.equal(read.detail.doneState, 'CANDIDATE');
  assert.equal(read.detail.verificationAdmission, null);
});
