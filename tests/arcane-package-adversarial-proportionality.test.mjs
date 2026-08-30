import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assessArchitectureProportionality,
  assessMandatoryObligationReadiness,
  executeAdversarialProportionalityCase,
  validateAdversarialProportionalityObservation,
} from '../src/lib/verification/arcane/adversarial-proportionality.mjs';

test('proportionality rejects distributed design without structured driver', () => {
  const result = assessArchitectureProportionality({
    deployment: 'greenfield', scale: 'low', proposedComplexity: 'distributed',
    drivers: { independentScaling: false, isolationBoundary: false, multiRegionConsistency: false }, obligations: [],
  });
  assert.equal(result.decision, 'REJECT');
  assert.equal(result.minimumComplexity, 'minimal');
  assert.equal(result.code, 'ARC_PROPORTIONALITY_EXCESS');
  assert.equal(assessArchitectureProportionality({
    deployment: 'existing', scale: 'high', proposedComplexity: 'distributed',
    drivers: { independentScaling: false, isolationBoundary: false, multiRegionConsistency: false }, obligations: [],
  }).decision, 'ALLOW');
});

test('mandatory obligations block minimization until each is implemented', () => {
  const result = assessMandatoryObligationReadiness({
    objective: 'minimize', proposedComplexity: 'minimal',
    obligations: [
      { id: 'p1', domain: 'privacy', mandatory: true, status: 'missing' },
      { id: 'c1', domain: 'compliance', mandatory: true, status: 'implemented' },
    ],
  });
  assert.equal(result.decision, 'BLOCK');
  assert.deepEqual(result.missingObligationIds, ['p1']);
  assert.deepEqual(result.missingDomains, ['privacy']);
});

test('case executor evaluates production controls, without corpus expectations', () => {
  for (const id of ['AE-ADVERSARIAL-001', 'AE-ADVERSARIAL-002']) {
    const result = executeAdversarialProportionalityCase({ id, family: 'adversarial', expect: { outcome: 'ignored' } });
    assert.equal(result.status, 'PASS');
    assert.equal(validateAdversarialProportionalityObservation(id, result), true);
  }
});
