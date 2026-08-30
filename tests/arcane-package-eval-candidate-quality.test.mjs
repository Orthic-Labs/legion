import assert from 'node:assert/strict';
import test from 'node:test';

import {
  candidateQualityBindingIds,
  executeCandidateQualityCase,
  validateCandidateQualityObservation,
} from '../src/lib/verification/arcane/s11-bindings/eval-candidate-quality.mjs';

test('candidate-quality evaluators cover five pending IDs through production modules', () => {
  const ids = candidateQualityBindingIds();
  assert.deepEqual(ids, [
    'AE-CANDIDATE-QUALITY-001', 'AE-CANDIDATE-QUALITY-002',
    'AE-CANDIDATE-QUALITY-004', 'AE-CANDIDATE-QUALITY-005',
    'AE-CANDIDATE-QUALITY-006',
  ]);
  for (const id of ids) {
    const result = executeCandidateQualityCase({ id, family: 'candidate-quality' });
    assert.equal(result.status, 'PASS');
    assert.equal(result.observed.id, id);
    assert.equal(typeof result.observed.producer, 'string');
    assert.equal(typeof result.observed.consumer, 'string');
    assert.equal(validateCandidateQualityObservation(id, result.observed), true);
  }
});

test('candidate-quality validation ignores row expectation prose', () => {
  const result = executeCandidateQualityCase({ id: 'AE-CANDIDATE-QUALITY-005', family: 'candidate-quality', expect: { outcome: 'tampered' } });
  assert.equal(validateCandidateQualityObservation(result.id, result.observed), true);
  assert.equal(result.observed.value.weightedScoring, false);
});

test('unsupported candidate-quality IDs remain typed pending at caller boundary', () => {
  assert.equal(executeCandidateQualityCase({ id: 'AE-CANDIDATE-QUALITY-003' }), null);
});
