import assert from 'node:assert/strict';
import test from 'node:test';

import {
  calibrationConvergenceScenarioFacts,
  classifyCalibrationDrift,
  convergeClarifications,
  disposeFrozenReviewFinding,
  evaluateCalibrationConvergenceCase,
  validateCalibrationConvergenceObservation,
} from '../src/lib/verification/arcane/calibration-convergence-policy.mjs';

test('runtime threshold doctrine drift is rejected into calibration table', () => {
  const result = classifyCalibrationDrift({
    measurement: { observation_id: 'retry-1', metric: 'retry_limit', value: 2, domain: 'retry' },
    publication: { target: 'PERMANENT_CANON' },
  });
  assert.equal(result.status, 'REJECTED');
  assert.equal(result.code, 'DRIFT_FAILURE');
  assert.equal(result.disposition, 'CALIBRATION_TABLE');
  assert.equal(result.canonical_write, false);
  assert.equal(classifyCalibrationDrift({ measurement: { metric: 'retry_limit', value: 2, domain: 'retry' }, publication: { target: 'CALIBRATION_TABLE' } }).status, 'ACCEPTED');
});

test('clarification convergence resolves exactly one current blocker', () => {
  const result = convergeClarifications({
    slice_id: 'slice-1',
    questions: [
      { id: 'q1', blocks_current_slice: false },
      { id: 'q2', blocks_current_slice: true },
      { id: 'q3', blocks_current_slice: false },
    ],
  });
  assert.equal(result.status, 'RESOLVE_ONE');
  assert.equal(result.active_question_id, 'q2');
  assert.deepEqual(result.deferred_question_ids, ['q1', 'q3']);
  assert.equal(convergeClarifications({ slice_id: 'slice-1', questions: [{ id: 'q1', blocks_current_slice: true }, { id: 'q2', blocks_current_slice: true }] }).code, 'MULTIPLE_BLOCKING_QUESTIONS');
});

test('non-falsifying post-freeze review becomes future opportunity', () => {
  const result = disposeFrozenReviewFinding({
    decision: { id: 'D-3', status: 'FROZEN' },
    finding: { id: 'cleaner-abstraction', kind: 'IMPROVEMENT', invalidates_decision: false },
  });
  assert.equal(result.status, 'FROZEN_RETAINED');
  assert.equal(result.code, 'FUTURE_OPPORTUNITY_RECORDED');
  assert.equal(result.decision_status, 'FROZEN');
  assert.equal(disposeFrozenReviewFinding({ decision: { id: 'D-3', status: 'FROZEN' }, finding: { id: 'failed-benchmark', kind: 'FAILURE', invalidates_decision: true } }).status, 'REOPEN_REQUIRED');
});

test('S11 adapter derives valid dispositions from structured facts', () => {
  for (const id of ['AE-CONTROL-PLANE-BUDGETS-002', 'AE-CONVERGENCE-001', 'AE-CONVERGENCE-003']) {
    const facts = calibrationConvergenceScenarioFacts(id);
    assert.ok(facts, id);
    const result = evaluateCalibrationConvergenceCase(id, facts);
    assert.equal(validateCalibrationConvergenceObservation(id, result), true, id);
  }
  assert.equal(evaluateCalibrationConvergenceCase('AE-UNKNOWN'), null);
});
