import assert from 'node:assert/strict';
import test from 'node:test';

import {
  concurrencyConvergenceBindingIds,
  executeConcurrencyConvergenceCase,
} from '../lib/s11-bindings/eval-concurrency-convergence.mjs';

test('S11 concurrency evaluators exercise scheduler barriers & capacity', () => {
  assert.deepEqual(concurrencyConvergenceBindingIds(), [
    'AE-CONCURRENCY-ATTENTION-002',
    'AE-CONCURRENCY-ATTENTION-006',
    'AE-CONTROL-PLANE-BUDGETS-002',
    'AE-CONVERGENCE-001',
    'AE-CONVERGENCE-003',
  ]);
  const barrier = executeConcurrencyConvergenceCase({ id: 'AE-CONCURRENCY-ATTENTION-002', family: 'concurrency-attention' });
  assert.equal(barrier.status, 'PASS');
  assert.equal(barrier.observed.value.outcome, 'PARALLEL_ADMITTED');
  assert.deepEqual(barrier.observed.value.consumedArtifacts, []);

  const capacity = executeConcurrencyConvergenceCase({ id: 'AE-CONCURRENCY-ATTENTION-006', family: 'concurrency-attention' });
  assert.equal(capacity.status, 'PASS');
  assert.equal(capacity.observed.value.outcome, 'INDEPENDENT_READY_WORK_ADMITTED');
  assert.deepEqual(capacity.observed.value.admitted, ['task-a', 'task-b']);
  assert.deepEqual(capacity.observed.value.ready, ['task-c']);
});

test('S11 irreducible judgment cases stay typed PENDING', () => {
  for (const [id, family] of [
    ['AE-CONTROL-PLANE-BUDGETS-002', 'control-plane-budgets'],
    ['AE-CONVERGENCE-001', 'convergence'],
    ['AE-CONVERGENCE-003', 'convergence'],
  ]) {
    const result = executeConcurrencyConvergenceCase({ id, family });
    assert.equal(result.status, 'PENDING', id);
    assert.equal(typeof result.reason, 'string', id);
    assert.equal(result.reason.includes('requires'), true, id);
  }
});

test('unknown S11 case has no evaluator', () => {
  assert.equal(executeConcurrencyConvergenceCase({ id: 'AE-NOT-REGISTERED', family: 'x' }), null);
});
