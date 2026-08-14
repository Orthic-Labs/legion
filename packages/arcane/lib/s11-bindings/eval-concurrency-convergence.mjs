// Deterministic S11 evaluators for scheduler-backed cases.  Cases without a
// production ingress/consumer pair remain explicitly typed PENDING; prose is
// never inspected or echoed as evidence.
import { scheduleProviders } from '../../../../lib/core/scheduler.mjs';

const IDS = Object.freeze([
  'AE-CONCURRENCY-ATTENTION-002',
  'AE-CONCURRENCY-ATTENTION-006',
  'AE-CONTROL-PLANE-BUDGETS-002',
  'AE-CONVERGENCE-001',
  'AE-CONVERGENCE-003',
]);

const observation = (id, producer, consumer, value) => Object.freeze({
  id, producer, consumer, value: Object.freeze(value),
});

const pending = (id, family, reason) => Object.freeze({
  id, family, status: 'PENDING', reason,
});

function rejectWholeStageBarrier() {
  // Dependencies are the only scheduler barrier. Disjoint tasks have no
  // consumed artifacts, so a common stage label must not serialize them.
  const providers = [
    { id: 'author-a', dependencies: [], files: ['src/a.mjs'], stage: 'authoring' },
    { id: 'fixture-b', dependencies: [], files: ['test/b.fixture'], stage: 'fixtures' },
  ];
  const waves = scheduleProviders(providers, { concurrency: 2 });
  return observation('AE-CONCURRENCY-ATTENTION-002', 'scheduleProviders', 'dispatch scheduler', {
    outcome: waves.length === 1 && waves[0].length === 2 ? 'PARALLEL_ADMITTED' : 'BARRIER_REJECTED',
    waves,
    consumedArtifacts: [],
  });
}

function admitIndependentReadyWork() {
  const providers = [
    { id: 'task-a', dependencies: [], resources: { cpu: 1 }, execution: { resourceClaims: { cpu: 1 } } },
    { id: 'task-b', dependencies: [], resources: { cpu: 1 }, execution: { resourceClaims: { cpu: 1 } } },
    { id: 'task-c', dependencies: [], resources: { cpu: 1 }, execution: { resourceClaims: { cpu: 1 } } },
  ];
  const scheduled = scheduleProviders(providers, { concurrency: 2, resources: { cpu: 2 } });
  return observation('AE-CONCURRENCY-ATTENTION-006', 'scheduleProviders', 'dispatch scheduler', {
    outcome: scheduled.admitted.length === 2 ? 'INDEPENDENT_READY_WORK_ADMITTED' : 'CAPACITY_NOT_ADMITTED',
    admitted: scheduled.admitted,
    ready: scheduled.ready,
    blocked: scheduled.blocked,
    waves: scheduled.waves,
  });
}

const EVALUATORS = Object.freeze({
  'AE-CONCURRENCY-ATTENTION-002': () => rejectWholeStageBarrier(),
  'AE-CONCURRENCY-ATTENTION-006': () => admitIndependentReadyWork(),
  'AE-CONTROL-PLANE-BUDGETS-002': () => pending('AE-CONTROL-PLANE-BUDGETS-002', 'control-plane-budgets', 'requires authenticated calibration authority to distinguish doctrine drift'),
  'AE-CONVERGENCE-001': () => pending('AE-CONVERGENCE-001', 'convergence', 'clarification priority requires Sage judgment'),
  'AE-CONVERGENCE-003': () => pending('AE-CONVERGENCE-003', 'convergence', 'post-freeze opportunity disposition requires authenticated review judgment'),
});

export function concurrencyConvergenceBindingIds() { return IDS; }

export function executeConcurrencyConvergenceCase(row) {
  const id = typeof row === 'string' ? row : row?.id;
  const evaluate = EVALUATORS[id];
  if (!evaluate) return null;
  const family = typeof row === 'object' && row?.family ? row.family : id.startsWith('AE-CONCURRENCY') ? 'concurrency-attention' : id.startsWith('AE-CONTROL') ? 'control-plane-budgets' : 'convergence';
  const result = evaluate();
  if (result.status) return result;
  const valid = validateConcurrencyConvergenceObservation(id, result);
  return Object.freeze({ id, family, status: valid ? 'PASS' : 'FAIL', reason: valid ? 'scheduler ingress and structured consumer observed' : 'structured scheduler observation failed independent validator', observed: result });
}

export function validateConcurrencyConvergenceObservation(id, observed) {
  const value = observed?.value ?? observed;
  if (id === 'AE-CONCURRENCY-ATTENTION-002') return value?.outcome === 'PARALLEL_ADMITTED' && value?.waves?.length === 1 && value.waves[0]?.length === 2 && Array.isArray(value.consumedArtifacts) && value.consumedArtifacts.length === 0;
  if (id === 'AE-CONCURRENCY-ATTENTION-006') return value?.outcome === 'INDEPENDENT_READY_WORK_ADMITTED' && value?.admitted?.length === 2 && value?.ready?.length === 1 && value?.blocked?.length === 0;
  return false;
}
