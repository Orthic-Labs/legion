export function sourceSliceQualification({ book, expectedTaskCount, tasks = [], checks = [], blockers = [] } = {}) {
  if (!Number.isInteger(expectedTaskCount) || expectedTaskCount < 1) throw new Error('expectedTaskCount must be a positive integer');
  if (tasks.length !== expectedTaskCount) throw new Error(`book ${book} task accounting mismatch: expected ${expectedTaskCount}, received ${tasks.length}`);
  const taskIds = new Set();
  for (const task of tasks) {
    if (!task?.id || taskIds.has(task.id)) throw new Error(`book ${book} task id missing or duplicated`);
    if (!['implemented', 'mapped', 'blocked'].includes(task.status)) throw new Error(`book ${book} invalid task status: ${task.status}`);
    taskIds.add(task.id);
  }
  return { schemaVersion: 1, kind: 'nemesis-book-qualification', book, expectedTaskCount, decision: 'SOURCE_COMPLETE',
    claimLevel: 'source', tasks, checks, blockers, externalGates: blockers.map((blocker) => blocker.id), receiptType: 'source-slice' };
}
