import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const TASK_STATES = new Set(['implemented', 'mapped', 'blocked']);
const DECISIONS = new Set(['QUALIFIED', 'SOURCE_COMPLETE', 'BLOCKED']);

export function validateBookReceipt(receipt, { root = process.cwd() } = {}) {
  const issues = [];
  if (receipt?.schemaVersion !== 1 || receipt?.kind !== 'nemesis-book-qualification') issues.push('invalid-contract');
  if (!Number.isInteger(receipt?.book) || receipt.book < 1 || receipt.book > 8) issues.push('invalid-book');
  if (!DECISIONS.has(receipt?.decision)) issues.push('invalid-decision');
  const tasks = receipt?.tasks ?? [];
  const expected = Array.from({ length: receipt?.expectedTaskCount ?? 0 }, (_, index) => `B${receipt.book}-${String(index + 1).padStart(3, '0')}`);
  const ids = tasks.map((task) => task.id);
  if (new Set(ids).size !== ids.length) issues.push('duplicate-task');
  if (JSON.stringify(ids) !== JSON.stringify(expected)) issues.push('task-denominator-mismatch');
  for (const task of tasks) {
    if (!TASK_STATES.has(task.status)) issues.push(`${task.id}:invalid-status`);
    if ((!Array.isArray(task.evidence) || task.evidence.length === 0) && !task.mapping?.trim()) issues.push(`${task.id}:missing-evidence`);
    for (const path of task.evidence ?? []) if (!existsSync(resolve(root, path))) issues.push(`${task.id}:absent:${path}`);
  }
  if (receipt.decision === 'QUALIFIED' && (tasks.some((task) => task.status === 'blocked') || (receipt.blockers ?? []).length)) issues.push('qualified-with-blockers');
  return { valid: issues.length === 0, issues, taskCount: tasks.length };
}

export function loadBookReceipt(path, options) {
  return validateBookReceipt(JSON.parse(readFileSync(path, 'utf8')), options);
}
