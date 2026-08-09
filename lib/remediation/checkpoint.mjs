// Checkpoint/restore per SNIP-WORKTREE-01's checkpoint contract. Captures a
// content digest of the worktree state; restore is the inverse patch.

import { createHash } from 'node:crypto';
// Cleanup receipts live with the sandbox cleanup they describe; re-exported
// here because checkpoint consumers have always imported them from this module.
export { cleanupReceipt } from './cleanup.mjs';

export function checkpointDigest(state) {
  const body = JSON.stringify(state);
  return `sha256:${createHash('sha256').update(`checkpoint\0${body}`).digest('hex')}`;
}

export function createCheckpoint({ worktreePath, baseCommit, files }) {
  const record = {
    schemaVersion: 1,
    kind: 'legion-remediation-checkpoint',
    worktreePath,
    baseCommit,
    files: (files ?? []).sort(),
    createdAt: null,
  };
  record.digest = checkpointDigest(record);
  return record;
}

export function restorePlan(checkpoint) {
  return {
    kind: 'legion-checkpoint-restore',
    checkpointDigest: checkpoint.digest,
    // The reverse of the mutation ledger: revert each changed file to base.
    steps: (checkpoint.files ?? []).map((file) => ({ file, action: 'revert-to-base' })),
    recoveryCommand: `git -C ${checkpoint.worktreePath} checkout -- ${(checkpoint.files ?? []).join(' ')}`,
  };
}

// Restore a checkpoint inside the sandbox. A failed restore is surfaced with
// the exact recovery command — never swallowed into a passing result.
export async function restoreCheckpoint({ checkpoint, processRunner }) {
  const plan = restorePlan(checkpoint);
  const files = plan.steps.map((step) => step.file);
  const result = files.length === 0
    ? { exitCode: 0 }
    : await processRunner.run({
      executable: 'git',
      args: ['-C', checkpoint.worktreePath, 'checkout', '--', ...files],
      cwd: checkpoint.worktreePath,
    });
  const restored = result?.exitCode === 0;
  return {
    schemaVersion: 1,
    kind: 'legion-checkpoint-restore-receipt',
    checkpointDigest: checkpoint.digest,
    worktreePath: checkpoint.worktreePath,
    files,
    restored,
    error: restored ? null : (result?.stderr ?? result?.error?.message ?? 'unknown'),
    recoveryCommand: plan.recoveryCommand,
  };
}
