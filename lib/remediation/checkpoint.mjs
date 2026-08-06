// Checkpoint/restore per SNIP-WORKTREE-01's checkpoint contract. Captures a
// content digest of the worktree state; restore is the inverse patch.

import { createHash } from 'node:crypto';

export function checkpointDigest(state) {
  const body = JSON.stringify(state);
  return `sha256:${createHash('sha256').update(`checkpoint\0${body}`).digest('hex')}`;
}

export function createCheckpoint({ worktreePath, baseCommit, files }) {
  const record = {
    schemaVersion: 1,
    kind: 'nemesis-remediation-checkpoint',
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
    kind: 'nemesis-checkpoint-restore',
    checkpointDigest: checkpoint.digest,
    // The reverse of the mutation ledger: revert each changed file to base.
    steps: (checkpoint.files ?? []).map((file) => ({ file, action: 'revert-to-base' })),
    recoveryCommand: `git -C ${checkpoint.worktreePath} checkout -- ${(checkpoint.files ?? []).join(' ')}`,
  };
}

export function cleanupReceipt({ path, removed, error, recoveryCommand }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-remediation-cleanup',
    path,
    removed,
    error: error ?? null,
    recoveryCommand: removed ? null : (recoveryCommand ?? `git worktree remove --force ${path}`),
  };
}
