// Isolated remediation worktree per SNIP-WORKTREE-01. Never uses the user's
// primary worktree as the remediation target.

import { join } from 'node:path';

export async function createRemediationWorktree({ repo, baseCommit, runId, processRunner }) {
  const path = join(repo.gitCommonDir, 'nemesis-worktrees', runId);
  const result = await processRunner.run({
    executable: 'git',
    args: ['worktree', 'add', '--detach', path, baseCommit],
    cwd: repo.root,
  });
  if (result?.exitCode !== 0) {
    throw new Error(`git worktree add failed: ${result?.stderr ?? result?.error?.message ?? 'unknown'}`);
  }
  return { path, baseCommit, cleanup: ['git', 'worktree', 'remove', '--force', path] };
}

export async function removeRemediationWorktree({ path, processRunner }) {
  const result = await processRunner.run({
    executable: 'git',
    args: ['worktree', 'remove', '--force', path],
    cwd: path,
  });
  return { removed: result?.exitCode === 0, error: result?.exitCode === 0 ? null : (result?.stderr ?? 'unknown') };
}

export function worktreeReceipt({ path, baseCommit, runId, cleanup }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-remediation-worktree',
    path,
    baseCommit,
    runId,
    cleanup,
    primaryWorktreeUntouched: true,
  };
}
