// Remediation sandbox cleanup (B7-030).
//
// A cleanup that failed is never reported as removed. The receipt carries the
// exact residual paths and the exact recovery command so a human can finish the
// job by hand.

export function cleanupReceipt({ path, removed, error = null, recoveryCommand = null, residualPaths = null }) {
  if (typeof removed !== 'boolean') throw new TypeError('cleanup receipt requires an explicit removed boolean');
  return {
    schemaVersion: 1,
    kind: 'nemesis-remediation-cleanup',
    path,
    removed,
    error: removed ? null : (error ?? 'unknown'),
    residualPaths: removed ? [] : (residualPaths ?? [path]),
    recoveryCommand: removed ? null : (recoveryCommand ?? ['git', 'worktree', 'remove', '--force', path]),
  };
}

export async function cleanupSandbox({ sandbox, processRunner }) {
  const command = sandbox?.cleanup?.command ?? ['git', 'worktree', 'remove', '--force', sandbox?.sandboxPath];
  const [executable, ...args] = command;
  const result = await processRunner.run({
    executable,
    args,
    cwd: sandbox?.cleanup?.cwd ?? undefined,
  });
  const removed = result?.exitCode === 0;
  return cleanupReceipt({
    path: sandbox?.sandboxPath,
    removed,
    error: removed ? null : (result?.stderr ?? result?.error?.message ?? 'unknown'),
    recoveryCommand: removed ? null : command,
    residualPaths: removed ? [] : [...new Set([sandbox?.sandboxPath, ...(sandbox?.createdPaths ?? [])])].sort(),
  });
}
