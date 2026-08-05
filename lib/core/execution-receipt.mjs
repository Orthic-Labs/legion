// Canonical execution receipt. spawnStatus describes the process outcome;
// providerResult.status describes the provider verdict. `spawnStatus:
// 'completed'` never implies `providerResult.status: 'pass'`.

export const SPAWN_STATUS = Object.freeze([
  'completed',
  'missing',
  'timeout',
  'signaled',
  'error',
  'blocked',
]);

export function executionReceipt({
  provider,
  command,
  startedAt,
  completedAt,
  spawnStatus,
  exitCode = null,
  signal = null,
  timedOut = false,
  stdoutArtifact = null,
  stderrArtifact = null,
  environmentKeys = [],
  sandboxReceipt = null,
  tool = null,
  providerResult = null,
}) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-execution-result',
    provider,
    command,
    startedAt,
    completedAt,
    durationMs: startedAt && completedAt ? completedAt - startedAt : null,
    spawnStatus,
    exitCode,
    signal,
    timedOut,
    stdoutArtifact,
    stderrArtifact,
    environmentKeys,
    sandboxReceipt,
    tool,
    providerResult,
  };
}

export function blocked(spec, reason) {
  return executionReceipt({
    provider: spec?.provider ?? 'unknown',
    command: { executable: spec?.executable ?? null, args: spec?.args ?? [], cwd: spec?.cwd ?? null },
    startedAt: null,
    completedAt: null,
    spawnStatus: 'blocked',
    environmentKeys: spec?.environmentKeys ?? [],
    providerResult: {
      provider: spec?.provider ?? 'unknown',
      status: 'blocked',
      complete: false,
      coverageGaps: [{ kind: 'execution-blocked', reason }],
    },
  });
}
