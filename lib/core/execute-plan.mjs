// Generic plan execution. Every selected provider must produce exactly one
// terminal receipt, including selected-but-not-activated providers (which emit
// a deterministic skipped receipt rather than disappearing).

import { executionReceipt, blocked } from './execution-receipt.mjs';

export async function executePlan(plan, host) {
  const receipts = [];
  for (const provider of plan.providers ?? []) {
    const runner = provider.runner;
    if (!runner) {
      receipts.push(skippedReceipt(provider, 'no-runner'));
      continue;
    }
    if (runner.kind === 'reasoning-contract' || runner.kind === 'runtime-script') {
      // Selected but not activated by this deterministic executor: PR12's
      // provider executor activates runtime-script/security-pack providers.
      receipts.push(skippedReceipt(provider, 'deterministic-executor-not-activated'));
      continue;
    }
    if (runner.kind === 'legacy-check') {
      receipts.push(await runLegacyCheck(provider, plan, host));
      continue;
    }
    receipts.push(skippedReceipt(provider, `unsupported-runner-${runner.kind}`));
  }
  return { receipts };
}

export function skippedReceipt(provider, reason) {
  return executionReceipt({
    provider: provider.id,
    command: null,
    startedAt: null,
    completedAt: null,
    spawnStatus: 'blocked',
    providerResult: {
      provider: provider.id,
      status: 'skipped',
      complete: true,
      activation: {
        kind: provider.activation?.kind ?? null,
        matched: false,
        reason,
      },
      coverageGaps: [],
    },
  });
}

async function runLegacyCheck(provider, plan, host) {
  const startedAt = host.clock.now();
  const spec = {
    provider: provider.id,
    executable: provider.runner.check,
    args: [],
    cwd: plan.root,
    timeoutMs: 120000,
    maxOutputBytes: 8388608,
    environmentKeys: ['PATH', 'HOME'],
  };
  try {
    const run = await host.processRunner.run(spec);
    const completedAt = host.clock.now();
    const exitCode = Number.isInteger(run?.exitCode) ? run.exitCode : null;
    const spawnStatus = run?.status ?? (run?.error ? 'error' : 'completed');
    const providerResult = {
      provider: provider.id,
      status: spawnStatus === 'completed' && exitCode === 0 ? 'pass' : spawnStatus === 'blocked' ? 'blocked' : 'error',
      complete: spawnStatus === 'completed' && exitCode === 0,
      coverageGaps: spawnStatus !== 'completed' ? [{ kind: 'execution-failed', spawnStatus, exitCode }] : [],
    };
    return executionReceipt({
      provider: provider.id,
      command: { executable: spec.executable, args: spec.args, cwd: spec.cwd },
      startedAt,
      completedAt,
      spawnStatus,
      exitCode,
      timedOut: Boolean(run?.timedOut),
      environmentKeys: spec.environmentKeys,
      sandboxReceipt: host.capabilities?.networkSandbox?.receipt ?? null,
      tool: { name: spec.executable, version: null, executableDigest: null },
      providerResult,
    });
  } catch (error) {
    return executionReceipt({
      provider: provider.id,
      command: { executable: spec.executable, args: spec.args, cwd: spec.cwd },
      startedAt,
      completedAt: host.clock.now(),
      spawnStatus: 'error',
      environmentKeys: spec.environmentKeys,
      providerResult: {
        provider: provider.id,
        status: 'error',
        complete: false,
        coverageGaps: [{ kind: 'execution-error', detail: error.message }],
      },
    });
  }
}
