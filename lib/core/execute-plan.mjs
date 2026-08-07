// Generic plan execution. Every selected provider must produce exactly one
// terminal receipt, including selected-but-not-activated providers (which emit
// a deterministic skipped receipt rather than disappearing).

import { executionReceipt, blocked } from './execution-receipt.mjs';
import { scheduleProviders } from './scheduler.mjs';

export async function executePlan(plan, host) {
  const receipts = [];
  const providerById = new Map((plan.providers ?? []).map((provider) => [provider.id, provider]));
  const terminal = new Map();
  for (const ids of scheduleProviders(plan.providers ?? [], { mode: plan.schedule ?? 'auto', concurrency: plan.config?.limits?.maxConcurrency ?? 4 })) {
   for (const id of ids) {
    const provider = providerById.get(id);
    const blockedDependency = (provider.dependsOn ?? []).find((dependency) => !terminal.get(dependency)?.providerResult?.complete);
    if (blockedDependency) { const receipt = blocked({ provider: provider.id }, `dependency-not-complete:${blockedDependency}`); receipts.push(receipt); terminal.set(provider.id, receipt); continue; }
    const runner = provider.runner;
    if (!runner) {
      const receipt = skippedReceipt(provider, 'no-runner'); receipts.push(receipt); terminal.set(provider.id, receipt);
      continue;
    }
    if (runner.kind === 'reasoning-contract' || runner.kind === 'runtime-script') {
      // Selected but not activated by this deterministic executor: PR12's
      // provider executor activates runtime-script/security-pack providers.
      const receipt = skippedReceipt(provider, 'deterministic-executor-not-activated'); receipts.push(receipt); terminal.set(provider.id, receipt);
      continue;
    }
    if (runner.kind === 'legacy-check') {
      const receipt = await runLegacyCheck(provider, plan, host); receipts.push(receipt); terminal.set(provider.id, receipt);
      continue;
    }
    const receipt = skippedReceipt(provider, `unsupported-runner-${runner.kind}`); receipts.push(receipt); terminal.set(provider.id, receipt);
   }
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
