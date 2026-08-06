// Run reconciliation. Process completion, provider verdict, quality gate, and
// audit status remain distinct. A zero-finding result is never a pass when
// selected evidence is missing.

export function reconcileRun({ plan, receipts = [], artifacts = null }, host) {
  const byProvider = new Map(receipts.map((receipt) => [receipt.provider, receipt]));
  const providerResults = (plan.providers ?? []).map((provider) => {
    const receipt = byProvider.get(provider.id);
    if (!receipt) {
      return {
        provider: provider.id,
        phase: provider.phase,
        status: 'missing',
        complete: false,
        benchmark: provider.benchmark,
        coverageGaps: [{ kind: 'missing-terminal-receipt' }],
      };
    }
    return {
      provider: provider.id,
      phase: provider.phase,
      status: receipt.providerResult?.status ?? 'unproven',
      complete: receipt.providerResult?.complete === true,
      spawnStatus: receipt.spawnStatus ?? null,
      exitCode: receipt.exitCode ?? null,
      benchmark: provider.benchmark,
      coverageGaps: receipt.providerResult?.coverageGaps ?? [],
    };
  });

  const incomplete = providerResults.some((result) => !result.complete)
    || providerResults.some((result) => ['unproven', 'missing', 'error', 'blocked', 'pending'].includes(result.status));
  const executionFailed = providerResults.some((result) => ['fail', 'error'].includes(result.status));

  return {
    schemaVersion: 1,
    kind: 'audit-facts',
    workspace: plan.root,
    out_dir: artifacts?.root ?? null,
    generated_at: host.clock.now().toISOString(),
    checks: receipts
      .filter((receipt) => receipt.providerResult?.status !== 'skipped')
      .map((receipt) => ({
        check: receipt.provider,
        status: receipt.providerResult?.status ?? receipt.spawnStatus,
        execution_status: receipt.spawnStatus,
        verdict: receipt.providerResult?.status === 'pass' ? 'pass' : 'unproven',
        exit_code: receipt.exitCode,
        findings_count: null,
      })),
    incomplete,
    executionFailed,
    provider_reconciliation: {
      providerResults,
      missingChecks: [],
      unplannedChecks: [],
      denominatorMismatches: [],
      unresolvedCoverage: [],
      missingRuntimeProviders: [],
    },
    plan,
  };
}
