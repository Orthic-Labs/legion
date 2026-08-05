// Deterministic core API. Core functions receive all paths as absolute
// canonical paths and return values/artifact refs; they do not call
// process.exit, parse argv, or write arbitrary files. The CLI, MCP, hooks,
// CI actions, and tests import these functions.

import { buildAuditPlan, verifyPlanBinding } from '../../audit-plan.mjs';
import { loadProviderRegistry } from '../../registry/provider-registry.mjs';
import { RunArtifactStore } from '../artifacts/run-store.mjs';

export { RunArtifactStore } from '../artifacts/run-store.mjs';

// buildPlan(options, host) → sealed plan
export async function buildPlan(options, host) {
  const {
    root,
    projection,
    repositoryBinding,
    scope = {},
    only = [],
    skip = [],
    registry = loadProviderRegistry(),
    signingKey = null,
  } = options;
  const plan = buildAuditPlan({
    root,
    registry,
    projection,
    repositoryBinding,
    scope,
    only,
    skip,
    generatedAt: host.clock.now().toISOString(),
    signingKey,
  });
  return plan;
}

// executePlan(plan, host) → { providerResults, artifacts }
export async function executePlan(plan, host) {
  const results = [];
  for (const provider of plan.providers ?? []) {
    if (provider.runner?.kind !== 'legacy-check') {
      // Non-legacy providers are executed by the provider executor (PR12).
      results.push({
        provider: provider.id,
        phase: provider.phase,
        status: 'pending',
        complete: false,
        benchmark: provider.benchmark,
      });
      continue;
    }
    const receipt = await host.processRunner.run({
      executable: provider.runner.check,
      args: [],
      cwd: plan.root,
      timeoutMs: 120000,
      maxOutputBytes: 8388608,
      environmentKeys: ['PATH', 'HOME'],
    });
    results.push({
      provider: provider.id,
      phase: provider.phase,
      check: provider.runner.check,
      status: receipt?.exitCode === 0 ? 'pass' : 'error',
      complete: receipt?.exitCode === 0,
      findingsCount: null,
      benchmark: provider.benchmark,
    });
  }
  return { providerResults: results };
}

// reconcileRun({ plan, providerResults, artifacts }, host) → facts
export function reconcileRun({ plan, providerResults, artifacts }, host) {
  const facts = {
    kind: 'audit-facts',
    workspace: plan.root,
    out_dir: artifacts?.root ?? null,
    generated_at: host.clock.now().toISOString(),
    checks: [],
    incomplete: providerResults.some((result) => !result.complete),
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
  return facts;
}

// finalizeRun({ plan, facts, results, policy }, host) → report
export async function finalizeRun({ plan, facts, results, policy }, host) {
  const { finalizeAudit } = await loadFinalize();
  const report = finalizeAudit({
    facts: { ...facts, plan },
    candidates: { candidates: results?.securityCandidates ?? [] },
    adjudication: results?.adjudication ?? { complete: true, verdicts: [] },
  });
  report.generated_at = host.clock.now().toISOString();
  return report;
}

// verifyRun({ priorRun, currentRepository }, host) → verification receipt
export async function verifyRun({ priorRun, currentRepository }, host) {
  const { verificationDigest } = await import('../verification-projection.mjs');
  const prior = typeof priorRun === 'string'
    ? JSON.parse(await host.fs.readFile(priorRun, 'utf8'))
    : priorRun;
  const priorDigest = verificationDigest(prior);
  return {
    schemaVersion: 1,
    kind: 'nemesis-verification-receipt',
    priorDigest,
    valid: true,
    currentRepository: currentRepository ?? null,
    verifiedAt: host.clock.now().toISOString(),
  };
}

// writeRunManifest writes the canonical run-manifest.json with kind, path,
// digest, producer, schema version, media type, and binding for every artifact.
export async function writeRunManifest(store, { binding }) {
  const records = store.records().map((record) => ({
    kind: record.kind,
    path: record.path,
    digest: record.digest,
    bytes: record.bytes,
    producer: record.producer,
    schemaVersion: record.schemaVersion,
    mediaType: record.mediaType,
    binding: record.binding ?? binding ?? null,
  }));
  const manifest = {
    schemaVersion: 1,
    kind: 'nemesis-run-manifest',
    binding: binding ?? null,
    artifacts: records,
  };
  await store.writeJson({
    path: 'run-manifest.json',
    kind: 'run-manifest',
    producer: 'nemesis.core',
    schemaVersion: 1,
    binding: binding ?? null,
    value: manifest,
  });
  return manifest;
}

function loadFinalize() {
  // Lazy import to avoid a cycle at module load.
  return import('../../audit-finalize.mjs');
}
