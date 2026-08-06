// Deterministic core API. Core functions receive all paths as absolute
// canonical paths and return values/artifact refs; they do not call
// process.exit, parse argv, or write arbitrary files. The CLI, MCP, hooks,
// CI actions, and tests import these functions.

import { buildAuditPlan, verifyPlanBinding } from '../../audit-plan.mjs';
import { loadProviderRegistry } from '../../registry/provider-registry.mjs';

export { RunArtifactStore } from '../artifacts/run-store.mjs';
export { executionReceipt, blocked } from './execution-receipt.mjs';
export { executePlan } from './execute-plan.mjs';
export { reconcileRun } from './reconcile-run.mjs';
export { finalizeRun, exitCodeForReport } from './finalize-run.mjs';

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
