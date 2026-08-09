// Deterministic core API. Core functions receive all paths as absolute
// canonical paths and return values/artifact refs; they do not call
// process.exit, parse argv, or write arbitrary files. The CLI, MCP, hooks,
// CI actions, and tests import these functions.

import { buildAuditPlan } from '../../audit-plan.mjs';
import { loadProviderRegistry } from '../../registry/provider-registry.mjs';
import { verifySealedRun } from './verify-run.mjs';
import { digest as coreDigest } from './binding.mjs';

export { RunArtifactStore } from '../artifacts/run-store.mjs';
export { executionReceipt, blocked } from './execution-receipt.mjs';
export { executePlan } from './execute-plan.mjs';
export { reconcileRun } from './reconcile-run.mjs';
export { finalizeRun, exitCodeForReport } from './finalize-run.mjs';
export { inspectProduct } from './inspect-product.mjs';
export { bindRepository } from './repository-binding.mjs';
export { assertArtifactBinding, digest, sameBinding } from './binding.mjs';
export { buildSealedPlan } from './build-plan.mjs';
export { verifySealedRun } from './verify-run.mjs';
export { audit } from './audit.mjs';

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
  return buildAuditPlan({
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
}

// verifyRun({ priorRun, currentRepository }, host) → verification receipt
export const verifyRun = verifySealedRun;

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
  const sourceRevision=binding?.sourceRevision??binding?.repositoryRevision??null;const manifest = {
    schemaVersion: 1,
    kind: 'legion-run-manifest',
    binding: binding ?? null,
    sourceRevision,
    terminalAbsences:records.filter(({status})=>status==='missing').map(({path})=>path).sort(),
    artifacts: records,
  };
  manifest.digest=coreDigest(manifest);
  await store.writeJson({
    path: 'run-manifest.json',
    kind: 'run-manifest',
    producer: 'legion.core',
    schemaVersion: 1,
    binding: binding ?? null,
    value: manifest,
  });
  return manifest;
}
