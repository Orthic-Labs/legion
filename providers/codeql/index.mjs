// Imported SARIF receipt per SNIP-IMPORTED-SARIF-01. Rejects SARIF whose
// repository root/base URI cannot be bound to the current plan. Imported
// results route through candidate/adjudication/variant contracts; they never
// bypass adjudication.

import { createHash } from 'node:crypto';

export function importedSarifReceipt({ provider, providerVersion, sourceArtifact, repositoryBinding, tool, capabilities }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-imported-sarif',
    provider,
    providerVersion,
    sourceArtifact,
    repositoryBinding,
    tool,
    capabilities: capabilities ?? {},
    complete: true,
    coverageGaps: [],
  };
}

export function assertRepositoryBinding(receipt, plan) {
  const planRevision = plan?.binding?.repositoryRevision;
  if (!planRevision) throw new Error('plan has no repository revision to bind against');
  const receiptRevision = receipt?.repositoryBinding?.repositoryRevision;
  if (!receiptRevision) throw new Error(`SARIF from ${receipt?.provider} has no repository binding`);
  if (receiptRevision !== planRevision) {
    throw new Error(`SARIF repository binding ${receiptRevision} does not match plan revision ${planRevision}`);
  }
  return true;
}

export function sarifSourceDigest(uri) {
  return `sha256:${createHash('sha256').update(`sarif-source\0${uri}`).digest('hex')}`;
}
