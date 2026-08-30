// Completion evidence is read, never caller-supplied: only authenticated
// Oracle evidence receipts already persisted by Arcane can satisfy a sealed
// contract's acceptance criteria.
import { AcceptanceEvidenceRegistry } from './evidence-registry.mjs';
import { EVIDENCE_RECEIPT_BOUND_FIELDS, verifyRecord } from '../../guard/compat/audit/receipt-auth.mjs';

const exact = (a, b) => JSON.stringify(a) === JSON.stringify(b);

export function loadCompletionEvidence({ receiptStore, keyRing, authorityProofIssuer = null, execution, integratedState, latestMaterialChange, now = new Date() }) {
  const registry = new AcceptanceEvidenceRegistry();
  const proofs = [];
  const criteria = execution?.acceptanceCriteria ?? [];
  if (!criteria.length || !keyRing || !authorityProofIssuer) return { evidenceRegistry: registry, acceptanceProofs: proofs, integratedState, latestMaterialChange, now };
  const expected = { runId: execution.runId, taskId: execution.taskId, contractId: execution.contractId };
  const records = receiptStore.list({ runId: execution.runId });
  for (const criterion of criteria) {
    const receipt = records.find((record) => {
      if (record?.kind !== 'legion-evidence-capability-receipt' || record.stale === true || record.producerAuthority !== 'oracle') return false;
      const observation = record.observation;
      if (!observation || observation.acceptanceId !== criterion.id || typeof observation.requirementId !== 'string' || !observation.requirementId || typeof observation.productionSymbol !== 'string' || !observation.productionSymbol || typeof observation.liveConsumer !== 'string' || !observation.liveConsumer || typeof observation.acceptanceSurface !== 'string' || !observation.acceptanceSurface || !exact(observation.integratedState, integratedState) || observation.latestMaterialChange !== latestMaterialChange || observation.contractVersion !== execution.contractVersion || observation.contractDigest !== execution.contractDigest || observation.sourceRevision !== execution.sourceRevision) return false;
      const authority = authorityProofIssuer.findByDigest(observation.authorityProofDigest);
      return Boolean(authority && authorityProofIssuer.verify(authority, { expected: { ...expected, contractVersion: execution.contractVersion, contractDigest: execution.contractDigest, sourceRevision: execution.sourceRevision } }).allowed && verifyRecord(record, record.authentication, { keyRing, boundFields: EVIDENCE_RECEIPT_BOUND_FIELDS, expectedBinding: expected }).allowed);
    });
    if (!receipt) continue;
    const observation = receipt.observation;
    registry.register({ acceptanceId: criterion.id, claimType: 'acceptance-surface', producer: 'oracle', durableStore: 'receipt-store', verifier: 'arcane', completionConsumer: 'legion', integratedStateBinding: 'exact-git-state', validityPolicy: 'latest-material-change' });
    proofs.push({ acceptanceId: criterion.id, producer: 'oracle', verifier: 'arcane', completionConsumer: 'legion', authenticated: true, integratedState: observation.integratedState, observedAt: receipt.observedAt, validUntil: observation.validUntil });
  }
  return { evidenceRegistry: registry, acceptanceProofs: proofs, integratedState, latestMaterialChange, now };
}
