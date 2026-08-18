// Controlled application (B7-034).
//
// LANE NOTE — propose-and-verify separation: this module owns the *contract*
// around application, not the mutation. Legion never writes to an audited
// repository; it gates on capability, a valid neutral verification, and a
// matching target fingerprint, then hands the patch to a host-supplied mutator
// (in Legion: Oracle proposes, Alchemist mutates). No filesystem API is imported
// here, so there is no code path by which this engine can mutate a repository
// itself.

import { createHash } from 'node:crypto';
import { assertProducerIsNotVerifier } from './reasoning-packets.mjs';

export const APPLY_RECEIPT_SCHEMA_VERSION = 1;

export function treeFingerprint(files) {
  const body = JSON.stringify((files ?? []).sort());
  return `sha256:${createHash('sha256').update(`tree-fingerprint\0${body}`).digest('hex')}`;
}

function digestOf(value) {
  return `sha256:${createHash('sha256').update(`apply\0${JSON.stringify(value)}`).digest('hex')}`;
}

export function requireApplyCapability(host) {
  if (host?.capabilities?.mutation !== true) {
    throw new Error('apply requires explicit host mutation capability');
  }
  return true;
}

function requireValidVerification(proposal, verification) {
  if (verification?.kind !== 'legion-remediation-verification' || verification.valid !== true) {
    throw new Error('apply requires a valid neutral verification for this proposal');
  }
  if (verification.proposalId !== proposal.id) {
    throw new Error('the verification does not belong to this proposal');
  }
  assertProducerIsNotVerifier(proposal, verification.verifier);
  return true;
}

/**
 * Apply a verified proposal through the host mutator. Either the mutation
 * completes and the receipt records the new fingerprint, or it stops with the
 * observed fingerprint and exact recovery data — never a partial success.
 */
export async function applyProposal({
  proposal,
  verification,
  host,
  mutator,
  targetFingerprint,
  observedFingerprint,
  binding,
}) {
  requireApplyCapability(host);
  requireValidVerification(proposal, verification);
  if (observedFingerprint !== targetFingerprint) {
    throw new Error('target repository fingerprint changed since verification; refusing to apply on stale identity');
  }
  if (typeof mutator?.apply !== 'function') {
    throw new TypeError('apply requires a host mutator; the audit engine does not mutate repositories');
  }

  const result = await mutator.apply({
    proposalId: proposal.id,
    patch: proposal.patch,
    patchDigest: proposal.patch?.digest ?? null,
    targetPaths: [...(proposal.targetPaths ?? [])].sort(),
    expectedFingerprint: targetFingerprint,
  });

  const applied = result?.ok === true;
  const body = {
    schemaVersion: APPLY_RECEIPT_SCHEMA_VERSION,
    kind: 'legion-remediation-apply-receipt',
    proposalId: proposal.id,
    findingIds: [...(proposal.findingIds ?? [])].sort(),
    patchDigest: proposal.patch?.digest ?? null,
    verificationDigest: verification.digest ?? null,
    appliedBy: 'host-mutator',
    applied,
    beforeFingerprint: targetFingerprint,
    afterFingerprint: applied ? (result.fingerprint ?? null) : null,
    observedFingerprint: applied ? (result.fingerprint ?? null) : (result?.fingerprint ?? targetFingerprint),
    reversePatchDigest: applied ? (result.reversePatchDigest ?? null) : null,
    error: applied ? null : (result?.error ?? 'unknown'),
    // A stopped application leaves a state the caller can recover from.
    recoverable: applied ? true : (result?.fingerprint ?? targetFingerprint) === targetFingerprint,
    recovery: applied
      ? { command: null, description: 'rollback via the reverse patch or the sandbox checkpoint' }
      : { command: ['legion', 'remediation', 'rollback', '--proposal', proposal.id], description: 'restore the pre-apply fingerprint through the host mutator' },
    rolledBack: false,
    binding,
  };
  return { ...body, digest: digestOf(body) };
}

export function buildApplyReceiptSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/remediation/apply-receipt-v1.json',
    title: 'RemediationApplyReceiptV1',
    type: 'object',
    required: [
      'schemaVersion', 'kind', 'proposalId', 'findingIds', 'patchDigest', 'verificationDigest',
      'appliedBy', 'applied', 'beforeFingerprint', 'afterFingerprint', 'observedFingerprint',
      'reversePatchDigest', 'error', 'recoverable', 'recovery', 'rolledBack', 'binding', 'digest',
    ],
    properties: {
      schemaVersion: { const: APPLY_RECEIPT_SCHEMA_VERSION },
      kind: { const: 'legion-remediation-apply-receipt' },
      proposalId: { type: 'string' },
      findingIds: { type: 'array', items: { type: 'string' } },
      patchDigest: { type: ['string', 'null'] },
      verificationDigest: { type: ['string', 'null'] },
      // The engine proposes; a host mutator applies.
      appliedBy: { const: 'host-mutator' },
      applied: { type: 'boolean' },
      beforeFingerprint: { type: 'string', pattern: '^sha256:' },
      afterFingerprint: { type: ['string', 'null'] },
      observedFingerprint: { type: ['string', 'null'] },
      reversePatchDigest: { type: ['string', 'null'] },
      error: { type: ['string', 'null'] },
      recoverable: { type: 'boolean' },
      recovery: {
        type: 'object',
        required: ['command', 'description'],
        properties: {
          command: { oneOf: [{ type: 'null' }, { type: 'array', items: { type: 'string' } }] },
          description: { type: 'string' },
        },
        additionalProperties: false,
      },
      rolledBack: { type: 'boolean' },
      binding: { type: 'object' },
      digest: { type: 'string', pattern: '^sha256:' },
    },
    additionalProperties: false,
  };
}

// ---------------------------------------------------------------------------
// Pre-existing helpers retained for their existing callers.
// ---------------------------------------------------------------------------

export function applyReceipt({ proposalId, patchDigest, worktreePath, beforeFingerprint, afterFingerprint, applied }) {
  return {
    schemaVersion: 1,
    kind: 'legion-patch-apply',
    proposalId,
    patchDigest,
    worktreePath,
    beforeFingerprint,
    afterFingerprint,
    applied,
    rolledBack: false,
  };
}

export function rollbackReceipt({ apply, reversePatchDigest, restoredFingerprint, worktreePath }) {
  return {
    schemaVersion: 1,
    kind: 'legion-patch-rollback',
    applyDigest: apply?.patchDigest ?? null,
    reversePatchDigest,
    restoredFingerprint,
    worktreePath,
    restored: restoredFingerprint === apply?.beforeFingerprint,
  };
}
