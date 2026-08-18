// Rollback (B7-034). Like apply, the mutation is the host's; this module owns
// the contract. A rollback that did not restore the expected fingerprint is
// reported as failed with exact recovery data — it is never suppressed.

import { createHash } from 'node:crypto';

function digestOf(value) {
  return `sha256:${createHash('sha256').update(`rollback\0${JSON.stringify(value)}`).digest('hex')}`;
}

export async function rollbackApply({ applyReceipt, mutator, expectedFingerprint }) {
  if (typeof mutator?.restore !== 'function') {
    throw new TypeError('rollback requires a host mutator; the audit engine does not mutate repositories');
  }
  const target = expectedFingerprint ?? applyReceipt?.beforeFingerprint ?? null;
  const result = await mutator.restore({
    proposalId: applyReceipt?.proposalId ?? null,
    reversePatchDigest: applyReceipt?.reversePatchDigest ?? null,
    expectedFingerprint: target,
  });

  const restoredFingerprint = result?.fingerprint ?? null;
  const restored = result?.ok === true && restoredFingerprint === target;
  const body = {
    schemaVersion: 1,
    kind: 'legion-remediation-rollback-receipt',
    proposalId: applyReceipt?.proposalId ?? null,
    applyDigest: applyReceipt?.digest ?? null,
    reversePatchDigest: applyReceipt?.reversePatchDigest ?? null,
    expectedFingerprint: target,
    restoredFingerprint,
    restored,
    error: restored ? null : (result?.error ?? 'restored fingerprint does not match the pre-apply state'),
    recovery: restored
      ? { command: null, description: 'no recovery needed' }
      : {
        command: ['legion', 'remediation', 'restore-checkpoint', '--proposal', applyReceipt?.proposalId ?? 'unknown'],
        description: 'the working tree is NOT at the pre-apply fingerprint; restore from the sandbox checkpoint before continuing',
      },
  };
  return { ...body, digest: digestOf(body) };
}
