// Controlled apply with rollback per SNIP-RISK-01's apply contract. Apply
// happens only after explicit user confirmation/capability; the target tree
// fingerprint is verified before apply; rollback is the reverse patch.

import { createHash } from 'node:crypto';

export function treeFingerprint(files) {
  const body = JSON.stringify((files ?? []).sort());
  return `sha256:${createHash('sha256').update(`tree-fingerprint\0${body}`).digest('hex')}`;
}

export function applyReceipt({ proposalId, patchDigest, worktreePath, beforeFingerprint, afterFingerprint, applied }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-patch-apply',
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
    kind: 'nemesis-patch-rollback',
    applyDigest: apply?.patchDigest ?? null,
    reversePatchDigest,
    restoredFingerprint,
    worktreePath,
    restored: restoredFingerprint === apply?.beforeFingerprint,
  };
}

export function requireApplyCapability(host) {
  if (host.capabilities?.mutation !== true) {
    throw new Error('apply requires explicit host mutation capability');
  }
  return true;
}
