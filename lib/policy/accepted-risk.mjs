// Accepted-risk lifecycle per SNIP-RISK-01. Expired or identity-changed
// subjects reopen automatically. Accepted risk affects workflow status, never
// evidence truth or severity.

import { createHash } from 'node:crypto';

export function acceptedRisk({ subjectKind, subjectId, acceptedBy, reason, acceptedAt, expiresAt, bindingDigest }) {
  const body = {
    schemaVersion: 1,
    kind: 'nemesis-accepted-risk',
    subjectKind,
    subjectId,
    acceptedBy,
    reason,
    acceptedAt,
    expiresAt,
    bindingDigest,
  };
  return {
    ...body,
    id: `sha256:${createHash('sha256').update(`accepted-risk\0${JSON.stringify(body)}`).digest('hex')}`,
  };
}

export function isExpired(record, now) {
  if (!record?.expiresAt) return false;
  return new Date(record.expiresAt) <= new Date(now);
}

export function appliesTo(record, subjectKind, subjectId) {
  return record?.subjectKind === subjectKind && record?.subjectId === subjectId;
}

export function evaluateRisk({ records, subjectKind, subjectId, currentBindingDigest, now }) {
  const applicable = (records ?? []).filter((record) => appliesTo(record, subjectKind, subjectId));
  const active = applicable.filter((record) => !isExpired(record, now));
  const expired = applicable.filter((record) => isExpired(record, now));
  const bindingMismatch = applicable.filter((record) => record.bindingDigest && record.bindingDigest !== currentBindingDigest);
  const open = active.filter((record) => !bindingMismatch.includes(record));
  return {
    subjectKind,
    subjectId,
    active: open.length > 0,
    open,
    expired,
    bindingMismatch,
    // Accepted risk affects workflow status only.
    truthUnchanged: true,
  };
}
