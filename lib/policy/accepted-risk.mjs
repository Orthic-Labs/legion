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

// Deliberately carries no severity and no evidence field: an acceptance is a
// workflow decision about a finding, never a statement about whether it is true
// or how bad it is.
export function buildAcceptedRiskSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/remediation/accepted-risk-v1.json',
    title: 'RemediationAcceptedRiskV1',
    type: 'object',
    required: ['schemaVersion', 'kind', 'id', 'subjectKind', 'subjectId', 'acceptedBy', 'reason', 'acceptedAt', 'expiresAt', 'bindingDigest', 'truthUnchanged'],
    properties: {
      schemaVersion: { const: 1 },
      kind: { const: 'nemesis-accepted-risk' },
      id: { type: 'string', pattern: '^sha256:' },
      subjectKind: { enum: ['finding', 'attack-path', 'rule', 'family'] },
      subjectId: { type: 'string', minLength: 1 },
      acceptedBy: { type: 'string', minLength: 1 },
      reason: { type: 'string', minLength: 1 },
      acceptedAt: { type: 'string', minLength: 1 },
      expiresAt: { type: ['string', 'null'] },
      bindingDigest: { type: ['string', 'null'] },
      truthUnchanged: { const: true },
    },
    additionalProperties: false,
  };
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
