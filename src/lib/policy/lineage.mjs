// Finding lineage (B7-034).
//
// Findings are tracked by a stable semantic fingerprint, so a moved line is the
// same finding and a changed root cause is a different one. Accepted risk sits
// beside the evidence and never inside it: it can change a finding's workflow
// state, never its severity, its evidence strength, or whether it is true.

import { createHash } from 'node:crypto';
import { evaluateRisk } from './accepted-risk.mjs';
import { findingFingerprint } from './baseline.mjs';

export const LINEAGE_STATES = Object.freeze([
  'new',
  'unchanged',
  'resolved',
  'reopened',
  'accepted',
  'expired',
  'superseded',
]);

const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });

function digestOf(value) {
  return `sha256:${createHash('sha256').update(`lineage\0${JSON.stringify(value)}`).digest('hex')}`;
}

export function classifyLineage({
  inBaseline,
  inCurrent,
  previouslyResolved = false,
  supersededBy = null,
  acceptedRisk = null,
  higherImpactThanAccepted = false,
}) {
  if (supersededBy) return 'superseded';
  if (!inCurrent) return inBaseline ? 'resolved' : 'new';
  if (!inBaseline) return 'new';
  // A higher-impact path reopens an acceptance rather than riding on it.
  if (higherImpactThanAccepted) return 'reopened';
  if (acceptedRisk?.active) return 'accepted';
  if (acceptedRisk?.expired) return 'expired';
  if (previouslyResolved) return 'reopened';
  return 'unchanged';
}

export function lineageLedger({
  baseline,
  current = [],
  acceptedRiskRecords = [],
  currentBindingDigest = null,
  resolvedHistory = [],
  supersessions = {},
  now,
  binding,
}) {
  const baselineFingerprints = new Set(baseline?.findingFingerprints ?? []);
  const baselineSeverity = new Map((baseline?.findings ?? []).map((item) => [item.fingerprint ?? item.id, item.severity]));
  const previouslyResolved = new Set(resolvedHistory);

  const entries = current.map((finding) => {
    const fingerprint = finding.fingerprint ?? findingFingerprint(finding);
    const risk = evaluateRisk({
      records: acceptedRiskRecords,
      subjectKind: 'finding',
      subjectId: fingerprint,
      currentBindingDigest,
      now,
    });
    const acceptedSeverity = baselineSeverity.get(fingerprint);
    const higherImpactThanAccepted = risk.active
      && acceptedSeverity !== undefined
      && (SEVERITY_RANK[finding.severity] ?? -1) > (SEVERITY_RANK[acceptedSeverity] ?? -1);

    const state = classifyLineage({
      inBaseline: baselineFingerprints.has(fingerprint),
      inCurrent: true,
      previouslyResolved: previouslyResolved.has(fingerprint),
      supersededBy: supersessions[fingerprint] ?? null,
      acceptedRisk: { active: risk.active, expired: risk.expired.length > 0 },
      higherImpactThanAccepted,
    });

    return {
      fingerprint,
      findingId: finding.id,
      state,
      // Evidence carried through untouched — accepted risk never rewrites it.
      severity: finding.severity ?? null,
      evidenceStrength: finding.evidenceStrength ?? null,
      truthUnchanged: true,
      acceptedRiskIds: risk.open.map((record) => record.id).sort(),
      expiredRiskIds: risk.expired.map((record) => record.id).sort(),
      bindingMismatchRiskIds: risk.bindingMismatch.map((record) => record.id).sort(),
      reopenReason: higherImpactThanAccepted
        ? `higher-impact path: severity rose from ${acceptedSeverity} to ${finding.severity}`
        : null,
      supersededBy: supersessions[fingerprint] ?? null,
    };
  });

  const currentFingerprints = new Set(entries.map((entry) => entry.fingerprint));
  for (const fingerprint of baselineFingerprints) {
    if (currentFingerprints.has(fingerprint)) continue;
    entries.push({
      fingerprint,
      findingId: null,
      state: classifyLineage({ inBaseline: true, inCurrent: false, supersededBy: supersessions[fingerprint] ?? null }),
      severity: baselineSeverity.get(fingerprint) ?? null,
      evidenceStrength: null,
      truthUnchanged: true,
      acceptedRiskIds: [],
      expiredRiskIds: [],
      bindingMismatchRiskIds: [],
      reopenReason: null,
      supersededBy: supersessions[fingerprint] ?? null,
    });
  }

  const body = {
    schemaVersion: 1,
    kind: 'legion-finding-lineage',
    baselineId: baseline?.id ?? null,
    baselineRevision: baseline?.revision ?? null,
    evaluatedAt: now ?? null,
    entries: entries.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)),
    binding,
  };
  return { ...body, digest: digestOf(body) };
}
