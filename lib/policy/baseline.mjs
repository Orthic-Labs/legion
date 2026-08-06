// Baseline and finding lineage per SNIP-RISK-01. Stable finding lineage with
// new/unchanged/resolved/reopened classification; a baseline never hides
// incomplete current coverage.

import { createHash } from 'node:crypto';

export function baselineRecord({ id, revision, findings, createdAt }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-baseline',
    id,
    revision,
    findingIds: [...(findings ?? [])].map((f) => f.id).sort(),
    findingFingerprints: [...(findings ?? [])].map((f) => f.fingerprint ?? f.id).sort(),
    createdAt,
  };
}

export function classifyFinding({ fingerprint, inBaseline, inCurrent }) {
  if (!inBaseline && inCurrent) return 'new';
  if (inBaseline && !inCurrent) return 'resolved';
  if (inBaseline && inCurrent) return 'unchanged';
  return 'reopened';
}

export function findingFingerprint(finding) {
  const body = JSON.stringify({
    ruleId: finding.ruleId,
    file: finding.file ? String(finding.file).replaceAll('\\', '/') : null,
    rootCause: finding.rootCauseDigest ?? finding.rootCauseSignature ?? null,
  });
  return `sha256:${createHash('sha256').update(`finding\0${body}`).digest('hex')}`;
}
