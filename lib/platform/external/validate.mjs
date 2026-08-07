import { sha256 } from '../contracts.mjs';

export function validateExternalEvidence(evidence, expected = {}) {
  const gaps = [];
  for (const key of ['producer', 'scope', 'environment', 'binding']) if (!evidence?.[key]) gaps.push(`missing-${key}`);
  for (const key of ['targetId', 'environment', 'artifactDigest']) if (expected[key] && evidence?.[key] !== expected[key]) gaps.push(`mismatched-${key}`);
  if (evidence?.kind === 'attestation' && expected.requiresExercise) gaps.push('exercise-required');
  return { schemaVersion: 1, kind: 'nemesis-external-evidence-validation', evidenceDigest: evidence ? sha256(evidence) : null, status: gaps.length ? 'unproven' : 'pass', gaps };
}
