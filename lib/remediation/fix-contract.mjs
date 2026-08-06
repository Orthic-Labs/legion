// Fix proposal contract per SNIP-FIX-01. A proposal binds finding/root cause,
// target files/ranges, preconditions, patch digest, expected behavior, risks,
// and validation commands. Tier: MECHANICAL | AGENT_GUIDED | MANUAL.

import { createHash } from 'node:crypto';

export function fixProposal({ findingId, rootCauseDigest, producer, targetPaths, preconditions, patch, expectedBehavior, risks, validationCommands, tier }) {
  const body = {
    schemaVersion: 1,
    kind: 'nemesis-fix-proposal',
    findingId,
    rootCauseDigest,
    producer: producer ?? {},
    targetPaths: [...(targetPaths ?? [])].sort(),
    preconditions: [...(preconditions ?? [])].sort(),
    patch,
    expectedBehavior: [...(expectedBehavior ?? [])].sort(),
    risks: [...(risks ?? [])].sort(),
    validationCommands: [...(validationCommands ?? [])].sort(),
    tier,
  };
  body.id = `sha256:${createHash('sha256').update(JSON.stringify(body)).digest('hex')}`;
  return body;
}

export const FIX_STOPS = Object.freeze([
  'max-batches',
  'no-progress',
  'regression',
  'plan-drift',
  'new-high-critical',
  'manual-finding-required',
  'missing-variant-or-proof',
  'scope-expansion',
]);

export function evaluateFixLoop({ batchIndex, maxBatches = 4, progress, regression, drift, newHighCritical, manualRequired, missingVariantProof, scopeExpansion }) {
  if (batchIndex >= maxBatches) return { stop: true, reason: 'max-batches' };
  if (progress === false) return { stop: true, reason: 'no-progress' };
  if (regression) return { stop: true, reason: 'regression' };
  if (drift) return { stop: true, reason: 'plan-drift' };
  if (newHighCritical) return { stop: true, reason: 'new-high-critical' };
  if (manualRequired) return { stop: true, reason: 'manual-finding-required' };
  if (missingVariantProof) return { stop: true, reason: 'missing-variant-or-proof' };
  if (scopeExpansion) return { stop: true, reason: 'scope-expansion' };
  return { stop: false, reason: null };
}
