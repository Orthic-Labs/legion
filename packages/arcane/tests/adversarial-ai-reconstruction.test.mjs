import assert from 'node:assert/strict';
import test from 'node:test';
import {
  AI_RECONSTRUCTION_BINDING_IDS,
  assessAiReadiness,
  assessArchitectureReconstruction,
  executeAdversarialAiReconstructionCase,
  validateAdversarialAiReconstructionObservation,
} from '../lib/adversarial-ai-reconstruction.mjs';

const aiEvidence = Object.freeze({
  systemId: 'assistant-routing',
  provenance: [{ sourceRef: 'registry:model-v4', digest: 'sha256:model-v4' }],
  evaluation: { status: 'PASS', reportRef: 'eval:2026-08-15', evaluatedAt: '2026-08-15T00:00:00.000Z', metrics: { safety: 1 } },
  fallback: { mode: 'deterministic-rules', owner: 'ops', testedAt: '2026-08-15T00:00:00.000Z' },
  humanAuthority: { role: 'risk-owner', authorityRef: 'authority:risk-owner', approvedAt: '2026-08-15T00:00:00.000Z' },
});

test('AI readiness requires independently structured provenance, evaluation, fallback & human authority', () => {
  const incomplete = assessAiReadiness({ ...aiEvidence, fallback: null });
  assert.equal(incomplete.disposition, 'NOT_READY');
  assert.deepEqual(incomplete.missing, ['fallback']);

  const observed = executeAdversarialAiReconstructionCase('AE-ADVERSARIAL-009', aiEvidence);
  assert.equal(observed.value.disposition, 'READY');
  assert.equal(validateAdversarialAiReconstructionObservation(observed.id, observed), true);
  assert.equal(validateAdversarialAiReconstructionObservation(observed.id, { ...observed, value: { ...observed.value, readiness: false } }), false);
});

test('stale or incomplete reconstruction evidence reports uncertainty & forbids broad clean conclusion', () => {
  const input = {
    asOf: '2026-08-15T00:00:00.000Z',
    evidence: [
      { scope: 'topology', sourceRef: 'cortex:topology', observedAt: '2026-08-10T00:00:00.000Z', expiresAt: '2026-09-01T00:00:00.000Z' },
      { scope: 'runtime', sourceRef: 'runtime:health', observedAt: '2026-07-01T00:00:00.000Z', expiresAt: '2026-07-02T00:00:00.000Z' },
      { scope: 'ownership', sourceRef: 'owners:map', observedAt: '2026-08-10T00:00:00.000Z', expiresAt: '2026-09-01T00:00:00.000Z' },
    ],
  };
  const verdict = assessArchitectureReconstruction(input);
  assert.equal(verdict.disposition, 'UNCERTAINTY_REPORTED');
  assert.equal(verdict.cleanAllowed, false);
  assert.deepEqual(verdict.missingScopes, ['runtime', 'deployment']);
  assert.deepEqual(verdict.staleScopes, ['runtime']);

  const observed = executeAdversarialAiReconstructionCase('AE-ADVERSARIAL-010', input);
  assert.equal(validateAdversarialAiReconstructionObservation(observed.id, observed), true);
  assert.equal(validateAdversarialAiReconstructionObservation(observed.id, { ...observed, value: { ...observed.value, cleanAllowed: true } }), false);
});

test('only declared AI & reconstruction bindings are accepted', () => {
  assert.deepEqual(AI_RECONSTRUCTION_BINDING_IDS, ['AE-ADVERSARIAL-009', 'AE-ADVERSARIAL-010']);
  assert.equal(executeAdversarialAiReconstructionCase('AE-ADVERSARIAL-999', {}).status, 'PENDING');
});
