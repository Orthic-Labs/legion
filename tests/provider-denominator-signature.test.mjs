import assert from 'node:assert/strict';
import test from 'node:test';
import { buildAuditPlan, verifyPlanBinding, verifyPlanSeal, verifyPlanSignature } from '../tools/audit/audit-plan.mjs';
import { loadProviderRegistry } from '../registry/provider-registry.mjs';

function projection() {
  return {
    state: 'ready',
    generationId: 'gen-1',
    manifestDigest: 'sha256:manifest',
    sourceObservation: { head: 'abc', statusDigest: 'status-1' },
    files: ['package.json', 'src/App.tsx', 'src/server.ts', 'README.md'],
    fileCount: 4,
    sourceFileCount: 2,
    parsedExtensions: ['ts', 'tsx'],
    unsupportedExtensions: [],
    fileSetDigest: 'sha256:files',
    auditFacts: {
      packageManifests: [{ path: 'package.json', dependencies: ['react'], scripts: ['dev'] }],
    },
  };
}

const repositoryBinding = {
  repositoryRevision: 'abc',
  dirty: false,
  dirtyPatchDigest: 'sha256:clean',
};
const cortexBinding = {
  state: 'ready',
  generationId: 'gen-1',
  manifestDigest: 'sha256:manifest',
  sourceObservation: { head: 'abc', statusDigest: 'status-1' },
};

test('dependency and script selected providers bind Cortex implementation files, not only package.json', () => {
  const plan = buildAuditPlan({
    root: '/repo',
    registry: loadProviderRegistry(),
    projection: projection(),
    repositoryBinding,
    signingKey: 'test-signing-key',
  });
  for (const id of ['react.hooks-config', 'runtime.app', 'framework.major-suite', 'accessibility.internal-suite', 'visual.core']) {
    const provider = plan.providers.find((item) => item.id === id);
    assert.ok(provider, id);
    assert.deepEqual(provider.denominator.paths, ['src/App.tsx', 'src/server.ts']);
    assert.equal(provider.denominator.pathCount, 2);
  }
});

test('signed plan verifies only with the matching key', () => {
  const plan = buildAuditPlan({
    root: '/repo', registry: loadProviderRegistry(), projection: projection(), repositoryBinding,
    signingKey: 'correct-key',
  });
  assert.equal(verifyPlanSeal(plan), true);
  assert.equal(verifyPlanSignature(plan, 'correct-key'), true);
  assert.equal(verifyPlanSignature(plan, 'wrong-key'), false);
  assert.equal(verifyPlanBinding(plan, repositoryBinding, cortexBinding, 'correct-key').valid, true);
  assert.ok(verifyPlanBinding(plan, repositoryBinding, cortexBinding, 'wrong-key').drift.some((item) => item.field === 'signature'));
});

test('unsigned plan is integrity-valid but explicitly UNPROVEN', () => {
  const plan = buildAuditPlan({
    root: '/repo', registry: loadProviderRegistry(), projection: projection(), repositoryBinding,
    signingKey: null,
  });
  assert.equal(verifyPlanSeal(plan), true);
  assert.equal(verifyPlanSignature(plan, null), false);
  assert.equal(plan.qualification.planSigned, false);
  assert.ok(plan.coverageGaps.some((gap) => gap.kind === 'unsigned-plan'));
  assert.equal(plan.qualification.state, 'unproven');
});
