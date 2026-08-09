// B7-033 — patch effect graphs and neutral verification.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  blocksAutoApply,
  buildEffectGraph,
  buildEffectGraphSchema,
  computeClosure,
  patchEffectGraph,
} from '../../lib/remediation/effect-graph.mjs';
import {
  buildVerificationSchema,
  verifyProposal,
} from '../../lib/remediation/verify-proposal.mjs';

const binding = {
  planDigest: 'sha256:plan',
  repositoryRevision: 'abc123',
  dirtyPatchDigest: null,
  cortexGenerationId: 'gen',
  cortexManifestDigest: 'sha256:manifest',
  registryDigest: 'sha256:registry',
};

// security.output-handling -> security.evidence-synthesis -> report.render
const planGraph = {
  providers: [
    { id: 'security.output-handling', family: 'security', dependsOn: [], requiredForCleanClaim: true, paths: ['src/render.mjs'] },
    { id: 'security.evidence-synthesis', family: 'security', dependsOn: ['security.output-handling'], requiredForCleanClaim: true },
    { id: 'report.render', family: 'report', dependsOn: ['security.evidence-synthesis'], requiredForCleanClaim: false },
    { id: 'copy.anti-slop', family: 'copy', dependsOn: [], requiredForCleanClaim: true, paths: ['content/home.md'] },
  ],
  baselineGates: [
    { id: 'gate.no-new-high', requiredForApply: true },
    { id: 'gate.tests-pass', requiredForApply: true },
  ],
};

const proposal = {
  schemaVersion: 1,
  kind: 'legion-remediation-proposal',
  id: 'sha256:proposal',
  findingIds: ['sha256:finding'],
  owner: 'code',
  producer: { id: 'code.agent', kind: 'reasoning', version: '1.0.0', contextId: 'ctx-producer' },
  targetPaths: ['src/render.mjs'],
  patch: { path: 'patches/code.patch', digest: 'sha256:patch' },
  changes: [{ kind: 'source-patch', path: 'src/render.mjs', symbols: ['renderBody'] }],
  tier: 'AGENT_GUIDED',
  binding,
  // A producer-supplied optimism the verifier must ignore.
  verified: true,
  providersPass: true,
};

const verifier = { id: 'verify.neutral', contextId: 'ctx-verifier' };

function graph(overrides = {}) {
  return buildEffectGraph({ proposal, planGraph, binding, ...overrides });
}

test('a proposal maps to its full effect surface', () => {
  const effect = graph();
  assert.equal(effect.kind, 'legion-patch-effect-graph');
  assert.equal(effect.schemaVersion, 1);
  assert.equal(effect.proposalId, proposal.id);
  assert.equal(effect.patchDigest, 'sha256:patch');
  assert.deepEqual(effect.changedFiles, ['src/render.mjs']);
  assert.deepEqual(effect.changedSymbols, ['renderBody']);
  for (const key of ['changedConfig', 'publicSurfaceChanges', 'contentItems', 'designStates', 'flows', 'runtimeSurfaces', 'securityPaths', 'residualRisks']) {
    assert.ok(Array.isArray(effect[key]), `effect graph missing ${key}`);
  }
  assert.deepEqual(effect.binding, binding);
  assert.match(effect.digest, /^sha256:/);
  assert.deepEqual(graph(), effect, 'effect graphs are deterministic');
});

test('the affected provider and family closure is transitive over the plan graph', () => {
  assert.deepEqual(
    computeClosure(planGraph, ['security.output-handling']),
    ['report.render', 'security.evidence-synthesis', 'security.output-handling'],
  );
  const effect = graph();
  assert.deepEqual(effect.affectedProviders, ['report.render', 'security.evidence-synthesis', 'security.output-handling']);
  assert.deepEqual(effect.affectedFamilies, ['report', 'security']);
  // A provider whose paths were untouched stays out of the closure.
  assert.ok(!effect.affectedProviders.includes('copy.anti-slop'));
  assert.deepEqual(effect.requiredProviders, ['security.evidence-synthesis', 'security.output-handling']);
  assert.deepEqual(effect.requiredGates, ['gate.no-new-high', 'gate.tests-pass']);
});

test('unplanned public-surface changes block application', () => {
  const declared = graph({ proposal: { ...proposal, publicSurfaceChanges: ['public-api:renderBody'] } });
  const undeclared = graph({ observedPublicSurfaceChanges: ['public-api:renderBody'] });
  assert.deepEqual(undeclared.unplannedPublicSurfaceChanges, ['public-api:renderBody']);
  assert.equal(blocksAutoApply(undeclared), true);
  assert.deepEqual(declared.unplannedPublicSurfaceChanges, []);
  assert.equal(blocksAutoApply(graph()), false);
});

test('every valid proposal has a complete effect graph', () => {
  assert.equal(graph().complete, true);
  assert.throws(() => buildEffectGraph({ proposal: { ...proposal, patch: null }, planGraph, binding }), /patch digest/);
  assert.throws(() => buildEffectGraph({ proposal: { ...proposal, targetPaths: [] }, planGraph, binding }), /target path/);
});

test('producer and verifier identities must be distinct', () => {
  const effect = graph();
  const results = [
    { provider: 'security.output-handling', complete: true, status: 'pass' },
    { provider: 'security.evidence-synthesis', complete: true, status: 'pass' },
  ];
  const gates = [{ id: 'gate.no-new-high', passed: true }, { id: 'gate.tests-pass', passed: true }];
  assert.equal(verifyProposal({ proposal, effectGraph: effect, verifier, providerResults: results, gateResults: gates, binding }).valid, true);
  assert.throws(
    () => verifyProposal({ proposal, effectGraph: effect, verifier: { id: 'code.agent', contextId: 'ctx-x' }, providerResults: results, gateResults: gates, binding }),
    /producer may not verify its own proposal/,
  );
  assert.throws(
    () => verifyProposal({ proposal, effectGraph: effect, verifier: { id: 'verify.neutral', contextId: 'ctx-producer' }, providerResults: results, gateResults: gates, binding }),
    /producer may not verify its own proposal/,
  );
});

test('verification never trusts producer-supplied pass booleans', () => {
  const effect = graph();
  const verdict = verifyProposal({
    proposal,
    effectGraph: effect,
    verifier,
    // The producer claimed verified:true and providersPass:true; independent
    // evidence says otherwise and independent evidence wins.
    providerResults: [
      { provider: 'security.output-handling', complete: true, status: 'fail' },
      { provider: 'security.evidence-synthesis', complete: true, status: 'pass' },
    ],
    gateResults: [{ id: 'gate.no-new-high', passed: true }, { id: 'gate.tests-pass', passed: true }],
    binding,
  });
  assert.equal(verdict.valid, false);
  assert.ok(verdict.coverageGaps.some((gap) => gap.kind === 'affected-provider-failed'));
  assert.equal(verdict.verifiedBy, 'neutral-verification');
  assert.equal(verdict.trustedProducerAssertions, false);
});

test('all affected mandatory evidence and baseline gates must be present and pass', () => {
  const effect = graph();
  const full = [
    { provider: 'security.output-handling', complete: true, status: 'pass' },
    { provider: 'security.evidence-synthesis', complete: true, status: 'pass' },
  ];
  const gates = [{ id: 'gate.no-new-high', passed: true }, { id: 'gate.tests-pass', passed: true }];
  const missingProvider = verifyProposal({ proposal, effectGraph: effect, verifier, providerResults: [full[0]], gateResults: gates, binding });
  assert.equal(missingProvider.valid, false);
  assert.ok(missingProvider.coverageGaps.some((gap) => gap.kind === 'missing-affected-provider' && gap.provider === 'security.evidence-synthesis'));
  const missingGate = verifyProposal({ proposal, effectGraph: effect, verifier, providerResults: full, gateResults: [gates[0]], binding });
  assert.equal(missingGate.valid, false);
  assert.ok(missingGate.coverageGaps.some((gap) => gap.kind === 'missing-baseline-gate' && gap.gate === 'gate.tests-pass'));
  const incomplete = verifyProposal({ proposal, effectGraph: effect, verifier, providerResults: [full[0], { provider: 'security.evidence-synthesis', complete: false, status: 'pass' }], gateResults: gates, binding });
  assert.equal(incomplete.valid, false);
});

test('vacuous verification is rejected when effects exist', () => {
  const effect = graph();
  const vacuous = verifyProposal({ proposal, effectGraph: effect, verifier, providerResults: [], gateResults: [], binding });
  assert.equal(vacuous.valid, false);
  assert.ok(vacuous.coverageGaps.some((gap) => gap.kind === 'vacuous-verification'));
  // Blocked application is never reported as valid either.
  const blocked = verifyProposal({
    proposal,
    effectGraph: graph({ observedPublicSurfaceChanges: ['public-api:renderBody'] }),
    verifier,
    providerResults: [
      { provider: 'security.output-handling', complete: true, status: 'pass' },
      { provider: 'security.evidence-synthesis', complete: true, status: 'pass' },
    ],
    gateResults: [{ id: 'gate.no-new-high', passed: true }, { id: 'gate.tests-pass', passed: true }],
    binding,
  });
  assert.equal(blocked.valid, false);
  assert.ok(blocked.coverageGaps.some((gap) => gap.kind === 'unplanned-public-surface-change'));
});

test('the committed effect-graph and verification schemas match their generators', () => {
  const effectSchema = JSON.parse(readFileSync(new URL('../../schemas/remediation/effect-graph-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(effectSchema, buildEffectGraphSchema());
  const verificationSchema = JSON.parse(readFileSync(new URL('../../schemas/remediation/verification-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(verificationSchema, buildVerificationSchema());
  assert.ok(effectSchema.required.includes('binding'));
  assert.ok(verificationSchema.required.includes('verifier'));
  assert.equal(verificationSchema.properties.trustedProducerAssertions.const, false);
});

test('the pre-existing patchEffectGraph helper still behaves', () => {
  const legacy = patchEffectGraph({
    patchDigest: 'sha256:p', findingIds: ['f1'], changedFiles: ['a.ts'], changedSymbols: ['updateProject'],
    publicSurfaceChanges: ['public-api:updateProject'], affectedProviders: ['language.javascript'],
    requiredTests: ['test/update.test.ts'], runtimeSurfaces: [], securityPaths: ['authorization.object-write'],
    residualRisks: ['behavior change'],
  });
  assert.equal(legacy.kind, 'legion-patch-effect-graph');
  assert.equal(blocksAutoApply(legacy), true);
});
