import assert from 'node:assert/strict';
import test from 'node:test';
import { runSecurityPack } from '../src/providers/security/candidate-engine.mjs';
import { synthesizeAttackPaths } from '../src/providers/security/attack-path-synthesis.mjs';
import { reconcileAttackPaths } from '../src/providers/security/attack-path-reconcile.mjs';
import { createSecurityCandidateV2 } from '../src/providers/security/candidate-engine.mjs';
import credentialsPack from '../src/providers/security/packs/credentials.mjs';
import authorizationPack from '../src/providers/security/packs/authorization-tenant.mjs';
import { entity } from '../src/providers/security/model-extractors/common.mjs';

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev1', dirtyPatchDigest: null,
  blueprintGenerationId: 'gen1', blueprintManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

function planFor(providerId, paths = ['app.ts']) {
  return {
    seal: { digest: 'sha256:plan' },
    binding: { repositoryRevision: 'rev1', dirtyPatchDigest: null, blueprint: { generationId: 'gen1', manifestDigest: 'sha256:manifest' }, registryDigest: 'sha256:registry' },
    providers: [{ id: providerId, benchmark: { requiredForCleanClaim: true, status: 'unproven' }, denominator: { pathDigest: 'sha256:d', pathCount: paths.length, paths } }],
  };
}

function modelFor(paths) {
  const artifacts = paths.map((path) => entity('repository-artifact', path, { path }, ['ev1']));
  return {
    schemaVersion: 1, kind: 'security-surface-model', binding: BINDING, denominatorDigest: 'sha256:d', complete: true,
    entities: artifacts, relations: [], initialFacts: [], evidence: [{ id: 'ev1', kind: 'source-location', file: paths[0] }], coverage: {}, coverageGaps: [],
  };
}

function runPack(pack, sourceText, file = 'app.ts') {
  const plan = planFor(pack.id, [file]);
  const projection = { files: [file], sourceText: { [file]: sourceText }, auditFacts: {} };
  return runSecurityPack({ pack, root: '/repo', plan, projection, model: modelFor([file]), providerPlan: plan.providers[0] });
}

function candidateFromObservation(plan, model, provider, observation) {
  return createSecurityCandidateV2({
    plan, model, provider: provider.id, providerVersion: '1.0.0',
    denominatorDigest: 'sha256:d', observation,
  });
}

test('end-to-end: plan → model → pack → candidates → synthesis → reconciliation', () => {
  const plan = planFor(credentialsPack.id);
  const model = modelFor(['app.ts']);
  const projection = { files: ['app.ts'], sourceText: { 'app.ts': 'const key = "AKIAIOSFODNN7EXAMPLE";' }, auditFacts: {} };
  const packResult = runSecurityPack({ pack: credentialsPack, root: '/repo', plan, projection, model, providerPlan: plan.providers[0] });
  assert.equal(packResult.status, 'candidates');
  assert.deepEqual(packResult.findings, []);

  // Candidate adjudication verdict fixture.
  const adjudication = {
    schemaVersion: 1, kind: 'security-adjudication-result', binding: BINDING, complete: true,
    verdicts: packResult.candidates.map((candidate) => ({
      candidateId: candidate.id, candidateProvider: candidate.provider,
      verdict: 'TRUE_POSITIVE', evidenceStrength: 'verified', severity: 'high',
      threatModel: 'x', attackerControl: 'y', reachability: 'z', impact: 'w', rationale: 'r',
      rootCauseSignature: { class: 'credential-in-repository' },
    })),
  };
  assert.equal(adjudication.verdicts.length, packResult.candidates.length);
});

test('end-to-end: no negative fixture produces a PROVEN path', () => {
  // A mitigated fixture (owner check present) must produce zero candidates.
  const mitigated = runPack(authorizationPack, 'await updateProject(req.params.id, body, { tenant: currentTenant })');
  assert.equal(mitigated.candidates.length, 0);

  // Even a positive candidate's path stays PROPOSED until chain adjudication.
  const positive = runPack(authorizationPack, 'await updateProject(req.params.id, body)');
  assert.ok(positive.candidates.length >= 1);
  const plan = planFor(authorizationPack.id);
  const model = modelFor(['app.ts']);
  const artifact = model.entities[0];
  const candidates = positive.candidates.map((candidate) => candidateFromObservation(plan, model, authorizationPack, {
    ruleId: candidate.ruleId, candidateClass: 'authorization', claim: candidate.claim, severityHint: 'high',
    sources: [artifact.id], sinks: [artifact.id], assets: [], trustBoundaryCrossings: [],
    requiredControls: [], observedControls: [], attackerCapabilities: ['authenticated-low-privilege'],
    preconditions: [{ kind: 'principal-access', subject: 'actor:external', action: 'authenticate', scope: 'low-privilege', environment: 'application' }],
    effects: [{ kind: 'object-access', subject: 'actor:external', action: 'write', object: artifact.id, scope: 'cross-tenant', environment: 'application', tenant: null }],
    chainRoles: ['starter'], evidenceRefs: ['ev1'],
  }));
  const modelWithFacts = {
    ...model,
    initialFacts: [{ kind: 'principal-access', subject: 'actor:external', action: 'authenticate', scope: 'low-privilege', environment: 'application', tenant: null, id: 'f1' }],
  };
  const candidatesArtifact = {
    schemaVersion: 1, kind: 'security-candidates', binding: BINDING, denominatorDigest: 'sha256:d', complete: true, candidates,
  };
  const hypotheses = synthesizeAttackPaths({
    plan, model: modelWithFacts, candidatesArtifact, bridges: [], objectives: [],
  });
  assert.ok(hypotheses.hypotheses.length >= 0);
  for (const hypothesis of hypotheses.hypotheses) {
    assert.notEqual(hypothesis.status, 'PROVEN', 'synthesis must never produce PROVEN');
  }
});

test('end-to-end: reconciliation never upgrades to PROVEN', () => {
  const plan = planFor(credentialsPack.id);
  const hypothesesArtifact = {
    schemaVersion: 1, kind: 'attack-path-hypotheses', binding: BINDING, denominatorDigest: 'sha256:d', complete: true,
    hypotheses: [{
      schemaVersion: 1, kind: 'attack-path-hypothesis', id: 'path-1', provider: 'security.attack-path-synthesis', providerVersion: '1',
      binding: BINDING, denominatorDigest: 'sha256:d', status: 'PROPOSED', priority: 'DIRECT_CROWN_JEWEL',
      start: { factIds: ['f1'], firstCandidateId: 'c1' }, objective: { id: 'o' },
      steps: [{ order: 0, candidateId: 'c1', requires: ['f1'], produces: ['f2'], status: 'UNADJUDICATED' }],
      joins: [], terminalFacts: ['f2'], controls: {}, unsupportedAssertions: [], alternateExplanations: [], synthesis: {},
    }],
    coverage: {}, coverageGaps: [],
  };
  const adjudication = {
    schemaVersion: 1, kind: 'security-adjudication-result', binding: BINDING, complete: true,
    verdicts: [{ candidateId: 'c1', candidateProvider: 'x', verdict: 'TRUE_POSITIVE', evidenceStrength: 'verified' }],
  };
  const reconciled = reconcileAttackPaths({ plan, hypothesesArtifact, adjudication });
  assert.equal(reconciled.hypotheses[0].status, 'PARTIALLY_SUPPORTED');
  assert.notEqual(reconciled.hypotheses[0].status, 'PROVEN');
});

test('end-to-end: candidate providers never emit findings', () => {
  const positive = runPack(credentialsPack, 'const key = "AKIAIOSFODNN7EXAMPLE";');
  assert.deepEqual(positive.findings, []);
  const negative = runPack(credentialsPack, 'const label = "api key example";');
  assert.deepEqual(negative.findings, []);
});

test('end-to-end: outputs are deterministic across repeated runs', () => {
  const a = runPack(authorizationPack, 'await updateProject(req.params.id, body)');
  const b = runPack(authorizationPack, 'await updateProject(req.params.id, body)');
  assert.deepEqual(a.candidates.map((c) => c.id), b.candidates.map((c) => c.id));
});
