import assert from 'node:assert/strict';
import test from 'node:test';
import { createSecurityCandidateV2, runSecurityPack, validateSecurityCandidateV2 } from '../providers/security/candidate-engine.mjs';
import credentialsPack from '../providers/security/packs/credentials.mjs';
import injectionPack from '../providers/security/packs/injection.mjs';
import { entity } from '../providers/security/model-extractors/common.mjs';

const BINDING = {
  planDigest: 'sha256:plan',
  repositoryRevision: 'rev1',
  dirtyPatchDigest: null,
  cortexGenerationId: 'gen1',
  cortexManifestDigest: 'sha256:manifest',
  registryDigest: 'sha256:registry',
};

function planWith() {
  return {
    seal: { digest: 'sha256:plan' },
    binding: {
      repositoryRevision: 'rev1', dirtyPatchDigest: null,
      cortex: { generationId: 'gen1', manifestDigest: 'sha256:manifest' },
      registryDigest: 'sha256:registry',
    },
    providers: [{ id: 'security.credentials', benchmark: { requiredForCleanClaim: true }, denominator: { pathDigest: 'sha256:denom', pathCount: 1, paths: ['env.ts'] } }],
  };
}

function modelWith() {
  const artifact = entity('repository-artifact', 'env.ts', { path: 'env.ts' }, ['ev1']);
  const control = entity('control', 'secret exclusion', { controlType: 'secret-exclusion' }, ['ev1']);
  return {
    schemaVersion: 1, kind: 'security-surface-model',
    binding: BINDING, denominatorDigest: 'sha256:denom', complete: true,
    entities: [artifact, control],
    relations: [], initialFacts: [], evidence: [{ id: 'ev1', kind: 'source-location', file: 'env.ts' }],
    coverage: {}, coverageGaps: [],
  };
}

test('createSecurityCandidateV2 builds a validated candidate', () => {
  const plan = planWith();
  const model = modelWith();
  const artifact = model.entities[0];
  const control = model.entities[1];
  const candidate = createSecurityCandidateV2({
    plan, model,
    provider: 'security.credentials', providerVersion: '1',
    denominatorDigest: 'sha256:denom',
    observation: {
      ruleId: 'credentials.format', candidateClass: 'credentials',
      claim: 'Credential-shaped value.', severityHint: 'high',
      sources: [artifact.id], sinks: [], assets: [], trustBoundaryCrossings: [],
      requiredControls: [control.id], observedControls: [],
      attackerCapabilities: ['read-repository'],
      preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'read-repository' }],
      effects: [{ kind: 'knowledge', subject: 'actor:external', action: 'possess', object: artifact.id, scope: 'credential-material' }],
      chainRoles: ['starter'], evidenceRefs: ['ev1'],
    },
  });
  assert.equal(candidate.schemaVersion, 2);
  assert.equal(candidate.verdict, 'UNADJUDICATED');
  assert.equal(candidate.adjudicationRequired, true);
  assert.ok(candidate.id.startsWith('sha256:'));
  assert.deepEqual(candidate.binding, BINDING);
  assert.doesNotThrow(() => validateSecurityCandidateV2(candidate, { plan, model }));
});

test('candidate rejects final severity and evidence verdicts', () => {
  const plan = planWith();
  const model = modelWith();
  const artifact = model.entities[0];
  const base = {
    plan, model, provider: 'p', providerVersion: '1', denominatorDigest: 'sha256:denom',
    observation: {
      ruleId: 'r', candidateClass: 'c', claim: 'x', severityHint: 'low',
      sources: [artifact.id], sinks: [], assets: [], trustBoundaryCrossings: [],
      requiredControls: [], observedControls: [], attackerCapabilities: [],
      preconditions: [], effects: [{ kind: 'knowledge', subject: 'a', action: 'read', object: artifact.id }],
      chainRoles: [], evidenceRefs: ['ev1'],
    },
  };
  const candidate = createSecurityCandidateV2(base);
  assert.throws(() => validateSecurityCandidateV2({ ...candidate, severity: 'high' }), /final severity/);
  assert.throws(() => validateSecurityCandidateV2({ ...candidate, evidenceStrength: 'verified' }), /final evidence/);
});

test('candidate without effects is rejected', () => {
  const plan = planWith();
  const model = modelWith();
  const artifact = model.entities[0];
  assert.throws(() => createSecurityCandidateV2({
    plan, model, provider: 'p', providerVersion: '1', denominatorDigest: 'sha256:denom',
    observation: {
      ruleId: 'r', candidateClass: 'c', claim: 'x', severityHint: 'low',
      sources: [artifact.id], sinks: [], assets: [], trustBoundaryCrossings: [],
      requiredControls: [], observedControls: [], attackerCapabilities: [],
      preconditions: [], effects: [], chainRoles: [], evidenceRefs: ['ev1'],
    },
  }), /at least one effect/);
});

test('candidate rejects unknown model entity references', () => {
  const plan = planWith();
  const model = modelWith();
  assert.throws(() => createSecurityCandidateV2({
    plan, model, provider: 'p', providerVersion: '1', denominatorDigest: 'sha256:denom',
    observation: {
      ruleId: 'r', candidateClass: 'c', claim: 'x', severityHint: 'low',
      sources: ['sha256:ghost'], sinks: [], assets: [], trustBoundaryCrossings: [],
      requiredControls: [], observedControls: [], attackerCapabilities: [],
      preconditions: [], effects: [{ kind: 'knowledge', subject: 'a', action: 'read', object: null }],
      chainRoles: [], evidenceRefs: ['ev1'],
    },
  }), /unknown security-model entity/);
});

test('runSecurityPack runs a pack and produces candidates with empty findings', () => {
  const plan = planWith();
  const model = modelWith();
  const projection = {
    files: ['env.ts'],
    sourceText: { 'env.ts': 'const key = "AKIAIOSFODNN7EXAMPLE";' },
    auditFacts: {},
  };
  const providerPlan = plan.providers[0];
  const result = runSecurityPack({ pack: credentialsPack, root: '/repo', plan, projection, model, providerPlan });
  assert.equal(result.status, 'candidates');
  assert.deepEqual(result.findings, []);
  assert.ok(result.candidates.length >= 1);
  assert.ok(result.candidates.every((candidate) => candidate.verdict === 'UNADJUDICATED'));
});

test('injection pack emits typed candidates with sink metadata', () => {
  const plan = planWith();
  const model = modelWith();
  const projection = {
    files: ['app.py'],
    sourceText: { 'app.py': 'import os\nos.system(request.args.get("cmd"))' },
    auditFacts: {},
  };
  const providerPlan = { id: 'security.injection', benchmark: { requiredForCleanClaim: true }, denominator: { pathDigest: 'sha256:denom', pathCount: 1, paths: ['app.py'] } };
  const result = runSecurityPack({ pack: injectionPack, root: '/repo', plan, projection, model, providerPlan });
  assert.ok(result.candidates.length >= 1);
  const shell = result.candidates.find((c) => c.detectorMetadata?.sinkKind === 'shell');
  assert.ok(shell, 'shell sink candidate present');
  assert.ok(shell.uncertainty.some((u) => /not automatically command injection/.test(u)));
});

test('runSecurityPack rejects out-of-denominator reads', () => {
  const plan = planWith();
  const model = modelWith();
  const projection = { files: ['env.ts'], sourceText: {}, auditFacts: {} };
  const providerPlan = plan.providers[0];
  const pack = { id: 'security.credentials', version: '1', rules: [], analyze(context) { context.readFile('outside.ts'); return []; } };
  assert.throws(() => runSecurityPack({ pack, root: '/repo', plan, projection, model, providerPlan }), /out-of-denominator/);
});

test('candidate v1 inputs are rejected with a migration error', () => {
  const plan = planWith();
  const model = modelWith();
  const v1 = { schemaVersion: 1, kind: 'security-candidate', id: 'x', provider: 'p' };
  assert.throws(() => validateSecurityCandidateV2(v1, { plan, model }), /schemaVersion must be 2/);
});
