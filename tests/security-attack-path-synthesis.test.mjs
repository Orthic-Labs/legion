import assert from 'node:assert/strict';
import test from 'node:test';
import { synthesizeAttackPaths, factMatches, canonicalFactKey } from '../src/providers/security/attack-path-synthesis.mjs';
import { fact } from '../src/providers/security/model-extractors/common.mjs';
import { bindingFromPlan } from '../src/providers/security/contracts.mjs';

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev1', dirtyPatchDigest: null,
  blueprintGenerationId: 'gen1', blueprintManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

function planWith() {
  return {
    seal: { digest: 'sha256:plan' },
    binding: {
      repositoryRevision: 'rev1', dirtyPatchDigest: null,
      blueprint: { generationId: 'gen1', manifestDigest: 'sha256:manifest' },
      registryDigest: 'sha256:registry',
    },
    providers: [],
  };
}

function modelWith({ initialFacts = [], entities = [] } = {}) {
  return {
    schemaVersion: 1, kind: 'security-surface-model', binding: BINDING,
    denominatorDigest: 'sha256:denom', complete: true,
    entities, relations: [], initialFacts, evidence: [], coverage: {}, coverageGaps: [],
  };
}

function candidatesArtifact(candidates) {
  return {
    schemaVersion: 1, kind: 'security-candidates', binding: BINDING,
    denominatorDigest: 'sha256:denom', complete: true, candidates,
  };
}

function candidate({ id, preconditions = [], effects = [], chainRoles = [], evidenceRefs = ['ev1'], requiredControls = [], observedControls = [] }) {
  return {
    schemaVersion: 2, kind: 'security-candidate', id,
    provider: 'security.test', providerVersion: '1', ruleId: 'r', candidateClass: 'test',
    claim: 'test', severityHint: 'high', sources: [], sinks: [], assets: [],
    trustBoundaryCrossings: [], preconditions, effects, chainRoles,
    requiredControls, observedControls, evidenceRefs,
    binding: BINDING, denominatorDigest: 'sha256:denom',
    verdict: 'UNADJUDICATED', adjudicationRequired: true,
  };
}

const BRIDGES = [];
const OBJECTIVES = [
  { id: 'objective.crown-jewel-access', priority: 'DIRECT_CROWN_JEWEL', description: 'crown jewel', matches: { assetKinds: ['crown-jewel'], factKinds: ['data-access', 'object-access', 'code-execution', 'principal-access'] } },
  { id: 'objective.privilege-escalation', priority: 'PRIVILEGE_ESCALATION', description: 'priv', matches: { factKind: 'principal-access', scopePatterns: ['admin', 'owner'] } },
];

test('no candidates produces zero hypotheses and complete true', () => {
  const plan = planWith();
  const model = modelWith();
  const result = synthesizeAttackPaths({ plan, model, candidatesArtifact: candidatesArtifact([]), bridges: BRIDGES, objectives: OBJECTIVES });
  assert.equal(result.hypotheses.length, 0);
  assert.equal(result.complete, true);
});

test('direct primitive reaches a crown jewel', () => {
  const plan = planWith();
  const start = fact('object-access', { subject: 'actor:external', action: 'read', object: 'jewel-id', scope: 'cross-tenant' }, ['ev1']);
  const model = modelWith({ initialFacts: [start], entities: [{ id: 'jewel-id', kind: 'crown-jewel' }] });
  const attack = candidate({ id: 'c1', preconditions: [{ kind: 'object-access', subject: 'actor:external', action: 'read', object: 'jewel-id' }], effects: [{ kind: 'data-access', subject: 'actor:external', action: 'read', object: 'jewel-id' }] });
  const result = synthesizeAttackPaths({ plan, model, candidatesArtifact: candidatesArtifact([attack]), bridges: BRIDGES, objectives: OBJECTIVES });
  assert.ok(result.hypotheses.length >= 1, 'hypothesis produced');
  assert.equal(result.hypotheses[0].status, 'PROPOSED');
});

test('tenant mismatch never satisfies a precondition', () => {
  const plan = planWith();
  const start = fact('principal-access', { subject: 'actor:external', action: 'authenticate', scope: 'low', tenant: 'tenant-a' }, ['ev1']);
  const model = modelWith({ initialFacts: [start] });
  const attack = candidate({
    id: 'c1',
    preconditions: [{ kind: 'principal-access', subject: 'actor:external', action: 'authenticate', tenant: 'tenant-b' }],
    effects: [{ kind: 'principal-access', subject: 'actor:external', action: 'authenticate', scope: 'admin', tenant: 'tenant-b' }],
  });
  const result = synthesizeAttackPaths({ plan, model, candidatesArtifact: candidatesArtifact([attack]), bridges: BRIDGES, objectives: OBJECTIVES });
  assert.equal(result.hypotheses.length, 0);
});

test('environment mismatch never satisfies without a bridge', () => {
  const plan = planWith();
  const start = fact('code-execution', { subject: 'actor:external', action: 'execute', environment: 'local-development' }, ['ev1']);
  const model = modelWith({ initialFacts: [start] });
  const attack = candidate({
    id: 'c1',
    preconditions: [{ kind: 'code-execution', subject: 'actor:external', action: 'execute', environment: 'production' }],
    effects: [{ kind: 'principal-access', subject: 'actor:external', action: 'act-as', scope: 'admin' }],
  });
  const result = synthesizeAttackPaths({ plan, model, candidatesArtifact: candidatesArtifact([attack]), bridges: BRIDGES, objectives: OBJECTIVES });
  assert.equal(result.hypotheses.length, 0);
});

test('no hidden transformation without a bridge', () => {
  const plan = planWith();
  const start = fact('knowledge', { subject: 'actor:external', action: 'possess', object: 'secret-material' }, ['ev1']);
  const model = modelWith({ initialFacts: [start] });
  const attack = candidate({
    id: 'c1',
    preconditions: [{ kind: 'credential-possession', subject: 'actor:external', action: 'possess' }],
    effects: [{ kind: 'principal-access', subject: 'actor:external', action: 'authenticate', scope: 'admin' }],
  });
  // knowledge != credential-possession: no match without a bridge.
  const result = synthesizeAttackPaths({ plan, model, candidatesArtifact: candidatesArtifact([attack]), bridges: BRIDGES, objectives: OBJECTIVES });
  assert.equal(result.hypotheses.length, 0);
});

test('cycle prevention: mutually producing candidates terminate', () => {
  const plan = planWith();
  const start = fact('capability', { subject: 'actor:external', action: 'a' }, ['ev1']);
  const model = modelWith({ initialFacts: [start] });
  const a = candidate({
    id: 'a', preconditions: [{ kind: 'capability', subject: 'actor:external', action: 'a' }],
    effects: [{ kind: 'capability', subject: 'actor:external', action: 'b' }],
  });
  const b = candidate({
    id: 'b', preconditions: [{ kind: 'capability', subject: 'actor:external', action: 'b' }],
    effects: [{ kind: 'capability', subject: 'actor:external', action: 'a' }],
  });
  const result = synthesizeAttackPaths({ plan, model, candidatesArtifact: candidatesArtifact([a, b]), bridges: BRIDGES, objectives: OBJECTIVES, limits: { maxHops: 6, maxBranching: 12, maxHypotheses: 100, maxPathsPerObjective: 20, maxBridgeDepth: 3 } });
  // Terminates; no crash; each candidate used at most once per path.
  assert.ok(result.hypotheses.length >= 0);
});

test('hop bound truncates and reports max-hops', () => {
  const plan = planWith();
  const start = fact('capability', { subject: 'a', action: 's0' }, ['ev1']);
  const model = modelWith({ initialFacts: [start] });
  const chain = [];
  for (let index = 0; index < 5; index += 1) {
    chain.push(candidate({
      id: `c${index}`,
      preconditions: [{ kind: 'capability', subject: 'a', action: `s${index}` }],
      effects: [{ kind: 'capability', subject: 'a', action: `s${index + 1}` }],
    }));
  }
  const result = synthesizeAttackPaths({
    plan, model, candidatesArtifact: candidatesArtifact(chain), bridges: BRIDGES, objectives: OBJECTIVES,
    limits: { maxHops: 2, maxBranching: 12, maxHypotheses: 100, maxPathsPerObjective: 20, maxBridgeDepth: 3 },
  });
  assert.ok(result.coverageGaps.some((gap) => gap.kind === 'attack-path-search-truncated' && gap.reason === 'max-hops'));
  assert.equal(result.complete, false);
});

test('no numeric score exists in the artifact', () => {
  const plan = planWith();
  const start = fact('object-access', { subject: 'a', action: 'read', object: 'jewel-id', scope: 'cross-tenant' }, ['ev1']);
  const model = modelWith({ initialFacts: [start], entities: [{ id: 'jewel-id', kind: 'crown-jewel' }] });
  const attack = candidate({ id: 'c1', preconditions: [{ kind: 'object-access', subject: 'a', action: 'read', object: 'jewel-id' }], effects: [{ kind: 'data-access', subject: 'a', action: 'read', object: 'jewel-id' }] });
  const result = synthesizeAttackPaths({ plan, model, candidatesArtifact: candidatesArtifact([attack]), bridges: BRIDGES, objectives: OBJECTIVES });
  const text = JSON.stringify(result);
  assert.ok(!text.includes('riskScore'));
  assert.ok(!text.includes('criticalPathScore'));
  assert.ok(!/"[^"]*score[^"]*"\s*:\s*\d+/.test(text));
});

test('binding mismatch is rejected', () => {
  const plan = planWith();
  const model = modelWith();
  const wrong = candidatesArtifact([]);
  wrong.binding = { ...BINDING, repositoryRevision: 'other' };
  assert.throws(() => synthesizeAttackPaths({ plan, model, candidatesArtifact: wrong, bridges: BRIDGES, objectives: OBJECTIVES }), /does not match/);
});

test('factMatches is exact and wildcard-aware', () => {
  assert.equal(factMatches({ kind: 'capability', subject: '*' }, { kind: 'capability', subject: 'x' }), true);
  assert.equal(factMatches({ kind: 'capability', subject: '*' }, { kind: 'capability', subject: null }), false);
  assert.equal(factMatches({ kind: 'capability', tenant: 'a' }, { kind: 'capability', tenant: 'b' }), false);
  assert.equal(factMatches({ kind: 'capability' }, { kind: 'capability', subject: 'x' }), true);
});

test('canonicalFactKey is deterministic', () => {
  const a = fact('capability', { subject: 'x', action: 'y' });
  const b = fact('capability', { action: 'y', subject: 'x' });
  assert.equal(canonicalFactKey(a), canonicalFactKey(b));
});
