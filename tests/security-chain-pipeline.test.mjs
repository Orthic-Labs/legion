import assert from 'node:assert/strict';
import test from 'node:test';
import { reconcileAttackPaths } from '../providers/security/attack-path-reconcile.mjs';
import { createChainAdjudicationPacket, finalizeChainVerdict } from '../adapters/security-chain-adjudication.mjs';
import { prepareChainAdjudicationBundle, finalizeChainAdjudicationBundle } from '../security-chain-pipeline.mjs';

const BINDING = {
  planDigest: 'sha256:plan', repositoryRevision: 'rev1', dirtyPatchDigest: null,
  cortexGenerationId: 'gen1', cortexManifestDigest: 'sha256:manifest', registryDigest: 'sha256:registry',
};

function planWith() {
  return {
    seal: { digest: 'sha256:plan' },
    binding: { repositoryRevision: 'rev1', dirtyPatchDigest: null, cortex: { generationId: 'gen1', manifestDigest: 'sha256:manifest' }, registryDigest: 'sha256:registry' },
    providers: [],
  };
}

function hypothesisArtifact(paths) {
  return {
    schemaVersion: 1, kind: 'attack-path-hypotheses', provider: 'security.attack-path-synthesis', providerVersion: '1',
    binding: BINDING, denominatorDigest: 'sha256:denom', complete: true, hypotheses: paths, coverage: {}, coverageGaps: [],
  };
}

function path({ id = 'path-1', steps = [{ order: 0, candidateId: 'c1', requires: ['f1'], produces: ['f2'], status: 'UNADJUDICATED' }], joins = [] }) {
  return {
    schemaVersion: 1, kind: 'attack-path-hypothesis', id, provider: 'security.attack-path-synthesis', providerVersion: '1',
    binding: BINDING, denominatorDigest: 'sha256:denom', status: 'PROPOSED', priority: 'PRIVILEGE_ESCALATION',
    start: { factIds: ['f1'], firstCandidateId: 'c1' }, objective: { id: 'objective.privilege-escalation', priority: 'PRIVILEGE_ESCALATION' },
    steps, joins, terminalFacts: ['f2'], controls: { required: [], observed: [], status: 'UNADJUDICATED' },
    unsupportedAssertions: [], alternateExplanations: [], synthesis: { truncated: false, truncationReasons: [] },
  };
}

function adjudication(verdicts) {
  return {
    schemaVersion: 1, kind: 'security-adjudication-result', binding: BINDING,
    complete: true, verdicts,
  };
}

function verdictFor(candidateId, verdict = 'TRUE_POSITIVE', extra = {}) {
  return { candidateId, candidateProvider: 'security.test', verdict, evidenceStrength: 'verified', ...extra };
}

function candidates() {
  return {
    schemaVersion: 1, kind: 'security-candidates', binding: BINDING, denominatorDigest: 'sha256:denom', complete: true,
    candidates: [{ id: 'c1', provider: 'security.test', providerVersion: '1', ruleId: 'r', sources: [], sinks: [], assets: [], requiredControls: [], observedControls: [], evidenceRefs: ['ev1'], binding: BINDING }],
  };
}

function model() {
  return {
    schemaVersion: 1, kind: 'security-surface-model', binding: BINDING, denominatorDigest: 'sha256:denom', complete: true,
    entities: [], relations: [], initialFacts: [], evidence: [], coverage: {}, coverageGaps: [],
  };
}

test('false-positive primitive refutes the path, no chain packet', () => {
  const plan = planWith();
  const hypotheses = hypothesisArtifact([path({})]);
  const result = reconcileAttackPaths({ plan, hypothesesArtifact: hypotheses, adjudication: adjudication([verdictFor('c1', 'FALSE_POSITIVE')]) });
  assert.equal(result.hypotheses[0].status, 'REFUTED');
  assert.equal(result.hypotheses[0].reconciliation.eligibleForChainAdjudication, false);
});

test('missing primitive verdict leaves the path unproven', () => {
  const plan = planWith();
  const hypotheses = hypothesisArtifact([path({})]);
  const result = reconcileAttackPaths({ plan, hypothesesArtifact: hypotheses, adjudication: adjudication([]) });
  assert.equal(result.hypotheses[0].status, 'UNPROVEN');
  assert.equal(result.hypotheses[0].reconciliation.eligibleForChainAdjudication, false);
});

test('all surviving primitives make the path eligible', () => {
  const plan = planWith();
  const hypotheses = hypothesisArtifact([path({})]);
  const result = reconcileAttackPaths({ plan, hypothesesArtifact: hypotheses, adjudication: adjudication([verdictFor('c1')]) });
  assert.equal(result.hypotheses[0].status, 'PARTIALLY_SUPPORTED');
  assert.equal(result.hypotheses[0].reconciliation.eligibleForChainAdjudication, true);
});

test('reconciliation can never set PROVEN', () => {
  const plan = planWith();
  const hypotheses = hypothesisArtifact([path({})]);
  const result = reconcileAttackPaths({ plan, hypothesesArtifact: hypotheses, adjudication: adjudication([verdictFor('c1')]) });
  assert.notEqual(result.hypotheses[0].status, 'PROVEN');
});

test('synthesizer cannot adjudicate its own path', () => {
  const plan = planWith();
  const hypotheses = hypothesisArtifact([path({})]);
  const reconciled = reconcileAttackPaths({ plan, hypothesesArtifact: hypotheses, adjudication: adjudication([verdictFor('c1')]) });
  const eligible = reconciled.hypotheses.filter((p) => p.reconciliation.eligibleForChainAdjudication);
  const p = eligible[0];
  assert.throws(() => createChainAdjudicationPacket({
    plan,
    path: { ...p, synthesisContextId: 'ctx-1' },
    candidates: candidates(),
    candidateAdjudication: adjudication([verdictFor('c1')]),
    model: model(),
    adjudicator: { provider: 'security.attack-path-synthesis', contextId: 'ctx-1' },
  }), /cannot adjudicate its own path/);
});

test('each path gets a unique context', () => {
  const plan = planWith();
  const two = hypothesisArtifact([
    path({ id: 'path-1' }),
    path({ id: 'path-2', steps: [{ order: 0, candidateId: 'c1', requires: ['f1'], produces: ['f3'], status: 'UNADJUDICATED' }] }),
  ]);
  const reconciled = reconcileAttackPaths({ plan, hypothesesArtifact: two, adjudication: adjudication([verdictFor('c1')]) });
  const bundle = prepareChainAdjudicationBundle({ plan, reconciledPaths: reconciled, candidates: candidates(), candidateAdjudication: adjudication([verdictFor('c1')]), model: model() });
  const contexts = new Set(bundle.packets.map((packet) => packet.adjudicator.contextId));
  assert.equal(contexts.size, 2);
});

test('PROVEN requires verified evidence, proof, negative control, usable steps, verified joins', () => {
  const plan = planWith();
  const p = path({});
  const hypotheses = hypothesisArtifact([p]);
  const reconciled = reconcileAttackPaths({ plan, hypothesesArtifact: hypotheses, adjudication: adjudication([verdictFor('c1')]) });
  const eligible = reconciled.hypotheses.filter((x) => x.reconciliation.eligibleForChainAdjudication);
  const packet = createChainAdjudicationPacket({
    plan,
    path: { ...eligible[0], synthesisContextId: 'synth' },
    candidates: candidates(),
    candidateAdjudication: adjudication([verdictFor('c1')]),
    model: model(),
    adjudicator: { provider: 'security.chain-adjudication', contextId: 'chain-ctx' },
  });
  // Missing proof → reject.
  assert.throws(() => finalizeChainVerdict(packet, {
    pathId: packet.pathId, contextId: 'chain-ctx', verdict: 'PROVEN', evidenceStrength: 'verified',
    stepAssessments: [{ candidateId: 'c1', usableInChain: true }],
    joinAssessments: [],
    terminalImpact: { kind: 'x' }, proof: null, negativeControl: { rationale: 'blocked' },
    devilsAdvocate: 'x', rationale: 'x', severity: 'critical',
  }), /bound proof/);
  // Strong-inference evidence → reject.
  assert.throws(() => finalizeChainVerdict(packet, {
    pathId: packet.pathId, contextId: 'chain-ctx', verdict: 'PROVEN', evidenceStrength: 'strong-inference',
    stepAssessments: [{ candidateId: 'c1', usableInChain: true }],
    joinAssessments: [],
    terminalImpact: { kind: 'x' }, proof: { digest: 'sha256:p' }, negativeControl: { rationale: 'blocked' },
    devilsAdvocate: 'x', rationale: 'x', severity: 'critical',
  }), /verified evidence/);
});

test('BLOCKED requires an effective control', () => {
  const plan = planWith();
  const p = path({});
  const hypotheses = hypothesisArtifact([p]);
  const reconciled = reconcileAttackPaths({ plan, hypothesesArtifact: hypotheses, adjudication: adjudication([verdictFor('c1')]) });
  const eligible = reconciled.hypotheses.filter((x) => x.reconciliation.eligibleForChainAdjudication);
  const packet = createChainAdjudicationPacket({
    plan,
    path: { ...eligible[0], synthesisContextId: 'synth' },
    candidates: candidates(),
    candidateAdjudication: adjudication([verdictFor('c1')]),
    model: model(),
    adjudicator: { provider: 'security.chain-adjudication', contextId: 'chain-ctx' },
  });
  assert.throws(() => finalizeChainVerdict(packet, {
    pathId: packet.pathId, contextId: 'chain-ctx', verdict: 'BLOCKED', evidenceStrength: 'verified',
    stepAssessments: [{ candidateId: 'c1', usableInChain: true }],
    joinAssessments: [],
    controlAssessments: [{ controlId: 'c', status: 'ABSENT' }],
    terminalImpact: null, proof: null, negativeControl: null,
    devilsAdvocate: 'x', rationale: 'x', severity: null,
  }), /effective blocking control/);
});

test('REFUTED requires a refuted join or unusable step', () => {
  const plan = planWith();
  const p = path({});
  const hypotheses = hypothesisArtifact([p]);
  const reconciled = reconcileAttackPaths({ plan, hypothesesArtifact: hypotheses, adjudication: adjudication([verdictFor('c1')]) });
  const eligible = reconciled.hypotheses.filter((x) => x.reconciliation.eligibleForChainAdjudication);
  const packet = createChainAdjudicationPacket({
    plan,
    path: { ...eligible[0], synthesisContextId: 'synth' },
    candidates: candidates(),
    candidateAdjudication: adjudication([verdictFor('c1')]),
    model: model(),
    adjudicator: { provider: 'security.chain-adjudication', contextId: 'chain-ctx' },
  });
  assert.throws(() => finalizeChainVerdict(packet, {
    pathId: packet.pathId, contextId: 'chain-ctx', verdict: 'REFUTED', evidenceStrength: 'verified',
    stepAssessments: [{ candidateId: 'c1', usableInChain: true }],
    joinAssessments: [],
    terminalImpact: null, proof: null, negativeControl: null,
    devilsAdvocate: 'x', rationale: 'x', severity: null,
  }), /refuted join or unusable step/);
});

test('partial verdicts carry no final severity', () => {
  const plan = planWith();
  const p = path({});
  const hypotheses = hypothesisArtifact([p]);
  const reconciled = reconcileAttackPaths({ plan, hypothesesArtifact: hypotheses, adjudication: adjudication([verdictFor('c1')]) });
  const eligible = reconciled.hypotheses.filter((x) => x.reconciliation.eligibleForChainAdjudication);
  const packet = createChainAdjudicationPacket({
    plan,
    path: { ...eligible[0], synthesisContextId: 'synth' },
    candidates: candidates(),
    candidateAdjudication: adjudication([verdictFor('c1')]),
    model: model(),
    adjudicator: { provider: 'security.chain-adjudication', contextId: 'chain-ctx' },
  });
  assert.throws(() => finalizeChainVerdict(packet, {
    pathId: packet.pathId, contextId: 'chain-ctx', verdict: 'PARTIALLY_SUPPORTED', evidenceStrength: 'strong-inference',
    stepAssessments: [{ candidateId: 'c1', usableInChain: true }],
    joinAssessments: [],
    terminalImpact: null, proof: null, negativeControl: null,
    devilsAdvocate: 'x', rationale: 'x', severity: 'high',
  }), /must not carry final severity/);
});

test('duplicate path verdicts are invalid', () => {
  const plan = planWith();
  const hypotheses = hypothesisArtifact([path({})]);
  const reconciled = reconcileAttackPaths({ plan, hypothesesArtifact: hypotheses, adjudication: adjudication([verdictFor('c1')]) });
  const bundle = prepareChainAdjudicationBundle({ plan, reconciledPaths: reconciled, candidates: candidates(), candidateAdjudication: adjudication([verdictFor('c1')]), model: model() });
  const packet = bundle.packets[0];
  const raw = {
    pathId: packet.pathId, contextId: packet.adjudicator.contextId, verdict: 'UNPROVEN', evidenceStrength: 'possible',
    stepAssessments: [{ candidateId: 'c1', usableInChain: false }],
    joinAssessments: [], terminalImpact: null, proof: null, negativeControl: null,
    devilsAdvocate: 'x', rationale: 'x', severity: null,
  };
  const result = finalizeChainAdjudicationBundle(bundle, { verdicts: [raw, raw] });
  assert.equal(result.complete, false);
  assert.ok(result.invalidVerdicts.some((item) => /duplicate/.test(item.error)));
});

test('all valid verdicts make the bundle complete', () => {
  const plan = planWith();
  const hypotheses = hypothesisArtifact([path({})]);
  const reconciled = reconcileAttackPaths({ plan, hypothesesArtifact: hypotheses, adjudication: adjudication([verdictFor('c1')]) });
  const bundle = prepareChainAdjudicationBundle({ plan, reconciledPaths: reconciled, candidates: candidates(), candidateAdjudication: adjudication([verdictFor('c1')]), model: model() });
  const packet = bundle.packets[0];
  const raw = {
    pathId: packet.pathId, contextId: packet.adjudicator.contextId, verdict: 'UNPROVEN', evidenceStrength: 'possible',
    stepAssessments: [{ candidateId: 'c1', usableInChain: false }],
    joinAssessments: [], terminalImpact: null, proof: null, negativeControl: null,
    devilsAdvocate: 'x', rationale: 'x', severity: null,
  };
  const result = finalizeChainAdjudicationBundle(bundle, { verdicts: [raw] });
  assert.equal(result.complete, true);
  assert.equal(result.verdicts.length, 1);
});
