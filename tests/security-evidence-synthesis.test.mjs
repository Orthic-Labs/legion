import assert from 'node:assert/strict';
import test from 'node:test';
import { synthesizeSecurityEvidence } from '../src/providers/security/evidence-synthesis.mjs';

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

function model() {
  return { schemaVersion: 1, kind: 'security-surface-model', binding: BINDING, denominatorDigest: 'sha256:denom', complete: true, entities: [{ id: 'ctrl1', kind: 'control', evidenceRefs: [] }], relations: [], initialFacts: [], evidence: [], coverage: {}, coverageGaps: [] };
}

function candidates(list) {
  return { schemaVersion: 1, kind: 'security-candidates', binding: BINDING, denominatorDigest: 'sha256:denom', complete: true, candidates: list };
}

function adjudication(verdicts, complete = true) {
  return { schemaVersion: 1, kind: 'security-adjudication-result', binding: BINDING, complete, verdicts };
}

function chainAdjudication(verdicts, complete = true) {
  return { schemaVersion: 1, kind: 'security-chain-adjudication-result', binding: BINDING, complete, verdicts };
}

function variants(receipts, complete = true) {
  return { schemaVersion: 2, kind: 'security-variant-results', binding: BINDING, complete, receipts };
}

const candidate = { id: 'c1', provider: 'security.credentials', ruleId: 'credentials.format', sources: [], sinks: [], assets: [], requiredControls: [], observedControls: [], evidenceRefs: ['ev1'], binding: BINDING };
const verdict = { candidateId: 'c1', candidateProvider: 'security.credentials', verdict: 'TRUE_POSITIVE', evidenceStrength: 'verified', severity: 'high', threatModel: 'x', attackerControl: 'y', reachability: 'z', impact: 'w', rationale: 'r', proof: { digest: 'sha256:p' }, rootCauseSignature: { class: 'credential-in-repository' } };

function completeReceipt() {
  return {
    schemaVersion: 2, kind: 'security-variant-receipt', findingId: 'c1', ruleId: 'credentials.format',
    rootCauseSignature: { class: 'credential-in-repository' }, provider: 'security.variant-analysis', providerVersion: '2',
    binding: BINDING, denominator: { kind: 'source-files', digest: 'sha256:d', expected: 1, examined: 1, unexamined: [] },
    strategies: [], matches: [{ id: 'm1', file: 'a.ts', line: 3, semanticFingerprint: 'sha256:f', disposition: 'CONFIRMED' }],
    summary: { enumerated: 1, examined: 1, confirmed: 1, rejected: 0, duplicates: 0, outOfScope: 0, unresolved: 0 },
    complete: true, coverageGaps: [], receiptDigest: 'sha256:receipt',
  };
}

test('surviving finding without a complete variant receipt makes synthesis incomplete', () => {
  const plan = planWith();
  const result = synthesizeSecurityEvidence({
    plan, model: model(), candidates: candidates([candidate]), adjudication: adjudication([verdict]),
    chainAdjudication: chainAdjudication([]), variants: variants([], true),
  });
  assert.equal(result.complete, false);
  assert.ok(result.coverageGaps.some((gap) => gap.kind === 'finding-missing-candidate-or-variant-receipt'));
});

test('false-positive candidate never becomes a finding', () => {
  const plan = planWith();
  const result = synthesizeSecurityEvidence({
    plan, model: model(), candidates: candidates([candidate]),
    adjudication: adjudication([{ ...verdict, verdict: 'FALSE_POSITIVE' }]),
    chainAdjudication: chainAdjudication([]), variants: variants([completeReceipt()], true),
  });
  assert.equal(result.findings.length, 0);
});

test('complete inputs produce findings and synthesis is complete', () => {
  const plan = planWith();
  const result = synthesizeSecurityEvidence({
    plan, model: model(), candidates: candidates([candidate]), adjudication: adjudication([verdict]),
    chainAdjudication: chainAdjudication([]), variants: variants([completeReceipt()], true),
  });
  assert.equal(result.complete, true);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].severity, 'high');
  assert.equal(result.findings[0].variantReceiptId, 'sha256:receipt');
});

test('proven path references its constituent findings and is not double-counted', () => {
  const plan = planWith();
  const proven = {
    pathId: 'path-1', verdict: 'PROVEN', severity: 'critical', priority: 'PRIVILEGE_ESCALATION',
    start: { factIds: ['f1'] }, objective: { id: 'objective.privilege-escalation' },
    steps: [{ candidateId: 'c1' }], controls: [], terminalImpact: { kind: 'x' }, proof: { digest: 'sha256:p' },
    stepAssessments: [], joinAssessments: [],
  };
  const result = synthesizeSecurityEvidence({
    plan, model: model(), candidates: candidates([candidate]), adjudication: adjudication([verdict]),
    chainAdjudication: chainAdjudication([proven]), variants: variants([completeReceipt()], true),
  });
  assert.equal(result.attackPaths.length, 1);
  assert.equal(result.attackPaths[0].constituentFindingIds.length, 1);
  // Path severity is distinct from primitive severity; counts are separate.
  assert.equal(result.coverage.survivingCandidateVerdicts, 1);
  assert.equal(result.coverage.provenPaths, 1);
});

test('partial and blocked paths carry no severity and are classified separately', () => {
  const plan = planWith();
  const partial = { pathId: 'p2', verdict: 'PARTIALLY_SUPPORTED', evidenceStrength: 'strong-inference', severity: null, stepAssessments: [], joinAssessments: [], controls: [], controlAssessments: [], terminalImpact: null, proof: null, negativeControl: null, devilsAdvocate: 'x', rationale: 'x', contextId: 'ctx', binding: BINDING, adjudicatorProvider: 'a', synthesizerProvider: 's' };
  const blocked = { ...partial, pathId: 'p3', verdict: 'BLOCKED', controlAssessments: [{ controlId: 'ctrl1', status: 'EFFECTIVE' }] };
  const result = synthesizeSecurityEvidence({
    plan, model: model(), candidates: candidates([candidate]), adjudication: adjudication([verdict]),
    chainAdjudication: chainAdjudication([partial, blocked]), variants: variants([completeReceipt()], true),
  });
  assert.equal(result.hypotheses.partiallySupported.length, 1);
  assert.equal(result.hypotheses.blocked.length, 1);
  assert.equal(result.attackPaths.length, 0);
  assert.equal(result.findings[0].severity, 'high');
});

test('accepted risk does not alter verdict or severity', () => {
  const plan = planWith();
  const result = synthesizeSecurityEvidence({
    plan, model: model(), candidates: candidates([candidate]), adjudication: adjudication([verdict]),
    chainAdjudication: chainAdjudication([]), variants: variants([completeReceipt()], true),
  });
  const finding = result.findings[0];
  finding.acceptedRisk = { id: 'risk-1', expiresAt: '2026-01-01' };
  assert.equal(finding.severity, 'high');
  assert.equal(finding.verdict, 'TRUE_POSITIVE');
});

test('binding mismatch fails synthesis', () => {
  const plan = planWith();
  const stale = candidates([candidate]);
  stale.binding = { ...BINDING, repositoryRevision: 'other' };
  assert.throws(() => synthesizeSecurityEvidence({
    plan, model: model(), candidates: stale, adjudication: adjudication([verdict]),
    chainAdjudication: chainAdjudication([]), variants: variants([completeReceipt()], true),
  }), /does not match/);
});

test('same root cause groups variants without destructive dedup', () => {
  const plan = planWith();
  const candidateB = { ...candidate, id: 'c2', ruleId: 'credentials.format' };
  const verdictB = { ...verdict, candidateId: 'c2' };
  const receiptB = { ...completeReceipt(), findingId: 'c2' };
  const result = synthesizeSecurityEvidence({
    plan, model: model(), candidates: candidates([candidate, candidateB]),
    adjudication: adjudication([verdict, verdictB]),
    chainAdjudication: chainAdjudication([]), variants: variants([completeReceipt(), receiptB], true),
  });
  assert.equal(result.findings.length, 2, 'two findings kept');
  assert.equal(result.systemicRootCauses.length, 1, 'grouped by root cause');
  assert.equal(result.systemicRootCauses[0].findingIds.length, 2);
});
