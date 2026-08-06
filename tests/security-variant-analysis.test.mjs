import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeVariants } from '../providers/security/variant-analysis.mjs';

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
  return { schemaVersion: 1, kind: 'security-surface-model', binding: BINDING, denominatorDigest: 'sha256:denom', complete: true, entities: [], relations: [], initialFacts: [], evidence: [], coverage: {}, coverageGaps: [] };
}

function candidates(list) {
  return { schemaVersion: 1, kind: 'security-candidates', binding: BINDING, denominatorDigest: 'sha256:denom', complete: true, candidates: list };
}

function adjudication(verdicts) {
  return { schemaVersion: 1, kind: 'security-adjudication-result', binding: BINDING, complete: true, verdicts };
}

const candidate = { id: 'c1', provider: 'security.credentials', providerVersion: '1', ruleId: 'credentials.format', sources: [], sinks: [], assets: [], requiredControls: [], observedControls: [], evidenceRefs: ['ev1'], binding: BINDING };
const verdict = { candidateId: 'c1', candidateProvider: 'security.credentials', verdict: 'TRUE_POSITIVE', evidenceStrength: 'verified', severity: 'high', rootCauseSignature: { class: 'credential-in-repository' } };

function strategyPack() {
  return {
    id: 'security.credentials',
    variantStrategies: {
      'credentials.format': {
        rootCause(candidate, v) { return { class: 'credential-in-repository' }; },
        enumerate(context, signature) {
          return {
            denominator: { kind: 'source-files', digest: 'sha256:d', expected: 2, examined: 2, unexamined: [] },
            strategies: [{ id: 's1', kind: 'lexical-fallback', complete: true, coverageGaps: [], queryDigest: 'sha256:q' }],
            matches: [
              { file: 'a.ts', line: 3, semanticFingerprint: 'sha256:f1', disposition: 'CONFIRMED' },
              { file: 'b.ts', line: 9, semanticFingerprint: 'sha256:f2', disposition: 'REJECTED', rationale: 'mitigated' },
            ],
            coverageGaps: [],
          };
        },
      },
    },
  };
}

test('surviving finding with a complete strategy produces a complete receipt', () => {
  const plan = planWith();
  const result = analyzeVariants({
    plan, model: model(), candidates: candidates([candidate]), adjudication: adjudication([verdict]),
    packByProvider: new Map([['security.credentials', strategyPack()]]),
  });
  assert.equal(result.complete, true);
  assert.equal(result.receipts.length, 1);
  assert.equal(result.receipts[0].complete, true);
  assert.equal(result.receipts[0].summary.confirmed, 1);
  assert.equal(result.receipts[0].summary.rejected, 1);
});

test('surviving finding without a strategy is incomplete with a gap', () => {
  const plan = planWith();
  const result = analyzeVariants({
    plan, model: model(), candidates: candidates([candidate]), adjudication: adjudication([verdict]),
    packByProvider: new Map(),
  });
  assert.equal(result.complete, false);
  assert.ok(result.coverageGaps.some((gap) => gap.kind === 'variant-incomplete'));
  assert.ok(result.receipts[0].coverageGaps.includes('missing-variant-strategy'));
});

test('incomplete denominator (expected 10 examined 9) is incomplete', () => {
  const plan = planWith();
  const pack = strategyPack();
  pack.variantStrategies['credentials.format'].enumerate = () => ({
    denominator: { kind: 'source-files', digest: 'sha256:d', expected: 10, examined: 9, unexamined: ['z.ts'] },
    strategies: [{ id: 's1', kind: 'lexical-fallback', complete: true, coverageGaps: [], queryDigest: 'sha256:q' }],
    matches: [],
    coverageGaps: [],
  });
  const result = analyzeVariants({
    plan, model: model(), candidates: candidates([candidate]), adjudication: adjudication([verdict]),
    packByProvider: new Map([['security.credentials', pack]]),
  });
  assert.equal(result.receipts[0].complete, false);
});

test('unresolved matches make the receipt incomplete', () => {
  const plan = planWith();
  const pack = strategyPack();
  pack.variantStrategies['credentials.format'].enumerate = () => ({
    denominator: { kind: 'source-files', digest: 'sha256:d', expected: 1, examined: 1, unexamined: [] },
    strategies: [{ id: 's1', kind: 'lexical-fallback', complete: true, coverageGaps: [], queryDigest: 'sha256:q' }],
    matches: [{ file: 'a.ts', line: 3, semanticFingerprint: 'sha256:f', disposition: 'UNRESOLVED' }],
    coverageGaps: [],
  });
  const result = analyzeVariants({
    plan, model: model(), candidates: candidates([candidate]), adjudication: adjudication([verdict]),
    packByProvider: new Map([['security.credentials', pack]]),
  });
  assert.equal(result.receipts[0].complete, false);
  assert.equal(result.receipts[0].summary.unresolved, 1);
});

test('false-positive candidates never generate variant receipts', () => {
  const plan = planWith();
  const fpVerdict = { ...verdict, verdict: 'FALSE_POSITIVE' };
  const result = analyzeVariants({
    plan, model: model(), candidates: candidates([candidate]), adjudication: adjudication([fpVerdict]),
    packByProvider: new Map([['security.credentials', strategyPack()]]),
  });
  assert.equal(result.receipts.length, 0);
  assert.equal(result.complete, true);
});

test('stale binding is rejected', () => {
  const plan = planWith();
  const staleCandidates = candidates([candidate]);
  staleCandidates.binding = { ...BINDING, repositoryRevision: 'other' };
  assert.throws(() => analyzeVariants({
    plan, model: model(), candidates: staleCandidates, adjudication: adjudication([verdict]),
    packByProvider: new Map(),
  }), /does not match/);
});

test('receipt summary counts must match the match list', () => {
  const plan = planWith();
  const pack = strategyPack();
  pack.variantStrategies['credentials.format'].enumerate = () => ({
    denominator: { kind: 'source-files', digest: 'sha256:d', expected: 1, examined: 1, unexamined: [] },
    strategies: [{ id: 's1', kind: 'lexical-fallback', complete: true, coverageGaps: [], queryDigest: 'sha256:q' }],
    matches: [{ file: 'a.ts', line: 3, semanticFingerprint: 'sha256:f', disposition: 'CONFIRMED' }],
    coverageGaps: [],
  });
  const result = analyzeVariants({
    plan, model: model(), candidates: candidates([candidate]), adjudication: adjudication([verdict]),
    packByProvider: new Map([['security.credentials', pack]]),
  });
  const receipt = result.receipts[0];
  assert.equal(receipt.summary.enumerated, receipt.matches.length);
  assert.equal(receipt.summary.examined, receipt.matches.length);
});
