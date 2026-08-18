import assert from 'node:assert/strict';
import test from 'node:test';
import { finalizeAdjudicationBundle, prepareAdjudicationBundle } from '../tools/audit/security-pipeline.mjs';

function candidates() {
  return {
    provider: 'security.internal-suite',
    candidates: [{
      id: 'candidate-1',
      provider: 'security.internal-suite',
      ruleId: 'security.command-injection',
      claim: 'Input reaches command execution.',
      evidence: [{ file: 'src/run.ts', line: 4 }],
    }],
  };
}

const baseVerdict = {
  candidateId: 'candidate-1',
  verdict: 'FALSE_POSITIVE',
  threatModel: 'remote unauthenticated',
  reachability: 'blocked',
  impact: 'none because input is fixed before the sink',
  rationale: 'The command argument is selected from a closed enum.',
};

test('adjudication bundle uses separate providers and contexts', () => {
  const bundle = prepareAdjudicationBundle(candidates(), { generatorContextId: 'generator', adjudicatorContextId: 'adjudicator' });
  assert.equal(bundle.packets[0].candidate.contextId, 'generator');
  assert.equal(bundle.packets[0].adjudicator.contextId, 'adjudicator');
  assert.notEqual(bundle.packets[0].candidate.provider, bundle.packets[0].adjudicator.provider);
});

test('each candidate gets its own fresh adjudication context', () => {
  const input = candidates();
  input.candidates.push({
    id: 'candidate-2',
    provider: 'security.internal-suite',
    ruleId: 'security.path-traversal',
    claim: 'Input reaches a filesystem path.',
    evidence: [{ file: 'src/files.ts', line: 9 }],
  });
  const bundle = prepareAdjudicationBundle(input, { generatorContextId: 'generator' });
  const contexts = bundle.packets.map((packet) => packet.adjudicator.contextId);
  assert.equal(new Set(contexts).size, 2);
  assert.ok(contexts.every((context) => context !== 'generator'));
  assert.equal(bundle.adjudicator.contextStrategy, 'one-context-per-candidate');
  assert.throws(
    () => prepareAdjudicationBundle(input, { generatorContextId: 'generator', adjudicatorContextId: 'reused' }),
    /each candidate requires a fresh context/,
  );
});

test('all candidates require verdicts', () => {
  const bundle = prepareAdjudicationBundle(candidates(), { generatorContextId: 'generator', adjudicatorContextId: 'adjudicator' });
  const result = finalizeAdjudicationBundle(bundle, { verdicts: [] });
  assert.equal(result.complete, false);
  assert.deepEqual(result.missingVerdicts, ['candidate-1']);
});

test('false-positive verdict closes without severity or variants', () => {
  const bundle = prepareAdjudicationBundle(candidates(), { generatorContextId: 'generator', adjudicatorContextId: 'adjudicator' });
  const result = finalizeAdjudicationBundle(bundle, { verdicts: [baseVerdict] });
  assert.equal(result.complete, true);
  assert.equal(result.status, 'pass');
  assert.equal(result.verdicts[0].severity, null);
});

test('true positive requires severity and completed matching variant receipt', () => {
  const bundle = prepareAdjudicationBundle(candidates(), { generatorContextId: 'generator', adjudicatorContextId: 'adjudicator' });
  const verdict = {
    candidateId: 'candidate-1', verdict: 'TRUE_POSITIVE', severity: 'critical',
    evidenceStrength: 'verified',
    threatModel: 'remote unauthenticated', attackerControl: 'proven', reachability: 'proven',
    impact: 'arbitrary command execution', proof: { kind: 'repro', artifact: 'tests/repro.ts' },
    devilsAdvocate: 'false positive excluded: attacker controls input and sink is reachable',
  };
  const missing = finalizeAdjudicationBundle(bundle, { verdicts: [verdict] });
  assert.equal(missing.complete, false);
  assert.equal(missing.missingVariantAnalysis.length, 1);
  const complete = finalizeAdjudicationBundle(bundle, { verdicts: [verdict] }, [{ findingId: 'candidate-1', ruleId: 'security.command-injection', complete: true, matchesExamined: 4 }]);
  assert.equal(complete.complete, true);
  assert.equal(complete.status, 'findings');
});
