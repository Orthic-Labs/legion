import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { detectAntiSlop } from '../providers/copy/anti-slop.mjs';

const fixtures = JSON.parse(readFileSync(
  new URL('../bench/corpora/copy/anti-slop/fixture-items.json', import.meta.url),
  'utf8',
));
const binding = { repository: 'sha256:fixture' };

test('B6-013 corpus separates unsupported copy from technical and bounded near misses', () => {
  const result = detectAntiSlop(fixtures, {
    binding,
    claimProofLedger: { claims: [{ id: 'claim:best', disposition: 'unproven', evidenceRefs: [] }] },
  });

  assert.ok(result.candidates.some(({ ruleId }) => ruleId === 'copy.anti-slop.generic-opener'));
  assert.ok(result.candidates.some(({ ruleId }) => ruleId === 'copy.anti-slop.unsupported-superlative'));
  for (const id of ['fixture:technical-near-miss', 'fixture:bounded-comparison']) {
    assert.equal(result.candidates.some(({ contentItemIds }) => contentItemIds.includes(id)), false);
  }
  for (const candidate of result.candidates) {
    assert.equal(candidate.detectorKind, 'interpretive');
    assert.equal(candidate.verdict, 'UNADJUDICATED');
    assert.ok(candidate.claim.includes('because'));
    assert.ok(candidate.featureVector.context);
    assert.equal('replacement' in candidate, false);
  }
});

test('B6-013 reserves deterministic findings for explicit policy bans', () => {
  const result = detectAntiSlop([{
    id: 'fixture:banned',
    text: 'Guaranteed profit arrives tomorrow.',
    surface: { type: 'paragraph' },
    audience: 'investors',
    purpose: 'state an expected outcome',
    binding,
  }], { binding, explicitBans: [{ id: 'claims.no-guaranteed-profit', phrase: 'guaranteed profit' }] });

  assert.deepEqual(result.findings.map(({ ruleId }) => ruleId), ['claims.no-guaranteed-profit']);
  assert.equal(result.findings[0].detectorKind, 'deterministic');
});
