import test from 'node:test';
import assert from 'node:assert/strict';

import { assessChronology } from '../src/providers/narrative/chronology.mjs';

const units = [
  { id: 'question', role: 'question', sourceOrder: 1 },
  { id: 'answer', role: 'answer', sourceOrder: 0 },
];

test('B6-025 blocks evidence-backed answer-before-question edges', () => {
  const result = assessChronology({
    units,
    edges: [{ from: 'question', to: 'answer', kind: 'question-answer', evidenceRefs: ['evidence:qa'] }],
  });

  assert.ok(result.findings.some(({ ruleId }) => ruleId === 'narrative.chronology.false-sequence'));
  assert.ok(result.alternateOrders.some(({ classification }) => classification === 'forbidden'));
});

test('B6-025 keeps unproven answer-before-question edges review-required', () => {
  const result = assessChronology({
    units,
    edges: [{ from: 'question', to: 'answer', kind: 'question-answer', evidenceRefs: [] }],
  });

  assert.equal(result.findings.length, 0);
  assert.ok(result.candidates.some(({ ruleId }) => ruleId === 'narrative.chronology.sequence-uncertain'));
  assert.ok(result.alternateOrders.some(({ classification }) => classification === 'review-required'));
});
