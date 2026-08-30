import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { advisoryJudgmentBindings, advisoryJudgmentRuntimeIds, validateAdvisoryJudgmentObservation } from '../src/lib/verification/arcane/s11-bindings/advisory-judgment.mjs';

const corpus = new Map(readdirSync(join(import.meta.dirname, '..', 'src', 'evals', 'architecture')).flatMap((name) => readFileSync(join(import.meta.dirname, '..', 'src', 'evals', 'architecture', name), 'utf8').trim().split('\n').map(JSON.parse).map((row) => [row.id, row])));
test('stage11 advisory judgment rows remain pending without external Sage/Oracle records', () => {
  const ids = advisoryJudgmentRuntimeIds();
  assert.equal(ids.length, 35);
  assert.equal(ids.includes('AD-1') || ids.includes('AD-2'), false);
  assert.equal(ids.includes('AE-ADVERSARIAL-010'), true);
  assert.equal(ids.includes('AE-REVIEW-VERDICT-SECURITY-002'), true);
  for (const id of ids) {
    const result = advisoryJudgmentBindings[id](corpus.get(id));
    assert.equal(result.allowed, false, id);
    assert.equal(result.detail.disposition, 'PENDING', id);
  }
});

test('advisory observation validator rejects pending output', () => {
  const source = corpus.get('AE-ADVERSARIAL-010');
  const pending = advisoryJudgmentBindings[source.id](source);
  assert.equal(validateAdvisoryJudgmentObservation(source, pending), false);
});
