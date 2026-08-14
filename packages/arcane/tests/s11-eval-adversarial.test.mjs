import assert from 'node:assert/strict';
import test from 'node:test';
import { adversarialBindingIds, executeAdversarialBinding, validateAdversarialObservation } from '../lib/s11-bindings/eval-adversarial.mjs';

test('adversarial bindings exercise deterministic routing controls', () => {
  for (const id of ['AE-ADVERSARIAL-003']) {
    const result = executeAdversarialBinding(id);
    assert.equal(result.producer, 'routeArchitecture');
    assert.equal(validateAdversarialObservation(id, result), true);
  }
});

test('judgment-only adversarial cases remain typed pending with exact producer', () => {
  const expected = {
    'AE-ADVERSARIAL-001': 'architecture proportionality assessment ingress',
    'AE-ADVERSARIAL-002': 'mandatory-obligation readiness ingress',
    'AE-ADVERSARIAL-004': 'migration target selection ingress',
    'AE-ADVERSARIAL-005': 'distributed failure-mode assessment ingress',
    'AE-ADVERSARIAL-006': 'source-of-truth ownership-conflict ingress',
    'AE-ADVERSARIAL-007': 'adverse-case vendor economics ingress',
    'AE-ADVERSARIAL-009': 'AI readiness governance ingress',
    'AE-ADVERSARIAL-010': 'architecture-reconstruction uncertainty verdict ingress',
  };
  for (const [id, producer] of Object.entries(expected)) {
    const result = executeAdversarialBinding(id);
    assert.equal(result.status, 'PENDING', id);
    assert.equal(result.missingProducer, producer, id);
    assert.equal(validateAdversarialObservation(id, result), false, id);
  }
  assert.equal(adversarialBindingIds().length, 9);
});
