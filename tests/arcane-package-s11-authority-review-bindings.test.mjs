import assert from 'node:assert/strict';
import test from 'node:test';

import { authorityReviewBindings, authorityReviewBlockers, authorityReviewRuntimeIds } from '../src/lib/verification/arcane/s11-bindings/authority-review.mjs';

test('S11 authority-review bindings use live ingress outputs with exact state identity', () => {
  assert.deepEqual(authorityReviewRuntimeIds(), [
    'AE-ADVERSARIAL-008',
    'AE-OWNERSHIP-DISPOSITION-002',
    'AE-REVIEW-VERDICT-SECURITY-003',
    'AE-SCOPE-AUTHORITY-002',
  ]);
  for (const id of authorityReviewRuntimeIds()) {
    const result = authorityReviewBindings[id]();
    assert.match(result.state_identity, /^sha256:[0-9a-f]{64}$/);
    assert.equal(typeof result.observed, 'object');
  }
});

test('S11 authority-review binding observations preserve consumer-specific denials', () => {
  assert.equal(authorityReviewBindings['AE-SCOPE-AUTHORITY-002']().observed.code, 'ARC_AUTHORITY_NOT_ASSERTED');
  assert.equal(authorityReviewBindings['AE-OWNERSHIP-DISPOSITION-002']().observed.code, 'ARC_INTEGRATION_OWNER_CONFLICT');
  assert.equal(authorityReviewBindings['AE-REVIEW-VERDICT-SECURITY-003']().observed.verdict.allowed, true);
  assert.deepEqual(authorityReviewBindings['AE-ADVERSARIAL-008']().observed.affectedClaims, ['decision-affected']);
});

test('S11 authority-review blockers name missing production ingress', () => {
  assert.equal(Object.keys(authorityReviewBlockers).length, 22);
  assert.match(authorityReviewBlockers['AE-NEGATIVE-TRIGGERS-002'], /diagnosis-state delta guard ingress is absent/);
});
