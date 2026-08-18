import assert from 'node:assert/strict';
import test from 'node:test';

import { executeM1M6Binding, m1M6BindingIds } from '../lib/s11-bindings/m1-m6-production.mjs';

test('M1-M6 S11 bindings expose structured production observations', () => {
  // 29, not 30: AE-ADOPTION-GOVERNANCE-001 was retired in 96b0f6d together
  // with its subject (lib/adoption-ledger.mjs) and its eval case. The count
  // guard is kept so an accidental drop still fails.
  assert.equal(m1M6BindingIds().length, 29);
  for (const id of m1M6BindingIds()) {
    const result = executeM1M6Binding(id);
    assert.equal(typeof result.producer, 'string', id);
    assert.equal(typeof result.consumer, 'string', id);
    assert.equal(typeof result.value, 'object', id);
    assert.equal('status' in result, false, id);
  }
});

test('M1-M6 bindings never answer from case id alone', () => {
  assert.equal(executeM1M6Binding('AE-UNSUPPORTED-001'), null);
});
