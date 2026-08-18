import assert from 'node:assert/strict';
import test from 'node:test';

import { executeM7Binding, m7BindingIds } from '../lib/s11-bindings/m7-production.mjs';

test('M7 S11 bindings expose full structured production observations', () => {
  assert.equal(m7BindingIds().length, 3);
  for (const id of m7BindingIds()) {
    const result = executeM7Binding(id);
    assert.equal(typeof result.producer, 'string', id);
    assert.equal(typeof result.consumer, 'string', id);
    assert.equal(typeof result.value, 'object', id);
  }
});
