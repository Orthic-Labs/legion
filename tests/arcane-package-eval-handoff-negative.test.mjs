import assert from 'node:assert/strict';
import test from 'node:test';

import {
  executeHandoffNegativeCase,
  handoffNegativeBindingIds,
  validateHandoffNegativeObservation,
} from '../src/lib/verification/arcane/s11-bindings/eval-handoff-negative.mjs';

const rows = [
  ['AE-HANDOFF-002', 'handoff'],
  ['AE-HANDOFF-004', 'handoff'],
  ['AE-NEGATIVE-TRIGGERS-001', 'negative-triggers'],
  ['AE-NEGATIVE-TRIGGERS-003', 'negative-triggers'],
  ['AE-NEGATIVE-TRIGGERS-004', 'negative-triggers'],
];

test('S11 handoff/negative bindings use production ingress and independent validators', () => {
  assert.deepEqual(handoffNegativeBindingIds(), rows.map(([id]) => id));
  for (const [id, family] of rows) {
    const result = executeHandoffNegativeCase({ id, family });
    if (id === 'AE-HANDOFF-004') {
      assert.equal(result.status, 'PENDING');
      assert.match(result.reason, /Sage\+Oracle judgment/);
      continue;
    }
    assert.equal(result.status, 'PASS', id);
    assert.equal(validateHandoffNegativeObservation(id, result.observed), true, id);
  }
});

test('S11 handoff/negative bindings do not claim unrelated rows', () => {
  assert.equal(executeHandoffNegativeCase({ id: 'AE-HANDOFF-003', family: 'handoff' }), null);
});
