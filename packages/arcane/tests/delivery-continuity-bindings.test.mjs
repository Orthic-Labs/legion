import assert from 'node:assert/strict';
import test from 'node:test';

import { deliveryContinuityBindings, executeDeliveryContinuityCase } from '../lib/s11-bindings/delivery-continuity.mjs';

const rows = [
  ['AE-HANDOFF-005', 'handoff'],
  ['AE-INTEGRATION-OWNERSHIP-001', 'integration-ownership'],
  ['AE-CONCURRENCY-ATTENTION-005', 'concurrency-attention'],
  ['AE-CONTROL-PLANE-BUDGETS-001', 'control-plane-budgets'],
  ['AE-LINEAGE-BUDGETS-001', 'lineage-budgets'],
  ['AE-MACHINERY-DEFECTS-001', 'machinery-defects'],
];

test('S11 delivery-continuity bindings use production guards & structured consumers', () => {
  assert.deepEqual(deliveryContinuityBindings(), rows.map(([id]) => id).sort());
  for (const [id, family] of rows) {
    const result = executeDeliveryContinuityCase({ id, family });
    assert.equal(result.status, 'PASS', id);
    assert.equal(typeof result.observed?.ingress, 'string', id);
    assert.equal(typeof result.observed?.consumer, 'string', id);
  }
});

test('S11 delivery-continuity bindings leave unrelated rows unclaimed', () => {
  assert.equal(executeDeliveryContinuityCase({ id: 'AE-RETRY-SEMANTICS-001', family: 'retry-semantics' }), null);
});
