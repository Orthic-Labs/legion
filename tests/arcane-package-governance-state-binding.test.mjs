import assert from 'node:assert/strict';
import test from 'node:test';

import { executeGovernanceStateBinding, governanceStateBindingIds } from '../src/lib/cli/commands/governance/execution/s11-bindings/governance-state.mjs';

test('S11 governance bindings invoke production ingress, consumer, & state projection', async () => {
  for (const id of governanceStateBindingIds()) {
    const result = await executeGovernanceStateBinding(id);
    assert.equal(result.case_id, id);
    assert.ok(result.ingress.module);
    assert.ok(result.consumer);
    assert.match(result.state_fingerprint, /^sha256:[0-9a-f]{64}$/);
  }
});

test('S11 governance bindings leave unsupported corpus IDs unbound', () => {
  for (const id of [
    'AE-CANDIDATE-QUALITY-001', 'AE-CANON-DRIFT-001',
    'AE-CLARIFICATION-CONVERGENCE-001', 'AE-CONTROL-RETIREMENT-001',
  ]) assert.equal(executeGovernanceStateBinding(id), null);
});
