import assert from 'node:assert/strict';
import test from 'node:test';

import { publicReason, renderHostRuntimeOutput, serializeHostRuntimeOutput } from '../host/host-runtime-output.mjs';

test('B6 renders only schema-closed host output with exact public reasons', () => {
  assert.equal(publicReason('ARC_GATE_UNAVAILABLE'), 'ARC_GATE_UNAVAILABLE: Pre-effect gate is unavailable.');
  assert.equal(publicReason('not-a-code'), 'ARC_SCHEMA_INVALID: Arcane rejected invalid structured input.');
  assert.deepEqual(renderHostRuntimeOutput({ eventType: 'PreToolUse', allowed: false, code: 'ARC_GATE_UNAVAILABLE' }), { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'ARC_GATE_UNAVAILABLE: Pre-effect gate is unavailable.' } });
  assert.deepEqual(renderHostRuntimeOutput({ eventType: 'Stop', allowed: false, code: 'ARC_NO_CONTRACT' }), { decision: 'block', reason: 'ARC_NO_CONTRACT: No sealed execution contract is bound.' });
  assert.deepEqual(renderHostRuntimeOutput({ eventType: 'PostToolUse', allowed: false, code: 'ARC_CAPABILITY_UNKNOWN' }), { hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'Arcane: ARC_CAPABILITY_UNKNOWN: Capability is missing.' } });
  assert.equal(serializeHostRuntimeOutput(null), '');
  assert.equal(serializeHostRuntimeOutput({ decision: 'block', reason: 'ARC_NO_CONTRACT: No sealed execution contract is bound.' }), '{"decision":"block","reason":"ARC_NO_CONTRACT: No sealed execution contract is bound."}\n');
});
