import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { publicReason, renderHostRuntimeOutput, serializeHostRuntimeOutput } from '../host/host-runtime-output.mjs';
import { RuntimeSchemaSet } from '../lib/runtime-schema.mjs';

test('B6 renders only schema-closed host output with exact public reasons', () => {
  assert.equal(publicReason('ARC_GATE_UNAVAILABLE'), 'ARC_GATE_UNAVAILABLE: Pre-effect gate is unavailable.');
  assert.equal(publicReason('not-a-code'), 'ARC_SCHEMA_INVALID: Arcane rejected invalid structured input.');
  assert.deepEqual(renderHostRuntimeOutput({ eventType: 'PreToolUse', allowed: false, code: 'ARC_GATE_UNAVAILABLE' }), { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'ARC_GATE_UNAVAILABLE: Pre-effect gate is unavailable.' } });
  assert.deepEqual(renderHostRuntimeOutput({ eventType: 'Stop', allowed: false, code: 'ARC_NO_CONTRACT' }), { decision: 'block', reason: 'ARC_NO_CONTRACT: No sealed execution contract is bound.' });
  assert.deepEqual(renderHostRuntimeOutput({ eventType: 'PostToolUse', allowed: false, code: 'ARC_CAPABILITY_UNKNOWN' }), { hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'Arcane: ARC_CAPABILITY_UNKNOWN: Capability is missing.' } });
  assert.equal(serializeHostRuntimeOutput(null), '');
  assert.equal(serializeHostRuntimeOutput({ decision: 'block', reason: 'ARC_NO_CONTRACT: No sealed execution contract is bound.' }), '{"decision":"block","reason":"ARC_NO_CONTRACT: No sealed execution contract is bound."}\n');
});

test('AC-5 additionalContext branch declares maxLength 4000; PreToolUse/Stop branches stay declared at 500', () => {
  // RuntimeSchemaSet.validate() routes through the shared, out-of-contract
  // ../../../lib/qualification/schema-validator.mjs, which does not enforce
  // maxLength for ANY branch (pre-existing, verified independent of this
  // change: a 9999-char Stop `reason` already produces zero issues today).
  // That validator is outside EC-501 T-2 scope (not owned, not read, not a
  // bounded artifact) and is adjacent to the locked qualification domain, so
  // it is not touched here. This assertion instead pins what B-5 actually
  // owns: the schema document's own declared limits.
  const schema = JSON.parse(readFileSync(new URL('../schemas/host-runtime-output-v1.schema.json', import.meta.url), 'utf8'));
  const [, preToolUseBranch, stopBranch, contextBranch] = schema.oneOf;
  assert.equal(preToolUseBranch.properties.hookSpecificOutput.properties.permissionDecisionReason.maxLength, 500);
  assert.equal(stopBranch.properties.reason.maxLength, 500);
  assert.equal(contextBranch.properties.hookSpecificOutput.properties.additionalContext.maxLength, 4000);
  assert.equal(contextBranch.properties.systemMessage.maxLength, 50);
  assert.equal(contextBranch.additionalProperties, false);

  const runtimeSchema = new RuntimeSchemaSet();
  const sessionStart = (len) => ({ hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: 'x'.repeat(len) } });
  assert.equal(runtimeSchema.validate('arcane-host-runtime-output-v1', sessionStart(1200)).length, 0);
  assert.equal(runtimeSchema.validate('arcane-host-runtime-output-v1', sessionStart(4000)).length, 0);

  const withSystemMessage = { hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: 'ok' }, systemMessage: 'MINIMIZE:ON' };
  assert.equal(runtimeSchema.validate('arcane-host-runtime-output-v1', withSystemMessage).length, 0);
});
