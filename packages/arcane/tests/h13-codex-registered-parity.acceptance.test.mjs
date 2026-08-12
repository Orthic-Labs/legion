import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  buildRawCodexEvent,
  normalizeCodexEvent,
} from '../host/codex-adapter.mjs';
import { classifyObservation } from '../lib/host-event.mjs';

const registrationPath = new URL('../../../../../codex-brief-plugin/plugins/arcane/hooks/hooks.json', import.meta.url);
const hooks = JSON.parse(readFileSync(registrationPath, 'utf8')).hooks;
const registeredEvents = [
  'SessionStart',
  'SubagentStart',
  'UserPromptSubmit',
  'PostCompact',
  'PreToolUse',
  'PostToolUse',
  'PostToolUseFailure',
  'Stop',
];

function matcher(eventName) {
  return new Set(hooks[eventName][0].matcher.split('|'));
}

test('H-13 oracle: adapter covers exactly the eight Arcane plugin registrations', () => {
  assert.deepEqual(Object.keys(hooks), registeredEvents);

  const expected = {
    SessionStart: 'session-start',
    SubagentStart: 'subagent-start',
    UserPromptSubmit: 'user-prompt-submit',
    PostCompact: 'post-compact',
    PreToolUse: 'pre-effect',
    PostToolUse: 'post-effect',
    Stop: 'stop',
  };

  for (const [hook_event_name, eventType] of Object.entries(expected)) {
    const event = normalizeCodexEvent({
      hook_event_name,
      session_id: 'h13-session',
      cwd: process.cwd(),
      tool_name: 'shell_command',
      tool_input: { command: 'Write-Output h13' },
      tool_response: { ok: true },
      tool_use_id: `h13-${hook_event_name}`,
    });
    assert.equal(event.eventType, eventType);
  }
});

test('H-13 oracle: Codex-only lifecycle events are non-qualifying telemetry', () => {
  for (const hook_event_name of ['SubagentStart', 'PostCompact']) {
    const event = normalizeCodexEvent({
      hook_event_name,
      session_id: 'h13-session',
      cwd: process.cwd(),
    });
    assert.equal(classifyObservation(event), 'non-qualifying-telemetry');
    assert.equal(event.effect, null);
    assert.equal(event.result, null);
  }
});

test('H-13 oracle: matcher coverage stays honest', () => {
  assert.ok(matcher('PreToolUse').has('shell_command'));
  assert.ok(matcher('PreToolUse').has('apply_patch'));
  assert.ok(matcher('PostToolUse').has('shell_command'));
  assert.ok(matcher('PostToolUse').has('apply_patch'));

  const patch = '*** Begin Patch\n*** End Patch';
  const pre = buildRawCodexEvent({
    hook_event_name: 'PreToolUse',
    tool_name: 'apply_patch',
    tool_input: { command: patch },
  });
  assert.equal(pre.operation.toolId, 'apply_patch');
  assert.equal(pre.effect, undefined);

  // PostToolUseFailure is registered on Codex for lifecycle parity.
  const failure = buildRawCodexEvent({
    hook_event_name: 'PostToolUseFailure',
    tool_name: 'apply_patch',
    tool_input: { command: patch },
    tool_response: { error: 'fixture' },
  });
  assert.equal(failure.result.outcome, 'failure');
  assert.equal(failure.effect, null);
});
