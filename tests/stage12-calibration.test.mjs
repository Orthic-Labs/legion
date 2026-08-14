import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { calibrateStage12 } from '../scripts/run-stage12-calibration.mjs';

const root = resolve(import.meta.dirname, '..');
const directPacketPath = join(root, 'skills/dispatch/assets/direct-packet.json');

function fixtureHistory() {
  const row = (timestamp, type, payload) => ({ timestamp, type, payload });
  const rows = [
    row('2026-08-14T13:47:50.164Z', 'event_msg', { type: 'user_message', message: 'actually give me lane A' }),
    row('2026-08-14T13:48:04.031Z', 'event_msg', { type: 'token_count', info: { total_token_usage: { total_tokens: 100, input_tokens: 80, cached_input_tokens: 50, output_tokens: 20 } } }),
    ...Array.from({ length: 51 }, (_, index) => row(`2026-08-14T13:49:${String(index).padStart(2, '0')}.000Z`, 'response_item', { type: index < 44 ? 'custom_tool_call' : 'function_call' })),
    row('2026-08-14T14:08:28.883Z', 'event_msg', { type: 'agent_message', message: 'Dispatch is written as 7 simultaneous workers' }),
    row('2026-08-14T14:08:37.526Z', 'event_msg', { type: 'token_count', info: { total_token_usage: { total_tokens: 500, input_tokens: 430, cached_input_tokens: 300, output_tokens: 70 } } }),
    row('2026-08-14T14:14:08.574Z', 'event_msg', { type: 'token_count', info: { total_token_usage: { total_tokens: 900, input_tokens: 760, cached_input_tokens: 500, output_tokens: 140 } } }),
    row('2026-08-14T14:14:11.813Z', 'event_msg', { type: 'task_complete', last_agent_message: 'DeepSeek Phase A dispatch' }),
    row('2026-08-14T14:35:30.393Z', 'event_msg', { type: 'agent_message', message: '500-line template packet; GoalRoute JSON; timing & critical-path calculations; Minimize authority receipt; 15-point author gate; validator receipt; 115 schema defects; direct 140-line DeepSeek packet; 7 owners; 175 unique paths; zero collisions' }),
  ];
  return rows.map(JSON.stringify).join('\n');
}

test('S12 replays real Dispatch history, ambient baseline, & governed workload', () => {
  const result = calibrateStage12({
    historyText: fixtureHistory(),
    directPacketText: readFileSync(directPacketPath, 'utf8'),
    directPacketPath,
    legacyTemplateText: readFileSync(join(root, 'skills/dispatch/assets/dispatch-template.md'), 'utf8'),
    s08Receipt: { workload: { actual_acceptance_surface: 'assembled package Handoff', artifact: { digest: `sha256:${'a'.repeat(64)}` }, result: { status: 'PASS' }, observed_failures: [] } },
  });
  assert.equal(result.schema, 'stage12-calibration.v1');
  assert.equal(result.scenarios.real_legion_history.outcome.legacy_validator, 'FAIL_115_FORMAT_DEFECTS');
  assert.equal(result.scenarios.real_legion_history.outcome.direct_packet, 'PASS_7_OWNERS_175_UNIQUE_PATHS_ZERO_COLLISIONS');
  assert.equal(result.scenarios.real_legion_history.tool_calls, 51);
  assert.equal(result.scenarios.real_legion_history.delivery_time_ms, 1_581_649);
  assert.equal(result.scenarios.minimal_ambient_baseline.outcome, 'PASS');
  assert.equal(result.scenarios.governed_s08_workload.outcome, 'PASS');
  assert.equal(result.deltas.outcome, 'FAIL_TO_PASS');
  assert.ok(result.deltas.history_to_ambient_tool_calls < 0);
  assert.ok(result.deltas.history_to_ambient_effective_tokens < 0);
  assert.ok(result.deltas.history_to_ambient_delivery_time_ms < 0);
  assert.equal(result.controls.length, 1);
  assert.equal(result.controls[0].lifecycle, 'RETIRED');
  assert.equal(result.controls[0].disposition, 'RETIRE');
  assert.equal(result.all_net_harmful_controls_disposed, true);
});
