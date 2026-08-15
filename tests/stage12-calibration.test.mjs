import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import { applyRetirementDecision, calibrateStage12, stage12TruthSemantics, validateRetirementDecisionRecord } from '../scripts/run-stage12-calibration.mjs';

const root = resolve(import.meta.dirname, '..');
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function directPacket(authority) {
  const counts = [4, 45, 24, 13, 35, 28, 26];
  let cursor = 0;
  return {
    schemaVersion: 1, kind: 'legion-authority-dispatch', packetType: 'direct', ...authority,
    modelRouting: { modelTier: 'MID', workerProfile: 'parallel', routingRationale: 'seven independent owners' },
    objective: 'Complete Phase A through seven frozen owners.', authority: ['AGENTS.md'], integrationOwner: 'codex',
    workers: counts.map((count, index) => {
      const own = Array.from({ length: count }, () => `owned/path-${String(cursor++).padStart(3, '0')}`);
      return { id: `worker-${index + 1}`, executor: 'deepseek', own, read: ['AGENTS.md'], forbidden: ['.git', 'secrets'], checks: ['focused test'], dependencies: [] };
    }),
    recovery: { maxRetries: 2, stopConditions: ['owned path is already dirty'], returnFields: ['changedPaths', 'checks', 'blockers', 'baselineRevision', 'patchDigest'] },
  };
}

function authorityFixture(temporary) {
  const repositoryRoot = join(temporary, 'repository');
  mkdirSync(repositoryRoot);
  writeFileSync(join(repositoryRoot, 'AGENTS.md'), 'fixture authority\n');
  const promptArtifact = join(repositoryRoot, 'captured-prompt.txt');
  writeFileSync(promptArtifact, 'exact captured dispatch prompt\n');
  execFileSync('git', ['init', '-q'], { cwd: repositoryRoot });
  execFileSync('git', ['config', 'user.email', 's12@example.test'], { cwd: repositoryRoot });
  execFileSync('git', ['config', 'user.name', 'S12 Fixture'], { cwd: repositoryRoot });
  execFileSync('git', ['add', 'AGENTS.md', 'captured-prompt.txt'], { cwd: repositoryRoot });
  execFileSync('git', ['commit', '-qm', 'fixture authority source'], { cwd: repositoryRoot });
  const sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repositoryRoot, encoding: 'utf8' }).trim();
  const packet = directPacket({ repositoryRoot, sourceRevision, promptArtifact: 'captured-prompt.txt', promptDigest: sha256(readFileSync(promptArtifact)) });
  const directPacketPath = join(repositoryRoot, 'direct-packet.json');
  const directPacketText = `${JSON.stringify(packet, null, 2)}\n`;
  writeFileSync(directPacketPath, directPacketText);
  return { directPacketPath, directPacketText };
}

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
  const temporary = mkdtempSync(join(tmpdir(), 'legion-s12-test-'));
  const { directPacketPath, directPacketText } = authorityFixture(temporary);
  const historyText = fixtureHistory();
  const result = calibrateStage12({ historyText, directPacketText, directPacketPath,
    legacyTemplateText: readFileSync(join(root, 'skills/dispatch/assets/dispatch-template.md'), 'utf8'),
    s08Receipt: { workload: { actual_acceptance_surface: 'assembled package Handoff', artifact: { digest: `sha256:${'a'.repeat(64)}` }, result: { status: 'PASS' }, observed_failures: [] } } });
  rmSync(temporary, { recursive: true, force: true });
  assert.equal(result.schema, 'stage12-calibration.v1');
  assert.equal(result.scenarios.real_legion_history.outcome.legacy_validator, 'UNPROVEN');
  assert.equal(result.scenarios.real_legion_history.outcome.direct_packet, 'UNPROVEN');
  assert.equal(result.scenarios.real_legion_history.tool_calls, 51);
  assert.equal(result.scenarios.real_legion_history.delivery_time_ms, 1_581_649);
  assert.match(result.scenarios.real_legion_history.source.digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(result.scenarios.real_legion_history.source.bytes, Buffer.byteLength(historyText));
  assert.equal(result.scenarios.minimal_ambient_baseline.outcome, 'PASS');
  assert.equal(result.scenarios.minimal_ambient_baseline.worker_count, 7);
  assert.equal(result.scenarios.minimal_ambient_baseline.owned_path_count, 175);
  assert.equal(result.scenarios.minimal_ambient_baseline.unique_path_count, 175);
  assert.match(result.scenarios.minimal_ambient_baseline.packet_digest, /^sha256:[a-f0-9]{64}$/);
  assert.match(result.scenarios.minimal_ambient_baseline.validator_receipt_digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(result.scenarios.governed_s08_workload.outcome, 'PASS');
  assert.equal(result.deltas.outcome, 'UNPROVEN');
  assert.ok(result.deltas.history_to_ambient_tool_calls < 0);
  assert.ok(result.deltas.history_to_ambient_effective_tokens < 0);
  assert.ok(result.deltas.history_to_ambient_delivery_time_ms < 0);
  assert.equal(result.controls.length, 1);
  assert.equal(result.controls[0].lifecycle, 'PENDING');
  assert.equal(result.controls[0].disposition, 'UNPROVEN');
  assert.equal(result.controls[0].disposition_authority, null);
  assert.equal(result.all_net_harmful_controls_disposed, false);
});

test('durable S12 evidence binds explicit current-user retirement decision', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'legion-s12-drift-'));
  const { directPacketPath, directPacketText } = authorityFixture(temporary);
  const runner = calibrateStage12({ historyText: fixtureHistory(), directPacketText, directPacketPath,
    legacyTemplateText: readFileSync(join(root, 'skills/dispatch/assets/dispatch-template.md'), 'utf8'),
    s08Receipt: { workload: { actual_acceptance_surface: 'assembled package Handoff', artifact: { digest: `sha256:${'a'.repeat(64)}` }, result: { status: 'PASS' }, observed_failures: [] } } });
  rmSync(temporary, { recursive: true, force: true });
  const decisionPath = resolve(root, '../../..', 'docs/plans/legion/evidence/2026-08-15-dispatch-retirement-user-decision.json');
  const decisionBytes = readFileSync(decisionPath);
  const decision = JSON.parse(decisionBytes);
  const applied = applyRetirementDecision(runner, decision, {
    sourcePath: 'docs/plans/legion/evidence/2026-08-15-dispatch-retirement-user-decision.json',
    sourceDigest: sha256(decisionBytes),
  });
  const durable = JSON.parse(readFileSync(resolve(root, '../../..', 'docs/plans/legion/evidence/2026-08-14-s12-calibration-retirement.json'), 'utf8'));
  assert.equal(validateRetirementDecisionRecord(decision), true);
  assert.deepEqual(stage12TruthSemantics(durable), stage12TruthSemantics(applied));
  assert.deepEqual(durable.missing_receipts, []);
  assert.equal(durable.all_net_harmful_controls_disposed, true);
  assert.throws(() => applyRetirementDecision(runner, { ...decision, authority: 'agent' }, { sourcePath: 'x', sourceDigest: sha256(decisionBytes) }), /invalid current-user/);
});
