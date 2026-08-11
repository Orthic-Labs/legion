import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { auditSuccessfulCommit, generatedLockTargets, preEffectDiscipline } from '../lib/discipline-controls.mjs';
import { createHostRuntime } from '../host/host-runtime.mjs';
import { claudeCodeHostAdapter } from '../host/claude-code-adapter.mjs';

test('discipline rejects no-verify before any commit receipt lookup', () => {
  const control = preEffectDiscipline({ tool_input: { command: 'git commit --no-verify -m x' } }, { workspace: tmpdir() });
  assert.equal(control.code, 'ARC_EFFECT_CLASS_UNAUTHORIZED');
});

test('runtime applies commit discipline before contracted pre-effect authorization', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-commit-runtime-'));
  try {
    const runtime = createHostRuntime({ adapter: claudeCodeHostAdapter, workspace, keyDir: join(workspace, 'keys') });
    const result = runtime.handle({ hook_event_name: 'PreToolUse', session_id: 's', cwd: workspace, tool_name: 'Bash', tool_use_id: 'u', tool_input: { command: 'git commit --no-verify -m x' } });
    assert.equal(result.code, 'ARC_EFFECT_CLASS_UNAUTHORIZED');
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test('discipline protects generated-lock patch targets', () => {
  const payload = { tool_input: { patch: '*** Update File: config/generated-lock.json\n@@\n-x\n+y' } };
  assert.deepEqual(generatedLockTargets(payload), ['config/generated-lock.json']);
  assert.equal(preEffectDiscipline(payload, { workspace: tmpdir() }).code, 'ARC_EFFECT_CLASS_UNAUTHORIZED');
});

test('successful shell commit creates identity audit only after success', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-commit-audit-'));
  try {
    auditSuccessfulCommit({ tool_input: { command: 'git commit -m x' } }, { eventType: 'post-effect', result: { outcome: 'success' }, sessionId: 's', runId: 'r', sourceRevision: 'abc' }, { workspace });
    const row = JSON.parse(readFileSync(join(workspace, '.audit', 'arcane', 'commit-identity.jsonl'), 'utf8'));
    assert.equal(row.sessionId, 's');
    assert.equal(row.runId, 'r');
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});
