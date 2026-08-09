import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createHostRuntime } from '../host/host-runtime.mjs';
import { normalizeCodexEvent } from '../host/codex-adapter.mjs';
import { claudeCodeHostAdapter } from '../host/claude-code-adapter.mjs';
import { b5Contract, seedStore } from './fixtures/runtime-binding-contract.mjs';
import { SessionBindingStore } from '../lib/session-binding.mjs';

test('B6 runtime composes stores & returns a closed refusal without throwing', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-runtime-'));
  try {
    const runtime = createHostRuntime({ adapter: { name: 'codex', normalize: normalizeCodexEvent }, workspace, keyDir: join(workspace, 'absent-keys') });
    const result = runtime.handle({ hook_event_name: 'PreToolUse', cwd: workspace, session_id: 'session', tool_name: 'Write', tool_input: { file_path: 'a.mjs' } });
    assert.equal(runtime.stateRoot, join(workspace, '.audit', 'arcane'));
    assert.equal(result.kind, 'arcane-host-runtime-result');
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'ARC_AUTH_KEY_UNAVAILABLE');
    assert.deepEqual(result.stdout, { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'ARC_AUTH_KEY_UNAVAILABLE: Host authentication key is unavailable.' } });
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test('B7 native Codex subprocess reserves once, consumes one durable capability & emits exact stdout', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-runtime-e2e-'));
  const workspace = join(root, 'workspace'); const stateRoot = join(root, 'state'); const keyDir = join(root, 'keys');
  const sessionId = 'session'; const runId = 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV';
  const contract = b5Contract();
  try {
    mkdirSync(workspace, { recursive: true }); mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    writeFileSync(join(workspace, 'README.md'), 'fixture\n');
    for (const args of [['init', '-q'], ['config', 'user.email', 'test@example.com'], ['config', 'user.name', 'test'], ['add', 'README.md'], ['commit', '-qm', 'init']]) execFileSync('git', args, { cwd: workspace });
    contract.sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: workspace, encoding: 'utf8' }).trim();
    contract.scope.own = ['src/**']; contract.artifacts.exact[0].path = 'src/a.mjs'; contract.authorizedEffectClasses = ['FILE_WRITE'];
    const sealed = seedStore(stateRoot, contract).record;
    new SessionBindingStore({ root: join(stateRoot, 'session-bindings') }).putBinding(sessionId, { runId, taskId: 'T-1', contractId: contract.contractId, contractVersion: contract.version, contractDigest: sealed.contractDigest });
    const env = { ...process.env, ARCANE_WORKSPACE: workspace, ARCANE_STATE_ROOT: stateRoot, ARCANE_KEY_DIR: keyDir };
    const run = (payload) => execFileSync(process.execPath, ['packages/arcane/host/codex-adapter.mjs'], { cwd: process.cwd(), env, input: JSON.stringify(payload), encoding: 'utf8' });
    const base = { session_id: sessionId, agent_id: 'agent', agent_type: 'alchemist', cwd: workspace };
    assert.equal(run({ ...base, hook_event_name: 'SessionStart' }), '');
    assert.equal(run({ ...base, hook_event_name: 'SubagentStart' }), '');
    assert.equal(run({ ...base, hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: 'src/a.mjs' }, tool_use_id: 'tool-1' }), '');
    assert.match(run({ ...base, hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: 'src/a.mjs' }, tool_use_id: 'tool-1' }), /ARC_REPLAY_NONCE_SEEN/);
    assert.equal(run({ ...base, hook_event_name: 'PostToolUse', tool_name: 'Write', tool_input: { file_path: 'src/a.mjs' }, tool_response: { ok: true }, tool_use_id: 'tool-1' }), '');
    assert.match(run({ ...base, hook_event_name: 'PostToolUseFailure', tool_name: 'Write', tool_input: { file_path: 'src/a.mjs' }, tool_response: { ok: false }, tool_use_id: 'tool-2' }), /ARC_INGEST_CORRELATION_MISSING/);
    // A bare Stop claims no completion level and this run touched no locked
    // domain, so there is nothing to certify and the turn ends. The previous
    // expectation (a hard block) was unsatisfiable by construction: hook-
    // emitted receipts are effect receipts and carry no `evidenceClass`, so
    // the old implicit 'signoff' claim could never be met by ANY session.
    assert.equal(run({ ...base, hook_event_name: 'Stop' }), '');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('ambient tier: an uncontracted Write outside every locked domain is observed, not denied', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-ambient-'));
  const keyDir = join(workspace, 'keys');
  try {
    mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    const runtime = createHostRuntime({ adapter: claudeCodeHostAdapter, workspace, keyDir });
    const result = runtime.handle({ hook_event_name: 'PreToolUse', cwd: workspace, session_id: 'session', tool_name: 'Write', tool_input: { file_path: 'src/app.mjs' }, tool_use_id: 'tu-1' });
    assert.notEqual(result.code, 'ARC_NO_CONTRACT');
    assert.equal(result.capabilityId, null); // observed, never authorized
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test('ambient tier: an uncontracted Write INSIDE a locked domain still fails closed', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-ambient-locked-'));
  const keyDir = join(workspace, 'keys');
  try {
    mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    const runtime = createHostRuntime({ adapter: claudeCodeHostAdapter, workspace, keyDir });
    const result = runtime.handle({ hook_event_name: 'PreToolUse', cwd: workspace, session_id: 'session', tool_name: 'Write', tool_input: { file_path: 'tools/rhook/src/main.rs' }, tool_use_id: 'tu-2' });
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'ARC_NO_CONTRACT');
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});
