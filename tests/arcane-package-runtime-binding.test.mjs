import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { after } from 'node:test';
import { fileURLToPath } from 'node:url';

import { createHostRuntime, evaluateLatestStopShape } from '../src/lib/host/arcane/host-runtime.mjs';
import { normalizeCodexEvent, mapCodexPreEffect, observeCodexIdentity } from '../src/lib/guard/compat/host/codex-adapter.mjs';
import { claudeCodeHostAdapter } from '../src/lib/guard/compat/host/claude-code-adapter.mjs';
import { evaluateStopShape } from '../src/lib/cognitive/arcane/stop-shape.mjs';
import { b5Contract, seedStore } from './fixtures/arcane-package/runtime-binding-contract.mjs';
import { SessionBindingStore } from '../src/lib/host/arcane/session-binding.mjs';
import { AuthorityBindingStore } from '../src/lib/contracts/arcane/authority-binding-store.mjs';
import { ArchitectureEventStore } from '../src/lib/verification/arcane/architecture-event-store.mjs';
import { createHostArchitectureState } from '../src/lib/host/arcane/continuity.mjs';
import { HostEventLedger } from '../src/lib/host/arcane/host-event-ledger.mjs';

const CODEX_ADAPTER = fileURLToPath(new URL('../src/lib/guard/compat/host/codex-adapter.mjs', import.meta.url));

const inheritedCodexThreadId = process.env.CODEX_THREAD_ID;
delete process.env.CODEX_THREAD_ID;
after(() => {
  if (inheritedCodexThreadId === undefined) delete process.env.CODEX_THREAD_ID;
  else process.env.CODEX_THREAD_ID = inheritedCodexThreadId;
});

test('EC-503 v6: fresh adapter process binds SubagentStart only to durable thread & rejects conflict', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-thread-binding-'));
  const workspace = join(root, 'workspace'); const stateRoot = join(root, 'state'); const keyDir = join(root, 'keys');
  try {
    mkdirSync(workspace, { recursive: true }); mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    const env = { ...process.env, ARCANE_WORKSPACE: workspace, ARCANE_STATE_ROOT: stateRoot, ARCANE_KEY_DIR: keyDir, CODEX_THREAD_ID: 'durable-thread' };
    const run = (payload) => execFileSync(process.execPath, [CODEX_ADAPTER], { cwd: process.cwd(), env, input: JSON.stringify(payload), encoding: 'utf8' });
    run({ hook_event_name: 'SessionStart', cwd: workspace, session_id: 'durable-thread', thread_id: 'durable-thread' });
    run({ hook_event_name: 'SubagentStart', cwd: workspace, session_id: 'durable-thread', thread_id: 'durable-thread', agent_id: 'agent-1', agent_type: 'alchemist' });
    const bindings = new AuthorityBindingStore({ root: join(stateRoot, 'authority-bindings') });
    assert.equal(bindings.findLatest({ adapter: 'codex', sessionId: 'durable-thread', authority: 'alchemist' })?.authority, 'alchemist');
    const ledger = JSON.parse(readFileSync(join(stateRoot, 'host-events', '0000000000000002.json'), 'utf8'));
    assert.equal(bindings.findLatest({ adapter: 'codex', sessionId: 'durable-thread', authority: 'alchemist' })?.observedEventId, ledger.eventId);
    assert.equal(bindings.findLatest({ adapter: 'codex', sessionId: 'transient-session', authority: 'alchemist' }), null);
    const output = run({ hook_event_name: 'SubagentStart', cwd: workspace, session_id: 'durable-thread', thread_id: 'conflicting-thread', agent_id: 'agent-2', agent_type: 'alchemist' });
    assert.match(output, /ARC_BINDING_MISMATCH/);
    assert.equal(bindings.findLatest({ adapter: 'codex', sessionId: 'conflicting-thread', authority: 'alchemist' }), null);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Codex caller/session aliases cannot mint root or subagent authority', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-codex-identity-'));
  const workspace = join(root, 'workspace'); const stateRoot = join(root, 'state'); const keyDir = join(root, 'keys');
  try {
    mkdirSync(workspace, { recursive: true }); mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    const runtime = createHostRuntime({ adapter: { name: 'codex', normalize: normalizeCodexEvent, observeIdentity: observeCodexIdentity }, workspace, keyDir, stateRoot });
    assert.equal(runtime.handle({ hook_event_name: 'SessionStart', cwd: workspace, sessionId: 'caller-session' }).allowed, true);
    assert.equal(new AuthorityBindingStore({ root: join(stateRoot, 'authority-bindings') }).findLatest({ adapter: 'codex', sessionId: 'caller-session', authority: 'legion' }), null);
    const denied = runtime.handle({ hook_event_name: 'SubagentStart', cwd: workspace, sessionId: 'caller-session', agent_id: 'sage-1', agent_type: 'sage' });
    assert.equal(denied.allowed, false); assert.equal(denied.code, 'ARC_AUTHORITY_NOT_ASSERTED');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('lifecycle binding write failure cannot leave an authority ledger record', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-binding-failure-'));
  const workspace = join(root, 'workspace'); const stateRoot = join(root, 'state'); const keyDir = join(root, 'keys');
  try {
    mkdirSync(workspace, { recursive: true }); mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    const runtime = createHostRuntime({ adapter: { name: 'codex', normalize: normalizeCodexEvent, observeIdentity: observeCodexIdentity }, workspace, keyDir, stateRoot });
    runtime.stores.authorityBinding.observeLegionSession = () => { throw Object.assign(new Error('injected binding write failure'), { code: 'ARC_STORE_CORRUPT' }); };
    const result = runtime.handle({ hook_event_name: 'SessionStart', cwd: workspace, session_id: 'binding-failure' });
    assert.equal(result.code, 'ARC_STORE_CORRUPT');
    assert.equal(new AuthorityBindingStore({ root: join(stateRoot, 'authority-bindings') }).findLatest({ adapter: 'codex', sessionId: 'binding-failure', authority: 'legion' }), null);
    assert.equal(existsSync(join(stateRoot, 'host-events', '0000000000000001.json')), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('ledger append failure rolls back a newly-created lifecycle binding', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-ledger-failure-'));
  const workspace = join(root, 'workspace'); const stateRoot = join(root, 'state'); const keyDir = join(root, 'keys');
  const append = HostEventLedger.prototype.append;
  try {
    mkdirSync(workspace, { recursive: true }); mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    HostEventLedger.prototype.append = () => { throw Object.assign(new Error('injected ledger failure'), { code: 'ARC_STORE_CORRUPT' }); };
    const runtime = createHostRuntime({ adapter: { name: 'codex', normalize: normalizeCodexEvent, observeIdentity: observeCodexIdentity }, workspace, keyDir, stateRoot });
    const result = runtime.handle({ hook_event_name: 'SessionStart', cwd: workspace, session_id: 'ledger-failure' });
    assert.equal(result.code, 'ARC_STORE_CORRUPT');
    assert.equal(new AuthorityBindingStore({ root: join(stateRoot, 'authority-bindings') }).findLatest({ adapter: 'codex', sessionId: 'ledger-failure', authority: 'legion' }), null);
    assert.equal(existsSync(join(stateRoot, 'host-events', '0000000000000001.json')), false);
  } finally { HostEventLedger.prototype.append = append; rmSync(root, { recursive: true, force: true }); }
});

test('B6 unavailable Arcane bypasses ambient tools without throwing', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-runtime-'));
  try {
    const runtime = createHostRuntime({ adapter: { name: 'codex', normalize: normalizeCodexEvent }, workspace, keyDir: join(workspace, 'absent-keys') });
    const result = runtime.handle({ hook_event_name: 'PreToolUse', cwd: workspace, session_id: 'session', tool_name: 'Write', tool_input: { file_path: 'a.mjs' } });
    assert.equal(runtime.stateRoot, join(workspace, '.audit', 'arcane'));
    assert.equal(result.kind, 'arcane-host-runtime-result');
    assert.equal(result.allowed, true);
    assert.equal(result.code, 'ARC_AUTH_KEY_UNAVAILABLE');
    assert.equal(result.enforcementHealth, 'degraded');
    assert.equal(result.stdout, null);
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test('B6 unavailable Arcane still refuses a directly identified locked-domain effect', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'arcane-runtime-locked-'));
  try {
    const runtime = createHostRuntime({ adapter: claudeCodeHostAdapter, workspace, keyDir: join(workspace, 'absent-keys') });
    const result = runtime.handle({ hook_event_name: 'PreToolUse', cwd: workspace, session_id: 'session', tool_name: 'Write', tool_input: { file_path: 'tools/rhook/src/main.rs' }, tool_use_id: 'locked-without-arcane' });
    assert.equal(result.allowed, false);
    assert.equal(result.code, 'ARC_AUTH_KEY_UNAVAILABLE');
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test('B6 corrupt lifecycle storage cannot block an ambient tool', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-runtime-lifecycle-'));
  const workspace = join(root, 'workspace'); const stateRoot = join(root, 'state'); const keyDir = join(root, 'keys');
  try {
    mkdirSync(workspace, { recursive: true }); mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    const runtime = createHostRuntime({ adapter: { name: 'codex', normalize: normalizeCodexEvent }, workspace, keyDir, stateRoot });
    assert.equal(runtime.handle({ hook_event_name: 'SessionStart', cwd: workspace, session_id: 'ambient-session' }).allowed, true);
    writeFileSync(join(stateRoot, 'receipts', 'receipts.jsonl'), '{\n');
    const result = runtime.handle({ hook_event_name: 'PreToolUse', cwd: workspace, session_id: 'ambient-session', tool_name: 'Bash', tool_input: { command: 'pwd' }, tool_use_id: 'ambient-after-corruption' });
    assert.equal(result.allowed, true);
    assert.equal(result.code, 'ARC_STORE_CORRUPT');
    assert.equal(result.enforcementHealth, 'degraded');
    assert.equal(result.stdout, null);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('fresh authenticated SessionStart binds only the Legion session root', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-host-event-ledger-'));
  const workspace = join(root, 'workspace'); const stateRoot = join(root, 'state'); const keyDir = join(root, 'keys');
  try {
    mkdirSync(workspace, { recursive: true }); mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    const runtime = createHostRuntime({ adapter: { name: 'codex', normalize: normalizeCodexEvent, observeIdentity: observeCodexIdentity }, workspace, keyDir, stateRoot });
    const start = { hook_event_name: 'SessionStart', cwd: workspace, session_id: 'fresh-session', agent_id: 'agent', agent_type: 'alchemist' };
    const result = runtime.handle(start);
    assert.equal(runtime.handle(start).code, 'ARC_REPLAY_NONCE_SEEN');
    const ledger = JSON.parse(readFileSync(join(stateRoot, 'host-events', '0000000000000001.json'), 'utf8'));
    assert.equal(result.allowed, true, result.code);
    assert.equal(ledger.observedAuthority, 'legion');
    assert.equal(Object.hasOwn(ledger, 'authority'), false);
    const bindings = new AuthorityBindingStore({ root: join(stateRoot, 'authority-bindings') });
    assert.equal(bindings.findLatest({ adapter: 'codex', sessionId: 'fresh-session', authority: 'legion' })?.agentType, 'legion');
    assert.equal(bindings.findLatest({ adapter: 'codex', sessionId: 'fresh-session', authority: 'alchemist' }), null);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('host ingress routes, stores, replays, & consumes an ambient lifecycle without injected architecture state', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-host-architecture-'));
  const workspace = join(root, 'workspace'); const stateRoot = join(root, 'state'); const keyDir = join(root, 'keys'); const sessionId = 'architecture-session';
  try {
    mkdirSync(workspace, { recursive: true }); mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    const runtime = createHostRuntime({ adapter: { name: 'codex', normalize: normalizeCodexEvent, mapPreEffect: mapCodexPreEffect }, workspace, keyDir, stateRoot });
    const base = { cwd: workspace, session_id: sessionId };
    assert.equal(runtime.handle({ ...base, hook_event_name: 'SessionStart' }).allowed, true);
    assert.equal(runtime.handle({ ...base, hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: 'src/app.mjs' }, tool_use_id: 'architecture-tool' }).allowed, true);
    assert.equal(runtime.handle({ ...base, hook_event_name: 'Stop' }).allowed, true);
    const store = new ArchitectureEventStore({ receiptStore: runtime.stores.receiptStore, keyRing: runtime.stores.keyRing, keyId: runtime.stores.keyRing.activeKeyId() });
    const initial = createHostArchitectureState({ workspace, sessionId });
    const replay = store.replay({ objective_lineage_id: initial.task.objective_lineage_id, initial_state: initial });
    assert.equal(replay.state.context.route.depth, 'D0');
    assert.equal(replay.state.task.architecture_status, 'TAILORED');
    assert.equal(replay.state.execution.episode_state, 'SUCCEEDED', JSON.stringify(store.events({ objective_lineage_id: initial.task.objective_lineage_id }).map((event) => event.event_type)));
    assert.equal(replay.event_count, 5);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('B7 native Codex subprocess reserves once, consumes one durable capability & emits exact stdout', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-runtime-e2e-'));
  const workspace = join(root, 'workspace'); const stateRoot = join(root, 'state'); const keyDir = join(root, 'keys');
  const sessionId = 'session'; const runId = 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV';
  const contract = b5Contract();
  try {
    mkdirSync(workspace, { recursive: true }); mkdirSync(join(workspace, 'docs'), { recursive: true }); mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    writeFileSync(join(workspace, 'docs', 'GOTCHAS.md'), '### Archive safely\n**Keys:** task archive\n**Fix:** prove reachability.\n');
    writeFileSync(join(workspace, 'README.md'), 'fixture\n');
    for (const args of [['init', '-q'], ['config', 'user.email', 'test@example.com'], ['config', 'user.name', 'test'], ['add', 'README.md'], ['commit', '-qm', 'init']]) execFileSync('git', args, { cwd: workspace });
    contract.sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: workspace, encoding: 'utf8' }).trim();
    contract.scope.own = ['src/**']; contract.artifacts.exact[0].path = 'src/a.mjs'; contract.authorizedEffectClasses = ['FILE_WRITE'];
    const sealed = seedStore(stateRoot, contract).record;
    new SessionBindingStore({ root: join(stateRoot, 'session-bindings') }).putBinding(sessionId, { runId, taskId: 'T-1', contractId: contract.contractId, contractVersion: contract.version, contractDigest: sealed.contractDigest });
    const env = { ...process.env, ARCANE_WORKSPACE: workspace, ARCANE_STATE_ROOT: stateRoot, ARCANE_KEY_DIR: keyDir };
    const run = (payload) => execFileSync(process.execPath, [CODEX_ADAPTER], { cwd: process.cwd(), env, input: JSON.stringify(payload), encoding: 'utf8' });
    const base = { session_id: sessionId, agent_id: 'agent', agent_type: 'alchemist', cwd: workspace };
    // Allowed SessionStart/SubagentStart now carry the absorbed policy
    // injection (brief + minimize; ccx only under the local gateway), since
    // renderHostRuntimeOutput returns null on allowed and that gap is exactly
    // why the standalone Python injectors existed (D-6/D-3 in EC-501).
    const sessionStartOut = run({ ...base, hook_event_name: 'SessionStart' });
    assert.match(sessionStartOut, /"additionalContext"/);
    assert.match(sessionStartOut, /Brief is default/);
    assert.match(sessionStartOut, /MINIMIZE:ON/);
    const subagentStartOut = run({ ...base, hook_event_name: 'SubagentStart' });
    assert.match(subagentStartOut, /"additionalContext"/);
    assert.match(subagentStartOut, /Brief is default/);
    const promptOut = run({ ...base, hook_event_name: 'UserPromptSubmit', prompt: 'task archive' });
    assert.match(promptOut, /Archive safely/);
    assert.doesNotMatch(promptOut, /Brief is default|MINIMIZE:ON/);
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

test('EC-503 v2: sealed apply_patch pre-authorizes all effects; unchanged post emits receipts & changed patch fails correlation', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-patch-runtime-'));
  const workspace = join(root, 'workspace'); const stateRoot = join(root, 'state'); const keyDir = join(root, 'keys'); const sessionId = 'patch-session';
  try {
    mkdirSync(workspace, { recursive: true }); mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64)); writeFileSync(join(workspace, 'README.md'), 'fixture\n');
    for (const args of [['init', '-q'], ['config', 'user.email', 'test@example.com'], ['config', 'user.name', 'test'], ['add', 'README.md'], ['commit', '-qm', 'init']]) execFileSync('git', args, { cwd: workspace });
    const contract = b5Contract(); contract.sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: workspace, encoding: 'utf8' }).trim();
    contract.scope.own = ['src/**']; contract.artifacts.exact = [{ id: 'a', path: 'src/a.mjs', latitude: 'EXACT', content: 'x' }, { id: 'b', path: 'src/b.mjs', latitude: 'EXACT', content: 'x' }]; contract.authorizedEffectClasses = ['FILE_WRITE'];
    const sealed = seedStore(stateRoot, contract).record;
    new SessionBindingStore({ root: join(stateRoot, 'session-bindings') }).putBinding(sessionId, { runId: 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV', taskId: 'T-1', contractId: contract.contractId, contractVersion: contract.version, contractDigest: sealed.contractDigest });
    const runtime = createHostRuntime({ adapter: { name: 'codex', normalize: normalizeCodexEvent, observeIdentity: observeCodexIdentity, mapPreEffect: mapCodexPreEffect }, workspace, keyDir, stateRoot });
    const command = '*** Begin Patch\n*** Update File: src/a.mjs\n@@\n-a\n+b\n*** Add File: src/b.mjs\n+b\n*** End Patch';
    const base = { session_id: sessionId, thread_id: sessionId, agent_id: 'agent', agent_type: 'alchemist', cwd: workspace, tool_name: 'apply_patch', tool_use_id: 'patch-1', tool_input: { command } };
    assert.equal(runtime.handle({ ...base, hook_event_name: 'SessionStart' }).allowed, true);
    assert.equal(runtime.handle({ ...base, hook_event_name: 'SubagentStart' }).allowed, true);
    const pre = runtime.handle({ ...base, hook_event_name: 'PreToolUse' }); assert.equal(pre.allowed, true, pre.code);
    const post = runtime.handle({ ...base, hook_event_name: 'PostToolUse', tool_response: { ok: true } }); assert.equal(post.allowed, true, post.code);
    const receipts = runtime.stores.receiptStore.list({ runId: 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV' });
    assert.equal(receipts.length, 2);
    const effects = mapCodexPreEffect(base, { workspace }).effects;
    for (const receipt of receipts) {
      const effect = effects.find(({ target }) => target === receipt.observed.target);
      const finalized = runtime.stores.preEffectCorrelation.getFinalized(effect?.toolUseId);
      assert.ok(receipt.authorized.capabilityId);
      assert.equal(receipt.requestId, finalized?.requestId);
      assert.equal(receipt.authorized.capabilityId, finalized?.capabilityId);
    }
    const changed = command.replace('src/b.mjs', 'src/c.mjs');
    const rejected = runtime.handle({ ...base, hook_event_name: 'PostToolUse', tool_input: { command: changed }, tool_response: { ok: true } });
    assert.equal(rejected.allowed, false); assert.equal(rejected.code, 'ARC_INGEST_CORRELATION_MISSING');
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

test('EC-503 host Stop authority uses latest admitted user turn only', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-stop-intent-'));
  const transcript = join(root, 'transcript.jsonl');
  try {
    writeFileSync(transcript, [
      JSON.stringify({ type: 'user', message: { content: [{ type: 'text', text: 'Fix it now.' }] } }),
      JSON.stringify({ type: 'assistant', message: { content: [{ type: 'text', text: 'Implementation is ready. Say go and I execute.' }] } }),
      JSON.stringify({ type: 'user', message: { content: [{ type: 'text', text: 'Plan only; make no changes.' }] } }),
    ].join('\n'));
    assert.equal(evaluateLatestStopShape({ transcript_path: transcript }).block, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('EC-603 T-4: standalone Stop shape keeps no unauthenticated local retry circuit', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-stop-state-'));
  const transcript = join(root, 'transcript.jsonl');
  const write = (entries) => writeFileSync(transcript, entries.map((entry) => JSON.stringify(entry)).join('\n'));
  const text = (type, value) => ({ type, message: { content: [{ type: 'text', text: value }] } });
  try {
    write([
      text('user', 'Fix the hook.'),
      { type: 'assistant', message: { content: [{ type: 'tool_use', id: 'write-gotcha', name: 'Write', input: { file_path: 'docs/GOTCHAS.md' } }] } },
      { type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 'write-gotcha', content: 'ok' }] } },
      text('assistant', 'Worth noting for future reference: this is now recorded.'),
    ]);
    assert.equal(evaluateLatestStopShape({ transcript_path: transcript, cwd: root, session_id: 'recorded' }).block, false);

    write([text('user', 'Fix the hook.'), text('assistant', 'Implementation is ready. Say go and I execute.')]);
    const payload = { transcript_path: transcript, cwd: root, session_id: 'pushes', stop_hook_active: true };
    assert.equal(evaluateLatestStopShape(payload).block, true);
    assert.equal(evaluateLatestStopShape(payload).block, true);
    assert.equal(evaluateLatestStopShape(payload).block, true);
    assert.equal(existsSync(join(root, '.audit', 'legion', 'stop-shape', 'pushes.json')), false);
    assert.doesNotMatch(readFileSync(new URL('../src/lib/cognitive/arcane/stop-shape.mjs', import.meta.url), 'utf8'), /intent\.intent === 'proceed'/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Wave 1: corrupt authority state is diagnostic-only for question, plan, & pause Stops, never a completion claim', () => {
  const root = mkdtempSync(join(tmpdir(), 'arcane-read-only-stop-'));
  const workspace = join(root, 'workspace'); const stateRoot = join(root, 'state'); const keyDir = join(root, 'keys'); const transcript = join(root, 'transcript.jsonl');
  const entry = (type, text) => JSON.stringify({ type, message: { content: [{ type: 'text', text }] } });
  try {
    mkdirSync(workspace, { recursive: true }); mkdirSync(keyDir, { recursive: true }); writeFileSync(join(keyDir, 'k1.key'), 'a'.repeat(64));
    const runtime = createHostRuntime({ adapter: { name: 'codex', normalize: normalizeCodexEvent, observeIdentity: observeCodexIdentity }, workspace, keyDir, stateRoot });
    const payload = { hook_event_name: 'Stop', cwd: workspace, session_id: 'read-only-session', agent_id: 'agent', agent_type: 'alchemist', transcript_path: transcript };
    assert.equal(runtime.handle({ ...payload, hook_event_name: 'SessionStart', agent_id: null, agent_type: null }).allowed, true);
    const corrupt = () => {
      const path = runtime.stores.authorityBinding.path('codex', 'read-only-session', 'agent');
      mkdirSync(join(stateRoot, 'authority-bindings'), { recursive: true }); writeFileSync(path, '{'); return path;
    };
    for (const userText of ['What is current status?', 'Plan only; make no changes.', 'Pause this work.']) {
      writeFileSync(transcript, [entry('user', userText), entry('assistant', 'Here is requested answer.')].join('\n'));
      const path = corrupt(); const result = runtime.handle(payload);
      assert.equal(result.allowed, true, userText); assert.equal(result.code, 'ARC_STORE_CORRUPT'); assert.equal(result.enforcementHealth, 'degraded'); assert.equal(result.stdout, null);
      assert.equal(existsSync(path), false, 'corrupt routing record is quarantined, not reused');
    }
    writeFileSync(transcript, [entry('user', 'Fix it now.'), entry('assistant', 'Completed.')].join('\n'));
    corrupt(); const completion = runtime.handle(payload);
    assert.equal(completion.allowed, true); assert.equal(completion.code, 'ARC_STORE_CORRUPT'); assert.equal(completion.enforcementHealth, 'degraded');
    const mutation = runtime.handle({ ...payload, hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: 'src/a.mjs' }, tool_use_id: 'wave-1-mutation' });
    assert.equal(mutation.allowed, true); assert.equal(mutation.code, null); assert.equal(mutation.enforcementHealth, 'strong');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Wave 1: two reopenings or two blocked closes opens Stop circuit', () => {
  const finalText = 'Implementation is ready. Say go and I execute.';
  assert.equal(evaluateLatestStopShape({}).block, false, 'missing transcript remains fail-open');
  assert.equal(evaluateStopShape(finalText, { intent: 'EXECUTE', authorized: true, pushes: 2 }).reason, 'stop-circuit-open');
  assert.equal(evaluateStopShape(finalText, { intent: 'EXECUTE', authorized: true, reopenings: 2 }).reason, 'stop-circuit-open');
});
