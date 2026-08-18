// EC-B — Codex host adapter (host/codex-adapter.mjs).
//
// Mirrors tests/claude-code-adapter.test.mjs's structure. Covers: all six
// documented Codex hook events normalizing to a schema-valid host event with
// adapter.name === 'codex'; the top-level-`command` vs nested-`tool_input.command`
// dual shape (forge/hooks/generic/hook.js evidence); the env-var session
// fallback; and per-tool effect mapping including the deliberate nulls
// (Bash/shell family, MultiEdit, and apply_patch — see codex-adapter.mjs's
// EFFECT_TOOL_MAP comment for why each is null).

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

import {
  buildRawCodexEvent,
  normalizeCodexEvent,
  handleCodexHookEvent,
  ADAPTER_NAME,
  observeCodexIdentity,
  mapCodexPreEffect,
  parseCodexApplyPatch,
  resolveCodexSessionId,
} from '../host/codex-adapter.mjs';
import { validateHostEvent } from '../lib/host-event.mjs';
import { generateTestKeyRing } from '../lib/keys.mjs';
import { ReplayGuard } from '../lib/replay.mjs';

// Host test runs may carry this process's real durable thread. Baseline
// fixtures model payload-only events, so isolate them from that ambient state.
const inheritedCodexThreadId = process.env.CODEX_THREAD_ID;
delete process.env.CODEX_THREAD_ID;
after(() => {
  if (inheritedCodexThreadId === undefined) delete process.env.CODEX_THREAD_ID;
  else process.env.CODEX_THREAD_ID = inheritedCodexThreadId;
});

test('B7 Codex identity & pre-effect tables are host-derived and closed', () => {
  const payload = { hook_event_name: 'PreToolUse', sessionId: 'session', agentId: 'agent', agentType: 'alchemist', tool_name: 'Edit', tool_input: { file_path: 'src/a.mjs' }, tool_use_id: 'tool' };
  assert.deepEqual(observeCodexIdentity(payload, { hostEvent: { eventId: 'hev_0123456789ABCDEFGHJKMNPQ' } }), { sessionId: 'session', agentId: 'agent', agentType: 'alchemist', eventId: 'hev_0123456789ABCDEFGHJKMNPQ' });
  assert.deepEqual(mapCodexPreEffect(payload), { effectClass: 'FILE_WRITE', target: 'src/a.mjs', operation: 'Edit', toolUseId: 'tool' });
  assert.deepEqual(observeCodexIdentity({ ...payload, authority: 'sage' }), { modelClaimed: true });
  assert.equal(mapCodexPreEffect({ ...payload, tool_name: 'shell' }), null);
});

test('EC-503 v2: apply_patch expands ordered add, delete & move effects with stable derived ids', () => {
  const command = ['*** Begin Patch', '*** Add File: src/a.mjs', '+a', '*** Update File: src/b.mjs', '*** Move to: src/c.mjs', '@@', '-b', '+c', '*** Delete File: src/d.mjs', '*** End Patch'].join('\n');
  const mapped = mapCodexPreEffect({ tool_name: 'apply_patch', tool_input: { command }, tool_use_id: 'host-tool' }, { workspace: '/work' });
  assert.deepEqual(mapped.effects.map(({ effectClass, target }) => ({ effectClass, target })), [
    { effectClass: 'FILE_WRITE', target: 'src/a.mjs' }, { effectClass: 'FILE_DELETE', target: 'src/b.mjs' },
    { effectClass: 'FILE_WRITE', target: 'src/c.mjs' }, { effectClass: 'FILE_DELETE', target: 'src/d.mjs' },
  ]);
  assert.equal(mapped.effects.every((effect) => /^[a-f0-9]{64}$/.test(effect.toolUseId)), true);
  assert.equal(parseCodexApplyPatch(command, { workspace: '/work' }).length, 4);
});

test('EC-503 v2: apply_patch rejects traversal, duplicate targets, malformed input & oversized effect sets', () => {
  assert.equal(parseCodexApplyPatch('*** Begin Patch\n*** Add File: ../x\n+x\n*** End Patch'), null);
  assert.equal(parseCodexApplyPatch('*** Begin Patch\n*** Add File: x\n+x\n*** Add File: x\n+x\n*** End Patch'), null);
  assert.equal(parseCodexApplyPatch('not a patch'), null);
  const sections = Array.from({ length: 257 }, (_, index) => `*** Add File: src/${index}.mjs\n+x`).join('\n');
  assert.equal(parseCodexApplyPatch(`*** Begin Patch\n${sections}\n*** End Patch`), null);
});
import { ReceiptStore } from '../lib/receipt-store.mjs';
import { loadPolicy, PolicyEngine, DEFAULT_POLICY_PATH } from '../lib/policy.mjs';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

function tempRoot() {
  const root = mkdtempSync(path.join(tmpdir(), 'arcane-codex-adapter-'));
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

function testPolicy() {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const bundle = { ...loaded.bundle, lockedDomains: [] };
  return new PolicyEngine({ ...loaded, bundle });
}

// ─────────────────────────────────────────────── six event types normalize

const SIX_EVENTS = [
  { hook_event_name: 'SessionStart', session_id: 's1', cwd: '/tmp/ws' },
  { hook_event_name: 'UserPromptSubmit', session_id: 's1', cwd: '/tmp/ws' },
  {
    hook_event_name: 'PreToolUse', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'Write', tool_input: { file_path: 'a.txt' }, tool_use_id: 'tu1',
  },
  {
    hook_event_name: 'PostToolUse', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'Write', tool_input: { file_path: 'a.txt' }, tool_response: { ok: true }, tool_use_id: 'tu1',
  },
  {
    hook_event_name: 'PostToolUseFailure', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'shell', command: 'ls', tool_response: { error: 'nope' }, tool_use_id: 'tu2',
  },
  { hook_event_name: 'Stop', session_id: 's1', cwd: '/tmp/ws' },
];

for (const payload of SIX_EVENTS) {
  test(`EC-B: Codex ${payload.hook_event_name} normalizes to a HOST_EVENT_SCHEMA-valid event with adapter.name === 'codex'`, () => {
    const normalized = normalizeCodexEvent(payload);
    const { valid, issues } = validateHostEvent(normalized);
    assert.equal(valid, true, JSON.stringify(issues));
    assert.equal(normalized.adapter.name, 'codex');
    assert.equal(ADAPTER_NAME, 'codex');
    assert.equal(normalized.sessionId, 's1');
    assert.equal(normalized.workspace, '/tmp/ws');
  });
}

test('EC-B: an unsupported hook_event_name is rejected, never guessed', () => {
  assert.throws(() => buildRawCodexEvent({ hook_event_name: 'SomeFutureHook' }), /ARC_HOST_EVENT_INVALID|unsupported/);
});

// ──────────────────────────────────────────── command: top-level vs nested

test('EC-B: shell tool with TOP-LEVEL event.command is read (Codex shape, per forge/hooks/generic/hook.js)', () => {
  const raw = buildRawCodexEvent({
    hook_event_name: 'PreToolUse', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'shell', command: 'ls -la', tool_use_id: 'tu1',
  });
  // command itself does not feed `effect` (shell stays null — see EFFECT_TOOL_MAP
  // comment); this test pins that buildRawCodexEvent does not choke on or
  // drop the top-level shape, mirroring generic/hook.js's own read pattern.
  assert.equal(raw.operation.toolId, 'shell');
});

test('EC-B: shell_command tool with NESTED tool_input.command is also read (Claude-Code-compatible shape)', () => {
  const raw = buildRawCodexEvent({
    hook_event_name: 'PreToolUse', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'shell_command', tool_input: { command: 'ls -la' }, tool_use_id: 'tu1',
  });
  assert.equal(raw.operation.toolId, 'shell_command');
});

// ─────────────────────────────────────────────────────── session id fallback

test('EC-B: sessionId falls back to CODEX_SESSION_ID env var when session_id/sessionId are absent', () => {
  const prior = process.env.CODEX_SESSION_ID;
  const priorThread = process.env.CODEX_THREAD_ID;
  delete process.env.CODEX_THREAD_ID;
  process.env.CODEX_SESSION_ID = 'env-session-123';
  try {
    const raw = buildRawCodexEvent({ hook_event_name: 'SessionStart', cwd: '/tmp/ws' });
    assert.equal(raw.sessionId, 'env-session-123');
  } finally {
    if (prior === undefined) delete process.env.CODEX_SESSION_ID;
    else process.env.CODEX_SESSION_ID = prior;
    if (priorThread === undefined) delete process.env.CODEX_THREAD_ID;
    else process.env.CODEX_THREAD_ID = priorThread;
  }
});

test('EC-B: Codex thread identity completes SubagentStart authority binding', () => {
  const prior = process.env.CODEX_THREAD_ID;
  process.env.CODEX_THREAD_ID = 'thread-019fe6fe';
  try {
    const payload = { hook_event_name: 'SubagentStart', cwd: '/tmp/ws', agent_id: 'agent-1', agent_type: 'sage' };
    const hostEvent = normalizeCodexEvent(payload);
    assert.equal(hostEvent.sessionId, 'thread-019fe6fe');
    assert.deepEqual(observeCodexIdentity(payload, { hostEvent }), {
      sessionId: 'thread-019fe6fe',
      agentId: 'agent-1',
      agentType: 'sage',
      eventId: hostEvent.eventId,
    });
  } finally {
    if (prior === undefined) delete process.env.CODEX_THREAD_ID;
    else process.env.CODEX_THREAD_ID = prior;
  }
});

test('EC-503 v6: fresh Codex process gives durable thread identity precedence over transient session id', () => {
  const adapter = new URL('../host/codex-adapter.mjs', import.meta.url).href;
  const script = `import { buildRawCodexEvent } from ${JSON.stringify(adapter)}; console.log(buildRawCodexEvent({ hook_event_name: 'SessionStart', session_id: 'transient-session', thread_id: 'durable-thread' }).sessionId);`;
  const output = execFileSync(process.execPath, ['--input-type=module', '--eval', script], {
    encoding: 'utf8', env: { ...process.env, CODEX_THREAD_ID: 'durable-thread' },
  });
  assert.equal(output.trim(), 'durable-thread');
});

test('EC-503 v6: matching payload thread is accepted & conflicting identity fails closed', () => {
  const prior = process.env.CODEX_THREAD_ID;
  process.env.CODEX_THREAD_ID = 'durable-thread';
  try {
    assert.equal(resolveCodexSessionId({ session_id: 'transient-session', thread_id: 'durable-thread' }), 'durable-thread');
    assert.throws(
      () => resolveCodexSessionId({ session_id: 'transient-session', thread_id: 'conflicting-thread' }),
      /ARC_BINDING_MISMATCH|conflicts/,
    );
  } finally {
    if (prior === undefined) delete process.env.CODEX_THREAD_ID;
    else process.env.CODEX_THREAD_ID = prior;
  }
});

test('EC-B: sessionId falls back to CLAUDE_SESSION_ID env var when session_id/sessionId/CODEX_SESSION_ID are absent', () => {
  const priorCodex = process.env.CODEX_SESSION_ID;
  const priorClaude = process.env.CLAUDE_SESSION_ID;
  const priorThread = process.env.CODEX_THREAD_ID;
  delete process.env.CODEX_THREAD_ID;
  delete process.env.CODEX_SESSION_ID;
  process.env.CLAUDE_SESSION_ID = 'env-claude-session-456';
  try {
    const raw = buildRawCodexEvent({ hook_event_name: 'SessionStart', cwd: '/tmp/ws' });
    assert.equal(raw.sessionId, 'env-claude-session-456');
  } finally {
    if (priorCodex === undefined) delete process.env.CODEX_SESSION_ID; else process.env.CODEX_SESSION_ID = priorCodex;
    if (priorClaude === undefined) delete process.env.CLAUDE_SESSION_ID; else process.env.CLAUDE_SESSION_ID = priorClaude;
    if (priorThread === undefined) delete process.env.CODEX_THREAD_ID; else process.env.CODEX_THREAD_ID = priorThread;
  }
});

test('EC-B: sessionId prefers payload session_id over sessionId camelCase, over env fallbacks', () => {
  const raw = buildRawCodexEvent({ hook_event_name: 'SessionStart', cwd: '/tmp/ws', session_id: 's-snake', sessionId: 's-camel' });
  assert.equal(raw.sessionId, 's-snake');
});

test('EC-B: sessionId falls back to camelCase sessionId when session_id is absent', () => {
  const raw = buildRawCodexEvent({ hook_event_name: 'SessionStart', cwd: '/tmp/ws', sessionId: 's-camel' });
  assert.equal(raw.sessionId, 's-camel');
});

// ───────────────────────────────────────────────────── effect mapping

test('EC-B: PostToolUse Write maps to effect {FILE_WRITE, tool_input.file_path}', () => {
  const raw = buildRawCodexEvent({
    hook_event_name: 'PostToolUse', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'Write', tool_input: { file_path: 'a.txt' }, tool_response: { ok: true }, tool_use_id: 'tu1',
  });
  assert.deepEqual(raw.effect, { effectClass: 'FILE_WRITE', target: 'a.txt', operation: 'Write' });
});

test('EC-B: PostToolUse Edit maps to effect {FILE_WRITE, tool_input.file_path}', () => {
  const raw = buildRawCodexEvent({
    hook_event_name: 'PostToolUse', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'Edit', tool_input: { file_path: 'b.txt' }, tool_response: { ok: true }, tool_use_id: 'tu1',
  });
  assert.deepEqual(raw.effect, { effectClass: 'FILE_WRITE', target: 'b.txt', operation: 'Edit' });
});

test('EC-B regression (deliberate non-fix): PostToolUse MultiEdit stays effect:null — same reasoning as Claude Code (single-target schema, multi-target tool)', () => {
  const raw = buildRawCodexEvent({
    hook_event_name: 'PostToolUse', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'MultiEdit', tool_input: { file_path: 'd.txt', edits: [{}, {}] }, tool_response: { ok: true }, tool_use_id: 'tu1',
  });
  assert.equal(raw.effect, null);
});

for (const shellTool of ['shell', 'shell_command', 'Bash', 'PowerShell']) {
  test(`EC-B regression (deliberate non-fix): PostToolUse ${shellTool} stays effect:null — a command string is not a path`, () => {
    const raw = buildRawCodexEvent({
      hook_event_name: 'PostToolUse', session_id: 's1', cwd: '/tmp/ws',
      tool_name: shellTool, command: 'rm -rf /tmp/x', tool_response: { ok: true }, tool_use_id: 'tu1',
    });
    assert.equal(raw.effect, null);
  });
}

// apply_patch: this tree carries NO evidence of its payload shape (only the
// matcher glob in forge/hooks/codex/hooks.json names it; no file anywhere
// reads an apply_patch-specific field). Per the contract's "do not guess"
// instruction, this pins the current honest behaviour — effect:null, exactly
// like any other tool absent from EFFECT_TOOL_MAP — and exists so a future
// change that DOES establish apply_patch's real shape is forced to touch
// this test deliberately rather than silently drift.
test('EC-B (evidence gap, pinned honest behaviour): PostToolUse apply_patch stays effect:null — payload shape has no evidence anywhere in this tree', () => {
  const raw = buildRawCodexEvent({
    hook_event_name: 'PostToolUse', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'apply_patch', tool_input: { patch: '*** Begin Patch\n*** End Patch' }, tool_response: { ok: true }, tool_use_id: 'tu1',
  });
  assert.equal(raw.effect, null);
});

test('EC-B regression (deliberate non-fix): PostToolUse unrecognized tool stays effect:null', () => {
  const raw = buildRawCodexEvent({
    hook_event_name: 'PostToolUse', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'SomeFutureTool', tool_input: { anything: true }, tool_response: { ok: true }, tool_use_id: 'tu1',
  });
  assert.equal(raw.effect, null);
});

test('EC-B: PostToolUse Write with a MISSING file_path degrades to effect:null, never "" or "unknown"', () => {
  const raw = buildRawCodexEvent({
    hook_event_name: 'PostToolUse', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'Write', tool_input: {}, tool_response: { ok: true }, tool_use_id: 'tu1',
  });
  assert.equal(raw.effect, null);
});

test('EC-B invariant I-1: PreToolUse Write NEVER gets an effect — a pre-execution claim is never an observation', () => {
  const raw = buildRawCodexEvent({
    hook_event_name: 'PreToolUse', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'Write', tool_input: { file_path: 'a.txt' }, tool_use_id: 'tu1',
  });
  assert.equal(raw.effect, undefined);
  const normalized = normalizeCodexEvent({
    hook_event_name: 'PreToolUse', session_id: 's1', cwd: '/tmp/ws',
    tool_name: 'Write', tool_input: { file_path: 'a.txt' }, tool_use_id: 'tu1',
  });
  assert.equal(normalized.effect, null);
});

// ────────────────────────────────────────── handleCodexHookEvent pipeline

test('EC-B: handleCodexHookEvent with a real key ring signs and ingests a lifecycle event', () => {
  const { root, cleanup } = tempRoot();
  try {
    const ring = generateTestKeyRing(['k1']);
    const receiptStore = new ReceiptStore({ root });
    const replayGuard = new ReplayGuard({});
    const policy = testPolicy();

    const outcome = handleCodexHookEvent(SIX_EVENTS[0], { keyRing: ring, receiptStore, replayGuard, policy });

    assert.equal(outcome.enforcementHealth, 'strong');
    assert.equal(outcome.accepted, true);
    assert.equal(outcome.hostEvent.adapter.name, 'codex');
    assert.equal(outcome.receipt, null);
  } finally {
    cleanup();
  }
});

test('EC-B: handleCodexHookEvent with an unavailable key ring sets enforcementHealth "degraded", not a throw or a silent pass', () => {
  const { root, cleanup } = tempRoot();
  try {
    const receiptStore = new ReceiptStore({ root });
    const replayGuard = new ReplayGuard({});
    const policy = testPolicy();

    const outcome = handleCodexHookEvent(SIX_EVENTS[3], { keyRing: null, receiptStore, replayGuard, policy });

    assert.equal(outcome.enforcementHealth, 'degraded');
    assert.equal(outcome.accepted, false);
    assert.equal(outcome.decision.code, 'ARC_AUTH_KEY_UNAVAILABLE');
  } finally {
    cleanup();
  }
});
