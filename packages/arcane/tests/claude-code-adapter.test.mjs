// EC-2 — Claude Code host adapter (host/claude-code-adapter.mjs).
//
// Covers: normalization of all six documented Claude Code hook events into a
// schema-valid host event; the mandatory degraded-signing path (never throws,
// never silently signs with a fallback key, marks enforcementHealth honestly);
// and the Stop -> completion-gate wiring (block/allow shape, reason fidelity).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  buildRawHostEvent,
  normalizeClaudeCodeEvent,
  signClaudeCodeEvent,
  handleClaudeCodeHookEvent,
  evaluateClaudeCodeStop,
  claudeCodeStopHookOutput,
  deriveTouchedPaths,
} from '../host/claude-code-adapter.mjs';
import { validateHostEvent } from '../lib/host-event.mjs';
import { generateTestKeyRing } from '../lib/keys.mjs';
import { HostIngestor } from '../lib/ingest.mjs';
import { ReplayGuard } from '../lib/replay.mjs';
import { ReceiptStore } from '../lib/receipt-store.mjs';
import { loadPolicy, PolicyEngine, DEFAULT_POLICY_PATH } from '../lib/policy.mjs';
import { signRecord } from '../lib/receipt-auth.mjs';
import { HOST_EVENT_BOUND_FIELDS } from '../lib/host-event.mjs';

const RUN_ID = 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV';

function tempRoot() {
  const root = mkdtempSync(path.join(tmpdir(), 'arcane-cc-adapter-'));
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

/** A policy engine with an empty lockedDomains override, so the base bundle's
 * real (currently populated) lockedDomains don't leak into these tests via
 * paths this suite never touches. */
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
    tool_name: 'Bash', tool_input: { command: 'ls' }, tool_response: { error: 'nope' }, tool_use_id: 'tu2',
  },
  { hook_event_name: 'Stop', session_id: 's1', cwd: '/tmp/ws' },
];

for (const payload of SIX_EVENTS) {
  test(`EC-2: ${payload.hook_event_name} normalizes to a HOST_EVENT_SCHEMA-valid event`, () => {
    const normalized = normalizeClaudeCodeEvent(payload);
    const { valid, issues } = validateHostEvent(normalized);
    assert.equal(valid, true, JSON.stringify(issues));
    assert.equal(normalized.sessionId, 's1');
    assert.equal(normalized.workspace, '/tmp/ws');
  });
}

test('EC-2: PreToolUse carries toolId/operationId/argumentDigest derived from tool_name/tool_input', () => {
  const raw = buildRawHostEvent(SIX_EVENTS[2]);
  assert.equal(raw.operation.toolId, 'Write');
  assert.equal(raw.operation.operationId, 'Write');
  assert.match(raw.operation.argumentDigest, /^sha256:[0-9a-f]{64}$/);
});

test('EC-2: PostToolUseFailure maps to result.outcome "failure"; PostToolUse maps to "success"', () => {
  const failure = buildRawHostEvent(SIX_EVENTS[4]);
  assert.equal(failure.result.outcome, 'failure');
  const success = buildRawHostEvent(SIX_EVENTS[3]);
  assert.equal(success.result.outcome, 'success');
});

test('EC-2: an unsupported hook_event_name is rejected, never guessed', () => {
  assert.throws(() => buildRawHostEvent({ hook_event_name: 'SomeFutureHook' }), /ARC_HOST_EVENT_INVALID|unsupported/);
});

// ───────────────────────────────────────────────────────── degraded signing

test('EC-2: signing with an available key ring yields enforcementHealth "strong"', () => {
  const ring = generateTestKeyRing(['k1']);
  const event = normalizeClaudeCodeEvent(SIX_EVENTS[0]);
  const signed = signClaudeCodeEvent(event, ring);
  assert.equal(signed.enforcementHealth, 'strong');
  assert.ok(signed.authorityAssertion);
  assert.equal(signed.authorityAssertion.assertedBy, 'host');
});

test('EC-2: signing with no key ring degrades honestly — never throws, never fakes a signature', () => {
  const event = normalizeClaudeCodeEvent(SIX_EVENTS[0]);
  const signed = signClaudeCodeEvent(event, null);
  assert.equal(signed.enforcementHealth, 'degraded');
  assert.equal(signed.authorityAssertion, null);
});

test('EC-2: handleClaudeCodeHookEvent with an unavailable key ring sets enforcementHealth "degraded" on the result, not a throw or a silent pass', () => {
  const { root, cleanup } = tempRoot();
  try {
    const receiptStore = new ReceiptStore({ root });
    const replayGuard = new ReplayGuard({});
    const policy = testPolicy();

    const outcome = handleClaudeCodeHookEvent(SIX_EVENTS[3], { keyRing: null, receiptStore, replayGuard, policy });

    assert.equal(outcome.enforcementHealth, 'degraded');
    assert.equal(outcome.accepted, false);
    assert.equal(outcome.decision.code, 'ARC_AUTH_KEY_UNAVAILABLE');
    // Nothing was appended to the receipt store — a degraded event is
    // observed, never silently ingested as if it were trusted.
    assert.equal(receiptStore.list({ runId: RUN_ID }).length, 0);
  } finally {
    cleanup();
  }
});

test('EC-2: handleClaudeCodeHookEvent with a real key ring signs and ingests a lifecycle event', () => {
  const { root, cleanup } = tempRoot();
  try {
    const ring = generateTestKeyRing(['k1']);
    const receiptStore = new ReceiptStore({ root });
    const replayGuard = new ReplayGuard({});
    const policy = testPolicy();

    const outcome = handleClaudeCodeHookEvent(SIX_EVENTS[0], { keyRing: ring, receiptStore, replayGuard, policy });

    assert.equal(outcome.enforcementHealth, 'strong');
    assert.equal(outcome.accepted, true);
    // session-start carries no effect -> no receipt minted, just accepted classification.
    assert.equal(outcome.receipt, null);
  } finally {
    cleanup();
  }
});

// ──────────────────────────────────────────────────── Stop -> completion gate

/** Ingest a signed FILE_WRITE post-effect event for RUN_ID via HostIngestor,
 * bypassing the adapter's own (deliberately null) effect mapping — this
 * simulates "what Arcane actually recorded for the run" that
 * deriveTouchedPaths/evaluateCompletion must read back, independent of
 * anything a Stop payload itself claims. */
function ingestOneFileWrite({ receiptStore, replayGuard, keyRing, policy, target }) {
  const ingestor = new HostIngestor({ receiptStore, replayGuard, keyRing, policy });
  const hostEvent = {
    schemaVersion: 1,
    kind: 'arcane-host-event',
    eventId: 'hev_01ARZ3NDEKTSV4RRFFQ69G5FAV',
    eventType: 'post-effect',
    time: new Date().toISOString(),
    adapter: { name: 'claude-code', version: '1' },
    client: { name: 'claude-code', version: '1' },
    host: { platform: 'test', version: '1' },
    runId: RUN_ID,
    taskId: 'T-1',
    sessionId: 's1',
    requestId: 'req_01ARZ3NDEKTSV4RRFFQ69G5FAV',
    contractId: 'EC-2',
    workspace: 'ws-main',
    subject: null,
    actor: { issuerId: 'host-process:1', processIdentity: null },
    operation: { toolId: 'Write', operationId: 'Write', argumentDigest: null },
    sourceRevision: '0123abcdef',
    effect: { effectClass: 'FILE_WRITE', target, operation: 'write' },
    result: { outcome: 'success', exitCode: 0, terminal: true, observedDigest: null },
    pathMeta: null, processMeta: null, networkMeta: null,
    priorCorrelation: {
      requestId: 'req_01ARZ3NDEKTSV4RRFFQ69G5FAV', capabilityId: 'cap_1', priorReceiptId: null,
      requestedEffect: { effectClass: 'FILE_WRITE', target, operation: 'write' },
      authorizedEffect: { effectClass: 'FILE_WRITE', target, operation: 'write' },
    },
    checkCorrelation: null,
    hostEnforcement: { capabilities: [], knownBypasses: [] },
    replayNonce: `nonce-${target}`,
    replaySequence: 1,
    idempotencyKey: `idem-${target}`,
  };
  const keyId = keyRing.activeKeyId();
  const receipt = signRecord(hostEvent, { keyRing, keyId, boundFields: HOST_EVENT_BOUND_FIELDS });
  return ingestor.ingest(hostEvent, { authorityAssertion: { assertedBy: 'host', receipt } });
}

test('EC-2: deriveTouchedPaths reads back what Arcane actually recorded for the run, not the Stop payload', () => {
  const { root, cleanup } = tempRoot();
  try {
    const ring = generateTestKeyRing(['k1']);
    const receiptStore = new ReceiptStore({ root });
    const replayGuard = new ReplayGuard({});
    const policy = testPolicy();
    const result = ingestOneFileWrite({ receiptStore, replayGuard, keyRing: ring, policy, target: 'src/exact.ts' });
    assert.equal(result.accepted, true, JSON.stringify(result.decision));

    const paths = deriveTouchedPaths(receiptStore, RUN_ID);
    assert.deepEqual(paths, ['src/exact.ts']);
  } finally {
    cleanup();
  }
});

test('EC-2: Stop is blocked with the gate\'s own reason when completion prerequisites are unmet', () => {
  const { root, cleanup } = tempRoot();
  try {
    const policy = testPolicy();
    const receiptStore = new ReceiptStore({ root }); // no evidence for RUN_ID at all
    const stopEvent = normalizeClaudeCodeEvent({ hook_event_name: 'Stop', session_id: 's1', cwd: '/tmp/ws' });
    stopEvent.runId = RUN_ID; // a real caller sets this from its own session/task binding

    const completionDecision = evaluateClaudeCodeStop(stopEvent, { policy, receiptStore });
    assert.equal(completionDecision.allowed, false);

    const output = claudeCodeStopHookOutput(completionDecision);
    assert.ok(output);
    assert.equal(output.decision, 'block');
    // The reason must carry the gate's actual code/message, not a generic string.
    assert.match(output.reason, new RegExp(completionDecision.code));
    assert.notEqual(output.reason, 'completion claim denied by Arcane completion gate');
  } finally {
    cleanup();
  }
});

test('EC-2: Stop passes through (no block output) when completion prerequisites are met', () => {
  const { root, cleanup } = tempRoot();
  try {
    const ring = generateTestKeyRing(['k1']);
    const policy = testPolicy();
    const receiptStore = new ReceiptStore({ root });
    const replayGuard = new ReplayGuard({});

    // Deterministic evidence receipt for RUN_ID, strongly authenticated —
    // satisfies the default 'signoff' claim level's prerequisites.
    receiptStore.append({
      schemaVersion: 1,
      kind: 'legion-evidence-capability-receipt',
      evidenceId: 'evid_01ARZ3NDEKTSV4RRFFQ69G5FAV',
      runId: RUN_ID,
      taskId: 'T-1',
      contractId: 'EC-2',
      producerAuthority: 'seer',
      capability: 'test-run',
      observation: { exitCode: 0 },
      evidenceClass: 'deterministic',
      authentication: {
        issuerIdentity: ring.activeKeyId(), verificationMethod: 'capability-signature', perMessage: true,
        verifiedAt: new Date().toISOString(),
      },
      replayDefense: { nonce: 'n-1', sequence: 1, freshnessWindowSeconds: 900, freshAt: new Date().toISOString() },
      sourceRevision: '0123abcdef',
      dependsOn: [],
      stale: false,
      observedAt: new Date().toISOString(),
    });

    const stopEvent = normalizeClaudeCodeEvent({ hook_event_name: 'Stop', session_id: 's1', cwd: '/tmp/ws' });
    stopEvent.runId = RUN_ID;

    const completionDecision = evaluateClaudeCodeStop(stopEvent, { policy, receiptStore });
    assert.equal(completionDecision.allowed, true, completionDecision.message);

    const output = claudeCodeStopHookOutput(completionDecision);
    assert.equal(output, null);
  } finally {
    cleanup();
  }
});
