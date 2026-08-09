// EC-5 items 2+4 — ambient session binding wired into the shared
// host-adapter core (host/hook-adapter-core.mjs).
//
// `handleHookEvent` takes an optional `sessionBinding` dep (default `null`,
// so every existing caller that omits it gets EXACTLY today's behaviour —
// covered separately by the byte-unchanged claude-code-adapter.test.mjs and
// codex-adapter.test.mjs). When supplied and the normalized event carries a
// sessionId: a `session-start` event calls `ensureBinding` (mint-or-get,
// race-safe); every other event calls `getBinding` (read-only) — matching
// H-11's "session-start mints, everything else only reads" design.
//
// Tested here at the host-agnostic core level (a minimal fake `normalize`,
// not a specific adapter's payload shape) because this file's own header
// promises ZERO host-specific field names — the binding logic must not care
// which adapter produced the event, only that both normalize `sessionId`
// identically.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { handleHookEvent } from '../host/hook-adapter-core.mjs';
import { normalizeHostEvent } from '../lib/host-event.mjs';
import { SessionBindingStore } from '../lib/session-binding.mjs';
import { generateTestKeyRing } from '../lib/keys.mjs';
import { ReceiptStore } from '../lib/receipt-store.mjs';
import { ReplayGuard } from '../lib/replay.mjs';
import { loadPolicy, PolicyEngine, DEFAULT_POLICY_PATH } from '../lib/policy.mjs';

function tempDir(prefix) {
  const root = mkdtempSync(path.join(tmpdir(), prefix));
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

/** Mirrors claude-code-adapter.test.mjs's testPolicy(): strip lockedDomains
 * so this suite's fixture paths never collide with the real bundle's. */
function testPolicy() {
  const loaded = loadPolicy({ path: DEFAULT_POLICY_PATH });
  const bundle = { ...loaded.bundle, lockedDomains: [] };
  return new PolicyEngine({ ...loaded, bundle });
}

/** A host-neutral fake `normalize`: ignores the real payload shape entirely
 * and produces a schema-valid host event carrying exactly the eventType/
 * sessionId the test asks for — proving the binding logic is host-agnostic. */
function fakeNormalize(eventType) {
  return (payload) => normalizeHostEvent(
    {
      eventType,
      sessionId: payload.sessionId ?? null,
      workspace: 'ws-main',
      time: new Date().toISOString(),
      client: { name: 'test-host', version: '1' },
      host: { platform: 'test', version: '1' },
    },
    { adapter: { name: 'test-host', version: '1' } },
  );
}

function harness() {
  const receiptDir = tempDir('arcane-hac-receipts-');
  const bindingDir = tempDir('arcane-hac-bindings-');
  const keyRing = generateTestKeyRing(['k1']);
  const receiptStore = new ReceiptStore({ root: receiptDir.root });
  const replayGuard = new ReplayGuard({});
  const policy = testPolicy();
  const sessionBinding = new SessionBindingStore({ root: bindingDir.root });
  return {
    keyRing, receiptStore, replayGuard, policy, sessionBinding,
    cleanup: () => { receiptDir.cleanup(); bindingDir.cleanup(); },
  };
}

test('EC-5 item 2+4: SessionStart with no prior binding mints and persists a runId visible via store.getBinding', () => {
  const h = harness();
  try {
    const outcome = handleHookEvent(
      { sessionId: 'sess-fresh' },
      { normalize: fakeNormalize('session-start'), keyRing: h.keyRing, receiptStore: h.receiptStore, replayGuard: h.replayGuard, policy: h.policy, sessionBinding: h.sessionBinding },
    );

    assert.match(outcome.hostEvent.runId, /^run_[0-9A-HJKMNP-TV-Z]{26}$/);
    assert.equal(outcome.hostEvent.taskId, null);
    assert.equal(outcome.hostEvent.contractId, null);

    const persisted = h.sessionBinding.getBinding('sess-fresh');
    assert.ok(persisted, 'the mint was actually written to the store, not just returned in-memory');
    assert.equal(persisted.runId, outcome.hostEvent.runId);
  } finally {
    h.cleanup();
  }
});

test('EC-5 item 2+4: a second SessionStart for the same session reuses the same runId', () => {
  const h = harness();
  try {
    const first = handleHookEvent(
      { sessionId: 'sess-repeat' },
      { normalize: fakeNormalize('session-start'), keyRing: h.keyRing, receiptStore: h.receiptStore, replayGuard: h.replayGuard, policy: h.policy, sessionBinding: h.sessionBinding },
    );
    const second = handleHookEvent(
      { sessionId: 'sess-repeat' },
      { normalize: fakeNormalize('session-start'), keyRing: h.keyRing, receiptStore: h.receiptStore, replayGuard: h.replayGuard, policy: h.policy, sessionBinding: h.sessionBinding },
    );
    assert.equal(first.hostEvent.runId, second.hostEvent.runId);
  } finally {
    h.cleanup();
  }
});

test('EC-5 item 2+4: a PostToolUse in an already-bound session gets hostEvent.runId populated, taskId/contractId still null pre-upgrade', () => {
  const h = harness();
  try {
    const sessionStart = handleHookEvent(
      { sessionId: 'sess-bound' },
      { normalize: fakeNormalize('session-start'), keyRing: h.keyRing, receiptStore: h.receiptStore, replayGuard: h.replayGuard, policy: h.policy, sessionBinding: h.sessionBinding },
    );

    const postEffect = handleHookEvent(
      { sessionId: 'sess-bound' },
      { normalize: fakeNormalize('post-effect'), keyRing: h.keyRing, receiptStore: h.receiptStore, replayGuard: h.replayGuard, policy: h.policy, sessionBinding: h.sessionBinding },
    );

    assert.equal(postEffect.hostEvent.runId, sessionStart.hostEvent.runId, 'post-effect READS the binding session-start minted, never mints its own');
    assert.equal(postEffect.hostEvent.taskId, null, 'no putBinding upgrade happened yet — taskId stays null');
    assert.equal(postEffect.hostEvent.contractId, null, 'no putBinding upgrade happened yet — contractId stays null');
  } finally {
    h.cleanup();
  }
});

test('EC-5 item 2+4: a PostToolUse in an UNBOUND session (no session-start ever ran) leaves runId null — never mints on a read-only event', () => {
  const h = harness();
  try {
    const outcome = handleHookEvent(
      { sessionId: 'sess-never-started' },
      { normalize: fakeNormalize('post-effect'), keyRing: h.keyRing, receiptStore: h.receiptStore, replayGuard: h.replayGuard, policy: h.policy, sessionBinding: h.sessionBinding },
    );
    assert.equal(outcome.hostEvent.runId, null);
    assert.equal(h.sessionBinding.getBinding('sess-never-started'), null, 'a read-only event must never mint a binding as a side effect');
  } finally {
    h.cleanup();
  }
});

test('EC-5 item 2+4: omitting sessionBinding entirely preserves EXACTLY today\'s behaviour (runId stays whatever normalize() set — null here)', () => {
  const h = harness();
  try {
    const outcome = handleHookEvent(
      { sessionId: 'sess-no-binding-dep' },
      { normalize: fakeNormalize('session-start'), keyRing: h.keyRing, receiptStore: h.receiptStore, replayGuard: h.replayGuard, policy: h.policy },
    );
    assert.equal(outcome.hostEvent.runId, null, 'default sessionBinding=null means the ambient-binding block never runs');
  } finally {
    h.cleanup();
  }
});

test('EC-5 item 2+4: a session-start event with no sessionId at all is left alone (nothing to key a binding on)', () => {
  const h = harness();
  try {
    const outcome = handleHookEvent(
      { sessionId: null },
      { normalize: fakeNormalize('session-start'), keyRing: h.keyRing, receiptStore: h.receiptStore, replayGuard: h.replayGuard, policy: h.policy, sessionBinding: h.sessionBinding },
    );
    assert.equal(outcome.hostEvent.runId, null);
  } finally {
    h.cleanup();
  }
});
