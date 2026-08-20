// S04 — host-event contract: closed schema, normalization, classification.
//
// Arcane owns one versioned host-event contract, closed except for a single
// `extensions` bag — exactly the discipline legacy Forge's closed-schema validator
// (orthic.observable-event.v1, legacy-semantic-inventory.json
// #hook_enforcement_points / #record_types) already enforced. Every other
// legacy record type was open; this module makes that the rule, not the
// exception.
//
// classifyObservation never decides trust — that is lib/ingest.mjs's job
// (S00 finding 5). It only names what kind of observation a completed
// operation is, structurally.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  HOST_EVENT_SCHEMA,
  EVENT_TYPE,
  LEGACY_HOST_EVENT_TYPE,
  validateHostEvent,
  normalizeHostEvent,
  EFFECT_OBSERVATION_CLASS,
  classifyObservation,
} from '../lib/host-event.mjs';
import { digest } from '../lib/canonical.mjs';
import { ArcaneError } from '../lib/errors.mjs';

const RUN_ID = 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV';
const REQUEST_ID = 'req_01ARZ3NDEKTSV4RRFFQ69G5FAV';
const EVENT_ID = 'hev_01ARZ3NDEKTSV4RRFFQ69G5FAV';
const ISO = () => new Date('2026-08-08T12:00:00.000Z').toISOString();

/** A fully-populated, schema-valid host event. Every override replaces top-level keys. */
function baseEvent(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'arcane-host-event',
    eventId: EVENT_ID,
    eventType: 'post-effect',
    time: ISO(),
    adapter: { name: 'claude-code', version: '1.2.3' },
    client: { name: 'claude-code', version: '1.2.3' },
    host: { platform: 'darwin', version: '24.0' },
    runId: RUN_ID,
    taskId: 'T-1',
    sessionId: 'sess-1',
    requestId: REQUEST_ID,
    contractId: 'EC-44',
    workspace: 'ws-main',
    subject: null,
    actor: { issuerId: 'host-process:1', processIdentity: 'pid:123' },
    operation: { toolId: 'Write', operationId: 'write', argumentDigest: digest('args') },
    sourceRevision: '0123abcdef',
    effect: { effectClass: 'FILE_WRITE', target: 'src/exact.ts', operation: 'write' },
    result: { outcome: 'success', exitCode: 0, terminal: true, observedDigest: digest('content') },
    pathMeta: null,
    processMeta: null,
    networkMeta: null,
    priorCorrelation: {
      requestId: REQUEST_ID,
      capabilityId: 'cap_1',
      priorReceiptId: null,
      requestedEffect: { effectClass: 'FILE_WRITE', target: 'src/exact.ts', operation: 'write' },
      authorizedEffect: { effectClass: 'FILE_WRITE', target: 'src/exact.ts', operation: 'write' },
    },
    checkCorrelation: null,
    hostEnforcement: { capabilities: ['preToolUse-intercept', 'postToolUse-observe'], knownBypasses: [] },
    replayNonce: 'nonce-1',
    replaySequence: 1,
    idempotencyKey: 'idem-1',
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────── structure

test('S04: HOST_EVENT_SCHEMA validates a well-formed host event', () => {
  const { valid, issues } = validateHostEvent(baseEvent());
  assert.equal(valid, true, JSON.stringify(issues));
});

test('S04: HOST_EVENT_SCHEMA is closed — an unknown top-level field is ARC_HOST_EVENT_INVALID-worthy (mandatory test 3)', () => {
  const event = { ...baseEvent(), sneakyField: 'whatever' };
  const { valid, issues } = validateHostEvent(event);
  assert.equal(valid, false);
  assert.ok(issues.some((i) => i.includes('sneakyField') && i.endsWith(':additional-property')), issues.join(','));
});

test('S04: the extensions object is the one open bag — arbitrary sub-fields inside it do not fail validation', () => {
  const event = baseEvent({ extensions: { anything: 'goes', nested: { ok: true } } });
  const { valid, issues } = validateHostEvent(event);
  assert.equal(valid, true, JSON.stringify(issues));
});

test('S04: normalizeHostEvent throws ARC_HOST_EVENT_INVALID when the normalized result cannot satisfy the schema', () => {
  assert.throws(
    () => normalizeHostEvent({ eventType: 'PreToolUse', workspace: '' }, { adapter: { name: 'claude-code', version: '1.0.0' } }),
    (err) => err instanceof ArcaneError && err.code === 'ARC_HOST_EVENT_INVALID',
  );
});

test('S04: normalizeHostEvent maps real adapter hook names (PreToolUse) onto the canonical EVENT_TYPE', () => {
  const raw = {
    eventType: 'PreToolUse',
    eventId: EVENT_ID,
    time: ISO(),
    runId: RUN_ID,
    taskId: 'T-1',
    sessionId: 'sess-1',
    requestId: REQUEST_ID,
    contractId: 'EC-44',
    workspace: 'ws-main',
    client: { name: 'claude-code', version: '1.2.3' },
    host: { platform: 'darwin', version: '24.0' },
    actor: { issuerId: 'host-process:1', processIdentity: null },
    operation: { toolId: 'Write', operationId: 'write', argumentDigest: null },
    sourceRevision: '0123abcdef',
    effect: { effectClass: 'FILE_WRITE', target: 'src/exact.ts', operation: 'write' },
    hostEnforcement: { capabilities: [], knownBypasses: [] },
  };
  const normalized = normalizeHostEvent(raw, { adapter: { name: 'claude-code', version: '1.2.3' } });
  assert.equal(normalized.eventType, 'pre-effect');
  assert.equal(LEGACY_HOST_EVENT_TYPE.PreToolUse, 'pre-effect');
  assert.ok(EVENT_TYPE.includes(normalized.eventType));
});

// ────────────────────────────────────────────────────────── classification

test('S04: EFFECT_OBSERVATION_CLASS is exactly the five named buckets', () => {
  assert.deepEqual(
    [...EFFECT_OBSERVATION_CLASS].sort(),
    ['deterministic-check-candidate', 'failure', 'mutation-observation', 'non-qualifying-telemetry', 'source-observation'].sort(),
  );
});

test('S04: an unknown command exiting 0 classifies as source-observation, never as a check candidate (mandatory test 6)', () => {
  const unknownCommand = baseEvent({
    effect: { effectClass: 'COMMAND_EXEC', target: 'some-random-script.sh', operation: 'exec' },
    checkCorrelation: null, // no host-observed correlation to a declared check
    result: { outcome: 'success', exitCode: 0, terminal: true, observedDigest: null },
  });
  const classification = classifyObservation(unknownCommand, { policy: null });
  assert.notEqual(classification, 'deterministic-check-candidate');
  assert.ok(['source-observation', 'non-qualifying-telemetry'].includes(classification), classification);
});

test('S04: a command exit-0 event WITH a host-observed declared-check correlation classifies as deterministic-check-candidate', () => {
  const knownCheck = baseEvent({
    effect: { effectClass: 'COMMAND_EXEC', target: 'npm test', operation: 'exec' },
    checkCorrelation: { declaredCheckId: 'AC-1', method: 'npm-test-exit-code' },
    result: { outcome: 'success', exitCode: 0, terminal: true, observedDigest: null },
  });
  assert.equal(classifyObservation(knownCheck, { policy: null }), 'deterministic-check-candidate');
});

test('S04: FILE_WRITE/FILE_MOVE/FILE_DELETE always classify as mutation-observation, never as proof (mandatory test 7)', () => {
  for (const effectClass of ['FILE_WRITE', 'FILE_MOVE', 'FILE_DELETE']) {
    const event = baseEvent({
      effect: { effectClass, target: 'src/exact.ts', operation: 'write' },
      result: { outcome: 'success', exitCode: 0, terminal: true, observedDigest: digest('x') },
    });
    const classification = classifyObservation(event, { policy: null });
    assert.equal(classification, 'mutation-observation', `${effectClass} -> ${classification}`);
    assert.notEqual(classification, 'deterministic-check-candidate');
  }
});

test('S04: a failed effect classifies as failure regardless of effect class', () => {
  const failedWrite = baseEvent({
    result: { outcome: 'failure', exitCode: 1, terminal: true, observedDigest: null },
  });
  assert.equal(classifyObservation(failedWrite, { policy: null }), 'failure');

  const failedExitCode = baseEvent({
    effect: { effectClass: 'COMMAND_EXEC', target: 'npm test', operation: 'exec' },
    result: { outcome: 'success', exitCode: 1, terminal: true, observedDigest: null },
  });
  assert.equal(classifyObservation(failedExitCode, { policy: null }), 'failure');
});

test('S04: a lifecycle event with no effect classifies as non-qualifying-telemetry', () => {
  const sessionStart = baseEvent({
    eventType: 'session-start',
    effect: null,
    result: null,
    priorCorrelation: null,
    checkCorrelation: null,
  });
  assert.equal(classifyObservation(sessionStart, { policy: null }), 'non-qualifying-telemetry');
});
