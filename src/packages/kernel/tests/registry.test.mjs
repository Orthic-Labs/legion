import assert from 'node:assert/strict';
import test from 'node:test';

import { OperationRegistry, negotiateCapabilities } from '../lib/registry.mjs';

const requestEnvelope = (operationId = 'legion.task.start') => ({
  schemaVersion: 1,
  kind: 'legion-operation-envelope',
  envelopeKind: 'request',
  operationId,
  operationVersion: '1.0.0',
  requestId: 'req_01J8Z3K9QG7X6M2N4P5R8S0T1V',
  runId: 'run_01J8Z3K9QG7X6M2N4P5R8S0T1V',
  callerAuthority: 'kernel',
  authorityAssertion: {
    assertedBy: 'kernel-test',
    perMessage: true,
    verificationMethod: 'capability-signature',
  },
  input: {},
  sourceRevision: 'abcdef0',
  requestedAt: '2026-08-09T00:00:00.000Z',
});

const descriptor = (operationId = 'legion.task.start') => {
  const envelope = requestEnvelope(operationId);
  return {
    operationId,
    version: envelope.operationVersion,
    title: operationId,
    purpose: 'registry test operation',
    envelope,
    handlerBinding: operationId,
  };
};

test('registers and looks up descriptors by operationId with a defensive copy', () => {
  const registry = new OperationRegistry();
  const original = descriptor();
  const registered = registry.register(original);

  assert.deepEqual(registry.lookup('legion.task.start'), registered);
  registered.title = 'changed';
  original.envelope.input.changed = true;
  assert.equal(registry.lookup('legion.task.start').title, 'legion.task.start');
  assert.deepEqual(registry.lookup('legion.task.start').envelope.input, {});
});

test('validates every registered descriptor envelope against operation-envelope-v1', () => {
  const registry = new OperationRegistry();
  const result = descriptor('legion.task.result');
  result.envelope = { ...result.envelope, envelopeKind: 'not-an-envelope' };

  assert.throws(() => registry.register(result), (error) => {
    assert.equal(error.code, 'INVALID_ARGUMENT');
    assert.equal(error.category, 'usage');
    assert.match(error.message, /invalid operation envelope/);
    return true;
  });
});

test('returns typed taxonomy for duplicate and unknown operations', () => {
  const registry = new OperationRegistry();
  registry.register(descriptor());

  assert.throws(() => registry.register(descriptor()), (error) => {
    assert.equal(error.code, 'SCOPE_CONFLICT');
    assert.equal(error.category, 'conflict');
    assert.equal(error.exitCode, 11);
    return true;
  });
  assert.throws(() => registry.lookup('legion.missing'), (error) => {
    assert.equal(error.code, 'OPERATION_NOT_AVAILABLE');
    assert.equal(error.category, 'usage');
    assert.equal(error.exitCode, 2);
    assert.equal(error.retryable, false);
    return true;
  });
});

test('negotiates capabilities deterministically, uniquely, and independent of input order', () => {
  const first = negotiateCapabilities({
    required: ['zeta', 'alpha', 'zeta', 'missing'],
    supported: ['zeta', 'alpha', 'alpha'],
  });
  const second = negotiateCapabilities({
    required: ['missing', 'zeta', 'alpha'],
    supported: ['alpha', 'zeta'],
  });

  const expected = {
    available: ['alpha', 'zeta'],
    missing: ['missing'],
    compatible: false,
  };
  assert.deepEqual(first, expected);
  assert.deepEqual(second, expected);
});

test('rejects malformed capability collections with typed usage errors', () => {
  assert.throws(() => negotiateCapabilities({ required: 'task.start', supported: [] }), (error) => {
    assert.equal(error.code, 'INVALID_ARGUMENT');
    assert.equal(error.category, 'usage');
    return true;
  });
});
