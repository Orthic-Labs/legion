import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateParityRow } from '../scripts/native-cli/gate.mjs';

function row(overrides = {}) {
  return { id: 'audit-help', manifestSha256: 'manifest', fixtureSha256: 'fixture',
    exitCode: 0, stdout: 'Usage: legion audit --old-option', stderr: '', error: null,
    signal: null, timedOut: false, outputLimitExceeded: false, mismatch: [],
    filesystem: { before: {}, after: {} }, ...overrides };
}

function evaluate(fixture, record, baseline = row()) {
  return evaluateParityRow({ fixture: { id: 'audit-help', ...fixture }, record,
    baseline, manifestSha256: 'manifest', fixtureSha256: 'fixture' });
}

test('captureOnly cannot hide a removed option behind a generic Usage oracle', () => {
  const result = evaluate({ captureOnly: true, nativeOracle: { exitCode: 0, stdoutIncludes: ['Usage:'] } },
    row({ stdout: 'Usage: legion audit' }));
  assert.equal(result.status, 'mismatched');
  assert.equal(result.comparison, 'node-parity');
  assert.deepEqual(result.mismatch, ['stdout differs from baseline']);
});

test('captureOnly still requires the exact Node baseline identity', () => {
  const fixture = { captureOnly: true, nativeOracle: { exitCode: 0, stdoutIncludes: ['Usage:'] } };
  assert.equal(evaluate(fixture, row(), null).status, 'unmatched');
  assert.equal(evaluate(fixture, row(), row({ fixtureSha256: 'old' })).status, 'unmatched');
});

test('nested captureOnly never grants native-only status or hides mutation', () => {
  const result = evaluate({ rustExpect: { captureOnly: true } }, row({ filesystem: { before: {}, after: { state: 'changed' } } }));
  assert.equal(result.status, 'mismatched');
  assert.ok(result.mismatch.includes('filesystem mutation differs from baseline'));
});

test('an explicit native-only oracle cannot certify unobserved process or filesystem state', () => {
  const fixture = { nativeOnly: true, nativeOracle: { exitCode: 0, stdoutIncludes: ['Usage:'] } };
  assert.equal(evaluate(fixture, row(), null).status, 'matched');
  assert.equal(evaluate(fixture, row({ signal: 'SIGTERM' }), null).status, 'blocked');
  assert.equal(evaluate(fixture, row({ filesystem: { after: {} } }), null).status, 'blocked');
  const mutation = evaluate(fixture, row({ filesystem: { before: {}, after: { state: 'changed' } } }), null);
  assert.equal(mutation.status, 'blocked');
  assert.ok(mutation.mismatch.includes('native-only row has unasserted filesystem mutations'));
});

test('rust:false is a blocked implementation, not an automatically passing native oracle', () => {
  assert.equal(evaluate({ rust: false, nativeOracle: { exitCode: 0 } }, row()).status, 'blocked');
});

test('a fully observed identical capture-only row is genuine Node parity', () => {
  const result = evaluate({ captureOnly: true }, row());
  assert.equal(result.status, 'matched');
  assert.equal(result.comparison, 'node-parity');
  assert.deepEqual(result.mismatch, []);
});
