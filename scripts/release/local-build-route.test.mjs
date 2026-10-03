import assert from 'node:assert/strict';
import test from 'node:test';
import { buildRoute } from './local-build-route.mjs';

const now = Date.parse('2026-10-03T14:00:00Z');
test('queued & running builds route to CI', () => {
  for (const state of ['QUEUED', 'RUNNING']) {
    assert.equal(buildRoute({ inFlight: [{ id: 'other', state }], recent: [] }, now).route, 'github');
  }
});
test('finished, failed & cancelled activity within 30 minutes routes to CI', () => {
  for (const state of ['SUCCEEDED', 'FAILED', 'CANCELLED']) {
    assert.equal(buildRoute({ inFlight: [], recent: [{ state, terminalAt: '2026-10-03T13:40:00Z' }] }, now).route, 'github');
  }
});
test('recent completion counts even when last compiler output is older', () => {
  assert.equal(buildRoute({ inFlight: [], recent: [{ startedAt: '2026-10-03T13:00:00Z', elapsedMs: 40 * 60_000, lastOutputAt: '2026-10-03T13:01:00Z' }] }, now).route, 'github');
});
test('30-minute boundary is inclusive; older history permits local', () => {
  const inventory = timestamp => ({ inFlight: [], recent: [{ terminalAt: timestamp }] });
  assert.equal(buildRoute(inventory('2026-10-03T13:30:00Z'), now).route, 'github');
  assert.equal(buildRoute(inventory('2026-10-03T13:29:59Z'), now).route, 'local');
});
test('missing inventory or activity evidence fails closed', () => {
  assert.equal(buildRoute(null, now).route, 'github');
  assert.equal(buildRoute({ inFlight: [], recent: [{}] }, now).route, 'github');
});
