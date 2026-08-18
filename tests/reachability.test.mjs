import assert from 'node:assert/strict';
import test from 'node:test';
import { joinReachability, reachabilityGap } from '../src/lib/analysis/reachability.mjs';

test('no call evidence is unknown', () => {
  assert.equal(joinReachability({ vulnerability: {}, callEvidence: [] }).reachability, 'unknown');
});

test('verified reach is reachable', () => {
  assert.equal(joinReachability({ vulnerability: {}, callEvidence: [{ reached: true }] }).reachability, 'reachable');
});

test('unknown is never inferred from missing graph', () => {
  const gap = reachabilityGap({ packageName: 'x', graphScope: null });
  assert.equal(gap.kind, 'reachability-unproven');
  // A clean claim can never rely on the absence of reachability evidence.
  assert.notEqual(gap.kind, 'reachable');
});
