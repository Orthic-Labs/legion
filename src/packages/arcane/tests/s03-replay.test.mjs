// S03 — lib/replay.mjs
//
// Mandatory negative coverage (task dispatch + INTERFACES.md §S03): replayed
// nonce, sequence regression, sequence repeat, stale (too old), stale (too
// far in the future / skew), plus scoping (same nonce in a different scope
// is accepted) and bounded memory (prune()/maxEntries). Deterministic clock
// throughout — this file never sleeps.

import assert from 'node:assert/strict';
import test from 'node:test';
import { ReplayGuard, scopeKey } from '../lib/replay.mjs';

const T0 = Date.parse('2026-01-01T00:00:00.000Z');

function makeClock(startMs = T0) {
  let now = startMs;
  return {
    clock: () => now,
    advance(ms) {
      now += ms;
    },
    iso() {
      return new Date(now).toISOString();
    },
  };
}

const SCOPE_A = { issuerId: 'issuer-1', sessionId: 'sess-1', runId: 'run-1', workspaceId: 'ws-1' };
const SCOPE_B = { issuerId: 'issuer-2', sessionId: 'sess-2', runId: 'run-2', workspaceId: 'ws-2' };

test('scopeKey() is stable for the same scope and differs across scopes', () => {
  assert.equal(scopeKey(SCOPE_A), scopeKey({ ...SCOPE_A }));
  assert.notEqual(scopeKey(SCOPE_A), scopeKey(SCOPE_B));
});

test('accepts a fresh, unique, monotonic message', () => {
  const { clock, iso } = makeClock();
  const guard = new ReplayGuard({ clock });
  const result = guard.check({ scope: SCOPE_A, nonce: 'n-1', sequence: 1, timestamp: iso() });
  assert.equal(result.allowed, true);
  assert.equal(result.code, null);
});

test('reject: replayed nonce -> ARC_REPLAY_NONCE_SEEN', () => {
  const { clock, iso } = makeClock();
  const guard = new ReplayGuard({ clock });
  const first = guard.check({ scope: SCOPE_A, nonce: 'n-1', sequence: 1, timestamp: iso() });
  assert.equal(first.allowed, true);

  const replay = guard.check({ scope: SCOPE_A, nonce: 'n-1', sequence: 2, timestamp: iso() });
  assert.equal(replay.allowed, false);
  assert.equal(replay.code, 'ARC_REPLAY_NONCE_SEEN');
});

test('reject: sequence regression -> ARC_REPLAY_SEQUENCE_REGRESSION', () => {
  const { clock, iso } = makeClock();
  const guard = new ReplayGuard({ clock });
  assert.equal(guard.check({ scope: SCOPE_A, nonce: 'n-1', sequence: 5, timestamp: iso() }).allowed, true);

  const regressed = guard.check({ scope: SCOPE_A, nonce: 'n-2', sequence: 4, timestamp: iso() });
  assert.equal(regressed.allowed, false);
  assert.equal(regressed.code, 'ARC_REPLAY_SEQUENCE_REGRESSION');
});

test('reject: sequence repeat (same sequence number twice) -> ARC_REPLAY_SEQUENCE_REGRESSION', () => {
  const { clock, iso } = makeClock();
  const guard = new ReplayGuard({ clock });
  assert.equal(guard.check({ scope: SCOPE_A, nonce: 'n-1', sequence: 3, timestamp: iso() }).allowed, true);

  const repeated = guard.check({ scope: SCOPE_A, nonce: 'n-2', sequence: 3, timestamp: iso() });
  assert.equal(repeated.allowed, false);
  assert.equal(repeated.code, 'ARC_REPLAY_SEQUENCE_REGRESSION');
});

test('reject: timestamp older than the freshness window -> ARC_REPLAY_STALE', () => {
  const { clock, iso } = makeClock();
  const guard = new ReplayGuard({ clock, freshnessWindowSeconds: 300 });
  const staleTimestamp = new Date(T0 - 301_000).toISOString();
  const result = guard.check({ scope: SCOPE_A, nonce: 'n-1', sequence: 1, timestamp: staleTimestamp });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_REPLAY_STALE');
  void iso;
});

test('reject: timestamp further in the future than maxSkewSeconds -> ARC_REPLAY_STALE', () => {
  const { clock } = makeClock();
  const guard = new ReplayGuard({ clock, maxSkewSeconds: 60 });
  const futureTimestamp = new Date(T0 + 61_000).toISOString();
  const result = guard.check({ scope: SCOPE_A, nonce: 'n-1', sequence: 1, timestamp: futureTimestamp });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_REPLAY_STALE');
});

test('reject: unparseable timestamp -> ARC_REPLAY_STALE (never trusted by default)', () => {
  const { clock } = makeClock();
  const guard = new ReplayGuard({ clock });
  const result = guard.check({ scope: SCOPE_A, nonce: 'n-1', sequence: 1, timestamp: 'not-a-date' });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_REPLAY_STALE');
});

test('scoping: the same nonce in a different scope is accepted', () => {
  const { clock, iso } = makeClock();
  const guard = new ReplayGuard({ clock });
  const inScopeA = guard.check({ scope: SCOPE_A, nonce: 'shared-nonce', sequence: 1, timestamp: iso() });
  assert.equal(inScopeA.allowed, true);

  const inScopeB = guard.check({ scope: SCOPE_B, nonce: 'shared-nonce', sequence: 1, timestamp: iso() });
  assert.equal(inScopeB.allowed, true, 'a nonce is scoped, not global');
});

test('bounded memory: maxEntries evicts the oldest nonce on insert', () => {
  const { clock, iso } = makeClock();
  const guard = new ReplayGuard({ clock, maxEntries: 3 });

  for (let i = 1; i <= 10; i++) {
    const result = guard.check({ scope: SCOPE_A, nonce: `n-${i}`, sequence: i, timestamp: iso() });
    assert.equal(result.allowed, true);
    assert.ok(guard.size() <= 3, `size() must never exceed maxEntries (was ${guard.size()} after n-${i})`);
  }
  assert.equal(guard.size(), 3);

  // The earliest nonces were evicted, so they are no longer recognized as
  // replays — an accepted memory/security tradeoff of a bounded cache, not a
  // bug: an attacker replaying a very old nonce would also fail the
  // freshness check on a real clock.
  const evictedNonceRetried = guard.check({ scope: SCOPE_A, nonce: 'n-1', sequence: 11, timestamp: iso() });
  assert.equal(evictedNonceRetried.allowed, true);
});

test('prune() drops nonce entries outside the freshness window', () => {
  const { clock, advance, iso } = makeClock();
  const guard = new ReplayGuard({ clock, freshnessWindowSeconds: 100 });

  guard.check({ scope: SCOPE_A, nonce: 'n-old', sequence: 1, timestamp: iso() });
  assert.equal(guard.size(), 1);

  advance(200_000); // 200s later — n-old is now outside the 100s freshness window
  guard.prune();
  assert.equal(guard.size(), 0, 'prune() must drop entries older than the freshness window');
});
