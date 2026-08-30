// S03 — replay defense: nonce cache + strictly monotonic per-scope sequence
// + freshness window + bounded clock skew.
//
// S00 finding 3: no nonce, sequence number, or freshness window exists on any
// receipt, evidence item, or check anywhere in predecessor code. `consumeRetry`'s
// fingerprinting (lib/budget.js) solves a different problem — bounding
// identical agent retries — not adversarial replay. This module is
// greenfield, not an adaptation of anything.
//
// A ReplayGuard is scoped by the composite `{issuerId, sessionId, runId,
// workspaceId}` (scopeKey()): the same nonce presented in a different scope
// is a different message, not a replay, so both the nonce cache and the
// sequence-monotonicity check are keyed per scope, never globally.
//
// Three independent rejections, deliberately distinct codes because each has
// a different remediation:
//   - ARC_REPLAY_NONCE_SEEN          — this exact nonce was already consumed
//     in this scope.
//   - ARC_REPLAY_SEQUENCE_REGRESSION — sequence must be strictly increasing
//     per scope. A repeat of the last-accepted sequence is a regression too,
//     not a separate case: a legitimate sender never re-sends a sequence
//     number it has already used.
//   - ARC_REPLAY_STALE               — timestamp is older than the freshness
//     window, or further in the future than the bounded clock-skew
//     allowance, or not a parsable date at all (Arcane cannot vouch for
//     freshness it cannot read, so "unreadable" is treated the same as
//     "too old", never as "trust it").
//
// `clock` is injectable so tests are deterministic: this module never sleeps
// and never reads the wall clock except through `clock()`.
//
// Memory is bounded by `maxEntries`, which governs the nonce cache (the
// resource whose size is driven by adversary-controlled traffic volume, not
// by the number of scopes in play). Once full, the oldest entry (by
// insertion order) is evicted to admit a new one. `prune()` proactively
// drops nonce entries already outside the freshness window: a replay of a
// dropped nonce would fail the freshness check on its own, before the nonce
// cache is ever consulted, so dropping it early is safe — it is not a laxer
// replay policy, only an eviction schedule.
//
// The per-scope sequence map is NOT part of the bounded nonce cache and is
// never pruned by `prune()`/`maxEntries` eviction: dropping a scope's
// last-accepted sequence would let a subsequent regression silently pass,
// which is exactly the attack this module exists to stop. In practice its
// size is bounded by the number of distinct active scopes, not by adversary
// traffic volume.

import { decision } from '../../../contracts/arcane/errors.mjs';
import { canonicalJson } from '../../../contracts/arcane/canonical.mjs';

/** Stable string form of a replay scope. Missing fields normalize to null. */
export function scopeKey(scope = {}) {
  const { issuerId = null, sessionId = null, runId = null, workspaceId = null } = scope || {};
  return canonicalJson({ issuerId, sessionId, runId, workspaceId });
}

export class ReplayGuard {
  #freshnessWindowSeconds;
  #maxSkewSeconds;
  #clock;
  #maxEntries;
  // `${scopeKey}\0${nonce}` -> timestampMs. Map preserves insertion
  // order, which is what makes the oldest-entry eviction in #recordNonce
  // correct without a separate LRU structure.
  #nonces = new Map();
  // scopeKey -> last accepted sequence number.
  #sequences = new Map();

  constructor({
    freshnessWindowSeconds = 300,
    maxSkewSeconds = 60,
    clock = () => Date.now(),
    maxEntries = 100000,
  } = {}) {
    this.#freshnessWindowSeconds = freshnessWindowSeconds;
    this.#maxSkewSeconds = maxSkewSeconds;
    this.#clock = clock;
    this.#maxEntries = maxEntries;
  }

  /**
   * @param {{scope: object, nonce: string, sequence: number, timestamp: string}} msg
   * @returns a decision(...) — never throws; a denial is data the caller
   *   must record, not an exception.
   */
  check({ scope, nonce, sequence, timestamp }) {
    const key = scopeKey(scope);
    const now = this.#clock();
    const tsMs = Date.parse(timestamp);

    if (!Number.isFinite(tsMs)) {
      return decision({
        allowed: false,
        code: 'ARC_REPLAY_STALE',
        message: 'timestamp is not a parsable date',
        detail: { scope, timestamp },
      });
    }

    const ageSeconds = (now - tsMs) / 1000;
    if (ageSeconds > this.#freshnessWindowSeconds) {
      return decision({
        allowed: false,
        code: 'ARC_REPLAY_STALE',
        message: 'timestamp is older than the freshness window',
        detail: { scope, ageSeconds, freshnessWindowSeconds: this.#freshnessWindowSeconds },
      });
    }
    if (-ageSeconds > this.#maxSkewSeconds) {
      return decision({
        allowed: false,
        code: 'ARC_REPLAY_STALE',
        message: 'timestamp is further in the future than the allowed clock skew',
        detail: { scope, skewSeconds: -ageSeconds, maxSkewSeconds: this.#maxSkewSeconds },
      });
    }

    const nonceKey = `${key}\0${String(nonce)}`;
    if (this.#nonces.has(nonceKey)) {
      return decision({
        allowed: false,
        code: 'ARC_REPLAY_NONCE_SEEN',
        message: 'nonce already consumed in this scope',
        detail: { scope, nonce },
      });
    }

    const lastSequence = this.#sequences.get(key);
    if (lastSequence !== undefined && sequence <= lastSequence) {
      return decision({
        allowed: false,
        code: 'ARC_REPLAY_SEQUENCE_REGRESSION',
        message: 'sequence must be strictly increasing within a scope',
        detail: { scope, sequence, lastSequence },
      });
    }

    this.#recordNonce(nonceKey, tsMs);
    this.#sequences.set(key, sequence);

    return decision({ allowed: true, detail: { scope, nonce, sequence } });
  }

  #recordNonce(nonceKey, tsMs) {
    if (this.#nonces.size >= this.#maxEntries) this.prune();
    if (this.#nonces.size >= this.#maxEntries) {
      const oldest = this.#nonces.keys().next().value;
      if (oldest !== undefined) this.#nonces.delete(oldest);
    }
    this.#nonces.set(nonceKey, tsMs);
  }

  /** Current size of the bounded nonce cache. */
  size() {
    return this.#nonces.size;
  }

  /** Drop nonce entries already outside the freshness window. See module note. */
  prune() {
    const now = this.#clock();
    const cutoffMs = now - this.#freshnessWindowSeconds * 1000;
    for (const [k, tsMs] of this.#nonces) {
      if (tsMs < cutoffMs) this.#nonces.delete(k);
    }
  }
}
