// S02 — authority identity assertion.
//
// Authority identity is asserted by kernel/host evidence per turn, never
// claimed by model text. That invariant is the whole design
// constraint here, and it has a sharp consequence the legacy system missed:
//
//   S00 finding — predecessor stored `authority` as a caller-supplied string on the
//   run/check/evidence rows (lib/core.js:55, :527-533). Anything that could
//   call the API could name its own authority. Worse, two of the four legal
//   values ('hook', 'operator') were never minted by any predecessor code path at
//   all, so their presence in the enum implied a capability that did not exist.
//
// Therefore: authority never travels inside a payload. It is asserted out of
// band, per turn, by the kernel or the host, and read back by reference. A
// payload that carries an `authority` field is not "ignored" — it is a typed
// refusal, because silently dropping it would let a caller believe it had been
// honored.

import { ArcaneError, decision } from './errors.mjs';
import { AUTHORITY_ID, AUTHENTICATION_METHOD } from '../../../packages/contracts/index.mjs';

/** Sources permitted to assert an authority. Deliberately excludes the model. */
export const ASSERTION_SOURCE = Object.freeze(['kernel', 'host']);

/** Field names that constitute a self-asserted authority claim in a payload. */
export const PAYLOAD_AUTHORITY_FIELDS = Object.freeze([
  'authority',
  'callerAuthority',
  'assertedAuthority',
  'trust_class',
  'trustClass',
  'executor',
]);

/**
 * Per-turn record of who the kernel says is acting.
 *
 * Deliberately NOT persisted: an authority assertion is scoped to one turn and
 * must be re-made, not recovered. Durability here would recreate exactly the
 * connection-level-trust problem S00 found (authenticate once, ride it
 * forever).
 */
export class AuthorityLedger {
  #turns = new Map();

  #clock;

  constructor({ clock = () => Date.now() } = {}) {
    this.#clock = clock;
  }

  /**
   * Record the authority for a turn.
   * @throws {ArcaneError} ARC_AUTHORITY_MODEL_CLAIMED when the source is not a
   *   permitted asserter, or the authority is not a canonical AUTHORITY_ID.
   */
  assertForTurn({ turnId, authority, assertedBy, verificationMethod, perMessage, source }) {
    if (!ASSERTION_SOURCE.includes(source)) {
      throw new ArcaneError(
        'ARC_AUTHORITY_MODEL_CLAIMED',
        `authority may only be asserted by ${ASSERTION_SOURCE.join(' or ')}, not '${source}'`,
        { turnId, source },
      );
    }
    if (!AUTHORITY_ID.includes(authority)) {
      // Catches the legacy 'operator'/'hook' values, which are not Legion
      // authorities and were never actually mintable in predecessor either.
      throw new ArcaneError(
        'ARC_AUTHORITY_MODEL_CLAIMED',
        `'${authority}' is not a canonical Legion authority`,
        { turnId, authority, known: [...AUTHORITY_ID] },
      );
    }
    if (!AUTHENTICATION_METHOD.includes(verificationMethod)) {
      throw new ArcaneError(
        'ARC_AUTHORITY_MODEL_CLAIMED',
        `unknown verification method '${verificationMethod}'`,
        { turnId, verificationMethod },
      );
    }
    if (typeof perMessage !== 'boolean') {
      throw new ArcaneError('ARC_AUTHORITY_MODEL_CLAIMED', 'perMessage must be stated explicitly', { turnId });
    }
    if (perMessage && verificationMethod === 'host-connection-trust') {
      // The whole point of the field: connection trust cannot be per-message.
      throw new ArcaneError(
        'ARC_AUTHORITY_MODEL_CLAIMED',
        'host-connection-trust authenticates a connection, not a message — perMessage cannot be true (S00 finding 2)',
        { turnId, verificationMethod },
      );
    }
    const assertion = Object.freeze({
      turnId,
      authority,
      assertedBy,
      verificationMethod,
      perMessage,
      source,
      assertedAt: this.#clock(),
    });
    this.#turns.set(turnId, assertion);
    return assertion;
  }

  /** The assertion for `turnId`, or null. */
  current(turnId) {
    return this.#turns.get(turnId) ?? null;
  }

  /** Drop a turn's assertion (turn ended). */
  clearTurn(turnId) {
    return this.#turns.delete(turnId);
  }

  size() {
    return this.#turns.size;
  }
}

/**
 * Always throws. Exists so the refusal is a callable, greppable thing rather
 * than a convention: no code path anywhere in Arcane may read an authority out
 * of a payload, and this function is the only place that names the attempt.
 */
export function extractAuthorityFromPayload(payload) {
  const found = PAYLOAD_AUTHORITY_FIELDS.filter((f) => payload && Object.prototype.hasOwnProperty.call(payload, f));
  throw new ArcaneError(
    'ARC_AUTHORITY_MODEL_CLAIMED',
    'authority cannot be read from a payload; it is asserted by kernel or host evidence per turn',
    { fields: found },
  );
}

/** True when a payload is trying to name its own authority. */
export function payloadClaimsAuthority(payload) {
  if (!payload || typeof payload !== 'object') return false;
  return PAYLOAD_AUTHORITY_FIELDS.some((f) => Object.prototype.hasOwnProperty.call(payload, f));
}

/**
 * Gate on the kernel-asserted authority for a turn.
 *
 * @param {AuthorityLedger} ledger
 * @param {string} turnId
 * @param {string[]} allowed authorities permitted to do this work
 * @param {{claimedAuthority?: string, requirePerMessage?: boolean}} [opts]
 *   `claimedAuthority` is what the caller's payload *said*; supplying it is how
 *   a caller gets its claim checked rather than trusted. A mismatch is refused.
 */
export function requireAuthority(ledger, turnId, allowed, opts = {}) {
  const assertion = ledger.current(turnId);
  if (!assertion) {
    return decision({
      allowed: false,
      code: 'ARC_AUTHORITY_NOT_ASSERTED',
      message: `no kernel-asserted authority for turn ${turnId}`,
      detail: { turnId },
    });
  }
  if (opts.claimedAuthority !== undefined && opts.claimedAuthority !== assertion.authority) {
    return decision({
      allowed: false,
      code: 'ARC_AUTHORITY_MODEL_CLAIMED',
      message: 'payload claims an authority the kernel did not assert for this turn',
      detail: { turnId, claimed: opts.claimedAuthority, asserted: assertion.authority },
    });
  }
  if (!allowed.includes(assertion.authority)) {
    return decision({
      allowed: false,
      code: 'ARC_AUTHORITY_NOT_ASSERTED',
      message: `authority '${assertion.authority}' is not permitted for this operation`,
      detail: { turnId, asserted: assertion.authority, allowed: [...allowed] },
    });
  }
  if (opts.requirePerMessage && !assertion.perMessage) {
    return decision({
      allowed: false,
      code: 'ARC_AUTHORITY_NOT_ASSERTED',
      message: 'this operation requires per-message authority; only connection-level trust is available',
      detail: { turnId, verificationMethod: assertion.verificationMethod },
      enforcementHealth: 'observed',
    });
  }
  return decision({ allowed: true, detail: { turnId, authority: assertion.authority } });
}

export function assertHostAuthorityForTurn(bindingStore, input) {
  if (!bindingStore || typeof bindingStore.assertForTurn !== 'function') {
    throw new ArcaneError('ARC_AUTHORITY_NOT_ASSERTED', 'host authority binding store is required', {});
  }
  return bindingStore.assertForTurn(input);
}
