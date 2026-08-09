// S04 — HostIngestor: trusted host activity flows into Arcane without model
// re-entry and without confusing success with proof (WP4 §"Objective").
//
// This module closes S00 finding 5: `lib/core.js:493-494,536-539` let
// `authority='host'` plus a non-empty `receipt` string mint unconditional
// tool-trust evidence with zero structural validation of that receipt's
// content. Here, `authority='host'` is necessary but never sufficient on its
// own — the caller must additionally present either:
//
//   - a real S03 auth envelope over the host event (`{alg, keyId, mac,
//     boundFieldsDigest}`), checked with `verifyRecord` — the receipt must
//     validate structurally AND verify, or ARC_HOST_EVENT_UNTRUSTED; or
//   - an explicit, honest connection-level trust assertion
//     (`{issuerIdentity, verifiedAt}`), which downgrades the resulting
//     receipt's `authentication` block to `host-connection-trust` +
//     `perMessage:false` rather than claiming a strength it lacks
//     (ARCHITECTURE §24a, S00 finding 2).
//
// A model-asserted authority is refused before either path is even
// considered (ARC_MODEL_SELF_REPORT) — a model's statement that it wrote,
// tested, or deployed something is never an effect receipt (§24a, I-07).

import { decision } from './errors.mjs';
import { validateHostEvent, classifyObservation } from './host-event.mjs';
import { HOST_EVENT_BOUND_FIELDS } from './host-event.mjs';
import { verifyRecord, authenticationBlock, connectionTrustBlock } from './receipt-auth.mjs';
import { assertValid } from './validate.mjs';
import { mintId } from './ids.mjs';
import { payloadClaimsAuthority } from './authority.mjs';

// Exported so hook-adapter-core.mjs's pre-effect/post-effect correlation
// minting (EC-5 item 5) can key off the identical set without re-declaring
// it — a divergent local copy would silently drift from what this module
// actually gates on.
export const POST_EFFECT_TYPES = Object.freeze(['post-effect', 'post-effect-failure']);

/** hostEvent.result.outcome -> effect-receipt-v1's `result` enum. */
const RESULT_OUTCOME_MAP = Object.freeze({
  success: 'applied',
  failure: 'failed',
  blocked: 'blocked',
  'no-op': 'no-op',
});

export class HostIngestor {
  #receiptStore;

  #capabilityStore;

  #replayGuard;

  #keyRing;

  #policy;

  #clock;

  #dependencyLedger;

  // idempotencyKey -> { receipt, observationClass }. Delivery-level
  // idempotency: a duplicate host event (same key) returns the original
  // receipt and appends nothing new, regardless of how many times it is
  // re-delivered by a retrying host.
  #seen = new Map();

  /**
   * @param {object} deps
   * @param {object} deps.receiptStore S03's ReceiptStore
   * @param {object|null} [deps.capabilityStore] S03's CapabilityStore — accepted
   *   for interface completeness; capability consumption/expiry is enforced
   *   upstream at the pre-effect gate, not re-checked here.
   * @param {object} deps.replayGuard S03's ReplayGuard
   * @param {object} deps.keyRing S03's KeyRing, used to verify a host's auth envelope
   * @param {object} deps.policy a PolicyEngine, or failClosedEngine(...)
   * @param {() => number} [deps.clock]
   * @param {object|null} [deps.dependencyLedger] S05's DependencyLedger — additive
   *   over the binding constructor shape (WP4 action 10: an observed mutation
   *   invalidates affected evidence). Optional: when absent, invalidation is
   *   simply not performed, never silently faked.
   */
  constructor({ receiptStore, capabilityStore = null, replayGuard, keyRing, policy, clock = () => Date.now(), dependencyLedger = null }) {
    this.#receiptStore = receiptStore;
    this.#capabilityStore = capabilityStore;
    this.#replayGuard = replayGuard;
    this.#keyRing = keyRing;
    this.#policy = policy;
    this.#clock = clock;
    this.#dependencyLedger = dependencyLedger;
  }

  /**
   * @param {object} hostEvent an `HOST_EVENT_SCHEMA` instance
   * @param {{authorityAssertion: {assertedBy: 'model'|'host', receipt?: any, connectionTrust?: {issuerIdentity: string, verifiedAt?: string}}}} ctx
   * @returns {{accepted: boolean, receipt: object|null, observationClass: string|null, decision: object}}
   */
  ingest(hostEvent, { authorityAssertion } = {}) {
    // 1. Authority — a model self-report is refused before anything else is
    //    even inspected (ARCHITECTURE §24a, I-07).
    if (authorityAssertion?.assertedBy === 'model') {
      return this.#refuse(null, decision({
        allowed: false,
        code: 'ARC_MODEL_SELF_REPORT',
        message: 'a model self-report is never an effect receipt (ARCHITECTURE §24a, I-07)',
        detail: { assertedBy: 'model' },
      }));
    }
    if (authorityAssertion?.assertedBy !== 'host') {
      return this.#refuse(null, decision({
        allowed: false,
        code: 'ARC_HOST_EVENT_UNTRUSTED',
        message: 'host ingestion requires an explicit authorityAssertion.assertedBy === "host"',
        detail: { assertedBy: authorityAssertion?.assertedBy ?? null },
      }));
    }

    // 2. Structure. A malformed event is refused before any trust check —
    //    there is no point authenticating something unparseable.
    const structural = validateHostEvent(hostEvent);
    if (!structural.valid) {
      return this.#refuse(null, decision({
        allowed: false,
        code: 'ARC_HOST_EVENT_INVALID',
        message: 'host event does not satisfy HOST_EVENT_SCHEMA',
        detail: { issues: structural.issues },
      }));
    }

    // 2b. Authority may never be smuggled in through the one open bag
    //     either — `extensions` is content, not a side channel for a claim
    //     this codebase never honors from a payload (ARCHITECTURE §24a).
    if (payloadClaimsAuthority(hostEvent.extensions)) {
      return this.#refuse(null, decision({
        allowed: false,
        code: 'ARC_MODEL_SELF_REPORT',
        message: 'authority cannot be asserted from within a host event payload, including extensions',
        detail: {},
      }));
    }

    // 3. Delivery-level idempotency — short-circuits before any crypto work
    //    or replay-guard consumption, so a legitimate retry of the exact
    //    same message is never mistaken for a nonce replay.
    if (hostEvent.idempotencyKey && this.#seen.has(hostEvent.idempotencyKey)) {
      const cached = this.#seen.get(hostEvent.idempotencyKey);
      return {
        accepted: true,
        receipt: cached.receipt,
        observationClass: cached.observationClass,
        decision: decision({ allowed: true, detail: { duplicate: true, idempotencyKey: hostEvent.idempotencyKey } }),
      };
    }

    // 4. Trust — S00 finding 5 is closed here. `authority=host` plus a bare
    //    receipt string is not authentication; see #resolveHostTrust.
    const trust = this.#resolveHostTrust(hostEvent, authorityAssertion);
    if (!trust.allowed) return this.#refuse(null, trust);

    // 5. Classification — pure, structural, always succeeds once the event
    //    is well-formed.
    const observationClass = classifyObservation(hostEvent, { policy: this.#policy });

    const isPostEffect = POST_EFFECT_TYPES.includes(hostEvent.eventType);
    if (!isPostEffect) {
      // Pre-effect / lifecycle events are accepted and classified, but there
      // is no observed effect yet, so no receipt is minted.
      return { accepted: true, receipt: null, observationClass, decision: decision({ allowed: true, detail: { eventType: hostEvent.eventType } }) };
    }

    // EC-5, amendment A-ER-1 (2026-08-09): contractId/taskId are now nullable
    // on effect-receipt-v1 — a "real runId, null contractId/taskId" event is
    // an AMBIENT observation (a host-observed effect in a session bound to a
    // run but not to a contract) and is accepted, not refused. A runId is
    // still mandatory: ambient is a typed tier, never a silent default, and
    // there is nothing to bucket the observation under without one.
    if (!hostEvent.effect || !hostEvent.sourceRevision || !hostEvent.runId) {
      return this.#refuse(observationClass, decision({
        allowed: false,
        code: 'ARC_HOST_EVENT_INVALID',
        message: 'a post-effect event must carry an observed effect, sourceRevision, and a run binding (contractId/taskId may be null — ambient tier, amendment A-ER-1)',
        detail: { eventId: hostEvent.eventId },
      }));
    }

    // 6. Correlation — a post-effect event that cannot name the pre-effect
    //    request it completes is refused (WP4 action 8/S04 acceptance).
    if (!hostEvent.priorCorrelation?.requestId) {
      return this.#refuse(observationClass, decision({
        allowed: false,
        code: 'ARC_INGEST_CORRELATION_MISSING',
        message: 'post-effect event has no correlated pre-effect request',
        detail: { eventId: hostEvent.eventId },
      }));
    }

    // 7. Build + replay-check + persist the receipt.
    const result = this.#recordEffectReceipt(hostEvent, trust, observationClass);
    if (!result.accepted) return result;

    if (hostEvent.idempotencyKey) {
      this.#seen.set(hostEvent.idempotencyKey, { receipt: result.receipt, observationClass });
    }

    // 8. WP4 action 10 — an observed mutation invalidates affected evidence.
    //    Additive over the binding constructor shape; a no-op when no ledger
    //    is wired, never a silent claim of invalidation that did not happen.
    if (observationClass === 'mutation-observation' && this.#dependencyLedger && hostEvent.result.observedDigest) {
      this.#dependencyLedger.observeChange({
        dimension: 'source-digest',
        ref: hostEvent.effect.target,
        digest: hostEvent.result.observedDigest,
      });
    }

    return result;
  }

  #refuse(observationClass, decisionValue) {
    return { accepted: false, receipt: null, observationClass, decision: decisionValue };
  }

  /**
   * Resolve host trust for this event. Returns a decision whose `detail`
   * carries `{method, issuerIdentity, keyId?, verifiedAt?}` on success.
   *
   * S00 finding 5 closure: a `receipt` that is anything other than a
   * structurally valid S03 auth envelope (`alg`/`keyId`/`mac`/
   * `boundFieldsDigest`) is refused outright — a bare string (the legacy
   * attack's exact shape) never even reaches `verifyRecord`. A receipt that
   * IS shaped correctly must still verify.
   */
  #resolveHostTrust(hostEvent, authorityAssertion) {
    const receipt = authorityAssertion?.receipt ?? null;
    const connectionTrust = authorityAssertion?.connectionTrust ?? null;

    if (receipt !== null) {
      if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)
        || typeof receipt.mac !== 'string' || typeof receipt.keyId !== 'string' || typeof receipt.alg !== 'string') {
        return decision({
          allowed: false,
          code: 'ARC_HOST_EVENT_UNTRUSTED',
          message: 'authority=host with a receipt that is not a structurally valid authentication envelope is not authentication (S00 finding 5) — it must validate structurally AND verify under verifyRecord',
          detail: { receiptType: typeof receipt },
        });
      }
      const verified = verifyRecord(hostEvent, receipt, { keyRing: this.#keyRing, boundFields: HOST_EVENT_BOUND_FIELDS });
      if (!verified.allowed) {
        return decision({
          allowed: false,
          code: 'ARC_HOST_EVENT_UNTRUSTED',
          message: `host receipt failed verification: ${verified.message}`,
          detail: { cause: verified.code },
        });
      }
      return decision({
        allowed: true,
        detail: { method: 'capability-signature', keyId: receipt.keyId, issuerIdentity: `key:${receipt.keyId}`, verifiedAt: null },
      });
    }

    if (connectionTrust && typeof connectionTrust.issuerIdentity === 'string' && connectionTrust.issuerIdentity.length > 0) {
      return decision({
        allowed: true,
        detail: {
          method: 'host-connection-trust',
          issuerIdentity: connectionTrust.issuerIdentity,
          verifiedAt: connectionTrust.verifiedAt ?? null,
        },
      });
    }

    return decision({
      allowed: false,
      code: 'ARC_HOST_EVENT_UNTRUSTED',
      message: 'authority=host asserted with no receipt and no connection-trust proof',
      detail: {},
    });
  }

  /** Build, replay-check, and persist an effect-receipt-v1 record. */
  #recordEffectReceipt(hostEvent, trust, observationClass) {
    const pc = hostEvent.priorCorrelation;
    const requested = pc.requestedEffect ?? hostEvent.effect;
    const authorizedBase = pc.authorizedEffect ?? hostEvent.effect;
    const authorized = { ...authorizedBase, capabilityId: pc.capabilityId ?? null };
    const observed = hostEvent.effect;

    const match = Boolean(
      requested && observed
      && requested.effectClass === observed.effectClass
      && requested.target === observed.target
      && requested.operation === observed.operation,
    );

    const scope = { issuerId: trust.detail.issuerIdentity, sessionId: hostEvent.sessionId, runId: hostEvent.runId, workspaceId: hostEvent.workspace };
    const replayCheck = this.#replayGuard.check({
      scope, nonce: hostEvent.replayNonce, sequence: hostEvent.replaySequence, timestamp: hostEvent.time,
    });
    if (!replayCheck.allowed) {
      return { accepted: false, receipt: null, observationClass, decision: replayCheck };
    }

    const authentication = trust.detail.method === 'capability-signature'
      ? authenticationBlock({ keyId: trust.detail.keyId, verifiedAt: new Date(this.#clock()).toISOString() })
      : connectionTrustBlock({ issuerIdentity: trust.detail.issuerIdentity, verifiedAt: trust.detail.verifiedAt });

    const receipt = {
      schemaVersion: 1,
      kind: 'legion-effect-receipt',
      receiptId: mintId('effectReceipt'),
      requestId: pc.requestId,
      runId: hostEvent.runId,
      contractId: hostEvent.contractId,
      taskId: hostEvent.taskId,
      requested,
      authorized,
      observed,
      match,
      actualDiffDigest: hostEvent.result.observedDigest ?? null,
      hostEventRef: hostEvent.eventId,
      authentication,
      replayDefense: {
        nonce: hostEvent.replayNonce,
        sequence: hostEvent.replaySequence,
        freshnessWindowSeconds: typeof this.#policy?.replayLimits === 'function' ? this.#policy.replayLimits().freshnessWindowSeconds : null,
        freshAt: hostEvent.time,
      },
      sourceRevision: hostEvent.sourceRevision,
      replayOf: null,
      idempotencyKey: hostEvent.idempotencyKey ?? null,
      result: RESULT_OUTCOME_MAP[hostEvent.result.outcome],
      observedAt: hostEvent.time,
    };

    try {
      assertValid('effect-receipt-v1', receipt);
    } catch (err) {
      return {
        accepted: false, receipt: null, observationClass,
        decision: decision({ allowed: false, code: 'ARC_HOST_EVENT_INVALID', message: 'host event correlation data does not produce a schema-valid effect receipt', detail: { issues: err.detail?.issues ?? [] } }),
      };
    }

    this.#receiptStore.append(receipt);

    return {
      accepted: true,
      receipt,
      observationClass,
      decision: decision({ allowed: true, detail: { receiptId: receipt.receiptId, observationClass } }),
    };
  }
}
