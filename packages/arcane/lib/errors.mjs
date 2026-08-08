// Arcane typed error taxonomy.
//
// Arcane is deterministic code on the host boundary (ARCHITECTURE.md §24a). It
// never throws untyped strings and never degrades silently: every refusal
// carries a machine-readable `code`, the subject it refused, and whether the
// refusal was a *fail-closed* (enforcement unavailable) or a *denial*
// (enforcement available and the request lost).

/** Every code Arcane can emit. Closed set — adding one is an API change. */
export const ARCANE_ERROR_CODE = Object.freeze([
  // structural / contract
  'ARC_SCHEMA_INVALID', // payload failed a frozen contract schema
  'ARC_ID_INVALID', // identifier violates ids.md grammar
  'ARC_CANONICALIZATION_FAILED', // value cannot be canonically serialized

  // policy plane (S02)
  'ARC_POLICY_UNAVAILABLE', // no policy bundle loaded -> fail closed
  'ARC_POLICY_MALFORMED', // bundle failed validation -> fail closed
  'ARC_POLICY_UNKNOWN_FIELD', // unknown field in bundle -> fail closed
  'ARC_AUTHORITY_NOT_ASSERTED', // no kernel-asserted authority for this turn
  'ARC_AUTHORITY_MODEL_CLAIMED', // authority arrived in a model-controlled payload
  'ARC_CLAIM_PREREQUISITE_UNMET', // claim released without its prerequisites

  // authentication / replay (S03)
  'ARC_AUTH_FORGED', // MAC does not verify
  'ARC_AUTH_UNAUTHENTICATED', // no authentication material at all
  'ARC_AUTH_KEY_UNAVAILABLE', // host key custody unavailable -> fail closed
  'ARC_AUTH_LEGACY_DIGEST', // legacy self-hash presented as authentication
  'ARC_REPLAY_NONCE_SEEN', // nonce already consumed in scope
  'ARC_REPLAY_SEQUENCE_REGRESSION', // sequence not monotonic in scope
  'ARC_REPLAY_STALE', // outside freshness window / clock skew bound
  'ARC_BINDING_MISMATCH', // right MAC, wrong run/task/workspace/operation
  'ARC_CAPABILITY_EXPIRED',
  'ARC_CAPABILITY_EXHAUSTED',
  'ARC_CAPABILITY_REVOKED',
  'ARC_CAPABILITY_UNKNOWN',

  // host ingestion (S04)
  'ARC_HOST_EVENT_INVALID', // host event failed its closed schema
  'ARC_HOST_EVENT_UNTRUSTED', // event did not come from an authenticated host path
  'ARC_MODEL_SELF_REPORT', // model asserted an effect; never a receipt
  'ARC_INGEST_CORRELATION_MISSING', // post-effect with no correlated pre-effect

  // evidence / invalidation (S05)
  'ARC_EVIDENCE_STALE',
  'ARC_EVIDENCE_INSUFFICIENT',
  'ARC_DEPENDENCY_UNKNOWN',
  'ARC_STORE_CORRUPT', // digest chain broken -> quarantine, block strong claims

  // pre-effect gate (deliverable 6)
  'ARC_GATE_UNAVAILABLE', // gate could not run -> mutation fails closed
  'ARC_NO_CONTRACT', // mutation without an execution contract (G2)
  'ARC_CONTRACT_NOT_EXECUTABLE', // openQuestions non-empty (G9)
  'ARC_CONTRACT_VERSION_MISMATCH',
  'ARC_PATH_NOT_OWNED',
  'ARC_PATH_FORBIDDEN',
  'ARC_EFFECT_CLASS_UNAUTHORIZED',
  'ARC_LATITUDE_VIOLATION',
  'ARC_APPROVAL_REQUIRED',

  // kernel dependency (Wave-2 sequencing)
  'ARC_KERNEL_PRIMITIVE_UNAVAILABLE', // Lane D primitive not landed yet
]);

const CODES = new Set(ARCANE_ERROR_CODE);

export class ArcaneError extends Error {
  /**
   * @param {string} code one of ARCANE_ERROR_CODE
   * @param {string} message human-readable, never contains secret material
   * @param {object} [detail] structured context: { subject, expected, actual, ... }
   */
  constructor(code, message, detail = {}) {
    if (!CODES.has(code)) throw new TypeError(`unknown ArcaneError code: ${code}`);
    super(message);
    this.name = 'ArcaneError';
    this.code = code;
    this.detail = Object.freeze({ ...detail });
    /**
     * true when the refusal is because enforcement itself was unavailable
     * (ARCHITECTURE §24a: "if the pre-effect gate is unavailable,
     * mutation-bearing operations fail closed"). Distinct from a denial,
     * where enforcement ran and said no.
     */
    this.failClosed = FAIL_CLOSED_CODES.has(code);
  }

  toJSON() {
    return { code: this.code, message: this.message, detail: this.detail, failClosed: this.failClosed };
  }
}

const FAIL_CLOSED_CODES = new Set([
  'ARC_POLICY_UNAVAILABLE',
  'ARC_POLICY_MALFORMED',
  'ARC_POLICY_UNKNOWN_FIELD',
  'ARC_AUTH_KEY_UNAVAILABLE',
  'ARC_GATE_UNAVAILABLE',
  'ARC_STORE_CORRUPT',
  'ARC_KERNEL_PRIMITIVE_UNAVAILABLE',
]);

/** Convenience constructor. */
export function arcErr(code, message, detail) {
  return new ArcaneError(code, message, detail);
}

/**
 * A typed decision record. Every Arcane gate returns one of these rather than
 * throwing on denial — a denial is data the caller must record, not an
 * exception it may swallow.
 */
export function decision({ allowed, code = null, message = '', detail = {}, enforcementHealth = 'strong' }) {
  if (!allowed && code && !CODES.has(code)) {
    throw new TypeError(`unknown ArcaneError code: ${code}`);
  }
  return Object.freeze({
    allowed: Boolean(allowed),
    code,
    message,
    detail: Object.freeze({ ...detail }),
    failClosed: code ? FAIL_CLOSED_CODES.has(code) : false,
    enforcementHealth,
  });
}

/** Enforcement levels Arcane may honestly report (detailed plan §7.3). */
export const ENFORCEMENT_LEVEL = Object.freeze(['strong', 'observed', 'read_only', 'unsupported']);
