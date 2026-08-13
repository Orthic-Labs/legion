// S03 — authenticated receipts: HMAC over an explicit bound-field list.
//
// This replaces, rather than upgrades, predecessor's `signature_or_mac`. S00 finding 1:
// that field is `hook:${sha256(receipt)}` computed by the same untrusted process
// that built the receipt — no secret key, no MAC, no signature. Nothing here
// derives from it, and presenting one is an explicit refusal
// (ARC_AUTH_LEGACY_DIGEST), never a downgrade path.
//
// Three properties the design turns on:
//
//   1. **The bound-field list is itself authenticated.** `boundFieldsDigest`
//      covers the ordered field names, so an attacker who can re-sign cannot
//      quietly shrink the covered set (drop `workspace`, keep a valid MAC).
//      The verifier recomputes it from ITS OWN expected list and compares
//      before it even looks at the MAC.
//   2. **Authority is never self-asserted.** A record that carries its own
//      `authority` field is refused outright, even when the MAC is perfect.
//      Authority identity is asserted by the kernel per turn (ARCHITECTURE
//      §24a), so a correctly signed self-assertion is still a forged claim —
//      it just proves the signer held a key, not that it holds that authority.
//   3. **Binding is checked separately from the MAC.** A valid signature over
//      the wrong run/session/workspace/operation is ARC_BINDING_MISMATCH, not
//      ARC_AUTH_FORGED: the two failures have different remediations and must
//      not be confused in an incident.
//
// A missing key is a *fail-closed throw*, not a denial: Arcane cannot say
// "this is unauthenticated" when the truth is "I could not check."

import { createHmac } from 'node:crypto';

import { ArcaneError, decision } from './errors.mjs';
import { canonicalJson, digest, projectBoundFields, constantTimeEqual } from './canonical.mjs';

export const MAC_ALGORITHM = 'HMAC-SHA256';

/**
 * Fields of `effect-receipt-v1` covered by the MAC.
 *
 * Excluded on purpose:
 *   - `authentication` — it *carries* the MAC; signing it is circular.
 *   - `replayDefense` — nonce/sequence/freshness are checked by lib/replay.mjs
 *     against the receipt store's view, and `freshAt` is stamped at verify
 *     time by the verifier, not by the issuer.
 *   - `result` — Arcane may reconcile a receipt's result after observation
 *     (requested vs authorized vs observed, §24a) without invalidating the
 *     issuer's signature over what was actually claimed.
 */
export const EFFECT_RECEIPT_BOUND_FIELDS = Object.freeze([
  'schemaVersion',
  'kind',
  'receiptId',
  'requestId',
  'runId',
  'contractId',
  'taskId',
  'requested',
  'authorized',
  'observed',
  'match',
  'sourceRevision',
  'idempotencyKey',
  'observedAt',
]);

/**
 * Fields of `evidence-capability-receipt-v1` covered by the MAC.
 * `stale` is excluded deliberately: it is set by the S05 invalidation cascade
 * AFTER issuance, and a receipt must not become unverifiable the moment its
 * dependencies change — staleness is a separate, appended fact.
 */
export const EVIDENCE_RECEIPT_BOUND_FIELDS = Object.freeze([
  'schemaVersion',
  'kind',
  'evidenceId',
  'runId',
  'taskId',
  'contractId',
  'producerAuthority',
  'capability',
  'observation',
  'evidenceClass',
  'sourceRevision',
  'dependsOn',
  'observedAt',
]);

/**
 * Fields a record may never assert about itself. A signed record carrying one
 * of these is refused: holding a signing key proves the signer is a trusted
 * issuer, not that it holds the authority it names.
 */
const SELF_ASSERTED_AUTHORITY_FIELDS = Object.freeze([
  'authority',
  'callerAuthority',
  'assertedAuthority',
  'trust_class',
  'trustClass',
]);

/** Bindings the verifier can constrain, and where each lives on a record. */
const BINDING_FIELDS = Object.freeze(['runId', 'taskId', 'workspace', 'workspaceId', 'operation', 'sessionId', 'contractId']);

function digestOfBoundFieldList(boundFields) {
  // Order matters: the same set in a different order is a different covered
  // message, so the digest is over the ordered list as written.
  return digest(canonicalJson([...boundFields]));
}

function macOver(key, record, boundFields, macDomain = null) {
  const projected = projectBoundFields(record, boundFields);
  const message = canonicalJson(macDomain === null ? {
    alg: MAC_ALGORITHM,
    boundFields: [...boundFields],
    subject: projected,
  } : {
    alg: MAC_ALGORITHM,
    boundFields: [...boundFields],
    macDomain,
    subject: projected,
  });
  return createHmac('sha256', key).update(message, 'utf8').digest('hex');
}

/**
 * Sign `record` over `boundFields` with the key `keyId` from `keyRing`.
 * @returns {{alg: string, keyId: string, mac: string, boundFieldsDigest: string}}
 * @throws {ArcaneError} ARC_AUTH_KEY_UNAVAILABLE (failClosed) when the key is absent.
 */
export function signRecord(record, { keyRing, keyId, boundFields, macDomain = null }) {
  if (!Array.isArray(boundFields) || boundFields.length === 0) {
    throw new ArcaneError('ARC_CANONICALIZATION_FAILED', 'signRecord requires a non-empty boundFields list', {});
  }
  const entry = keyRing.get(keyId); // throws ARC_AUTH_KEY_UNAVAILABLE
  return {
    alg: MAC_ALGORITHM,
    keyId: entry.keyId,
    mac: macOver(entry.key, record, boundFields, macDomain),
    ...(macDomain === null ? {} : { macDomain }),
    boundFieldsDigest: digestOfBoundFieldList(boundFields),
  };
}

/**
 * Verify `auth` over `record`.
 *
 * Returns a decision (a denial is data the caller must record). The one case
 * that throws is an unavailable key — Arcane must not report "unauthenticated"
 * when it means "could not verify".
 *
 * @param {object} record
 * @param {object|null} auth
 * @param {{keyRing: object, boundFields: string[], expectedBinding?: object}} ctx
 */
export function verifyRecord(record, auth, { keyRing, boundFields, expectedBinding = {}, macDomain = undefined }) {
  // 1. Legacy self-hash — checked FIRST, so a record cannot smuggle one past
  //    the verifier by also carrying a well-formed `mac`. S03 action 11:
  //    imported only as unauthenticated legacy metadata, never as proof.
  if (auth && typeof auth === 'object' && 'signature_or_mac' in auth) {
    return decision({
      allowed: false,
      code: 'ARC_AUTH_LEGACY_DIGEST',
      message:
        'legacy predecessor signature_or_mac is a self-hash by the producing process, not authentication (S00 finding 1)',
      detail: { field: 'signature_or_mac' },
    });
  }

  // 2. No authentication material at all.
  if (!auth || typeof auth !== 'object' || typeof auth.mac !== 'string' || typeof auth.keyId !== 'string') {
    return decision({
      allowed: false,
      code: 'ARC_AUTH_UNAUTHENTICATED',
      message: 'no authentication material present on this record',
      detail: {},
    });
  }

  if (auth.alg !== MAC_ALGORITHM) {
    return decision({
      allowed: false,
      code: 'ARC_AUTH_FORGED',
      message: `unsupported MAC algorithm: ${auth.alg}`,
      detail: { alg: auth.alg, expected: MAC_ALGORITHM },
    });
  }

  if (macDomain !== undefined && auth.macDomain !== macDomain) {
    return decision({
      allowed: false,
      code: 'ARC_AUTH_FORGED',
      message: 'MAC domain does not match verifier requirement',
      detail: { expectedMacDomain: macDomain, presented: auth.macDomain ?? null },
    });
  }

  // 3. The covered field list must be exactly the one the verifier demands.
  //    Compared before the MAC so a shrunken-and-re-signed record fails here
  //    rather than appearing to verify over a narrower message.
  const expectedFieldsDigest = digestOfBoundFieldList(boundFields);
  if (!constantTimeEqual(auth.boundFieldsDigest ?? '', expectedFieldsDigest)) {
    return decision({
      allowed: false,
      code: 'ARC_AUTH_FORGED',
      message: 'signed bound-field list does not match the verifier’s required field list',
      detail: { expectedBoundFieldsDigest: expectedFieldsDigest, presented: auth.boundFieldsDigest ?? null },
    });
  }

  // 4. Key must be present and usable. Absent key => fail closed, not "denied".
  const entry = keyRing.get(auth.keyId); // throws ARC_AUTH_KEY_UNAVAILABLE
  if (entry.status === 'revoked') {
    return decision({
      allowed: false,
      code: 'ARC_CAPABILITY_REVOKED',
      message: `signing key ${auth.keyId} is revoked`,
      detail: { keyId: auth.keyId },
    });
  }

  // 5. The MAC itself. A missing bound field throws
  //    ARC_CANONICALIZATION_FAILED rather than hashing an implicit null.
  let expectedMac;
  try {
    expectedMac = macOver(entry.key, record, boundFields, macDomain === undefined ? (auth.macDomain ?? null) : macDomain);
  } catch (err) {
    if (err instanceof ArcaneError && err.code === 'ARC_CANONICALIZATION_FAILED') {
      return decision({
        allowed: false,
        code: 'ARC_AUTH_FORGED',
        message: `record is missing a bound field: ${err.detail.field ?? 'unknown'}`,
        detail: { ...err.detail },
      });
    }
    throw err;
  }
  if (!constantTimeEqual(auth.mac, expectedMac)) {
    return decision({
      allowed: false,
      code: 'ARC_AUTH_FORGED',
      message: 'MAC does not verify over the bound fields',
      detail: { keyId: auth.keyId },
    });
  }

  // 6. A valid MAC over a self-asserted authority is still not authority.
  //    Checked after the MAC so the message is accurate: the signature is
  //    genuine, the claim is not admissible.
  for (const field of SELF_ASSERTED_AUTHORITY_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(record, field)) {
      return decision({
        allowed: false,
        code: 'ARC_AUTHORITY_MODEL_CLAIMED',
        message: `record asserts its own authority via '${field}'; authority is kernel-asserted per turn, never carried in the payload`,
        detail: { field, value: String(record[field]) },
      });
    }
  }

  // 7. Right signature, wrong subject. Distinct from a forgery.
  for (const field of BINDING_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(expectedBinding, field)) continue;
    if (record[field] !== expectedBinding[field]) {
      return decision({
        allowed: false,
        code: 'ARC_BINDING_MISMATCH',
        message: `authenticated record is bound to a different ${field}`,
        detail: { field, expected: expectedBinding[field], actual: record[field] ?? null },
      });
    }
  }

  return decision({
    allowed: true,
    detail: { keyId: auth.keyId, boundFields: [...boundFields] },
  });
}

/**
 * The `authentication` block to attach to a receipt after a successful verify.
 * `perMessage: true` is only ever set from a real per-message MAC check —
 * connection-level trust must report `host-connection-trust` + `perMessage:false`
 * and accept the honest downgrade (ARCHITECTURE §24a, S00 finding 2).
 */
export function authenticationBlock({ keyId, verifiedAt = new Date().toISOString() }) {
  return {
    issuerIdentity: `key:${keyId}`,
    verificationMethod: 'capability-signature',
    perMessage: true,
    verifiedAt,
  };
}

/** The honest downgrade when only connection-level trust is available. */
export function connectionTrustBlock({ issuerIdentity, verifiedAt = null }) {
  return {
    issuerIdentity,
    verificationMethod: 'host-connection-trust',
    perMessage: false,
    verifiedAt,
  };
}
