// S03 — lib/receipt-auth.mjs
//
// HMAC-SHA256 authentication over an explicit bound-field list. Mandatory
// negative coverage (task dispatch + INTERFACES.md §S03): forged MAC, altered
// signed data, shrunken bound-field list re-signed, legacy Forge
// `signature_or_mac` self-hash, missing key, caller-selected authority, and
// wrong run/session/workspace/operation binding. Positive coverage: a
// correctly signed record verifies, and a real effect-receipt-v1 object
// built around it satisfies assertValid.

import assert from 'node:assert/strict';
import test from 'node:test';
import { signRecord, verifyRecord, EFFECT_RECEIPT_BOUND_FIELDS, EVIDENCE_RECEIPT_BOUND_FIELDS } from '../src/lib/guard/compat/audit/receipt-auth.mjs';
import { generateTestKeyRing } from '../src/lib/guard/compat/host/keys.mjs';
import { assertValid } from '../src/lib/contracts/arcane/validate.mjs';
import { mintId } from '../src/lib/contracts/arcane/ids.mjs';
import { ArcaneError } from '../src/lib/contracts/arcane/errors.mjs';

const BOUND_FIELDS = ['runId', 'taskId', 'workspace', 'operation', 'sessionId', 'payload'];

function baseRecord(overrides = {}) {
  return {
    runId: 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV',
    taskId: 'T-1',
    workspace: 'ws-main',
    operation: 'FILE_WRITE',
    sessionId: 'sess-1',
    payload: { path: 'a.txt' },
    ...overrides,
  };
}

test('EFFECT_RECEIPT_BOUND_FIELDS / EVIDENCE_RECEIPT_BOUND_FIELDS are non-empty and exclude self-referential fields', () => {
  assert.ok(Array.isArray(EFFECT_RECEIPT_BOUND_FIELDS));
  assert.ok(Array.isArray(EVIDENCE_RECEIPT_BOUND_FIELDS));
  assert.ok(EFFECT_RECEIPT_BOUND_FIELDS.length > 0);
  assert.ok(EVIDENCE_RECEIPT_BOUND_FIELDS.length > 0);
  assert.ok(!EFFECT_RECEIPT_BOUND_FIELDS.includes('authentication'));
  assert.ok(!EFFECT_RECEIPT_BOUND_FIELDS.includes('replayDefense'));
  assert.ok(!EVIDENCE_RECEIPT_BOUND_FIELDS.includes('authentication'));
  assert.ok(!EVIDENCE_RECEIPT_BOUND_FIELDS.includes('replayDefense'));
  assert.ok(!EVIDENCE_RECEIPT_BOUND_FIELDS.includes('stale'), 'stale mutates after issuance and must not be signed');
});

test('positive: a correctly signed record verifies', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = baseRecord();
  const auth = signRecord(record, { keyRing, keyId: 'k1', boundFields: BOUND_FIELDS });
  assert.equal(auth.alg, 'HMAC-SHA256');
  assert.equal(auth.keyId, 'k1');
  assert.match(auth.mac, /^[0-9a-f]{64}$/);
  assert.match(auth.boundFieldsDigest, /^sha256:[0-9a-f]{64}$/);

  const result = verifyRecord(record, auth, { keyRing, boundFields: BOUND_FIELDS });
  assert.equal(result.allowed, true);
  assert.equal(result.code, null);
});

test('reject: forged MAC', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = baseRecord();
  const auth = signRecord(record, { keyRing, keyId: 'k1', boundFields: BOUND_FIELDS });
  const forged = { ...auth, mac: auth.mac.replace(/^./, auth.mac[0] === '0' ? '1' : '0') };
  const result = verifyRecord(record, forged, { keyRing, boundFields: BOUND_FIELDS });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_AUTH_FORGED');
});

test('reject: altered signed data (mutate a bound field after signing)', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = baseRecord();
  const auth = signRecord(record, { keyRing, keyId: 'k1', boundFields: BOUND_FIELDS });
  const mutated = { ...record, payload: { path: 'b.txt' } };
  const result = verifyRecord(mutated, auth, { keyRing, boundFields: BOUND_FIELDS });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_AUTH_FORGED');
});

test('reject: shrunken bound-field list re-signed (boundFieldsDigest mismatch)', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = baseRecord();
  const shrunkFields = BOUND_FIELDS.filter((f) => f !== 'workspace');
  const auth = signRecord(record, { keyRing, keyId: 'k1', boundFields: shrunkFields });
  // Verifier insists on the full canonical field list.
  const result = verifyRecord(record, auth, { keyRing, boundFields: BOUND_FIELDS });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_AUTH_FORGED');
});

test('reject: legacy Forge signature_or_mac self-hash presented as authentication', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = baseRecord();
  const legacyAuth = { signature_or_mac: 'deadbeef'.repeat(8) };
  const result = verifyRecord(record, legacyAuth, { keyRing, boundFields: BOUND_FIELDS });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_AUTH_LEGACY_DIGEST');
});

test('reject: legacy signature_or_mac takes priority even alongside a well-formed-looking mac', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = baseRecord();
  const auth = signRecord(record, { keyRing, keyId: 'k1', boundFields: BOUND_FIELDS });
  const mixed = { ...auth, signature_or_mac: 'deadbeef'.repeat(8) };
  const result = verifyRecord(record, mixed, { keyRing, boundFields: BOUND_FIELDS });
  assert.equal(result.code, 'ARC_AUTH_LEGACY_DIGEST');
});

test('reject: missing authentication material -> ARC_AUTH_UNAUTHENTICATED', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = baseRecord();
  const result = verifyRecord(record, null, { keyRing, boundFields: BOUND_FIELDS });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_AUTH_UNAUTHENTICATED');
});

test('reject: missing key -> ARC_AUTH_KEY_UNAVAILABLE, failClosed === true (throws)', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = baseRecord();
  const auth = signRecord(record, { keyRing, keyId: 'k1', boundFields: BOUND_FIELDS });
  const unknownKeyRing = generateTestKeyRing(['other']);
  assert.throws(() => verifyRecord(record, auth, { keyRing: unknownKeyRing, boundFields: BOUND_FIELDS }), (err) => {
    assert.ok(err instanceof ArcaneError);
    assert.equal(err.code, 'ARC_AUTH_KEY_UNAVAILABLE');
    assert.equal(err.failClosed, true);
    return true;
  });
});

test('signRecord() with a missing key propagates ARC_AUTH_KEY_UNAVAILABLE, failClosed === true', () => {
  const keyRing = generateTestKeyRing(['k1']);
  assert.throws(() => signRecord(baseRecord(), { keyRing, keyId: 'ghost', boundFields: BOUND_FIELDS }), (err) => {
    assert.equal(err.code, 'ARC_AUTH_KEY_UNAVAILABLE');
    assert.equal(err.failClosed, true);
    return true;
  });
});

test('reject: caller-selected authority (a record asserting its own authority value)', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = { ...baseRecord(), authority: 'operator' };
  const fields = [...BOUND_FIELDS, 'authority'];
  const auth = signRecord(record, { keyRing, keyId: 'k1', boundFields: fields });
  const result = verifyRecord(record, auth, { keyRing, boundFields: fields });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_AUTHORITY_MODEL_CLAIMED');
});

test('reject: wrong run binding', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = baseRecord();
  const auth = signRecord(record, { keyRing, keyId: 'k1', boundFields: BOUND_FIELDS });
  const result = verifyRecord(record, auth, {
    keyRing, boundFields: BOUND_FIELDS, expectedBinding: { runId: 'run_00000000000000000000000000' },
  });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_BINDING_MISMATCH');
});

test('reject: wrong session binding', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = baseRecord();
  const auth = signRecord(record, { keyRing, keyId: 'k1', boundFields: BOUND_FIELDS });
  const result = verifyRecord(record, auth, { keyRing, boundFields: BOUND_FIELDS, expectedBinding: { sessionId: 'sess-other' } });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_BINDING_MISMATCH');
});

test('reject: wrong workspace binding', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = baseRecord();
  const auth = signRecord(record, { keyRing, keyId: 'k1', boundFields: BOUND_FIELDS });
  const result = verifyRecord(record, auth, { keyRing, boundFields: BOUND_FIELDS, expectedBinding: { workspace: 'ws-other' } });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_BINDING_MISMATCH');
});

test('reject: wrong operation/arguments binding', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const record = baseRecord();
  const auth = signRecord(record, { keyRing, keyId: 'k1', boundFields: BOUND_FIELDS });
  const result = verifyRecord(record, auth, { keyRing, boundFields: BOUND_FIELDS, expectedBinding: { operation: 'FILE_DELETE' } });
  assert.equal(result.allowed, false);
  assert.equal(result.code, 'ARC_BINDING_MISMATCH');
});

test('positive: a valid effect-receipt-v1 record satisfies assertValid after signing/verification', () => {
  const keyRing = generateTestKeyRing(['k1']);
  const receipt = {
    schemaVersion: 1,
    kind: 'legion-effect-receipt',
    receiptId: mintId('effectReceipt'),
    requestId: 'req_01ARZ3NDEKTSV4RRFFQ69G5FAV',
    runId: 'run_01ARZ3NDEKTSV4RRFFQ69G5FAV',
    contractId: 'EC-1',
    taskId: 'T-1',
    requested: { effectClass: 'FILE_WRITE', target: 'a.txt', operation: 'write' },
    authorized: { effectClass: 'FILE_WRITE', target: 'a.txt', operation: 'write', capabilityId: 'cap_1' },
    observed: { effectClass: 'FILE_WRITE', target: 'a.txt', operation: 'write' },
    match: true,
    sourceRevision: '0123abcd',
    replayOf: null,
    idempotencyKey: 'idem-1',
    observedAt: new Date().toISOString(),
  };
  const auth = signRecord(receipt, { keyRing, keyId: 'k1', boundFields: EFFECT_RECEIPT_BOUND_FIELDS });
  const verified = verifyRecord(receipt, auth, { keyRing, boundFields: EFFECT_RECEIPT_BOUND_FIELDS });
  assert.equal(verified.allowed, true);

  const finalReceipt = {
    ...receipt,
    authentication: {
      issuerIdentity: `key:${auth.keyId}`,
      verificationMethod: 'capability-signature',
      perMessage: true,
      verifiedAt: new Date().toISOString(),
    },
    replayDefense: { nonce: 'n-1', sequence: 1, freshnessWindowSeconds: 300, freshAt: new Date().toISOString() },
  };
  assertValid('effect-receipt-v1', finalReceipt);
});
