// Canonical serialization + digests.
//
// Every HMAC and per-record digest uses canonical serialization. This module is
// the single implementation; nothing in Arcane may hand-roll
// JSON.stringify over a security-relevant value.
//
// Rules (deliberately strict — ambiguity here is a forgery surface):
//   - object keys sorted by code unit, recursively;
//   - no insignificant whitespace;
//   - `undefined` and functions are rejected, never silently dropped;
//   - non-finite numbers are rejected (NaN/Infinity have no JSON form);
//   - -0 normalizes to 0;
//   - integers and floats serialize via JS number formatting (no exponent
//     rewriting) — Arcane never puts a float in a signed field, and the
//     validator enforces integer-typed fields upstream;
//   - Date instances are rejected: callers must pass ISO strings, so the
//     serialization is stable across timezone/precision behavior.

import { createHash, timingSafeEqual } from 'node:crypto';
import { ArcaneError } from './errors.mjs';

function fail(path, message) {
  throw new ArcaneError('ARC_CANONICALIZATION_FAILED', `${message} at ${path || '<root>'}`, { path });
}

function encode(value, path) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(value)) fail(path, 'non-finite number');
    return Object.is(value, -0) ? '0' : String(value);
  }
  if (t === 'string') return JSON.stringify(value);
  if (t === 'bigint') fail(path, 'bigint has no canonical JSON form');
  if (t === 'undefined') fail(path, 'undefined is not encodable');
  if (t === 'function' || t === 'symbol') fail(path, `${t} is not encodable`);
  if (Array.isArray(value)) {
    return `[${value.map((v, i) => encode(v, `${path}[${i}]`)).join(',')}]`;
  }
  if (value instanceof Date) fail(path, 'Date is not encodable — pass an ISO 8601 string');
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    fail(path, 'only plain objects are encodable');
  }
  const keys = Object.keys(value).sort();
  const parts = [];
  for (const k of keys) {
    const v = value[k];
    if (v === undefined) fail(`${path}.${k}`, 'undefined property');
    parts.push(`${JSON.stringify(k)}:${encode(v, `${path}.${k}`)}`);
  }
  return `{${parts.join(',')}}`;
}

/** Canonical JSON text for `value`. Throws ArcaneError on unencodable input. */
export function canonicalJson(value) {
  return encode(value, '');
}

/** Raw lowercase hex sha256 of a string or Buffer. */
export function sha256Hex(input) {
  return createHash('sha256').update(typeof input === 'string' ? Buffer.from(input, 'utf8') : input).digest('hex');
}

/** Repo-wide digest form: `sha256:<64 lowercase hex>` (ids.md). */
export function digest(input) {
  return `sha256:${sha256Hex(input)}`;
}

/** Digest of the canonical serialization of a structured value. */
export function digestValue(value) {
  return digest(canonicalJson(value));
}

export const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;

export function isDigest(value) {
  return typeof value === 'string' && DIGEST_PATTERN.test(value);
}

/**
 * Constant-time comparison of two hex strings / Buffers of equal length.
 * Returns false (never throws) on length mismatch, so callers cannot leak
 * length information through an exception path.
 */
export function constantTimeEqual(a, b) {
  const ba = typeof a === 'string' ? Buffer.from(a, 'utf8') : a;
  const bb = typeof b === 'string' ? Buffer.from(b, 'utf8') : b;
  if (!Buffer.isBuffer(ba) || !Buffer.isBuffer(bb)) return false;
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

/**
 * Project a record down to an explicit field list before signing. Detailed
 * plan §4.2: an HMAC must cover *bound fields*, and which fields are bound
 * must be explicit rather than "whatever happened to be on the object".
 * Missing bound fields are an error, not an implicit null.
 */
export function projectBoundFields(record, fields) {
  const out = {};
  for (const f of fields) {
    if (!Object.prototype.hasOwnProperty.call(record, f)) {
      throw new ArcaneError('ARC_CANONICALIZATION_FAILED', `bound field missing: ${f}`, { field: f });
    }
    out[f] = record[f];
  }
  return out;
}
