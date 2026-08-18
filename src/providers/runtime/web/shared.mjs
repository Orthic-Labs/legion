import { createHash } from 'node:crypto';

export const CAPABILITY_STATUSES = Object.freeze(['available', 'unavailable', 'unsupported', 'permission-denied', 'stale', 'partial']);
export const RESULT_STATUSES = Object.freeze(['pass', 'fail', 'partial', 'unproven', 'blocked', 'error']);
export const BINDING_KEYS = Object.freeze(['targetId', 'environment', 'actorId', 'tenantId', 'browser', 'browserVersion', 'viewport', 'locale', 'sourceRevision', 'artifactDigest']);

const opaque = (type, value) => `opaque-${createHash('sha256').update(`${type}:${value}`).digest('hex').slice(0, 24)}`;

export function canonicalize(value, seen = new Map()) {
  if (typeof value === 'bigint') return opaque('bigint', value.toString());
  if (typeof value === 'symbol') return opaque('symbol', Symbol.keyFor(value) ?? value.description ?? '');
  if (typeof value === 'function') return opaque('function', `${value.name}:${value.length}`);
  if (typeof value === 'undefined') return 'opaque-undefined';
  if (Array.isArray(value) || value && typeof value === 'object') {
    if (seen.has(value)) return `opaque-cycle-${seen.get(value)}`;
    const index = seen.size; seen.set(value, index);
    if (Array.isArray(value)) return value.map((item) => canonicalize(item, seen));
    return Object.fromEntries(Object.keys(value).sort().map((key) => { try { return [key, canonicalize(value[key], seen)]; } catch { return [key, opaque('unreadable', key)]; } }));
  }
  return value;
}

export function digest(value) {
  return `sha256:${createHash('sha256').update(JSON.stringify(canonicalize(value))).digest('hex')}`;
}

export function sortById(values = []) {
  return [...values].sort((left, right) => String(left.id ?? left.controlId ?? left.name ?? '').localeCompare(String(right.id ?? right.controlId ?? right.name ?? '')) || JSON.stringify(canonicalize(left)).localeCompare(JSON.stringify(canonicalize(right))));
}

export function exactBinding(binding = {}) {
  const source = binding && typeof binding === 'object' && !Array.isArray(binding) ? binding : {};
  const invalid = BINDING_KEYS.filter((key) => typeof source[key] !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(source[key]));
  const extras = Object.keys(source).filter((key) => !BINDING_KEYS.includes(key));
  const normalized = Object.fromEntries([...BINDING_KEYS].sort().map((key) => [key, invalid.includes(key) ? opaque('binding', JSON.stringify(canonicalize(source[key]))) : source[key]]));
  const gaps = [...invalid, ...(extras.some(sensitiveKey) ? ['binding-extra-sensitive'] : []), ...(extras.some((key) => !sensitiveKey(key)) ? ['binding-extra-undeclared'] : [])];
  return { binding: normalized, gaps };
}

export function sameBinding(expected = {}, actual = {}) {
  return BINDING_KEYS.every((key) => expected[key] === actual[key]);
}

const SENSITIVE_KEYS = new Set(['apikey', 'apitoken', 'authorization', 'authorizationheader', 'clientsecret', 'cookie', 'email', 'password', 'passwd', 'phone', 'privatekey', 'secret', 'sessioncookie', 'setcookie', 'token', 'accesstoken', 'refreshtoken']);
const SENSITIVE_SUFFIXES = Object.freeze(['apikey', 'authorization', 'cookie', 'password', 'passwd', 'privatekey', 'secret', 'secretkey', 'token']);
const SENSITIVE_VALUE = /(bearer\s+\S+|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,})/gi;
const normalizedKey = (key) => String(key).replace(/[^A-Za-z0-9]/g, '').toLowerCase();
const sensitiveKey = (key) => { const normalized = normalizedKey(key); return SENSITIVE_KEYS.has(normalized) || SENSITIVE_SUFFIXES.some((suffix) => normalized.endsWith(suffix)); };

export function redact(value, key = '', seen = new WeakSet()) {
  if (sensitiveKey(key) && (!value || typeof value !== 'object' || Array.isArray(value))) return '[REDACTED]';
  if (Array.isArray(value) || value && typeof value === 'object') {
    if (seen.has(value)) return 'opaque-cycle-redacted';
    seen.add(value);
    const redacted = Array.isArray(value) ? value.map((item) => redact(item, '', seen)) : Object.fromEntries(Object.entries(value).map(([childKey, child]) => [childKey, redact(child, childKey, seen)]));
    seen.delete(value);
    return redacted;
  }
  if (typeof value === 'string') return value.replace(SENSITIVE_VALUE, '[REDACTED]');
  return value;
}

export function denominator(expected = [], receipts = [], omitted = []) {
  const expectedIds = [...new Set(expected)].sort();
  const receiptIds = new Set(receipts.map((item) => item.id ?? item.controlId));
  const omittedIds = new Set(omitted.map((item) => item.id));
  const missing = expectedIds.filter((id) => !receiptIds.has(id) && !omittedIds.has(id));
  return { total: expectedIds.length, accounted: expectedIds.length - missing.length, receipts: receiptIds.size, omitted: omittedIds.size, missing, expectedIds };
}

export function finalize(kind, value) {
  const bindingGaps = [];
  const normalizeBindings = (current, key = '', seen = new Map()) => {
    if (key === 'binding') { const result = exactBinding(current); bindingGaps.push(...result.gaps); return result.binding; }
    if (Array.isArray(current) || current && typeof current === 'object') {
      if (seen.has(current)) return `opaque-cycle-${seen.get(current)}`;
      const index = seen.size; seen.set(current, index);
      if (Array.isArray(current)) return current.map((item) => normalizeBindings(item, '', seen));
      return Object.fromEntries(Object.keys(current).sort().map((childKey) => { try { return [childKey, normalizeBindings(current[childKey], childKey, seen)]; } catch { return [childKey, opaque('unreadable', childKey)]; } }));
    }
    return current;
  };
  let safeValue = normalizeBindings(value);
  if (bindingGaps.length) safeValue = { ...safeValue, status: 'error', terminal: true, ...(Object.hasOwn(safeValue, 'complete') ? { complete: false } : {}), ...(Object.hasOwn(safeValue, 'proof') ? { proof: false } : {}), coverageGaps: [...new Set([...(Array.isArray(safeValue.coverageGaps) ? safeValue.coverageGaps : []), ...bindingGaps.map((gap) => gap.startsWith('binding-extra-') ? gap : `binding-invalid:${gap}`)])].sort() };
  const normalized = canonicalize({ schemaVersion: 1, kind, ...safeValue });
  return { ...normalized, digest: digest(normalized) };
}
