import { createHash } from 'node:crypto';

const EMAIL = /[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]{4,}/gi;
const SSN = /\b\d{3}-\d{2}-\d{4}\b/g;
const PHONE = /(?:\+\d[\d\s().-]{6,}\d|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b|\(\d{3}\)\s*\d{3}[-.\s]\d{4}\b)/g;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const normalize = (value) => String(value ?? '').replace(/[^a-z0-9]/gi, '').toLowerCase();
const commonSensitiveKey = (key) => /(?:secret|password|token|privatekey|apikey|cookie|authorization)$/.test(key) || ['email', 'phone', 'phonenumber', 'ssn', 'socialsecuritynumber', 'taxid'].includes(key);
const configuredKeys = (fields) => (Array.isArray(fields) ? fields : []).map((field) => typeof field === 'string' ? field : field?.path ?? field?.key).filter((field) => typeof field === 'string').map((field) => normalize(field.match(/[A-Za-z_$][A-Za-z0-9_$-]*$/)?.[0] ?? field));

const sanitizeString = (value) => value.replace(BEARER, '[REDACTED]').replace(EMAIL, '[REDACTED]').replace(SSN, '[REDACTED]').replace(PHONE, '[REDACTED]');

function sanitizeValue(value, configured, state) {
  if (Array.isArray(value)) return value.map((item) => sanitizeValue(item, configured, state));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, child]) => {
    const normalized = normalize(key);
    if (commonSensitiveKey(normalized) || configured.includes(normalized)) { if (child !== '[REDACTED]') state.changed = true; return [key, '[REDACTED]']; }
    return [key, sanitizeValue(child, configured, state)];
  }));
  if (typeof value !== 'string') return value;
  const sanitized = sanitizeString(value);
  if (sanitized !== value) state.changed = true;
  return sanitized;
}

export function sanitizeSensitiveValue(value, sensitiveFields = []) {
  const state = { changed: false };
  return { value: sanitizeValue(value, configuredKeys(sensitiveFields), state), sensitive: state.changed };
}

export function sanitizeArtifactContent(artifact, sensitiveFields = []) {
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) return { artifact, sensitive: false };
  const hasContent = typeof artifact.content === 'string';
  const hasBytes = typeof artifact.bytesBase64 === 'string';
  if (hasContent === hasBytes) return { artifact, sensitive: false };
  if (hasBytes && !isCanonicalBase64(artifact.bytesBase64)) return { artifact: null, sensitive: true, invalid: true };
  const original = hasContent ? artifact.content : Buffer.from(artifact.bytesBase64, 'base64').toString('utf8');
  const state = { changed: false };
  let sanitized;
  try { sanitized = JSON.stringify(sanitizeValue(JSON.parse(original), configuredKeys(sensitiveFields), state)); }
  catch { sanitized = sanitizeString(original); state.changed = sanitized !== original; }
  if (!state.changed) return { artifact, sensitive: false };
  const { content: _content, bytesBase64: _bytesBase64, digest: _digest, ...rest } = artifact;
  return { sensitive: true, artifact: { ...rest, content: sanitized, digest: `sha256:${createHash('sha256').update(sanitized).digest('hex')}` } };
}

export function isCanonicalBase64(value) {
  if (typeof value !== 'string' || !BASE64.test(value)) return false;
  try { return Buffer.from(value, 'base64').toString('base64') === value; }
  catch { return false; }
}

export function sanitizeProducedArtifact(artifact, sensitiveFields = []) {
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) return { artifact: null, valid: false, sensitive: false };
  const hasContent = typeof artifact.content === 'string', hasBytes = typeof artifact.bytesBase64 === 'string';
  if (hasContent === hasBytes) return { artifact: null, valid: false, sensitive: false };
  const bytes = hasContent ? Buffer.from(artifact.content, 'utf8') : isCanonicalBase64(artifact.bytesBase64) ? Buffer.from(artifact.bytesBase64, 'base64') : null;
  if (!bytes?.length || artifact.digest !== `sha256:${createHash('sha256').update(bytes).digest('hex')}`) return { artifact: null, valid: false, sensitive: false };
  return { ...sanitizeArtifactContent(artifact, sensitiveFields), valid: true };
}
