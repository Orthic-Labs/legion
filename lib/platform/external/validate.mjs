import { verify as verifySignature } from 'node:crypto';
import { sha256 } from '../contracts.mjs';
import { isCanonicalBase64, sanitizeArtifactContent, sanitizeProducedArtifact } from '../artifact-sanitize.mjs';

const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  return value;
};
const equal = (left, right) => JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
const utc = (value) => typeof value === 'string' && value.endsWith('Z') && Number.isFinite(Date.parse(value)) ? Date.parse(value) : null;
const safePath = (value) => { if (typeof value !== 'string' || !value || value.includes('\\') || value.startsWith('/') || /^[A-Za-z]:/.test(value)) return false; const segments = value.split('/'); return segments.length > 1 && segments.every((segment) => /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(segment) && segment !== '.' && segment !== '..') && segments.join('/') === value; };
const artifactValid = (artifact, binding) => {
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact) || !safePath(artifact.path) || !equal(artifact.binding, binding)) return false;
  return sanitizeProducedArtifact(artifact).valid;
};

export function validateExternalEvidence(evidence, expected = {}) {
  const gaps = [];
  for (const key of ['producer', 'scope', 'targetId', 'environment', 'artifactDigest', 'controlId', 'binding', 'issuedAt', 'checkedAt', 'expiresAt']) if (!evidence?.[key]) gaps.push(`missing-${key}`);
  let payload = null;
  const trusted = expected.trustedProducers?.find((item) => item.id === evidence?.producer);
  if (!trusted) gaps.push('producer-untrusted');
  if (typeof evidence?.signedContent !== 'string' || typeof evidence?.signature !== 'string') gaps.push('signature-unproven');
  else if (!isCanonicalBase64(evidence.signature)) gaps.push('signature-noncanonical');
  else if (trusted) { try { if (!verifySignature(null, Buffer.from(evidence.signedContent), trusted.publicKey, Buffer.from(evidence.signature, 'base64'))) gaps.push('signature-invalid'); else payload = JSON.parse(evidence.signedContent); } catch { gaps.push('signature-invalid'); } }
  for (const key of ['targetId', 'environment', 'artifactDigest', 'controlId']) {
    if (expected[key] !== undefined && payload?.[key] !== expected[key]) gaps.push(`mismatched-${key}`);
    if (payload && evidence?.[key] !== payload[key]) gaps.push(`envelope-${key}-mismatch`);
  }
  if (expected.scope !== undefined && payload?.scope !== expected.scope) gaps.push('mismatched-scope');
  if (payload?.producer !== evidence?.producer) gaps.push('mismatched-producer');
  if (payload && payload.scope !== evidence?.scope) gaps.push('envelope-scope-mismatch');
  if (expected.binding !== undefined && !equal(payload?.binding, expected.binding)) gaps.push('mismatched-binding');
  if (payload && !equal(evidence?.binding, payload.binding)) gaps.push('envelope-binding-mismatch');
  for (const key of ['issuedAt', 'checkedAt', 'expiresAt']) if (payload && evidence?.[key] !== payload[key]) gaps.push(`envelope-${key}-mismatch`);
  const issuedAt = utc(payload?.issuedAt), checkedAt = utc(payload?.checkedAt), expiresAt = utc(payload?.expiresAt), now = utc(expected.now);
  if (issuedAt === null) gaps.push('issuedAt-invalid');
  if (checkedAt === null) gaps.push('checkedAt-invalid');
  if (expiresAt === null) gaps.push('expiresAt-invalid');
  if (now === null) gaps.push('clock-invalid');
  if (!Number.isFinite(expected.maxAgeMs) || expected.maxAgeMs < 0) gaps.push('max-age-invalid');
  if ([issuedAt, checkedAt, expiresAt, now].every((value) => value !== null)) {
    if (!(issuedAt <= checkedAt && checkedAt <= now && now <= expiresAt)) gaps.push('timestamp-order-invalid');
    if (now > expiresAt) gaps.push('evidence-expired');
    if (Number.isFinite(expected.maxAgeMs) && now - checkedAt > expected.maxAgeMs) gaps.push('evidence-stale');
  }
  const artifacts = payload?.artifacts ?? [];
  if (!Array.isArray(artifacts) || !artifacts.length || !artifacts.every((artifact) => artifactValid(artifact, payload?.binding))) gaps.push('produced-artifact-invalid');
  const sanitizedArtifacts = Array.isArray(artifacts) ? artifacts.map((artifact) => sanitizeArtifactContent(artifact, expected.sensitiveFields ?? artifact?.sensitiveFields ?? [])) : [];
  if (sanitizedArtifacts.some((item) => item.sensitive)) gaps.push('produced-artifact-sensitive-data');
  if (expected.requiresExercise) {
    if (payload?.exerciseReceipt?.terminal !== true || payload?.exerciseReceipt?.status !== 'pass' || payload.exerciseReceipt.controlId !== expected.controlId || !equal(payload.exerciseReceipt.binding, expected.binding)) gaps.push('exercise-required');
    if (!equal(evidence?.exerciseReceipt, payload?.exerciseReceipt)) gaps.push('envelope-exercise-mismatch');
  }
  const safePayload = payload && Array.isArray(artifacts) ? { ...payload, artifacts: sanitizedArtifacts.map((item) => item.artifact) } : payload;
  return { schemaVersion: 1, kind: 'nemesis-external-evidence-validation', evidenceDigest: evidence ? sha256(evidence) : null, status: gaps.length ? 'unproven' : 'pass', payload: safePayload, gaps: [...new Set(gaps)].sort() };
}
