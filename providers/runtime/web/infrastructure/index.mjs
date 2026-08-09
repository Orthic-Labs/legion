import { createHash, verify as verifySignature } from 'node:crypto';
import { isCanonicalBase64, sanitizeArtifactContent, sanitizeSensitiveValue } from '../../../../lib/platform/artifact-sanitize.mjs';
import { exactBinding, finalize, sameBinding } from '../shared.mjs';

const utcMillis = (value) => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) && Number.isFinite(Date.parse(value)) ? Date.parse(value) : null;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const safePath = (value) => { if (typeof value !== 'string' || !value || value.includes('\\') || value.startsWith('/') || /^[A-Za-z]:/.test(value)) return false; const segments = value.split('/'); return segments.length > 1 && segments.every((segment) => /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(segment) && segment !== '.' && segment !== '..') && segments.join('/') === value; };
const validArtifact = (artifact, binding) => {
  if (!artifact || !safePath(artifact.path) || !sameBinding(binding, artifact.binding ?? {}) || sanitizeArtifactContent(artifact).sensitive) return false;
  const hasContent = typeof artifact.content === 'string', hasBytes = typeof artifact.bytesBase64 === 'string';
  if (hasContent === hasBytes) return false;
  const bytes = hasContent ? Buffer.from(artifact.content, 'utf8') : BASE64.test(artifact.bytesBase64) ? Buffer.from(artifact.bytesBase64, 'base64') : null;
  return Boolean(bytes?.length) && artifact.digest === `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
};
const REQUIRED_CONTROLS = Object.freeze(['cdn', 'deployment', 'dns', 'drift', 'health', 'iam', 'infra', 'network', 'region', 'rollback', 'runtime', 'scaling', 'secrets', 'storage', 'tls']);
const typedFact = (fact) => fact && typeof fact === 'object' && !Array.isArray(fact) && typeof fact.id === 'string' && fact.id.length > 0 && typeof fact.kind === 'string';

function infrastructureFactGaps(payload, binding) {
  const gaps = [];
  const denominator = Array.isArray(payload.applicableControls) ? payload.applicableControls : [];
  if (JSON.stringify([...new Set(denominator)].sort()) !== JSON.stringify(REQUIRED_CONTROLS)) gaps.push('infrastructure-control-denominator-mismatch');
  const factsValid = Array.isArray(payload.controlFacts) && payload.controlFacts.every(typedFact);
  if (!factsValid) gaps.push('infrastructure-control-facts-invalid');
  const facts = factsValid ? payload.controlFacts : [];
  for (const id of REQUIRED_CONTROLS) {
    const matches = facts.filter((fact) => fact?.id === id);
    if (!matches.length) { gaps.push(`infrastructure-control-missing:${id}`); continue; }
    if (matches.length > 1) gaps.push(`infrastructure-control-duplicate:${id}`);
    const fact = matches[0];
    if (fact.kind !== 'infrastructure-control-fact' || fact.applicable !== true) gaps.push(`infrastructure-control-type-invalid:${id}`);
    if (fact.configured !== true) gaps.push(`infrastructure-control-not-configured:${id}`);
    if (fact.deployed !== true) gaps.push(`infrastructure-control-not-deployed:${id}`);
    if (fact.exercised !== true || fact.status !== 'pass' || fact.terminal !== true) gaps.push(`infrastructure-control-not-exercised:${id}`);
    if (!sameBinding(binding, fact.binding ?? {})) gaps.push(`infrastructure-control-binding-mismatch:${id}`);
    const artifacts = Array.isArray(fact.artifacts) ? fact.artifacts : [];
    if (!artifacts.length || !artifacts.every((artifact) => validArtifact(artifact, binding))) gaps.push(`infrastructure-control-artifact-invalid:${id}`);
  }
  for (const fact of facts) if (!REQUIRED_CONTROLS.includes(fact?.id)) gaps.push(`infrastructure-control-unplanned:${fact?.id ?? 'missing'}`);
  return gaps;
}

export function verifyInfrastructureExercise({ binding = {}, evidence = null, trustedProducers = [], now = null, maxAgeMs = null } = {}) {
  if (!Array.isArray(trustedProducers) || trustedProducers.some((item) => !item || typeof item !== 'object' || Array.isArray(item) || typeof item.id !== 'string' || !item.id || !item.publicKey)) return finalize('legion-web-infrastructure-exercise', { status: 'error', terminal: true, claimLevel: 'external', suppliedOnly: true, networkAttempted: false, binding, producer: evidence?.producer ?? null, payload: null, evidenceDigest: null, coverageGaps: [...exactBinding(binding).gaps.map((key) => `binding-missing:${key}`), 'trusted-producers-invalid'].sort() });
  const gaps = exactBinding(binding).gaps.map((key) => `binding-missing:${key}`);
  let payload = null;
  const producer = trustedProducers.find((item) => item.id === evidence?.producer);
  if (!evidence) gaps.push('supplied-evidence-missing');
  if (!producer) gaps.push('producer-untrusted');
  if (typeof evidence?.signedContent !== 'string' || typeof evidence?.signature !== 'string') gaps.push('signature-unproven');
  else if (!isCanonicalBase64(evidence.signature)) gaps.push('signature-noncanonical');
  else if (producer) { try { if (!verifySignature(null, Buffer.from(evidence.signedContent), producer.publicKey, Buffer.from(evidence.signature, 'base64'))) gaps.push('signature-invalid'); else payload = JSON.parse(evidence.signedContent); } catch { gaps.push('signature-invalid'); } }
  if (!payload) gaps.push('deployed-proof-required', 'rollback-not-exercised');
  else {
    if (payload.producer !== evidence.producer) gaps.push('producer-mismatch');
    for (const key of ['targetId', 'environment', 'artifactDigest']) if (payload[key] !== binding[key]) gaps.push(`${key}-mismatch`);
    if (!sameBinding(binding, payload.binding ?? {})) gaps.push('binding-mismatch');
    const issued = utcMillis(payload.issuedAt), checked = utcMillis(payload.checkedAt), current = utcMillis(now), expires = utcMillis(payload.expiresAt);
    for (const [key, value] of [['issuedAt', issued], ['checkedAt', checked], ['now', current], ['expiresAt', expires]]) if (value === null) gaps.push(`${key}-timestamp-invalid`);
    if (!Number.isFinite(maxAgeMs) || maxAgeMs < 0) gaps.push('freshness-window-invalid');
    if (issued !== null && checked !== null && issued > checked) gaps.push('issued-after-checked');
    if (checked !== null && current !== null && checked > current) gaps.push('checked-in-future');
    if (checked !== null && expires !== null && checked > expires) gaps.push('checked-after-expiry');
    if (current !== null && expires !== null && current > expires) gaps.push('evidence-expired');
    if (checked !== null && current !== null && Number.isFinite(maxAgeMs) && current - checked > maxAgeMs) gaps.push('evidence-stale');
    if (payload.exerciseReceipt?.terminal !== true || payload.exerciseReceipt?.status !== 'pass') gaps.push('exercise-receipt-unproven');
    const artifactsValid = Array.isArray(payload.exerciseReceipt?.artifacts)
      && payload.exerciseReceipt.artifacts.length > 0
      && payload.exerciseReceipt.artifacts.every((artifact) => artifact && typeof artifact === 'object' && !Array.isArray(artifact));
    if (!artifactsValid) gaps.push('exercise-receipt-artifacts-invalid');
    const artifacts = artifactsValid ? payload.exerciseReceipt.artifacts : [];
    if (!artifacts.length || !artifacts.every((artifact) => validArtifact(artifact, binding))) gaps.push('produced-evidence-invalid');
    gaps.push(...infrastructureFactGaps(payload, binding));
    const sanitized = sanitizeSensitiveValue(payload);
    const sanitizeArtifacts = (values) => Array.isArray(values) ? values.map((artifact) => sanitizeArtifactContent(artifact).artifact) : values;
    const safeControlFacts = Array.isArray(payload.controlFacts) && payload.controlFacts.every(typedFact) ? payload.controlFacts.map((fact) => ({ ...sanitized.value.controlFacts.find((item) => item.id === fact.id), artifacts: sanitizeArtifacts(fact.artifacts) })) : [];
    payload = { ...sanitized.value, controlFacts: safeControlFacts, exerciseReceipt: payload.exerciseReceipt ? { ...sanitized.value.exerciseReceipt, artifacts: sanitizeArtifacts(payload.exerciseReceipt.artifacts) } : sanitized.value.exerciseReceipt };
    if (sanitized.sensitive) gaps.push('infrastructure-sensitive-data');
  }
  return finalize('legion-web-infrastructure-exercise', { status: gaps.length ? 'unproven' : 'pass', terminal: true, claimLevel: 'external', suppliedOnly: true, networkAttempted: false, binding, producer: evidence?.producer ?? null, payload, evidenceDigest: evidence?.signedContent ? `sha256:${createHash('sha256').update(evidence.signedContent).digest('hex')}` : null, coverageGaps: [...new Set(gaps)].sort() });
}
