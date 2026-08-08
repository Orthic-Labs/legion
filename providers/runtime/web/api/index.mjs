import { createHash } from 'node:crypto';
import { sanitizeProducedArtifact } from '../../../../lib/platform/artifact-sanitize.mjs';
import { canonicalize, denominator, exactBinding, finalize, redact, sameBinding, sortById } from '../shared.mjs';

const PROTOCOLS = new Set(['rest', 'graphql', 'websocket', 'webhook']);
const RESILIENCE = ['idempotency', 'pagination', 'retry', 'rateLimit', 'malformed', 'partialFailure'];
const equal = (left, right) => JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const HTTP_METHODS = new Set(['DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT']);
const schemaValid = (value) => value && typeof value.id === 'string' && value.id.length > 0 && typeof value.version === 'string' && value.version.length > 0 && SHA256.test(value.digest ?? '');
const operationValid = (value, types) => value && typeof value.name === 'string' && value.name.length > 0 && types.includes(value.type);
const canonicalPathValid = (value) => {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.includes('\\') || value.includes('://') || value.includes('?') || value.includes('#') || /[\u0000-\u001f\u007f]/.test(value)) return false;
  try { if (decodeURIComponent(value) !== value) return false; } catch { return false; }
  if (value === '/') return true;
  if (value !== '/' && value.endsWith('/')) return false;
  const segments = value.split('/').slice(1);
  return segments.every((segment) => segment.length > 0 && segment !== '.' && segment !== '..' && !segment.includes(':'));
};
const rawArtifactBindingValid = (artifact, kind, binding, item) => artifact?.kind === kind && artifact.redacted === true && artifact.caseId === item.id && artifact.protocol === item.protocol && artifact.method === item.method && artifact.path === (item.path ?? null) && equal(artifact.operation ?? null, item.operation ?? null) && artifact.correlationId === item.correlationId && sameBinding(binding, artifact.binding ?? {});
const sanitized = (value) => value === null || value === undefined || value === '[REDACTED]' || typeof value === 'string' && /^\*+$/.test(value);
const commonPiiKey = (key) => ['email', 'phone', 'phonenumber', 'socialsecuritynumber', 'ssn'].includes(String(key).replaceAll('-', '').replaceAll('_', '').toLowerCase());
function configuredPath(root, path) {
  if (typeof path !== 'string' || path[0] !== '$' || path.length === 1) return { valid: false, values: [] };
  const matcher = /(?:\.([A-Za-z_$][A-Za-z0-9_$-]*))|\[(\*|0|[1-9]\d*)\]/gy;
  const tokens = [];
  let index = 1;
  while (index < path.length) {
    matcher.lastIndex = index;
    const match = matcher.exec(path);
    if (!match || match.index !== index) return { valid: false, values: [] };
    tokens.push(match[1] ?? (match[2] === '*' ? '*' : Number(match[2])));
    index = matcher.lastIndex;
  }
  const resolve = (current, tokenIndex, broadenIndices) => {
    if (tokenIndex === tokens.length) return { valid: true, values: [current] };
    const token = tokens[tokenIndex];
    if (token === '*' || typeof token === 'number' && broadenIndices) {
      if (!Array.isArray(current) || current.length === 0) return { valid: false, values: [] };
      const results = current.map((item) => resolve(item, tokenIndex + 1, broadenIndices));
      return { valid: results.every((item) => item.valid), values: results.flatMap((item) => item.values) };
    }
    if (current === null || typeof current !== 'object' || !Object.hasOwn(current, token)) return { valid: false, values: [] };
    return resolve(current[token], tokenIndex + 1, broadenIndices);
  };
  const exact = resolve(root, 0, false);
  if (!exact.valid) return exact;
  return tokens.some((token) => typeof token === 'number') ? resolve(root, 0, true) : exact;
}
function rawPiiLeak(content, configured = []) {
  if (/(?:authorization|bearer|password|clientsecret|apitoken|privatekey|accesstoken|refreshtoken|sessioncookie)/i.test(content)) return true;
  let parsed;
  try { parsed = JSON.parse(content); } catch { const withoutDates = content.replace(/\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2}))?\b/g, ''); return /[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|\b\d{3}-\d{2}-\d{4}\b|\+?\d[\d\s().-]{6,}\d/.test(withoutDates); }
  let leaked = false;
  const visit = (value) => { if (!value || typeof value !== 'object') return; for (const [key, child] of Object.entries(value)) { if (commonPiiKey(key) && !sanitized(child)) leaked = true; visit(child); } };
  visit(parsed);
  for (const field of configured) {
    if (!field || typeof field.path !== 'string' || !['email', 'phone', 'ssn', 'string'].includes(field.type)) { leaked = true; continue; }
    const resolved = configuredPath(parsed, field.path);
    if (!resolved.valid || resolved.values.length === 0 || resolved.values.some((value) => !sanitized(value))) leaked = true;
  }
  return leaked;
}
const graphqlPackValid = (pack, item, binding) => pack?.kind === 'graphql' && sameBinding(binding, pack.binding ?? {}) && Number.isFinite(pack.depth?.limit) && Number.isFinite(pack.depth?.observed) && pack.depth.limit > 0 && pack.depth.observed >= 0 && pack.depth.observed <= pack.depth.limit && pack.depth.passed === true && Number.isFinite(pack.cost?.limit) && Number.isFinite(pack.cost?.observed) && pack.cost.limit > 0 && pack.cost.observed >= 0 && pack.cost.observed <= pack.cost.limit && pack.cost.passed === true && pack.schemaCompatibility?.status === 'compatible' && pack.schemaCompatibility?.requestDigest === item.requestSchema?.digest && pack.schemaCompatibility?.responseDigest === item.responseSchema?.digest;
const websocketPackValid = (pack, binding) => pack?.kind === 'websocket' && sameBinding(binding, pack.binding ?? {}) && pack.auth === true && pack.backpressure === true && pack.reconnect === true;
const webhookPackValid = (pack, binding) => pack?.kind === 'webhook' && sameBinding(binding, pack.binding ?? {}) && pack.signature === true && pack.replay === true && pack.idempotency === true && pack.delivery === true;
const SENSITIVE_PATH = /^\$(?:(?:\.[A-Za-z_$][A-Za-z0-9_$-]*)|\[(?:\*|0|[1-9]\d*)\])+$/;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
const sensitiveFieldsValid = (value) => value === undefined || Array.isArray(value) && value.every((field) => typeof field === 'string' ? SENSITIVE_PATH.test(field) : field && typeof field === 'object' && !Array.isArray(field) && SENSITIVE_PATH.test(field.path ?? '') && ['email', 'phone', 'ssn', 'string'].includes(field.type));

export function verifyApiExercise({ binding = {}, cases = [], applicability = null } = {}) {
  if (!Array.isArray(cases) || cases.some((item) => !item || typeof item !== 'object' || Array.isArray(item))) return finalize('nemesis-web-api-exercise', { status: 'error', applicable: null, terminal: true, binding, denominator: denominator([], []), receipts: [], coverageGaps: [...exactBinding(binding).gaps.map((key) => `binding-missing:${key}`), 'api-cases-invalid'].sort() });
  if (cases.some((item) => typeof item.id !== 'string' || !SAFE_IDENTIFIER.test(item.id))) {
    const safeCases = cases.filter((item) => typeof item.id === 'string' && SAFE_IDENTIFIER.test(item.id));
    const safeIds = safeCases.map((item) => item.id), gaps = ['api-case-id-invalid'];
    if (cases.some((item) => item.id === undefined || item.id === null || item.id === '')) gaps.push('api-case-id-missing');
    for (const id of new Set(safeIds)) if (safeIds.filter((value) => value === id).length > 1) gaps.push(`api-case-id-duplicate:${id}`);
    for (const item of safeCases) { if (item.actorId !== binding.actorId) gaps.push(`${item.id}:actor-binding-mismatch`); if (item.tenantId !== binding.tenantId) gaps.push(`${item.id}:tenant-binding-mismatch`); }
    return finalize('nemesis-web-api-exercise', { status: 'error', applicable: null, terminal: true, binding, denominator: denominator(safeIds, []), receipts: [], coverageGaps: [...new Set(gaps)].sort() });
  }
  if (cases.length === 0) {
    const source = applicability?.source;
    const valid = applicability?.status === 'not-applicable' && typeof applicability.reason === 'string' && applicability.reason.length > 0 && source?.kind === 'configured' && typeof source.id === 'string' && /^sha256:[a-f0-9]{64}$/.test(source.digest ?? '') && sameBinding(binding, source.binding ?? {});
    const gaps = [...exactBinding(binding).gaps.map((key) => `binding-missing:${key}`), ...(valid ? [] : ['api-case-denominator-empty', 'applicability-source-unproven'])];
    return finalize('nemesis-web-api-exercise', { status: gaps.length ? 'unproven' : 'pass', applicable: valid ? false : null, terminal: true, binding, applicability, denominator: denominator([], []), receipts: [], coverageGaps: gaps.sort() });
  }
  const receipts = sortById(cases).map((item) => {
    const gaps = [];
    const sensitiveFields = sensitiveFieldsValid(item.sensitiveFields) ? item.sensitiveFields ?? [] : [];
    if (!sensitiveFieldsValid(item.sensitiveFields)) gaps.push('sensitive-fields-invalid');
    for (const key of ['actorId', 'tenantId', 'dataScope', 'lifecycle']) if (item[key] === undefined || item[key] === null) gaps.push(`missing-${key}`);
    if (item.actorId !== binding.actorId) gaps.push('actor-binding-mismatch');
    if (item.tenantId !== binding.tenantId) gaps.push('tenant-binding-mismatch');
    if (!PROTOCOLS.has(item.protocol)) gaps.push('protocol-unsupported');
    if (typeof item.method !== 'string' || !item.method) gaps.push('missing-method');
    else if (item.protocol === 'rest' && !HTTP_METHODS.has(item.method)) gaps.push('rest-method-invalid');
    else if (item.protocol === 'graphql' && !['GET', 'POST'].includes(item.method)) gaps.push('graphql-method-invalid');
    else if (item.protocol === 'websocket' && item.method !== 'CONNECT') gaps.push('websocket-method-invalid');
    else if (item.protocol === 'webhook' && item.method !== 'POST') gaps.push('webhook-method-invalid');
    if (item.protocol === 'rest' && !canonicalPathValid(item.path)) gaps.push('rest-path-invalid');
    if (item.protocol === 'graphql' && !operationValid(item.operation, ['mutation', 'query', 'subscription'])) gaps.push('graphql-operation-invalid');
    if (item.protocol === 'websocket' && (!canonicalPathValid(item.path) || !operationValid(item.operation, ['message', 'subscribe']))) gaps.push('websocket-contract-invalid');
    if (item.protocol === 'webhook' && (!canonicalPathValid(item.path) || !operationValid(item.operation, ['event']))) gaps.push('webhook-contract-invalid');
    if (!schemaValid(item.requestSchema)) gaps.push('request-schema-unproven');
    if (!schemaValid(item.responseSchema)) gaps.push('response-schema-unproven');
    if (item.compatibility?.status !== 'compatible' || item.compatibility?.requestDigest !== item.requestSchema?.digest || item.compatibility?.responseDigest !== item.responseSchema?.digest) gaps.push('schema-compatibility-unproven');
    if (!Object.hasOwn(item, 'expectedError') || !Object.hasOwn(item, 'observedError') || !equal(item.expectedError, item.observedError)) gaps.push('error-contract-unproven');
    if (typeof item.correlationId !== 'string' || !item.correlationId) gaps.push('correlation-id-missing');
    if (item.dependencyBehavior?.status !== 'pass' || item.dependencyBehavior?.terminal !== true || !Array.isArray(item.dependencyBehavior?.dependencies) || !sameBinding(binding, item.dependencyBehavior?.binding ?? {})) gaps.push('dependency-behavior-unproven');
    if (item.protocol === 'graphql' && !graphqlPackValid(item.protocolPack, item, binding)) gaps.push('graphql-pack-unproven');
    if (item.protocol === 'websocket' && !websocketPackValid(item.protocolPack, binding)) gaps.push('websocket-pack-unproven');
    if (item.protocol === 'webhook' && !webhookPackValid(item.protocolPack, binding)) gaps.push('webhook-pack-unproven');
    const rawArtifacts = Array.isArray(item.rawArtifacts) ? [...item.rawArtifacts].sort((left, right) => String(JSON.stringify(canonicalize(left))).localeCompare(String(JSON.stringify(canonicalize(right))))) : [];
    if (!Array.isArray(item.rawArtifacts)) gaps.push('raw-artifact-collection-invalid');
    for (const artifact of rawArtifacts.filter((candidate) => !['request', 'response'].includes(candidate?.kind))) gaps.push(`raw-artifact-unplanned:${artifact?.kind ?? 'missing'}`);
    const safeRawArtifacts = [];
    for (const kind of ['request', 'response']) {
      const matches = rawArtifacts.filter((candidate) => candidate?.kind === kind);
      if (matches.length > 1) gaps.push(`raw-${kind}-evidence-duplicate`);
      const artifact = matches.length === 1 && rawArtifactBindingValid(matches[0], kind, binding, item) ? matches[0] : null;
      const produced = sanitizeProducedArtifact(artifact, sensitiveFields);
      if (!artifact || !produced.valid) gaps.push(`raw-${kind}-evidence-invalid`);
      else { safeRawArtifacts.push(produced.artifact); if (produced.sensitive || rawPiiLeak(artifact.content ?? Buffer.from(artifact.bytesBase64 ?? '', 'base64').toString('utf8'), sensitiveFields.map((field) => typeof field === 'string' ? { path: field, type: 'string' } : field))) gaps.push(`raw-${kind}-pii-leak`); }
    }
    if (item.boundaries !== true) gaps.push('boundaries-unproven');
    if (typeof item.expected?.exists !== 'boolean') gaps.push('expected-exists-unbound');
    if (item.expected?.exists === true && !Object.hasOwn(item.observed ?? {}, 'value')) gaps.push('observed-value-missing');
    if (item.expected?.exists === true && !Object.hasOwn(item.durableEffect ?? {}, 'value')) gaps.push('durable-effect-missing');
    if (item.expected?.exists === true && item.observed?.exists !== true) gaps.push('observed-exists-not-true');
    if (item.expected?.exists === true && item.durableEffect?.exists !== true) gaps.push('durable-exists-not-true');
    if (item.expected?.exists === false && item.observed?.exists !== false) gaps.push('observed-exists-not-false');
    if (item.expected?.exists === false && item.durableEffect?.exists !== false) gaps.push('durable-exists-not-false');
    if (item.expected?.exists === false && Object.hasOwn(item.observed ?? {}, 'value')) gaps.push('observed-value-present');
    if (item.expected?.exists === false && Object.hasOwn(item.durableEffect ?? {}, 'value')) gaps.push('durable-effect-present');
    if (Object.hasOwn(item.expected ?? {}, 'value') && Object.hasOwn(item.observed ?? {}, 'value') && !equal(item.expected.value, item.observed.value)) gaps.push('observed-value-mismatch');
    if (Object.hasOwn(item.expected ?? {}, 'value') && Object.hasOwn(item.durableEffect ?? {}, 'value') && !equal(item.expected.value, item.durableEffect.value)) gaps.push('durable-effect-mismatch');
    for (const key of RESILIENCE) if (item[key] !== true) gaps.push(`${key}-unproven`);
    return redact({ id: item.id, protocol: item.protocol, method: item.method ?? null, path: item.path ?? null, operation: item.operation ?? null, protocolPack: item.protocolPack ?? null, status: gaps.includes('sensitive-fields-invalid') ? 'error' : gaps.length ? 'unproven' : 'pass', terminal: true, actorId: item.actorId, tenantId: item.tenantId, dataScope: item.dataScope, lifecycle: item.lifecycle, requestSchema: item.requestSchema ?? null, responseSchema: item.responseSchema ?? null, compatibility: item.compatibility ?? null, expectedError: Object.hasOwn(item, 'expectedError') ? item.expectedError : null, observedError: Object.hasOwn(item, 'observedError') ? item.observedError : null, correlationId: item.correlationId ?? null, dependencyBehavior: item.dependencyBehavior ?? null, rawArtifacts: safeRawArtifacts, checks: { boundaries: item.boundaries === true, idempotency: item.idempotency ?? null, pagination: item.pagination ?? null, retry: item.retry ?? null, rateLimit: item.rateLimit ?? null, malformed: item.malformed ?? null, partialFailure: item.partialFailure ?? null }, observed: item.observed ?? null, durableEffect: item.durableEffect ?? null, coverageGaps: [...new Set(gaps)].sort() });
  });
  const counts = denominator(cases.map((item) => item.id), receipts);
  const gaps = [...exactBinding(binding).gaps.map((key) => `binding-missing:${key}`), ...receipts.flatMap((item) => item.coverageGaps.map((gap) => `${item.id}:${gap}`))];
  const ids = cases.map((item) => item.id);
  if (ids.some((id) => typeof id !== 'string' || id.length === 0)) gaps.push('api-case-id-missing');
  for (const id of new Set(ids.filter((value) => typeof value === 'string'))) if (ids.filter((value) => value === id).length > 1) gaps.push(`api-case-id-duplicate:${id}`);
  return finalize('nemesis-web-api-exercise', { status: receipts.some((item) => item.status === 'error') ? 'error' : gaps.length ? 'unproven' : 'pass', applicable: true, terminal: true, binding, denominator: counts, receipts, coverageGaps: gaps.sort() });
}
