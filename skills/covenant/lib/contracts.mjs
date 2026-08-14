import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const REQUEST_SCHEMA = loadSchema('./schemas/covenant-request-v1.schema.json');
const RECORD_SCHEMA = loadSchema('./schemas/covenant-record-v1.schema.json');

const REQUEST_OUTCOMES = Object.freeze({
  DECISION_CHALLENGE: new Set(['SUPPORTED', 'REVISE', 'UNRESOLVED']),
  BLOCKER_CONSULT: new Set(['CONTRACT_SAFE', 'AMENDMENT_REQUIRED', 'INSUFFICIENT_EVIDENCE']),
  DISPUTE_REVIEW: new Set(['SUPPORTED', 'REVISE', 'UNRESOLVED']),
});
const FORBIDDEN_AUTHORITY_TOKENS = ['DECISION_SEALED', 'CONTROL_PASS'];

function loadSchema(relativePath) {
  return JSON.parse(readFileSync(new URL(relativePath, import.meta.url), 'utf8'));
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function digestValue(value) {
  return `sha256:${createHash('sha256').update(canonical(value)).digest('hex')}`;
}

function requestDigest(request) {
  const { packetDigest: ignored, ...content } = request;
  return digestValue(content);
}

function cloneDefined(value) {
  return JSON.parse(JSON.stringify(value));
}

export function createCovenantRequest(input) {
  const request = cloneDefined({ schemaVersion: 1, kind: 'legion-covenant-request', ...input });
  delete request.packetDigest;
  request.packetDigest = requestDigest(request);
  const errors = validateCovenantRequest(request);
  if (errors.length) throw new TypeError(`Invalid CovenantRequest: ${errors.join('; ')}`);
  return request;
}

export function validateCovenantRequest(request) {
  const errors = validateSchema(REQUEST_SCHEMA, request, '$');
  if (!request || typeof request !== 'object') return errors;
  if (typeof request.packetDigest === 'string' && request.packetDigest !== requestDigest(request)) {
    errors.push('$.packetDigest does not match canonical request content');
  }
  if (request.mode === 'DECISION_CHALLENGE' && !['SAGE', 'USER_OVERRIDE'].includes(request.callerAuthority)) {
    errors.push('$.callerAuthority must be SAGE or USER_OVERRIDE for DECISION_CHALLENGE');
  }
  if (request.mode === 'BLOCKER_CONSULT' && request.callerAuthority !== 'ALCHEMIST') {
    errors.push('$.callerAuthority must be ALCHEMIST for BLOCKER_CONSULT');
  }
  if (request.mode === 'DISPUTE_REVIEW' && !['SAGE', 'USER_OVERRIDE'].includes(request.callerAuthority)) {
    errors.push('$.callerAuthority must be SAGE or USER_OVERRIDE for exceptional DISPUTE_REVIEW');
  }
  if (request.mode === 'BLOCKER_CONSULT' && !/blocker|contract|task/i.test(request.subjectType ?? '')) {
    errors.push('$.subjectType must identify an Alchemist blocker, contract, or task');
  }
  return errors;
}

export function createCovenantRecord(request, input) {
  if (request.mode === 'PACKET_ONLY') throw new TypeError('PACKET_ONLY produces no CovenantRecord');
  const record = cloneDefined({
    schemaVersion: 1,
    kind: 'legion-covenant-record',
    requestId: request.requestId,
    mode: request.mode,
    packetDigest: request.packetDigest,
    sourceRevision: request.sourceRevision,
    ...input,
  });
  const errors = validateCovenantRecord(record, request);
  if (errors.length) throw new TypeError(`Invalid CovenantRecord: ${errors.join('; ')}`);
  return record;
}

export function validateCovenantRecord(record, request = null) {
  const errors = validateSchema(RECORD_SCHEMA, record, '$');
  if (!record || typeof record !== 'object') return errors;
  if (record.mode === 'PACKET_ONLY') errors.push('$.mode PACKET_ONLY cannot produce a CovenantRecord');
  if (request) {
    if (record.requestId !== request.requestId) errors.push('$.requestId does not match request');
    if (record.mode !== request.mode) errors.push('$.mode does not match request');
    if (record.packetDigest !== request.packetDigest) errors.push('$.packetDigest does not match request');
    if (record.sourceRevision !== request.sourceRevision) errors.push('$.sourceRevision does not match request');
  }
  const allowed = REQUEST_OUTCOMES[record.mode];
  if (allowed && !allowed.has(record.outcome)) errors.push(`$.outcome is invalid for ${record.mode}`);
  const forbidden = findForbiddenToken(record);
  if (forbidden) errors.push(`$ contains forbidden authority token ${forbidden}`);
  if (record.integrity?.digestVerified !== true) errors.push('$.integrity.digestVerified must be true');
  if (record.integrity?.mutationDetected === true) errors.push('$.integrity.mutationDetected invalidates review');
  if (Array.isArray(record.seatRecords) && record.seatRecords.some((seat) => seat.isolated !== true)) {
    errors.push('$.seatRecords must all be isolated');
  }
  if (record.mode === 'DECISION_CHALLENGE') validateDispositions(record, errors);
  return errors;
}

function validateDispositions(record, errors) {
  const dispositions = new Map((record.callerDispositions ?? []).map((item) => [item.findingId, item]));
  for (const finding of record.findings ?? []) {
    const item = dispositions.get(finding.findingId);
    if (!item) {
      errors.push(`$.callerDispositions missing terminal disposition for ${finding.findingId}`);
      continue;
    }
    if (item.disposition === 'REJECT' && !item.rationale?.trim()) {
      errors.push(`$.callerDispositions ${finding.findingId} REJECT requires rationale`);
    }
    if (item.disposition === 'DEFER_TO_PHASE' && !item.owningPhase?.trim()) {
      errors.push(`$.callerDispositions ${finding.findingId} DEFER_TO_PHASE requires owningPhase`);
    }
  }
}

function findForbiddenToken(value) {
  if (typeof value === 'string') return FORBIDDEN_AUTHORITY_TOKENS.find((token) => value.includes(token));
  if (Array.isArray(value)) return value.map(findForbiddenToken).find(Boolean);
  if (value && typeof value === 'object') return Object.values(value).map(findForbiddenToken).find(Boolean);
  return undefined;
}

export function covenantGateSatisfied(record, currentRequest, policy = {}) {
  if (validateCovenantRequest(currentRequest).length) return false;
  if (validateCovenantRecord(record, currentRequest).length) return false;
  if (record.providerMetadata?.degraded && policy.allowDegraded !== true) return false;
  if (policy.outcomes && !policy.outcomes.includes(record.outcome)) return false;
  if (policy.sourceRevision && record.sourceRevision !== policy.sourceRevision) return false;
  if (policy.requireFreshVerdict && !record.freshVerdictRecordId) return false;
  return true;
}

function validateSchema(schema, value, path) {
  const errors = [];
  const types = Array.isArray(schema.type) ? schema.type : schema.type ? [schema.type] : [];
  if (types.length && !types.some((type) => isType(value, type))) {
    return [`${path} must be ${types.join(' or ')}`];
  }
  if (Object.hasOwn(schema, 'const') && value !== schema.const) errors.push(`${path} must equal ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.includes(value)) errors.push(`${path} must be one of ${schema.enum.join(', ')}`);
  if (value === null) return errors;
  if (typeof value === 'string') {
    if (schema.minLength && value.length < schema.minLength) errors.push(`${path} is too short`);
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) errors.push(`${path} does not match ${schema.pattern}`);
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${path} must be >= ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${path} must be <= ${schema.maximum}`);
  }
  if (Array.isArray(value) && schema.items) {
    value.forEach((item, index) => errors.push(...validateSchema(schema.items, item, `${path}[${index}]`)));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required)) errors.push(`${path}.${required} is required`);
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.hasOwn(schema.properties ?? {}, key)) errors.push(`${path}.${key} is not allowed`);
      }
    }
    for (const [key, childSchema] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(value, key)) errors.push(...validateSchema(childSchema, value[key], `${path}.${key}`));
    }
  }
  return errors;
}

function isType(value, type) {
  if (type === 'null') return value === null;
  if (type === 'array') return Array.isArray(value);
  if (type === 'object') return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  if (type === 'integer') return Number.isInteger(value);
  return typeof value === type;
}
