import { decision } from './errors.mjs';

const LATENCY_RECORD_FIELDS = Object.freeze(['authorityId', 'scopeId', 'targetMs']);
const TECHNOLOGY_RECORD_FIELDS = Object.freeze(['authorityId', 'scopeId', 'technology', 'consequence']);
const LATENCY_INPUT_FIELDS = Object.freeze(['scopeId', 'targetMs', 'assumption', 'authorityRequest']);
const TECHNOLOGY_INPUT_FIELDS = Object.freeze(['scopeId', 'technology', 'consequence']);
const ASSUMPTION_FIELDS = Object.freeze(['id', 'rationaleDigest']);
const AUTHORITY_REQUEST_FIELDS = Object.freeze(['id', 'question']);

const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
const text = (value) => typeof value === 'string' && value.length > 0;
const milliseconds = (value) => Number.isFinite(value) && value > 0;
const scope = (value) => value === null || text(value);
const sameScope = (recordScope, requestedScope) => recordScope === requestedScope;
const deny = (code, message, detail) => decision({ allowed: false, code, message, detail });

function validLatencyRecord(record) {
  return exact(record, LATENCY_RECORD_FIELDS)
    && text(record.authorityId) && scope(record.scopeId) && milliseconds(record.targetMs);
}

function validTechnologyRecord(record) {
  return exact(record, TECHNOLOGY_RECORD_FIELDS)
    && text(record.authorityId) && scope(record.scopeId) && text(record.technology) && text(record.consequence);
}

function validAssumption(value) {
  return exact(value, ASSUMPTION_FIELDS) && text(value.id) && text(value.rationaleDigest);
}

function validAuthorityRequest(value) {
  return exact(value, AUTHORITY_REQUEST_FIELDS) && text(value.id) && text(value.question);
}

/**
 * Host-owned authority facts for evidence classification.  Request payloads
 * cannot carry an authority claim: callers can only reference these records.
 */
export class EvidenceAuthorityRegistry {
  #latency = [];
  #technology = [];

  constructor({ latencyTargets = [], technologyConstraints = [] } = {}) {
    if (!Array.isArray(latencyTargets) || !latencyTargets.every(validLatencyRecord)
      || !Array.isArray(technologyConstraints) || !technologyConstraints.every(validTechnologyRecord)) {
      throw new TypeError('invalid host evidence-authority records');
    }
    this.#latency = Object.freeze(latencyTargets.map((record) => Object.freeze({ ...record })));
    this.#technology = Object.freeze(technologyConstraints.map((record) => Object.freeze({ ...record })));
  }

  latencyTarget(scopeId) {
    return this.#latency.find((record) => sameScope(record.scopeId, scopeId)) ?? null;
  }

  technologyConstraint(scopeId, technology, consequence) {
    return this.#technology.find((record) => sameScope(record.scopeId, scopeId)
      && record.technology === technology && record.consequence === consequence) ?? null;
  }
}

/**
 * Resolves an SLO only from host authority.  An unbacked numeric target is a
 * refusal, while a target-less assumption or authority request stays explicit.
 */
export function resolveLatencyTarget(input, { registry } = {}) {
  if (!(registry instanceof EvidenceAuthorityRegistry) || !exact(input, LATENCY_INPUT_FIELDS) || !scope(input.scopeId)
    || !(input.targetMs === null || milliseconds(input.targetMs))
    || !(input.assumption === null || validAssumption(input.assumption))
    || !(input.authorityRequest === null || validAuthorityRequest(input.authorityRequest))
    || (input.assumption !== null && input.authorityRequest !== null)
    || (input.targetMs !== null && (input.assumption !== null || input.authorityRequest !== null))) {
    return deny('ARC_SCHEMA_INVALID', 'latency evidence input is invalid', { disposition: 'AUTHORITY_REQUEST' });
  }

  const authorized = registry.latencyTarget(input.scopeId);
  if (input.targetMs !== null) {
    if (!authorized) return deny('ARC_EVIDENCE_INSUFFICIENT', 'numeric latency target has no authorized source', {
      disposition: 'AUTHORITY_REQUEST', reason: 'UNAUTHORIZED_NUMERIC_TARGET', requestedTargetMs: input.targetMs,
    });
    if (authorized.targetMs !== input.targetMs) return deny('ARC_BINDING_MISMATCH', 'numeric latency target differs from authorized source', {
      disposition: 'AUTHORITY_REQUEST', authorityId: authorized.authorityId, authorizedTargetMs: authorized.targetMs, requestedTargetMs: input.targetMs,
    });
    return decision({ allowed: true, detail: { disposition: 'CONSTRAINT', authorityId: authorized.authorityId, targetMs: authorized.targetMs } });
  }

  if (input.assumption) return decision({ allowed: true, detail: { disposition: 'ASSUMPTION', assumptionId: input.assumption.id, rationaleDigest: input.assumption.rationaleDigest } });
  if (input.authorityRequest) return decision({ allowed: true, detail: { disposition: 'AUTHORITY_REQUEST', requestId: input.authorityRequest.id, question: input.authorityRequest.question } });
  return decision({ allowed: true, detail: { disposition: 'AUTHORITY_REQUEST', reason: 'NO_AUTHORIZED_LATENCY_TARGET' } });
}

/**
 * A technology is a constraint only when host authority binds an exact,
 * concrete consequence.  Unbacked Kubernetes selection is therefore PREFERENCE.
 */
export function classifyTechnologyRequirement(input, { registry } = {}) {
  if (!(registry instanceof EvidenceAuthorityRegistry) || !exact(input, TECHNOLOGY_INPUT_FIELDS)
    || !scope(input.scopeId) || !text(input.technology) || !(input.consequence === null || text(input.consequence))) {
    return deny('ARC_SCHEMA_INVALID', 'technology evidence input is invalid', { disposition: 'PREFERENCE' });
  }
  const authority = input.consequence === null ? null : registry.technologyConstraint(input.scopeId, input.technology, input.consequence);
  if (!authority) return decision({ allowed: true, detail: { classification: 'PREFERENCE', technology: input.technology, consequence: input.consequence } });
  return decision({ allowed: true, detail: { classification: 'CONSTRAINT', technology: authority.technology, consequence: authority.consequence, authorityId: authority.authorityId } });
}
