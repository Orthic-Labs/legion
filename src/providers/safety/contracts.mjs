// Safety hazard-model contracts (B7-020). Deliberately SEPARATE from
// providers/security/contracts.mjs: a hazard is not a security candidate,
// carries no attacker model, and can never be closed by an automated or
// model verdict — only a `human-decision` closure is accepted (see
// `closeHazard` in ./hazard-model.mjs).
//
// REASONING_REQUIREMENT below is copied verbatim from the dispatch's SNIP-01
// core enum (`REASONING_REQUIREMENT = ['none', 'bounded-review',
// 'independent-adjudication', 'human-decision']`). As of this task, no core
// module (lib/contracts/enums.mjs, providers/security/contracts.mjs,
// registry/provider-contracts.mjs) exports this vocabulary yet — it is not
// part of B7-020's Own paths, so this lane cannot add it there. This file is
// the authoritative import site for the safety domain until a future task
// lands the shared core copy; every other safety module imports the
// constant from here rather than re-declaring it. This is a documented
// judgment call, not an attempt to redefine core semantics: the array
// content matches SNIP-01 exactly.

import { createHash } from 'node:crypto';

export { REASONING_REQUIREMENT } from '../../lib/contracts/enums.mjs';

// Every outcome class this hazard model addresses is, by definition,
// high-consequence (physical, medical, financial, child-facing,
// operational, irreversible, catastrophic data loss). There is no "low
// consequence" outcome class in this model; a lower-consequence concern
// belongs in providers/security/** or another audit family, not here.
export const OUTCOME_CLASS = Object.freeze([
  'physical',
  'medical',
  'financial',
  'child-facing',
  'operational',
  'irreversible',
  'catastrophic-data-loss',
]);

// The seven required fixture/disposition counterparts (dispatch acceptance
// criteria): every domain scanner must be able to produce each of these.
export const HAZARD_DISPOSITION = Object.freeze([
  'positive',
  'mitigated',
  'blocked',
  'unsafe-degraded',
  'missing-interlock',
  'human-override',
  'clean',
]);

export const INTERLOCK_STATE = Object.freeze(['present', 'missing', 'not-applicable']);
export const FAILSAFE_DEFAULT = Object.freeze(['safe', 'unsafe', 'unknown']);
export const DEGRADED_MODE = Object.freeze(['safe', 'unsafe', 'unknown', 'not-applicable']);
export const EMERGENCY_STOP = Object.freeze(['present', 'absent', 'not-applicable']);
export const HUMAN_OVERRIDE = Object.freeze(['present', 'absent', 'required-and-present', 'required-and-absent', 'not-applicable']);
export const CONFIRMATION_STATE = Object.freeze(['present', 'absent', 'not-applicable']);
export const RECOVERY_PATH = Object.freeze(['defined', 'absent', 'not-applicable']);
export const INCIDENT_CONTROLS = Object.freeze(['defined', 'absent', 'not-applicable']);

// Never 'certified', never 'pass', never 'clean' — a hazard candidate can
// only ever request review or declare itself unproven pending qualified
// domain evidence.
export const HAZARD_STATUS = Object.freeze(['review-required', 'unproven']);

// Closure methods a caller may attempt against a hazard. Only 'human-decision'
// is ever accepted by closeHazard(); the others exist so the rejection path
// itself is representable and testable.
export const CLOSURE_METHOD = Object.freeze(['human-decision', 'model-verdict', 'automated-verdict']);

export const SEVERITY_HINTS = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);

export const SAFETY_SCHEMA_VERSIONS = Object.freeze({
  'hazard-model': Object.freeze([1]),
});

export function assertEnum(label, values, value) {
  if (!values.includes(value)) throw new TypeError(`unknown ${label}: ${String(value)}`);
  return value;
}

export function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

export function requireNonEmptyArray(value, label) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty array`);
  }
  return value;
}

export function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  return value;
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

export function stableId(namespace, value) {
  const body = JSON.stringify(canonicalize(value));
  return `sha256:${createHash('sha256').update(`${namespace}\0${body}`).digest('hex')}`;
}

export function digest(value) {
  return stableId('digest', value);
}
