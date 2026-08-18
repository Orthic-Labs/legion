// Central source of truth for provider result statuses, roles, and phases.
// Runtime validators and generated JSON schemas both import from here so the
// schema/runtime status sets can never drift.

export const PROVIDER_STATUS = Object.freeze([
  'pass',
  'fail',
  'partial',
  'unproven',
  'skipped',
  'error',
  'pending',
  'missing',
  'candidates',
  'blocked',
]);

export const PROVIDER_ROLES = Object.freeze([
  'deterministic',
  'model-builder',
  'candidate-generator',
  'hypothesis-generator',
  'adjudicator',
  'variant-analyzer',
  'evidence-synthesizer',
]);

export const PROVIDER_PHASES = Object.freeze([
  'facts',
  'model',
  'runtime',
  'hypothesis',
  'reasoning',
  'variants',
  'synthesis',
]);

export function assertEnum(name, value, allowed) {
  if (!allowed.includes(value)) {
    throw new Error(`${name} must be one of ${allowed.join(', ')}; got ${JSON.stringify(value)}`);
  }
  return value;
}
