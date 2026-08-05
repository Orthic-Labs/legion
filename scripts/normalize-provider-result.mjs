#!/usr/bin/env node
/**
 * normalize-provider-result.mjs — Validates and normalizes a provider result
 * against the provider-result-v1 schema. Every provider result must pass through
 * this boundary before reaching facts or finalization.
 */

const REQUIRED_FIELDS = ['schemaVersion', 'provider', 'status', 'complete'];
const STATUS_ENUM = new Set([
  'pass', 'fail', 'unproven', 'error', 'skipped', 'missing',
  'candidates', 'partial', 'blocked',
]);

export class ProviderResultValidationError extends Error {
  constructor(field, detail) {
    super(`provider result validation: ${field}: ${detail}`);
    this.name = 'ProviderResultValidationError';
    this.field = field;
    this.detail = detail;
  }
}

export function validateProviderResult(result) {
  if (!result || typeof result !== 'object') {
    throw new ProviderResultValidationError('root', 'result must be a non-null object');
  }
  for (const field of REQUIRED_FIELDS) {
    if (result[field] === undefined || result[field] === null) {
      throw new ProviderResultValidationError(field, 'required field is missing');
    }
  }
  if (typeof result.provider !== 'string' || !result.provider) {
    throw new ProviderResultValidationError('provider', 'must be a non-empty string');
  }
  if (!STATUS_ENUM.has(result.status)) {
    throw new ProviderResultValidationError('status', `invalid status ${JSON.stringify(result.status)}; expected one of ${[...STATUS_ENUM].join(', ')}`);
  }
  if (typeof result.complete !== 'boolean') {
    throw new ProviderResultValidationError('complete', 'must be a boolean');
  }
  if (result.schemaVersion !== 1) {
    throw new ProviderResultValidationError('schemaVersion', `expected 1, got ${result.schemaVersion}`);
  }
  if (result.candidates && !Array.isArray(result.candidates)) {
    throw new ProviderResultValidationError('candidates', 'must be an array if present');
  }
  if (result.findings && !Array.isArray(result.findings)) {
    throw new ProviderResultValidationError('findings', 'must be an array if present');
  }
  if (result.coverageGaps && !Array.isArray(result.coverageGaps)) {
    throw new ProviderResultValidationError('coverageGaps', 'must be an array if present');
  }
  return true;
}

export function normalizeProviderResult(planContract, rawOutput) {
  const normalized = {
    schemaVersion: 1,
    provider: planContract?.id ?? rawOutput?.provider ?? 'unknown',
    applicable: rawOutput?.applicable ?? true,
    required: planContract?.benchmark?.requiredForCleanClaim ?? false,
    status: rawOutput?.status ?? 'unproven',
    complete: rawOutput?.complete ?? false,
    coverage: {
      ...(rawOutput?.coverage ?? {}),
      denominatorDigest: planContract?.denominator?.pathDigest ?? null,
    },
    candidates: rawOutput?.candidates ?? [],
    findings: rawOutput?.findings ?? [],
    coverageGaps: rawOutput?.coverageGaps ?? [],
    degradation: rawOutput?.degradation ?? null,
  };
  validateProviderResult(normalized);
  return normalized;
}

if (process.argv[1] && process.argv[1].endsWith('normalize-provider-result.mjs')) {
  // Self-test when run directly
  const testResult = normalizeProviderResult(
    { id: 'test.provider', denominator: { pathDigest: 'sha256:test' }, benchmark: { requiredForCleanClaim: true } },
    { status: 'pass', complete: true, findings: [] },
  );
  console.assert(testResult.provider === 'test.provider', 'provider preserved');
  console.assert(testResult.status === 'pass', 'status preserved');
  console.assert(testResult.coverage.denominatorDigest === 'sha256:test', 'digest bound');
  console.assert(testResult.required === true, 'required from contract');

  try {
    validateProviderResult({ schemaVersion: 1, provider: 'x', status: 'invalid-status', complete: true });
    console.error('FAIL: should have rejected invalid status');
    process.exit(1);
  } catch (e) {
    console.assert(e.field === 'status', 'rejected invalid status');
  }

  console.log('OK: normalize-provider-result.mjs self-test passed');
}
