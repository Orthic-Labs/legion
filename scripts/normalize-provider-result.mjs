#!/usr/bin/env node
/**
 * normalize-provider-result.mjs — Validates and normalizes a provider result
 * against the provider-result-v1 schema. Every provider result must pass through
 * this boundary before reaching facts or finalization.
 *
 * The status enum is imported from registry/provider-contracts.mjs — the single
 * source of truth shared with the generated provider-result-v1.schema.json — so
 * the runtime validator and the JSON schema accept exactly the same values.
 */

import { PROVIDER_STATUS } from '../registry/provider-contracts.mjs';

const REQUIRED_FIELDS = ['schemaVersion', 'provider', 'status', 'complete'];
const STATUS_ENUM = new Set(PROVIDER_STATUS);

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
    throw new ProviderResultValidationError('status', `invalid status ${JSON.stringify(result.status)}; expected one of ${PROVIDER_STATUS.join(', ')}`);
  }
  if (typeof result.complete !== 'boolean') {
    throw new ProviderResultValidationError('complete', 'must be a boolean');
  }
  if (result.schemaVersion !== 1) {
    throw new ProviderResultValidationError('schemaVersion', `expected 1, got ${result.schemaVersion}`);
  }
  // Normalized arrays must be arrays, never null.
  for (const field of ['commands', 'receipts', 'inventory', 'candidates', 'findings', 'coverageGaps', 'artifacts', 'degradation', 'inputArtifacts']) {
    if (result[field] === null) {
      throw new ProviderResultValidationError(field, 'must be an array, never null');
    }
    if (result[field] !== undefined && !Array.isArray(result[field])) {
      throw new ProviderResultValidationError(field, 'must be an array when present');
    }
  }
  if (result.artifacts) {
    for (const artifact of result.artifacts) {
      if (!artifact || typeof artifact !== 'object'
          || !artifact.kind || !artifact.path || !artifact.digest) {
        throw new ProviderResultValidationError('artifacts', 'each artifact requires kind, path, and digest');
      }
      if (typeof artifact.digest !== 'string' || !artifact.digest.startsWith('sha256:')) {
        throw new ProviderResultValidationError('artifacts.digest', 'must be a sha256: prefixed string');
      }
    }
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
      denominatorDigest:
        rawOutput?.coverage?.denominatorDigest
        ?? planContract?.denominator?.pathDigest
        ?? 'sha256:unbound',
    },
    commands: rawOutput?.commands ?? [],
    receipts: rawOutput?.receipts ?? [],
    inventory: rawOutput?.inventory ?? [],
    candidates: rawOutput?.candidates ?? [],
    findings: rawOutput?.findings ?? [],
    coverageGaps: rawOutput?.coverageGaps ?? [],
    artifacts: rawOutput?.artifacts ?? [],
    degradation: rawOutput?.degradation ?? [],
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
  console.assert(Array.isArray(testResult.degradation), 'degradation normalized to array');

  try {
    validateProviderResult({ schemaVersion: 1, provider: 'x', status: 'invalid-status', complete: true });
    console.error('FAIL: should have rejected invalid status');
    process.exit(1);
  } catch (e) {
    console.assert(e.field === 'status', 'rejected invalid status');
  }

  try {
    validateProviderResult({ schemaVersion: 1, provider: 'x', status: 'pass', complete: true, findings: null });
    console.error('FAIL: should have rejected null findings');
    process.exit(1);
  } catch (e) {
    console.assert(e.field === 'findings', 'rejected null findings array');
  }

  console.log('OK: normalize-provider-result.mjs self-test passed');
}
