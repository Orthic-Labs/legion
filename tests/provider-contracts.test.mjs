import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { PROVIDER_PHASES, PROVIDER_ROLES, PROVIDER_STATUS, assertEnum } from '../src/registry/provider-contracts.mjs';
import {
  EVIDENCE_STRENGTH,
  FACT_KINDS,
  PATH_PRIORITY,
  PATH_STATUS,
  SECURITY_VERDICTS,
  assertBinding,
  canonicalize,
  stableId,
} from '../src/providers/security/contracts.mjs';
import { validateProviderResult, normalizeProviderResult } from '../scripts/normalize-provider-result.mjs';

function baseResult(status) {
  return {
    schemaVersion: 1,
    provider: 'test.provider',
    status,
    complete: status === 'pass' || status === 'candidates',
    applicable: true,
    required: false,
    coverage: { denominatorDigest: 'sha256:test' },
    commands: [], receipts: [], inventory: [], candidates: [], findings: [],
    coverageGaps: [], artifacts: [], degradation: [],
  };
}

for (const status of PROVIDER_STATUS) {
  test(`provider status ${status} is accepted`, () => {
    assert.equal(validateProviderResult(baseResult(status)), true);
  });
}

test('provider result statuses match the committed schema enum', () => {
  const schema = JSON.parse(readFileSync(new URL('../src/schemas/provider-result-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(schema.properties.status.enum, [...PROVIDER_STATUS]);
});

test('normalized arrays are never null', () => {
  // A result with null arrays must be rejected; normalizeProviderResult must
  // always produce arrays.
  assert.throws(() => validateProviderResult({
    ...baseResult('pass'),
    findings: null,
  }), /findings/);
  const normalized = normalizeProviderResult(
    { id: 'p', denominator: { pathDigest: 'sha256:x' }, benchmark: {} },
    { status: 'pass', complete: true, degradation: null, coverage: null },
  );
  assert.ok(Array.isArray(normalized.degradation));
  assert.ok(Array.isArray(normalized.findings));
  assert.ok(Array.isArray(normalized.coverageGaps));
  assert.ok(Array.isArray(normalized.candidates));
});

test('required provider with unbound denominator is a validation gap', () => {
  // The normalizer falls back to 'sha256:unbound' when no denominator digest is
  // available; a required provider bound to that digest must not be treated as
  // covered by finalization (the plan reconciliation layer owns that gate, so
  // here we assert the fallback value is produced and is not a valid bound digest).
  const result = normalizeProviderResult(
    { id: 'p', denominator: null, benchmark: { requiredForCleanClaim: true } },
    { status: 'pass', complete: true, coverage: null, findings: [] },
  );
  assert.equal(result.coverage.denominatorDigest, 'sha256:unbound');
  assert.equal(result.required, true);
});

test('provider roles and phases are frozen and asserted', () => {
  assert.equal(assertEnum('role', 'candidate-generator', PROVIDER_ROLES), 'candidate-generator');
  assert.throws(() => assertEnum('role', 'not-a-role', PROVIDER_ROLES), /not-a-role/);
  assert.ok(PROVIDER_PHASES.includes('synthesis'));
});

test('security verdicts and evidence strength are canonical', () => {
  assert.ok(SECURITY_VERDICTS.includes('TRUE_POSITIVE'));
  assert.ok(SECURITY_VERDICTS.includes('HARDENING_GAP'));
  assert.ok(EVIDENCE_STRENGTH.includes('strong-inference'));
  assert.ok(!EVIDENCE_STRENGTH.includes('observed'), 'observed evidence strength is gone');
  assert.ok(FACT_KINDS.includes('credential-possession'));
  assert.ok(PATH_STATUS.includes('PROVEN'));
  assert.ok(PATH_PRIORITY.includes('DIRECT_CROWN_JEWEL'));
});

test('security binding helper rejects incomplete bindings', () => {
  assert.throws(() => assertBinding({ planDigest: 'sha256:a' }), /binding\.repositoryRevision/);
  assert.throws(() => assertBinding({
    planDigest: 'sha256:a', repositoryRevision: 'r', blueprintGenerationId: 'g',
    blueprintManifestDigest: 'sha256:m', registryDigest: 'sha256:r', dirtyPatchDigest: 5,
  }), /dirtyPatchDigest/);
  assert.doesNotThrow(() => assertBinding({
    planDigest: 'sha256:a', repositoryRevision: 'r', dirtyPatchDigest: null,
    blueprintGenerationId: 'g', blueprintManifestDigest: 'sha256:m', registryDigest: 'sha256:r',
  }));
});

test('stable IDs are deterministic and canonicalize is stable', () => {
  // canonicalize sorts object keys (not array element order), so two objects
  // with the same key/value pairs in different key order produce the same ID.
  const first = stableId('ns', { b: 1, a: [1, 2] });
  const second = stableId('ns', { a: [1, 2], b: 1 });
  assert.equal(first, second);
  assert.ok(first.startsWith('sha256:'));
  assert.deepEqual(canonicalize({ b: 1, a: [1, 2] }), { a: [1, 2], b: 1 });
  // Different array order is a different value (deterministic, not folded).
  const third = stableId('ns', { b: 1, a: [2, 1] });
  assert.notEqual(first, third);
});
