import assert from 'node:assert/strict';
import test from 'node:test';
import { stableId, pathDenominator, validateProviderRecord, normalizeProviderResult, topologicalProviders } from '../lib/providers/sdk/index.mjs';
import { skippedReceipt } from '../lib/core/execute-plan.mjs';

test('stableId is deterministic and canonical', () => {
  const a = stableId('ns', { b: 1, a: [1, 2] });
  const b = stableId('ns', { a: [1, 2], b: 1 });
  assert.equal(a, b);
  assert.ok(a.startsWith('sha256:'));
});

test('pathDenominator normalizes, dedupes, sorts, and digests', () => {
  const denominator = pathDenominator(['b.ts', 'a.ts', 'b.ts', 'c.ts'], { exclude: ['node_modules'] });
  assert.deepEqual(denominator.paths, ['a.ts', 'b.ts', 'c.ts']);
  assert.equal(denominator.pathCount, 3);
  assert.ok(denominator.pathDigest.startsWith('sha256:'));
  // Exclusion filters vendor paths.
  const filtered = pathDenominator(['src/a.ts', 'vendor/lib.ts'], { exclude: ['vendor'] });
  assert.deepEqual(filtered.paths, ['src/a.ts']);
});

test('validateProviderRecord checks the v2 minimum', () => {
  assert.equal(validateProviderRecord({ id: 'x', providerVersion: '1', role: 'deterministic', phase: 'facts' }), true);
  assert.equal(validateProviderRecord({ id: 'x' }), false);
});

test('normalizeProviderResult is re-exported through the SDK', () => {
  const result = normalizeProviderResult(
    { id: 'p', denominator: { pathDigest: 'sha256:d' }, benchmark: { requiredForCleanClaim: true } },
    { status: 'pass', complete: true, findings: [] },
  );
  assert.equal(result.provider, 'p');
  assert.equal(result.required, true);
});

test('topologicalProviders is exported through the SDK', () => {
  const ordered = topologicalProviders([
    { id: 'b', dependsOn: ['a'] }, { id: 'a', dependsOn: [] },
  ]);
  assert.deepEqual(ordered.map((p) => p.id), ['a', 'b']);
});

test('selected-but-not-activated provider emits a deterministic skipped receipt', () => {
  const receipt = skippedReceipt({ id: 'security.chain-adjudication', activation: { kind: 'chain-eligible-paths-present' } }, 'no-path-retained');
  assert.equal(receipt.providerResult.status, 'skipped');
  assert.equal(receipt.providerResult.complete, true);
  assert.equal(receipt.providerResult.activation.matched, false);
});
