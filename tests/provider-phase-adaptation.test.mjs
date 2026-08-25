import assert from 'node:assert/strict';
import test from 'node:test';
import { loadProviderRegistry } from '../src/registry/provider-registry.mjs';

test('v2 judgment providers remain selected reasoning contracts', () => {
  const registry = loadProviderRegistry();
  const adjudication = registry.providers.find(({ id }) => id === 'security.adjudication');
  const variant = registry.providers.find(({ id }) => id === 'security.variant-analysis');
  assert.equal(adjudication.phase, 'reasoning');
  assert.equal(variant.phase, 'reasoning');
  assert.equal(adjudication.runner.kind, 'reasoning-contract');
});
