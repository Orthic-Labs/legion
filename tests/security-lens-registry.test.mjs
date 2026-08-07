import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { expandSecurityLensProviders, extendRegistryWithSecurityLenses, loadProviderRegistry, loadSecurityLensRegistry } from '../registry/provider-registry.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('security lens registry loads and validates', () => {
  const registry = loadSecurityLensRegistry();
  assert.equal(registry.kind, 'security-lens-registry');
  assert.ok(registry.lenses.length >= 5);
  const ids = new Set(registry.lenses.map((lens) => lens.id));
  assert.equal(ids.size, registry.lenses.length, 'lens ids unique');
});

test('lenses expand to candidate-generator provider records', () => {
  const lenses = loadSecurityLensRegistry();
  const providers = expandSecurityLensProviders(lenses);
  for (const provider of providers) {
    assert.equal(provider.role, 'candidate-generator');
    assert.equal(provider.producesSecurityCandidates, true);
    assert.equal(provider.mayCloseOwnCandidates, false);
    assert.equal(provider.runner.kind, 'runtime-script');
  }
});

test('no provider id exists in both runtime registry and lens registry', () => {
  const runtime = loadProviderRegistry();
  const lenses = loadSecurityLensRegistry();
  const runtimeIds = new Set(runtime.providers.map((provider) => provider.id));
  for (const lens of lenses.lenses) {
    assert.ok(!runtimeIds.has(lens.id), `lens ${lens.id} must not duplicate a runtime provider`);
  }
});

test('extendRegistryWithSecurityLenses rejects duplicates', () => {
  const runtime = loadProviderRegistry();
  const lenses = loadSecurityLensRegistry();
  const extended = extendRegistryWithSecurityLenses(runtime, lenses);
  assert.ok(extended.providers.some((provider) => provider.id === 'security.credentials'));
  // Duplicate extension must throw.
  assert.throws(() => extendRegistryWithSecurityLenses(extended, lenses), /duplicates provider id/);
});

test('lens registry marks unmeasured lenses as required for clean claim', () => {
  const registry = loadSecurityLensRegistry();
  for (const lens of registry.lenses) {
    assert.equal(lens.benchmark.requiredForCleanClaim, true);
  }
});

test('every registered security lens has an implemented module', async () => {
  const registry = loadSecurityLensRegistry();
  const planned = registry.lenses.filter((lens) => lens.implementationState === 'planned');
  assert.deepEqual(planned, []);
  for (const lens of registry.lenses) {
    const loaded = await import(new URL(`../${lens.module}`, import.meta.url));
    assert.equal(loaded.default.id, lens.id);
    assert.equal(typeof loaded.default.analyze, 'function');
  }
});

test('rule alias registry preserves history references', () => {
  const aliases = JSON.parse(readFileSync(new URL('../registry/security-rule-aliases.json', import.meta.url), 'utf8'));
  assert.equal(aliases.kind, 'security-rule-aliases');
  assert.ok(aliases.aliases['data.sql-interpolation']);
  assert.ok(aliases.aliases['security.command-injection']);
});

test('security-suite compatibility wrapper exposes the legacy pack mapping', async () => {
  const { legacyPackMapping } = await import('../providers/security-suite.mjs');
  const mapping = legacyPackMapping();
  assert.equal(mapping.credentials, 'security.credentials');
  assert.equal(mapping['misuse-resistance'], 'security.misuse-resistance');
});
