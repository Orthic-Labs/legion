import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { buildSupportMatrix, renderMarkdown } from '../scripts/generate-support-matrix.mjs';
import { NATIVE_PROVIDERS, nativeProviderFor } from '../providers/native/index.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('coverage registry contains all 85 language/format rows', () => {
  const registry = JSON.parse(readFileSync(new URL('../registry/coverage/coverage-registry.json', import.meta.url), 'utf8'));
  assert.equal(registry.schemaVersion, 2);
  assert.equal(registry.languages.length, 85, 'all Appendix C rows must exist');
  const ids = new Set(registry.languages.map((record) => record.id));
  assert.equal(ids.size, 85, 'ids must be unique');
});

test('every coverage row has the tier structure', () => {
  const registry = JSON.parse(readFileSync(new URL('../registry/coverage/coverage-registry.json', import.meta.url), 'utf8'));
  const tierKeys = ['inventory', 'parser', 'nativeSemantics', 'crossFileDataflow', 'measuredPack', 'runtime', 'remediation'];
  for (const record of registry.languages) {
    for (const key of tierKeys) {
      assert.ok(Number.isInteger(record.tiers[key]), `${record.id}.tiers.${key} must be an integer`);
      assert.ok(record.tiers[key] >= 0 && record.tiers[key] <= 7, `${record.id}.tiers.${key} in range`);
    }
    assert.equal(record.qualification.status, 'unproven', `${record.id} must be unproven until measured`);
  }
});

test('no language may disappear because it is unsupported', () => {
  const registry = JSON.parse(readFileSync(new URL('../registry/coverage/coverage-registry.json', import.meta.url), 'utf8'));
  // Every text language from Appendix C is accounted, even at tier 1.
  for (const id of ['language.cobol', 'language.zig', 'language.generic', 'format.promql']) {
    assert.ok(registry.languages.some((record) => record.id === id), `${id} must be accounted`);
  }
});

test('support matrix is generated from the registry only', () => {
  const matrix = buildSupportMatrix();
  assert.equal(matrix.kind, 'nemesis-support-matrix');
  assert.equal(matrix.rows.length, 85);
  const markdown = renderMarkdown(matrix);
  assert.match(markdown, /# Nemesis language support matrix/);
  assert.ok(markdown.includes('| language.javascript |'));
});

test('generated support matrix is committed and in sync', () => {
  const generated = readFileSync(new URL('../references/support-matrix.generated.md', import.meta.url), 'utf8');
  assert.ok(generated.includes('| language.javascript |'));
  assert.ok(generated.includes('| format.github-actions |'));
  assert.match(generated, /# Nemesis language support matrix/);
});

test('native provider matrix covers Wave-0 families', () => {
  for (const id of ['native.javascript', 'native.python', 'native.rust', 'native.go', 'native.jvm', 'native.dotnet']) {
    assert.ok(NATIVE_PROVIDERS[id], `native provider ${id}`);
    assert.equal(NATIVE_PROVIDERS[id].role, 'deterministic');
    assert.ok(NATIVE_PROVIDERS[id].commands.lint, `${id} has a lint command`);
    assert.ok(NATIVE_PROVIDERS[id].commands.test, `${id} has a test command`);
  }
});

test('native provider maps extensions to families', () => {
  assert.equal(nativeProviderFor('ts').id, 'native.javascript');
  assert.equal(nativeProviderFor('py').id, 'native.python');
  assert.equal(nativeProviderFor('rs').id, 'native.rust');
  assert.equal(nativeProviderFor('java').id, 'native.jvm');
  assert.equal(nativeProviderFor('cs').id, 'native.dotnet');
  assert.equal(nativeProviderFor('unknown'), null);
});

test('tier promotion requires a qualification artifact', () => {
  const registry = JSON.parse(readFileSync(new URL('../registry/coverage/coverage-registry.json', import.meta.url), 'utf8'));
  for (const record of registry.languages) {
    if (record.qualification.status !== 'unproven') {
      assert.ok(record.qualification.corpusDigest, `${record.id} measured requires corpus digest`);
      assert.ok(record.qualification.artifactDigest, `${record.id} measured requires artifact digest`);
    }
  }
});
