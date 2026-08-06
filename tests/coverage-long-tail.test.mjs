import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { lexicalAccounting } from '../providers/generic/index.mjs';
import { customGrammarRecord, rejectRepositoryGrammar, stableGrammarId } from '../providers/systems/custom-grammar.mjs';
import { componentDenominator, componentIdentity, inferPackageManager, reconcileComponents } from '../providers/monorepo/index.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('lexical accounting reports unsupported extensions as gaps, never silent omission', () => {
  const accounting = lexicalAccounting({ files: ['a.py', 'b.unknownext', 'c.ts'], parsedExtensions: ['py', 'ts'] });
  assert.equal(accounting.fileCount, 3);
  assert.deepEqual(accounting.unsupportedExtensions, ['unknownext']);
  assert.ok(accounting.coverageGaps.some((g) => g.kind === 'unsupported-extension'));
  assert.equal(accounting.precisionTier, 'lexical');
});

test('lexical fallback never claims AST support', () => {
  const accounting = lexicalAccounting({ files: ['a.unknownext'], parsedExtensions: [] });
  assert.equal(accounting.precisionTier, 'lexical');
  assert.ok(!accounting.coverageGaps.some((g) => g.kind === 'parsed'));
});

test('custom grammar requires host-config source and pinned digest', () => {
  const record = customGrammarRecord({ languageId: 'language.custom', grammarPath: '/trusted/parser.wasm', grammarDigest: 'sha256:g' });
  assert.equal(record.source, 'host-config');
  assert.equal(record.qualified, false);
  assert.throws(() => customGrammarRecord({ languageId: 'x', grammarPath: '/p', grammarDigest: 'sha256:g', source: 'repository' }), /host-config/);
});

test('repository config cannot introduce custom grammar path or digest', () => {
  assert.throws(() => rejectRepositoryGrammar({ grammarPath: '/evil.wasm' }), /may not introduce/);
  assert.throws(() => rejectRepositoryGrammar({ grammarDigest: 'sha256:e' }), /may not introduce/);
  assert.doesNotThrow(() => rejectRepositoryGrammar({ grammarId: 'language.custom' }));
});

test('custom grammar id is stable', () => {
  assert.equal(stableGrammarId('language.custom', 'sha256:g'), stableGrammarId('language.custom', 'sha256:g'));
});

test('monorepo component identity is stable and manager-aware', () => {
  const component = componentIdentity({ repoId: 'repo', manifestPath: 'packages/a/package.json', packageName: 'a' });
  assert.equal(component.packageManager, 'npm');
  assert.ok(component.id.startsWith('sha256:'));
  const again = componentIdentity({ repoId: 'repo', manifestPath: 'packages/a/package.json', packageName: 'a' });
  assert.equal(component.id, again.id);
});

test('package manager inference covers the primary ecosystems', () => {
  assert.equal(inferPackageManager('Cargo.toml'), 'cargo');
  assert.equal(inferPackageManager('go.mod'), 'go');
  assert.equal(inferPackageManager('pom.xml'), 'maven');
  assert.equal(inferPackageManager('Gemfile'), 'bundler');
  assert.equal(inferPackageManager('unknown.txt'), 'unknown');
});

test('component denominator is component-aware', () => {
  const a = componentIdentity({ repoId: 'r', manifestPath: 'packages/a/package.json', packageName: 'a' });
  const b = componentIdentity({ repoId: 'r', manifestPath: 'packages/b/package.json', packageName: 'b' });
  const denominator = componentDenominator([a, b]);
  assert.equal(denominator.componentCount, 2);
  assert.ok(denominator.digest.startsWith('sha256:'));
});

test('one failing component cannot be hidden by aggregate success', () => {
  const a = componentIdentity({ repoId: 'r', manifestPath: 'packages/a/package.json', packageName: 'a' });
  const reconciliation = reconcileComponents([a], [{ componentId: a.id, complete: false, status: 'error' }]);
  assert.equal(reconciliation.complete, false);
  assert.equal(reconciliation.incomplete.length, 1);
});

test('coverage registry still accounts long-tail languages', () => {
  const registry = JSON.parse(readFileSync(new URL('../registry/coverage/coverage-registry.json', import.meta.url), 'utf8'));
  for (const id of ['language.cobol', 'language.zig', 'language.generic', 'format.promql', 'language.assembly']) {
    assert.ok(registry.languages.some((record) => record.id === id), `${id} accounted`);
  }
});
