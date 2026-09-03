import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { lexicalAccounting } from '../src/providers/generic/index.mjs';
import { customGrammarRecord, rejectRepositoryGrammar, stableGrammarId } from '../src/providers/systems/custom-grammar.mjs';
import { componentDenominator, componentIdentity, inferPackageManager, reconcileComponents } from '../src/providers/monorepo/index.mjs';

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
  const registry = JSON.parse(readFileSync(new URL('../src/registry/coverage/coverage-registry.json', import.meta.url), 'utf8'));
  for (const id of ['language.cobol', 'language.zig', 'language.generic', 'format.promql', 'language.assembly']) {
    assert.ok(registry.languages.some((record) => record.id === id), `${id} accounted`);
  }
});

// --- coverage corpus: language.long-tail ------------------------------------
// bench/corpora/long-tail is the measured-pack corpus sealed against this file
// by scripts/seal-coverage-evidence.mjs. parsedExtensions is fixed by the
// corpus, so each case's gap (or absence of one) is a known answer.
{
  const corpusRoot = fileURLToPath(new URL('../bench/corpora/long-tail/', import.meta.url));
  const corpus = JSON.parse(readFileSync(new URL('../bench/corpora/long-tail/qualification.json', import.meta.url), 'utf8'));
  const corpusPaths = corpus.cases.map(({ path }) => path);

  test('language.long-tail: every corpus file carries a declared known answer', () => {
    const walk = (dir) => readdirSync(dir, { withFileTypes: true })
      .flatMap((entry) => (entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)]));
    const onDisk = walk(corpusRoot)
      .map((file) => relative(corpusRoot, file).split(sep).join('/'))
      .filter((file) => file !== 'qualification.json')
      .sort();
    assert.deepEqual([...corpusPaths].sort(), onDisk);
    for (const kind of ['positive', 'negative', 'unsupported', 'denominator']) {
      assert.ok(corpus.cases.some((item) => item.kind === kind), `missing ${kind} case`);
    }
  });

  for (const item of corpus.cases) {
    test(`language.long-tail: ${item.id} reports ${item.unsupportedExtension ?? 'no'} gap`, () => {
      const accounting = lexicalAccounting({ files: [item.path], parsedExtensions: corpus.parsedExtensions });
      assert.equal(accounting.fileCount, 1);
      assert.equal(accounting.precisionTier, 'lexical');
      // Zero false positives: a control declaring no gap must produce none.
      assert.deepEqual(accounting.unsupportedExtensions, item.unsupportedExtension ? [item.unsupportedExtension] : []);
      assert.deepEqual(
        accounting.coverageGaps,
        item.unsupportedExtension ? [{ kind: 'unsupported-extension', extension: item.unsupportedExtension }] : [],
      );
    });
  }

  test('language.long-tail: whole-corpus accounting matches the declared answer', () => {
    const accounting = lexicalAccounting({ files: corpusPaths, parsedExtensions: corpus.parsedExtensions });
    assert.equal(accounting.fileCount, corpus.expected.fileCount);
    assert.deepEqual(accounting.unsupportedExtensions, corpus.expected.unsupportedExtensions);
    assert.equal(accounting.precisionTier, corpus.expected.precisionTier);
  });
}
