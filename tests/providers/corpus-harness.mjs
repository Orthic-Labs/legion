// Shared known-answer harness for the language coverage corpora under
// bench/corpora/<language>/. House style follows bench/manifest.json: every
// positive case is paired with a negative control, and the gate requires zero
// false positives — a file the corpus declares unselected must never appear in
// a provider denominator.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import test from 'node:test';

const REQUIRED_KINDS = ['positive', 'negative', 'unsupported', 'denominator'];
const digest = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

function corpusFiles(dir) {
  const walk = (path) => readdirSync(path, { withFileTypes: true })
    .flatMap((entry) => (entry.isDirectory() ? walk(join(path, entry.name)) : [join(path, entry.name)]));
  return walk(dir)
    .map((file) => relative(dir, file).split(sep).join('/'))
    .filter((file) => file !== 'qualification.json')
    .sort();
}

// A fully evidenced tool receipt: the only shape shared.mjs accepts without
// emitting a tool-evidence-gap. Digests are computed here, never transcribed.
function toolEvidence(tools) {
  return Object.fromEntries(tools.map((id) => [id, {
    status: 'pass',
    identity: { version: '0.0.0-corpus', executableDigest: digest(`corpus-tool-executable\0${id}`) },
    artifactDigest: digest(`corpus-tool-artifact\0${id}`),
    scope: 'corpus',
  }]));
}

export function runLanguageCorpus({ corpusRoot, analyze, config }) {
  const dir = resolve(corpusRoot);
  const qualification = JSON.parse(readFileSync(join(dir, 'qualification.json'), 'utf8'));
  const cases = qualification.cases ?? [];
  const label = qualification.recordId;

  test(`${label}: every corpus file carries a declared known answer`, () => {
    assert.deepEqual(cases.map(({ path }) => path).sort(), corpusFiles(dir));
    assert.equal(new Set(cases.map(({ id }) => id)).size, cases.length);
  });

  test(`${label}: corpus declares positive, negative, unsupported and denominator cases`, () => {
    for (const kind of REQUIRED_KINDS) {
      assert.ok(cases.some((item) => item.kind === kind), `missing ${kind} case`);
    }
    assert.ok(cases.some(({ selected }) => selected === true), 'corpus has no positive selection');
    assert.ok(cases.some(({ selected }) => selected === false), 'corpus has no negative control');
  });

  for (const item of cases) {
    test(`${label}: ${item.id} is ${item.selected ? 'selected' : 'not selected'}`, () => {
      const result = analyze({ files: [item.path] });
      assert.equal(result.provider, `code.${config.id}`);
      assert.equal(result.denominator.expected, item.selected ? 1 : 0);
      assert.equal(result.denominator.examined, result.denominator.expected);
      if (item.selected) {
        assert.equal(result.denominator.variants[item.variant], 1);
      } else {
        // Zero false positives: an unselected file yields an empty denominator.
        assert.ok(result.coverageGaps.some(({ kind }) => kind === 'denominator-gap'));
        assert.deepEqual(Object.values(result.denominator.variants).filter(Boolean), []);
      }
    });
  }

  test(`${label}: whole-corpus denominator and variants match the declared answer`, () => {
    const result = analyze({ files: cases.map(({ path }) => path) });
    assert.deepEqual(result.denominator, {
      kind: `${config.id}-files`,
      expected: qualification.expected.denominator.expected,
      examined: qualification.expected.denominator.examined,
      variants: qualification.expected.variants,
    });
    assert.equal(result.denominator.expected, cases.filter(({ selected }) => selected).length);
  });

  test(`${label}: missing tool and context evidence is reported, never assumed`, () => {
    const result = analyze({ files: cases.map(({ path }) => path) });
    assert.equal(result.complete, false);
    assert.deepEqual(
      result.coverageGaps.filter(({ kind }) => kind === 'tool-evidence-gap').map(({ tool }) => tool),
      config.tools ?? [],
    );
    assert.deepEqual(
      result.coverageGaps.filter(({ kind }) => kind === 'context-gap').map(({ context }) => context),
      config.requiredContext ?? [],
    );
  });

  test(`${label}: complete evidence closes every coverage gap`, () => {
    const result = analyze({
      files: cases.map(({ path }) => path),
      tools: toolEvidence(config.tools ?? []),
      context: Object.fromEntries((config.requiredContext ?? []).map((key) => [key, ['corpus']])),
    });
    assert.deepEqual(result.coverageGaps, []);
    assert.equal(result.complete, true);
  });
}
