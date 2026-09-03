// Known-answer harness for the structured-artifact corpora under
// bench/corpora/frameworks/<name>/. Each case file carries its own authority
// (evidence index, binding, instant) so the expected result is reproducible
// from the corpus bytes alone. Negative controls must never come back
// `measured`: the gate requires zero false positives.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import test from 'node:test';

const REQUIRED_KINDS = ['positive', 'negative', 'unsupported', 'denominator'];

function corpusFiles(dir) {
  const walk = (path) => readdirSync(path, { withFileTypes: true })
    .flatMap((entry) => (entry.isDirectory() ? walk(join(path, entry.name)) : [join(path, entry.name)]));
  return walk(dir)
    .map((file) => relative(dir, file).split(sep).join('/'))
    .filter((file) => file !== 'qualification.json')
    .sort();
}

// `run` receives the case input plus an authority whose `root` is the corpus
// directory, so evidence digests are verified against real bytes on disk.
export function runFrameworkCorpus({ corpusRoot, run }) {
  const dir = resolve(corpusRoot);
  const qualification = JSON.parse(readFileSync(join(dir, 'qualification.json'), 'utf8'));
  const cases = qualification.cases ?? [];
  const label = qualification.recordId;

  test(`${label}: every corpus file carries a declared known answer`, () => {
    assert.deepEqual(cases.map(({ path }) => path).sort(), corpusFiles(dir));
    assert.equal(new Set(cases.map(({ id }) => id)).size, cases.length);
    for (const kind of REQUIRED_KINDS) {
      assert.ok(cases.some((item) => item.kind === kind), `missing ${kind} case`);
    }
  });

  for (const item of cases.filter(({ expect }) => expect)) {
    test(`${label}: ${item.id} returns its declared answer`, () => {
      const { authority, ...input } = JSON.parse(readFileSync(join(dir, item.path), 'utf8'));
      const result = run(input, { ...authority, root: dir });
      assert.equal(result.status, item.expect.status);
      assert.equal(result.complete, item.expect.complete);
      if (item.expect.denominator) assert.deepEqual(result.denominator, item.expect.denominator);
      assert.deepEqual(result.coverageGaps, item.expect.coverageGaps);
      // Zero false positives: only a positive case may be reported measured.
      if (item.kind !== 'positive') assert.notEqual(result.status, 'measured');
    });
  }
}
