// measured-pack means reproducible precision and recall over a provider's own
// rule output (references/provider-architecture.md). A `selected-scope`
// provider accounts for the denominator — which files it claims — and emits no
// findings, so there is nothing to measure. All thirteen language records once
// carried the tier over exactly such providers.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { validateCoverageRegistry } from '../src/lib/coverage/index.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const registry = () => JSON.parse(readFileSync(new URL('../src/registry/coverage/index.json', import.meta.url), 'utf8'));

test('the shipped coverage registry validates', () => {
  assert.ok(validateCoverageRegistry(registry(), { root }));
});

test('measured-pack is refused over accounting-only providers', () => {
  const probe = registry();
  const record = probe.records.find((r) => r.id === 'language.javascript');
  record.tiers['measured-pack'] = 1;
  assert.throws(
    () => validateCoverageRegistry(probe, { root }),
    /accounting-only providers/,
    'a language record must not be able to claim rule-output coverage',
  );
});

test('language providers emit no findings to measure', async () => {
  for (const language of ['javascript', 'python', 'rust']) {
    const { analyze } = await import(`../src/providers/code/${language}/index.mjs`);
    const result = analyze({ files: [`fixture.${language}`] });
    assert.equal(result.findings, undefined, `${language} unexpectedly emits findings`);
    assert.equal(result.candidates, undefined, `${language} unexpectedly emits candidates`);
    assert.ok(result.denominator, `${language} must still account for its denominator`);
  }
});
