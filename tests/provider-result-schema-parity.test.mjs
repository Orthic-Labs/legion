// A shipped provider must satisfy the schema its own executor validates it
// against. provider-executor.mjs throws on any issue, so a divergence here is a
// runtime failure, not a lint: the schema had been tightened to a closed set
// that omitted receipts, artifacts, commands, inventory and every
// provider-specific coverage key, while normalize-provider-result.mjs emitted
// all of them.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { validateSchema } from '../src/lib/qualification/schema-validator.mjs';
import { normalizeProviderResult } from '../scripts/normalize-provider-result.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const schema = JSON.parse(readFileSync(join(root, 'src/schemas/provider-result-v1.schema.json'), 'utf8'));

test('every runnable suite provider satisfies provider-result-v1', async () => {
  const suites = readdirSync(join(root, 'src/providers')).filter((f) => f.endsWith('-suite.mjs'));
  assert.ok(suites.length >= 4, 'expected the suite providers to be present');

  let checked = 0;
  for (const file of suites) {
    const module = await import(new URL(`../src/providers/${file}`, import.meta.url));
    const run = Object.values(module).find((value) => typeof value === 'function');
    if (!run) continue;
    let raw;
    // A suite needing richer input than this stub is out of scope here; the
    // point is that whatever a provider emits must validate.
    try {
      raw = run({ files: ['a.js'], projection: { files: ['a.js'] } });
    } catch {
      continue;
    }
    const issues = validateSchema(schema, normalizeProviderResult({ id: file }, raw));
    assert.deepEqual(issues, [], `${file} violates provider-result-v1: ${issues.join(', ')}`);
    checked += 1;
  }
  assert.ok(checked >= 4, `expected to validate at least four providers, validated ${checked}`);
});
