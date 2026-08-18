import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  buildProviderResultSchema,
  buildSchemas,
  buildSecurityVerdictSchema,
} from '../scripts/generate-schemas.mjs';
import { PROVIDER_STATUS } from '../src/registry/provider-contracts.mjs';
import { EVIDENCE_STRENGTH, SECURITY_VERDICTS } from '../src/providers/security/contracts.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('generated provider-result schema deep-equals the committed schema', () => {
  const committed = JSON.parse(readFileSync(new URL('../src/schemas/provider-result-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(buildProviderResultSchema(), committed,
    'committed schema drifted from the generator; run node scripts/generate-schemas.mjs');
});

test('generated security-verdict schema deep-equals the committed schema', () => {
  const committed = JSON.parse(readFileSync(new URL('../src/schemas/security-verdict-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(buildSecurityVerdictSchema(), committed,
    'committed schema drifted from the generator; run node scripts/generate-schemas.mjs');
});

test('schema enums match the code-owned contract enums', () => {
  const provider = buildProviderResultSchema();
  assert.deepEqual(provider.properties.status.enum, [...PROVIDER_STATUS]);
  const verdict = buildSecurityVerdictSchema();
  assert.deepEqual(verdict.properties.verdict.enum, [...SECURITY_VERDICTS]);
  assert.deepEqual(verdict.properties.evidenceStrength.enum, [...EVIDENCE_STRENGTH]);
});

test('buildSchemas covers every committed schema', () => {
  const generated = buildSchemas();
  assert.ok(generated['src/schemas/provider-result-v1.schema.json']);
  assert.ok(generated['src/schemas/security-verdict-v1.schema.json']);
  for (const [path, value] of Object.entries(generated)) {
    assert.ok(value && typeof value === 'object', `generated schema ${path} is invalid`);
  }
});

test('schemas contain no legacy operator identity', () => {
  for (const path of Object.keys(buildSchemas())) {
    const committed = readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
    assert.ok(!committed.includes('operator'), `${path} still references the legacy operator identity`);
  }
});
