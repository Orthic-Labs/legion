import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { buildSecurityBindingSchema, buildSecurityModelSchema, buildVerdictSchema } from '../scripts/generate-security-schemas.mjs';
import { EVIDENCE_STRENGTH, SECURITY_VERDICTS } from '../src/providers/security/contracts.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

test('security schemas are generated from code-owned enums', () => {
  const verdict = buildVerdictSchema();
  assert.deepEqual(verdict.properties.verdict.enum, [...SECURITY_VERDICTS]);
  assert.deepEqual(verdict.properties.evidenceStrength.enum, [...EVIDENCE_STRENGTH]);
});

test('committed security schemas match the generators', () => {
  const binding = JSON.parse(readFileSync(new URL('../src/schemas/security-binding-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(buildSecurityBindingSchema(), binding);
  const model = JSON.parse(readFileSync(new URL('../src/schemas/security-model-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(buildSecurityModelSchema(), model);
  const verdict = JSON.parse(readFileSync(new URL('../src/schemas/security-verdict-v1.schema.json', import.meta.url), 'utf8'));
  assert.deepEqual(buildVerdictSchema(), verdict);
});

test('security binding schema requires all binding fields', () => {
  const schema = buildSecurityBindingSchema();
  assert.deepEqual(schema.required, ['planDigest', 'repositoryRevision', 'dirtyPatchDigest', 'blueprintGenerationId', 'blueprintManifestDigest', 'registryDigest']);
});

test('no security schema references legacy identity', () => {
  for (const name of ['security-binding-v1.schema.json', 'security-model-v1.schema.json', 'security-verdict-v1.schema.json']) {
    const content = readFileSync(new URL(`../src/schemas/${name}`, import.meta.url), 'utf8');
    assert.ok(!content.includes('operator'), `${name} must not reference legacy identity`);
  }
});
