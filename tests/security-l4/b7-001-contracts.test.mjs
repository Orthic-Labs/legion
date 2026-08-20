// B7-001 — canonical security contracts and generated schemas.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  CONTROL_STATES,
  ENTITY_KINDS,
  EVIDENCE_CLASS,
  EVIDENCE_STRENGTH,
  FACT_KINDS,
  JUDGMENT_VERDICT,
  PATH_PRIORITY,
  PATH_STATUS,
  PROVIDER_STATUS,
  RELATION_KINDS,
  SECURITY_VERDICTS,
  assertControlState,
  assertEntityKind,
  assertRelationKind,
  assertSecurityArtifact,
  assertSecuritySchemaVersion,
  securityArtifactRecord,
} from '../../src/providers/security/contracts.mjs';
import {
  EVIDENCE_CLASS as CORE_EVIDENCE_CLASS,
  JUDGMENT_VERDICT as CORE_JUDGMENT_VERDICT,
  PROVIDER_STATUS as CORE_PROVIDER_STATUS,
} from '../../src/lib/contracts/enums.mjs';
import {
  SECURITY_SCHEMA_FILES,
  buildSecurityEnumRegistry,
  buildSecuritySchemas,
} from '../../scripts/generate-security-schemas.mjs';

const binding = {
  planDigest: 'sha256:plan',
  repositoryRevision: 'rev',
  dirtyPatchDigest: null,
  blueprintGenerationId: 'gen',
  blueprintManifestDigest: 'sha256:manifest',
  registryDigest: 'sha256:registry',
};

test('security contracts re-export core provider and evidence enums instead of duplicating them', () => {
  assert.deepEqual([...PROVIDER_STATUS], [...CORE_PROVIDER_STATUS]);
  assert.deepEqual([...EVIDENCE_CLASS], [...CORE_EVIDENCE_CLASS]);
  assert.deepEqual([...JUDGMENT_VERDICT], [...CORE_JUDGMENT_VERDICT]);
});

test('entity, relation, and control vocabularies are code-owned and frozen', () => {
  for (const list of [ENTITY_KINDS, RELATION_KINDS, CONTROL_STATES, EVIDENCE_STRENGTH, SECURITY_VERDICTS, PATH_STATUS, PATH_PRIORITY, FACT_KINDS]) {
    assert.ok(Object.isFrozen(list));
    assert.ok(list.length > 0);
  }
  for (const kind of ['actor', 'principal', 'identity', 'entrypoint', 'asset', 'crown-jewel', 'trust-boundary', 'control', 'source', 'sink', 'service', 'process', 'repository-artifact', 'data-store', 'tool-capability', 'permission-scope', 'deployment-context', 'workflow-state']) {
    assert.equal(assertEntityKind(kind), kind);
  }
  assert.throws(() => assertEntityKind('unicorn'), /unknown security entity kind/);
  assert.throws(() => assertRelationKind('teleports-to'), /unknown security relation kind/);
  assert.throws(() => assertControlState('probably-fine'), /unknown security control state/);
  assert.equal(assertControlState('absent'), 'absent');
});

test('unknown future security schema versions are rejected', () => {
  assert.equal(assertSecuritySchemaVersion('security-model', 1), 1);
  assert.throws(() => assertSecuritySchemaVersion('security-model', 2), /unsupported schema version/);
  assert.throws(() => assertSecuritySchemaVersion('security-model', 99), /unsupported schema version/);
  assert.equal(assertSecuritySchemaVersion('security-candidate', 2), 2);
});

test('every security artifact requires binding and denominator digest', () => {
  const artifact = { schemaVersion: 1, kind: 'security-surface-model', binding, denominatorDigest: 'sha256:denom' };
  assert.equal(assertSecurityArtifact(artifact, 'security-model'), artifact);
  assert.throws(() => assertSecurityArtifact({ ...artifact, binding: undefined }, 'security-model'), /binding/);
  assert.throws(() => assertSecurityArtifact({ ...artifact, denominatorDigest: undefined }, 'security-model'), /denominatorDigest/);
});

test('the canonical artifact store record carries binding and denominator digest', () => {
  const record = securityArtifactRecord({
    path: 'provider-results/security.json',
    digest: 'sha256:abc',
    bytes: 12,
    producer: 'security.surface-model',
    producerVersion: '1',
    binding,
    denominatorDigest: 'sha256:denom',
  });
  assert.equal(record.kind, 'legion-artifact-record');
  assert.equal(record.mediaType, 'application/json');
  assert.deepEqual(record.binding, binding);
  assert.equal(record.denominatorDigest, 'sha256:denom');
  assert.throws(() => securityArtifactRecord({ path: 'x', digest: 'sha256:a', bytes: 1, producer: 'p', producerVersion: '1', binding }), /denominatorDigest/);
});

test('runtime enum vocabulary and the committed enum registry are identical', () => {
  const committed = JSON.parse(readFileSync(new URL('../../src/registry/rules/security/enums.json', import.meta.url), 'utf8'));
  assert.deepEqual(committed, buildSecurityEnumRegistry());
});

test('generated security schemas are committed byte-identically and are enum-closed', () => {
  const schemas = buildSecuritySchemas();
  assert.ok(SECURITY_SCHEMA_FILES.length >= 5);
  for (const relativePath of SECURITY_SCHEMA_FILES) {
    const committed = JSON.parse(readFileSync(new URL(`../../${relativePath}`, import.meta.url), 'utf8'));
    assert.deepEqual(committed, schemas[relativePath], `${relativePath} drifted from its generator`);
  }
  const model = schemas['src/schemas/security/security-model-v1.schema.json'];
  assert.deepEqual(model.properties.entities.items.properties.kind.enum, [...ENTITY_KINDS]);
  assert.deepEqual(model.properties.relations.items.properties.kind.enum, [...RELATION_KINDS]);
  assert.deepEqual(model.required.includes('binding') && model.required.includes('denominatorDigest'), true);
  const candidate = schemas['src/schemas/security/security-candidate-v2.schema.json'];
  assert.equal(candidate.properties.schemaVersion.const, 2);
  assert.deepEqual(candidate.properties.effects.items.properties.kind.enum, [...FACT_KINDS]);
  for (const [relativePath, schema] of Object.entries(schemas)) {
    if (relativePath.endsWith('security-binding-v1.schema.json')) continue;
    assert.ok(schema.required.includes('binding'), `${relativePath} must require binding`);
    assert.ok(schema.required.includes('denominatorDigest'), `${relativePath} must require denominatorDigest`);
  }
});
