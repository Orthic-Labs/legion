#!/usr/bin/env node
// Generates committed security schemas from the code-owned security enums so
// schema/runtime enums can never drift.

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  EVIDENCE_STRENGTH,
  FACT_KINDS,
  SECURITY_VERDICTS,
} from '../providers/security/contracts.mjs';
import { PROVIDER_STATUS } from '../registry/provider-contracts.mjs';

function write(path, value) {
  writeFileSync(resolve(path), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function buildSecurityBindingSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/security-binding-v1.json',
    title: 'SecurityBindingV1',
    type: 'object',
    required: ['planDigest', 'repositoryRevision', 'dirtyPatchDigest', 'cortexGenerationId', 'cortexManifestDigest', 'registryDigest'],
    properties: {
      planDigest: { type: 'string', pattern: '^sha256:' },
      repositoryRevision: { type: 'string', minLength: 1 },
      dirtyPatchDigest: { oneOf: [{ type: 'null' }, { type: 'string', pattern: '^sha256:' }] },
      cortexGenerationId: { type: 'string', minLength: 1 },
      cortexManifestDigest: { type: 'string', pattern: '^sha256:' },
      registryDigest: { type: 'string', pattern: '^sha256:' },
    },
    additionalProperties: false,
  };
}

export function buildSecurityModelSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/security-model-v1.json',
    title: 'SecurityModelV1',
    type: 'object',
    required: ['schemaVersion', 'kind', 'provider', 'providerVersion', 'binding', 'denominatorDigest', 'complete', 'entities', 'relations', 'initialFacts', 'evidence', 'coverage', 'coverageGaps'],
    properties: {
      schemaVersion: { const: 1 },
      kind: { const: 'security-surface-model' },
      provider: { const: 'security.surface-model' },
      providerVersion: { type: 'string' },
      binding: { $ref: 'security-binding-v1.schema.json' },
      denominatorDigest: { type: 'string', pattern: '^sha256:' },
      complete: { type: 'boolean' },
      entities: { type: 'array' },
      relations: { type: 'array' },
      initialFacts: { type: 'array' },
      evidence: { type: 'array' },
      coverage: { type: 'object' },
      coverageGaps: { type: 'array' },
    },
    additionalProperties: true,
  };
}

export function buildSecuritySchemas() {
  return {
    'schemas/security-binding-v1.schema.json': buildSecurityBindingSchema(),
    'schemas/security-model-v1.schema.json': buildSecurityModelSchema(),
    'schemas/security-verdict-v1.schema.json': buildVerdictSchema(),
  };
}

export function buildVerdictSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/security-verdict-v1.json',
    title: 'SecurityVerdictV1',
    type: 'object',
    required: ['schemaVersion', 'kind', 'candidateId', 'candidateProvider', 'adjudicatorProvider', 'adjudicatorContextId', 'evidenceStrength', 'verdict', 'threatModel', 'reachability', 'impact', 'variantAnalysisRequired'],
    properties: {
      schemaVersion: { const: 1 },
      kind: { const: 'security-verdict' },
      candidateId: { type: 'string' },
      candidateProvider: { type: 'string' },
      adjudicatorProvider: { type: 'string' },
      adjudicatorContextId: { type: 'string' },
      evidenceStrength: { enum: [...EVIDENCE_STRENGTH] },
      verdict: { enum: [...SECURITY_VERDICTS] },
      severity: { type: ['string', 'null'], enum: ['critical', 'high', 'medium', 'low', null] },
      threatModel: { type: 'string' },
      attackerControl: { type: 'string' },
      reachability: { type: 'string' },
      trustBoundaries: { type: 'array', items: { type: 'string' } },
      impact: { type: 'string' },
      proof: { type: ['object', 'null'] },
      variantAnalysisRequired: { type: 'boolean' },
      verdictDigest: { type: 'string', pattern: '^sha256:' },
    },
    additionalProperties: true,
  };
}

export function providerStatusFragment() {
  return { enum: [...PROVIDER_STATUS] };
}

function main() {
  for (const [path, value] of Object.entries(buildSecuritySchemas())) {
    write(path, value);
    console.log(`wrote ${path}`);
  }
}

if (process.argv[1] && process.argv[1].endsWith('generate-security-schemas.mjs')) main();
