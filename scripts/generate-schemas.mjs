#!/usr/bin/env node
// Generates committed JSON schemas from the code-owned contract enums so the
// runtime validators and JSON schemas can never drift. Run without arguments to
// regenerate; run with --check to fail when committed schemas differ.

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { PROVIDER_STATUS, PROVIDER_PHASES, PROVIDER_ROLES } from '../registry/provider-contracts.mjs';
import {
  EVIDENCE_STRENGTH,
  FACT_KINDS,
  SECURITY_VERDICTS,
} from '../providers/security/contracts.mjs';

function write(path, value) {
  writeFileSync(resolve(path), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function buildProviderResultSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/audit-provider-result-v1.json',
    title: 'AuditProviderResultV1',
    type: 'object',
    required: ['schemaVersion', 'provider', 'applicable', 'required', 'status', 'complete', 'coverage', 'candidates', 'findings', 'coverageGaps', 'degradation'],
    properties: {
      schemaVersion: { const: 1 },
      provider: { type: 'string', minLength: 1 },
      applicable: { type: 'boolean' },
      required: { type: 'boolean' },
      status: { enum: [...PROVIDER_STATUS] },
      complete: { type: 'boolean' },
      coverage: {
        type: 'object',
        required: ['denominatorDigest'],
        properties: {
          denominatorDigest: { type: 'string', pattern: '^sha256:' },
          expected: { type: 'integer', minimum: 0 },
          examined: { type: 'integer', minimum: 0 },
          unexamined: { type: 'array', items: { type: 'string' } },
        },
        additionalProperties: true,
      },
      commands: { type: 'array', items: { type: 'object' } },
      receipts: { type: 'array', items: { type: 'object' } },
      inventory: { type: 'array' },
      candidates: { type: 'array' },
      findings: { type: 'array' },
      coverageGaps: { type: 'array' },
      inputArtifacts: { type: 'array', items: { type: 'string' } },
      artifacts: {
        type: 'array',
        items: {
          type: 'object',
          required: ['kind', 'path', 'digest'],
          properties: {
            kind: { type: 'string' },
            path: { type: 'string' },
            digest: { type: 'string', pattern: '^sha256:' },
          },
        },
      },
      degradation: { type: 'array' },
    },
    additionalProperties: true,
  };
}

export function buildSecurityVerdictSchema() {
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

export function buildSchemas() {
  return {
    'schemas/provider-result-v1.schema.json': buildProviderResultSchema(),
    'schemas/security-verdict-v1.schema.json': buildSecurityVerdictSchema(),
  };
}

export function providerStatusFragment() {
  return { enum: [...PROVIDER_STATUS] };
}

export function providerRolesFragment() {
  return { enum: [...PROVIDER_ROLES] };
}

export function providerPhasesFragment() {
  return { enum: [...PROVIDER_PHASES] };
}

export function evidenceStrengthFragment() {
  return { enum: [...EVIDENCE_STRENGTH] };
}

export function securityVerdictsFragment() {
  return { enum: [...SECURITY_VERDICTS] };
}

export function factKindsFragment() {
  return { enum: [...FACT_KINDS] };
}

function main() {
  const check = process.argv.includes('--check');
  let failed = false;
  for (const [path, value] of Object.entries(buildSchemas())) {
    const generated = `${JSON.stringify(value, null, 2)}\n`;
    const committed = readFileSync(resolve(path), 'utf8');
    if (committed !== generated) {
      if (check) {
        console.error(`SCHEMA DRIFT: ${path} is not up to date with the code-owned enums; run node scripts/generate-schemas.mjs`);
        failed = true;
      } else {
        write(path, value);
        console.log(`wrote ${path}`);
      }
    } else if (check) {
      console.log(`OK ${path}`);
    }
  }
  if (check) {
    if (failed) process.exit(1);
    console.log('schemas are in sync with contracts');
    process.exit(0);
  }
}

if (process.argv[1] && process.argv[1].endsWith('generate-schemas.mjs')) {
  main();
}
