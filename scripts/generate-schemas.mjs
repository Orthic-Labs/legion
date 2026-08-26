#!/usr/bin/env node
// Generates committed JSON schemas from the code-owned contract enums so the
// runtime validators and JSON schemas can never drift. Run without arguments to
// regenerate; run with --check to fail when committed schemas differ.

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { PROVIDER_STATUS, PROVIDER_PHASES, PROVIDER_ROLES } from '../src/registry/provider-contracts.mjs';
import {
  EVIDENCE_STRENGTH,
  FACT_KINDS,
  SECURITY_VERDICTS,
} from '../src/providers/security/contracts.mjs';

function write(path, value) {
  writeFileSync(resolve(path), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function buildProviderResultSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/audit-provider-result-v1.json',
    type: 'object',
    additionalProperties: false,
    required: ['schemaVersion', 'provider', 'applicable', 'required', 'status', 'complete', 'coverage', 'candidates', 'findings', 'coverageGaps', 'degradation', 'details'],
    properties: {
      schemaVersion: { const: 1 },
      provider: { type: 'string', minLength: 1 },
      applicable: { type: 'boolean' },
      required: { type: 'boolean' },
      status: { enum: [...PROVIDER_STATUS] },
      complete: { type: 'boolean' },
      coverage: {
        type: 'object',
        additionalProperties: false,
        required: ['denominatorDigest','expected','examined'],
        properties: {
          denominatorDigest: { type: 'string', pattern: '^sha256:[a-f0-9]{64}$' },
          expected: { type: 'integer', minimum: 0 },
          examined: { type: 'integer', minimum: 0 },
        },
      },
      candidates: { type: 'array' },
      findings: { type: 'array' },
      coverageGaps: { type: 'array' },
      degradation: { type: 'array' },
      details:{type:'object',additionalProperties:false,required:['family','componentIds','limitations','rawArtifacts'],properties:{family:{type:'string',minLength:1},componentIds:{type:'array',items:{type:'string'}},limitations:{type:'array'},rawArtifacts:{type:'array'}}},
    },
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

export function buildWebActorFixtureSchema() {
  const nonempty = { type: 'string', minLength: 1 };
  const bindingKeys = ['targetId', 'environment', 'actorId', 'tenantId', 'browser', 'browserVersion', 'viewport', 'locale', 'sourceRevision', 'artifactDigest'];
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/platform/web-actor-fixture-v1.json',
    type: 'object',
    additionalProperties: false,
    required: ['schemaVersion', 'kind', 'status', 'complete', 'proof', 'terminal', 'binding', 'actors', 'denominator', 'coverageGaps', 'digest'],
    properties: {
      schemaVersion: { const: 1 },
      kind: { const: 'legion-web-actor-fixtures' },
      status: { const: 'pass' },
      complete: { const: true },
      proof: { const: true },
      terminal: { const: true },
      binding: { type: 'object', additionalProperties: false, required: bindingKeys, properties: Object.fromEntries(bindingKeys.map((key) => [key, nonempty])) },
      actors: { type: 'array', minItems: 1, items: { $ref: '#/$defs/actor' } },
      denominator: {
        type: 'object',
        additionalProperties: false,
        required: ['total', 'accounted', 'receipts', 'omitted', 'missing', 'expectedIds'],
        properties: {
          total: { type: 'integer', minimum: 1 },
          accounted: { type: 'integer', minimum: 1 },
          receipts: { type: 'integer', minimum: 1 },
          omitted: { const: 0 },
          missing: { type: 'array', maxItems: 0, items: nonempty },
          expectedIds: { type: 'array', minItems: 1, items: nonempty },
        },
      },
      coverageGaps: { type: 'array', maxItems: 0, items: nonempty },
      digest: { type: 'string', pattern: '^sha256:[a-f0-9]{64}$' },
    },
    $defs: {
      credentialReference: {
        type: 'object',
        required: ['type', 'id'],
        additionalProperties: false,
        properties: { type: { enum: ['env', 'keychain', 'secret-manager', 'vault'] }, id: { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9._:/-]*$' } },
      },
      transitionCapability: {
        type: 'object',
        required: ['id', 'toActorId', 'fromTenantId', 'toTenantId', 'authorizationId'],
        additionalProperties: false,
        properties: { id: nonempty, toActorId: nonempty, fromTenantId: nonempty, toTenantId: nonempty, authorizationId: nonempty },
      },
      actor: {
        type: 'object',
        additionalProperties: false,
        required: ['id', 'identityId', 'credentialPolicyId', 'sessionPolicyId', 'role', 'tier', 'tenantId', 'accountState', 'credential', 'issuedAt', 'expiresAt', 'revokedAt', 'serverAuthorizations', 'uiVisibility', 'transitionCapabilities', 'concurrencyKey'],
        properties: {
          id: nonempty,
          identityId: nonempty,
          credentialPolicyId: nonempty,
          sessionPolicyId: nonempty,
          role: nonempty,
          tier: nonempty,
          tenantId: nonempty,
          accountState: { enum: ['active', 'disabled', 'expired', 'locked', 'revoked'] },
          credential: { $ref: '#/$defs/credentialReference' },
          issuedAt: { type: ['string', 'null'] },
          expiresAt: { type: ['string', 'null'] },
          revokedAt: { type: ['string', 'null'] },
          serverAuthorizations: { type: 'array', items: nonempty },
          uiVisibility: { type: 'array', items: nonempty },
          transitionCapabilities: { type: 'array', items: { $ref: '#/$defs/transitionCapability' } },
          concurrencyKey: nonempty,
        },
      },
    },
  };
}

export function buildSchemas() {
  return {
    'src/schemas/provider-result-v1.schema.json': buildProviderResultSchema(),
    'src/schemas/security-verdict-v1.schema.json': buildSecurityVerdictSchema(),
    'src/schemas/platform/web-actor-fixture-v1.schema.json': buildWebActorFixtureSchema(),
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

if (process.argv[1]?.endsWith('generate-schemas.mjs')) {
  main();
}
