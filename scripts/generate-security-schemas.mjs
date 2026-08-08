#!/usr/bin/env node
// Generates committed security schemas and the committed enum registry from
// the code-owned security constants, so schema, registry, and runtime enums can
// never drift. Every generated security schema uses the canonical binding
// (SNIP-05) and requires the denominator digest.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CHAIN_ROLES,
  CONTROL_STATES,
  ENTITY_KINDS,
  EVIDENCE_CLASS,
  EVIDENCE_STRENGTH,
  FACT_KINDS,
  PATH_PRIORITY,
  PATH_STATUS,
  RELATION_KINDS,
  SECURITY_SCHEMA_VERSIONS,
  SECURITY_VERDICTS,
} from '../providers/security/contracts.mjs';
import { PROVIDER_STATUS } from '../registry/provider-contracts.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

const SHA = { type: 'string', pattern: '^sha256:' };
const NULLABLE_SHA = { oneOf: [{ type: 'null' }, { type: 'string', pattern: '^sha256:' }] };
const STRINGS = { type: 'array', items: { type: 'string' } };

function write(path, value) {
  const target = resolve(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function bindingRef() {
  return { $ref: 'security-binding-v1.schema.json' };
}

// The canonical binding fragment, inlined where a schema lives outside the
// security schema directory.
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

// ---------------------------------------------------------------------------
// Canonical security schema set (schemas/security/**). Every member binds and
// carries a denominator digest.
// ---------------------------------------------------------------------------

function factSchema() {
  return {
    type: 'object',
    required: ['kind'],
    properties: {
      kind: { enum: [...FACT_KINDS] },
      subject: { type: ['string', 'null'] },
      action: { type: ['string', 'null'] },
      object: { type: ['string', 'null'] },
      scope: { type: ['string', 'null'] },
      environment: { type: ['string', 'null'] },
      tenant: { type: ['string', 'null'] },
      attributes: { type: 'object' },
      evidenceRefs: STRINGS,
      id: { type: 'string' },
    },
    additionalProperties: true,
  };
}

export function buildCanonicalModelSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/security/security-model-v1.json',
    title: 'SecurityModelV1',
    type: 'object',
    required: ['schemaVersion', 'kind', 'provider', 'providerVersion', 'binding', 'denominatorDigest', 'complete', 'entities', 'relations', 'initialFacts', 'evidence', 'coverage', 'coverageGaps'],
    properties: {
      schemaVersion: { const: 1 },
      kind: { const: 'security-surface-model' },
      provider: { const: 'security.surface-model' },
      providerVersion: { type: 'string' },
      binding: bindingRef(),
      denominatorDigest: SHA,
      complete: { type: 'boolean' },
      entities: {
        type: 'array',
        items: {
          type: 'object',
          required: ['id', 'kind', 'name', 'attributes', 'assertion', 'evidenceStrength', 'evidenceRefs'],
          properties: {
            id: { type: 'string' },
            kind: { enum: [...ENTITY_KINDS] },
            name: { type: 'string' },
            attributes: { type: 'object' },
            assertion: { enum: ['observed', 'assumed', 'derived'] },
            evidenceStrength: { enum: [...EVIDENCE_STRENGTH] },
            evidenceClass: { enum: [...EVIDENCE_CLASS] },
            controlState: { enum: [...CONTROL_STATES] },
            evidenceRefs: STRINGS,
          },
          additionalProperties: true,
        },
      },
      relations: {
        type: 'array',
        items: {
          type: 'object',
          required: ['id', 'kind', 'from', 'to', 'assertion', 'evidenceStrength', 'evidenceRefs'],
          properties: {
            id: { type: 'string' },
            kind: { enum: [...RELATION_KINDS] },
            from: { type: 'string' },
            to: { type: 'string' },
            attributes: { type: 'object' },
            assertion: { enum: ['observed', 'assumed', 'derived'] },
            evidenceStrength: { enum: [...EVIDENCE_STRENGTH] },
            evidenceRefs: STRINGS,
          },
          additionalProperties: true,
        },
      },
      initialFacts: { type: 'array', items: factSchema() },
      evidence: { type: 'array', items: { type: 'object' } },
      coverage: { type: 'object' },
      coverageGaps: { type: 'array' },
    },
    additionalProperties: false,
  };
}

export function buildCanonicalCandidateSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/security/security-candidate-v2.json',
    title: 'SecurityCandidateV2',
    type: 'object',
    required: ['schemaVersion', 'kind', 'id', 'provider', 'providerVersion', 'ruleId', 'candidateClass', 'claim', 'severityHint', 'effects', 'evidenceRefs', 'binding', 'denominatorDigest', 'verdict', 'adjudicationRequired'],
    properties: {
      schemaVersion: { const: 2 },
      kind: { const: 'security-candidate' },
      id: SHA,
      provider: { type: 'string' },
      providerVersion: { type: 'string' },
      ruleId: { type: 'string' },
      candidateClass: { type: 'string' },
      claim: { type: 'string' },
      severityHint: { enum: ['critical', 'high', 'medium', 'low', 'info'] },
      sources: STRINGS,
      sinks: STRINGS,
      attackerCapabilities: STRINGS,
      preconditions: { type: 'array', items: factSchema() },
      effects: { type: 'array', minItems: 1, items: factSchema() },
      assets: STRINGS,
      trustBoundaryCrossings: STRINGS,
      requiredControls: STRINGS,
      observedControls: STRINGS,
      chainRoles: { type: 'array', items: { enum: [...CHAIN_ROLES] } },
      evidenceRefs: STRINGS,
      detectorMetadata: { type: 'object' },
      uncertainty: STRINGS,
      binding: bindingRef(),
      denominatorDigest: SHA,
      // A candidate is an allegation: it never carries a final verdict or severity.
      verdict: { const: 'UNADJUDICATED' },
      adjudicationRequired: { const: true },
    },
    additionalProperties: false,
  };
}

export function buildCanonicalVerdictSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/security/security-verdict-v1.json',
    title: 'SecurityVerdictV1',
    type: 'object',
    required: ['schemaVersion', 'kind', 'candidateId', 'candidateProvider', 'adjudicatorProvider', 'adjudicatorContextId', 'evidenceStrength', 'verdict', 'threatModel', 'reachability', 'impact', 'variantAnalysisRequired', 'binding', 'denominatorDigest'],
    properties: {
      schemaVersion: { const: 1 },
      kind: { const: 'security-verdict' },
      candidateId: { type: 'string' },
      candidateProvider: { type: 'string' },
      adjudicatorProvider: { type: 'string' },
      adjudicatorContextId: { type: 'string' },
      evidenceStrength: { enum: [...EVIDENCE_STRENGTH] },
      evidenceClass: { enum: [...EVIDENCE_CLASS] },
      verdict: { enum: [...SECURITY_VERDICTS] },
      severity: { type: ['string', 'null'], enum: ['critical', 'high', 'medium', 'low', null] },
      threatModel: { type: 'string' },
      attackerControl: { type: 'string' },
      reachability: { type: 'string' },
      trustBoundaries: STRINGS,
      impact: { type: 'string' },
      proof: { type: ['object', 'null'] },
      variantAnalysisRequired: { type: 'boolean' },
      verdictDigest: SHA,
      binding: bindingRef(),
      denominatorDigest: SHA,
    },
    additionalProperties: false,
  };
}

export function buildCanonicalHypothesisSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/security/attack-path-hypothesis-v1.json',
    title: 'AttackPathHypothesisV1',
    type: 'object',
    required: ['schemaVersion', 'kind', 'id', 'objectiveId', 'status', 'priority', 'steps', 'binding', 'denominatorDigest'],
    properties: {
      schemaVersion: { const: 1 },
      kind: { const: 'attack-path-hypothesis' },
      id: SHA,
      objectiveId: { type: 'string' },
      status: { enum: [...PATH_STATUS] },
      priority: { enum: [...PATH_PRIORITY] },
      steps: {
        type: 'array',
        items: {
          type: 'object',
          required: ['candidateId', 'role'],
          properties: {
            candidateId: { type: 'string' },
            role: { enum: [...CHAIN_ROLES] },
            producedFacts: { type: 'array', items: factSchema() },
            evidenceRefs: STRINGS,
          },
          additionalProperties: true,
        },
      },
      unsatisfiedPreconditions: { type: 'array', items: factSchema() },
      blockedBy: STRINGS,
      uncertainty: STRINGS,
      binding: bindingRef(),
      denominatorDigest: SHA,
    },
    additionalProperties: false,
  };
}

export function buildCanonicalChainVerdictSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/security/security-chain-verdict-v1.json',
    title: 'SecurityChainVerdictV1',
    type: 'object',
    required: ['schemaVersion', 'kind', 'hypothesisId', 'adjudicatorProvider', 'adjudicatorContextId', 'status', 'evidenceStrength', 'binding', 'denominatorDigest'],
    properties: {
      schemaVersion: { const: 1 },
      kind: { const: 'security-chain-verdict' },
      hypothesisId: { type: 'string' },
      adjudicatorProvider: { type: 'string' },
      adjudicatorContextId: { type: 'string' },
      status: { enum: [...PATH_STATUS] },
      priority: { type: ['string', 'null'], enum: [...PATH_PRIORITY, null] },
      evidenceStrength: { enum: [...EVIDENCE_STRENGTH] },
      refutedSteps: STRINGS,
      counterargument: { type: ['string', 'null'] },
      uncertainty: STRINGS,
      binding: bindingRef(),
      denominatorDigest: SHA,
    },
    additionalProperties: false,
  };
}

export function buildCanonicalVariantReceiptSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/security/security-variant-receipt-v2.json',
    title: 'SecurityVariantReceiptV2',
    type: 'object',
    required: ['schemaVersion', 'kind', 'rootCause', 'denominator', 'strategies', 'matches', 'complete', 'binding', 'denominatorDigest'],
    properties: {
      schemaVersion: { const: 2 },
      kind: { const: 'security-variant-receipt' },
      rootCause: {
        type: 'object',
        required: ['class', 'semanticFeatures'],
        properties: {
          class: { type: 'string' },
          semanticFeatures: STRINGS,
          digest: NULLABLE_SHA,
        },
        additionalProperties: true,
      },
      denominator: { type: 'object' },
      strategies: { type: 'array' },
      matches: { type: 'array' },
      coverageGaps: { type: 'array' },
      complete: { type: 'boolean' },
      binding: bindingRef(),
      denominatorDigest: SHA,
    },
    additionalProperties: false,
  };
}

export function buildCanonicalEvidenceSynthesisSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/security/security-evidence-synthesis-v1.json',
    title: 'SecurityEvidenceSynthesisV1',
    type: 'object',
    required: ['schemaVersion', 'kind', 'findings', 'coverage', 'providerStatus', 'binding', 'denominatorDigest'],
    properties: {
      schemaVersion: { const: 1 },
      kind: { const: 'security-evidence-synthesis' },
      findings: { type: 'array' },
      coverage: { type: 'object' },
      coverageGaps: { type: 'array' },
      providerStatus: providerStatusFragment(),
      residualRisk: { type: 'array' },
      binding: bindingRef(),
      denominatorDigest: SHA,
    },
    additionalProperties: false,
  };
}

const CANONICAL = Object.freeze({
  'schemas/security/security-binding-v1.schema.json': buildSecurityBindingSchema,
  'schemas/security/security-model-v1.schema.json': buildCanonicalModelSchema,
  'schemas/security/security-candidate-v2.schema.json': buildCanonicalCandidateSchema,
  'schemas/security/security-verdict-v1.schema.json': buildCanonicalVerdictSchema,
  'schemas/security/attack-path-hypothesis-v1.schema.json': buildCanonicalHypothesisSchema,
  'schemas/security/security-chain-verdict-v1.schema.json': buildCanonicalChainVerdictSchema,
  'schemas/security/security-variant-receipt-v2.schema.json': buildCanonicalVariantReceiptSchema,
  'schemas/security/security-evidence-synthesis-v1.schema.json': buildCanonicalEvidenceSynthesisSchema,
});

export const SECURITY_SCHEMA_FILES = Object.freeze(Object.keys(CANONICAL));

// Legacy top-level security schemas predate the canonical set; they are still
// generated from the same constants so neither copy can drift.
const LEGACY = Object.freeze({
  'schemas/security-binding-v1.schema.json': buildSecurityBindingSchema,
  'schemas/security-model-v1.schema.json': buildSecurityModelSchema,
  'schemas/security-verdict-v1.schema.json': buildVerdictSchema,
});

export function buildSecuritySchemas({ includeLegacy = false } = {}) {
  const source = includeLegacy ? { ...CANONICAL, ...LEGACY } : CANONICAL;
  return Object.fromEntries(Object.entries(source).map(([path, build]) => [path, build()]));
}

export function buildSecurityEnumRegistry() {
  return {
    schemaVersion: 1,
    kind: 'nemesis-security-enum-registry',
    source: 'providers/security/contracts.mjs',
    generator: 'scripts/generate-security-schemas.mjs',
    license: 'internal',
    enums: {
      providerStatus: [...PROVIDER_STATUS],
      evidenceClass: [...EVIDENCE_CLASS],
      evidenceStrength: [...EVIDENCE_STRENGTH],
      securityVerdict: [...SECURITY_VERDICTS],
      pathStatus: [...PATH_STATUS],
      pathPriority: [...PATH_PRIORITY],
      chainRole: [...CHAIN_ROLES],
      factKind: [...FACT_KINDS],
      entityKind: [...ENTITY_KINDS],
      relationKind: [...RELATION_KINDS],
      controlState: [...CONTROL_STATES],
    },
    schemaVersions: Object.fromEntries(
      Object.entries(SECURITY_SCHEMA_VERSIONS).map(([kind, versions]) => [kind, [...versions]]),
    ),
  };
}

function main() {
  for (const [path, value] of Object.entries(buildSecuritySchemas())) {
    write(path, value);
    console.log(`wrote ${path}`);
  }
  write('registry/rules/security/enums.json', buildSecurityEnumRegistry());
  console.log('wrote registry/rules/security/enums.json');
}

if (process.argv[1] && process.argv[1].endsWith('generate-security-schemas.mjs')) main();
