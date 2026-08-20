// Code-owned JSON-schema builder for the evaluation-receipt-v1 artifact.
// Mirrors the pattern in scripts/generate-security-schemas.mjs: the schema
// is generated FROM these code-owned enums, never hand-edited, and a test
// asserts the committed schemas/ai-quality/evaluation-receipt-v1.schema.json
// is byte-identical to buildEvaluationReceiptSchema()'s output.

import { AI_QUALITY_METRICS, AI_QUALITY_VERDICTS } from './contracts.mjs';

const SHA = { type: 'string', pattern: '^sha256:' };
const NULLABLE_SHA = { oneOf: [{ type: 'null' }, { type: 'string', pattern: '^sha256:' }] };
const STRINGS = { type: 'array', items: { type: 'string' } };

export function buildEvaluationReceiptSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/ai-quality/evaluation-receipt-v1.json',
    title: 'AiQualityEvaluationReceiptV1',
    type: 'object',
    required: [
      'schemaVersion', 'kind', 'id', 'metric', 'metricVersion', 'verdict',
      'modelIdentity', 'promptIdentity', 'datasetVersion', 'runConditions',
      'judgeIdentity', 'denominator', 'measurement', 'limitations',
      'uncertainty', 'evidenceRefs', 'binding',
    ],
    properties: {
      schemaVersion: { const: 1 },
      kind: { const: 'ai-quality-evaluation-receipt' },
      id: SHA,
      metric: { enum: [...AI_QUALITY_METRICS] },
      metricVersion: { type: 'string' },
      verdict: { enum: [...AI_QUALITY_VERDICTS] },
      modelIdentity: {
        type: 'object',
        required: ['provider', 'model', 'version'],
        properties: {
          provider: { type: 'string' },
          model: { type: 'string' },
          version: { type: 'string' },
        },
        additionalProperties: true,
      },
      promptIdentity: {
        type: 'object',
        required: ['templateId', 'templateVersion', 'promptDigest'],
        properties: {
          templateId: { type: 'string' },
          templateVersion: { type: 'string' },
          promptDigest: SHA,
        },
        additionalProperties: true,
      },
      retrievalToolConfig: {
        oneOf: [
          { type: 'null' },
          {
            type: 'object',
            properties: {
              retrieverId: { type: 'string' },
              retrieverConfigDigest: NULLABLE_SHA,
              toolsetId: { type: 'string' },
              toolsetConfigDigest: NULLABLE_SHA,
            },
            additionalProperties: true,
          },
        ],
      },
      datasetVersion: {
        type: 'object',
        required: ['datasetId', 'version', 'digest'],
        properties: {
          datasetId: { type: 'string' },
          version: { type: 'string' },
          digest: SHA,
        },
        additionalProperties: true,
      },
      runConditions: {
        type: 'object',
        required: ['runId', 'environment'],
        properties: {
          runId: { type: 'string' },
          environment: { type: 'string' },
          seed: { type: ['string', 'number', 'null'] },
        },
        additionalProperties: true,
      },
      judgeIdentity: {
        type: 'object',
        required: ['kind', 'id'],
        properties: {
          kind: { enum: ['human', 'automated-metric', 'llm-judge'] },
          id: { type: 'string' },
        },
        additionalProperties: true,
      },
      denominator: {
        type: 'object',
        required: ['kind', 'expected', 'examined'],
        properties: {
          kind: { type: 'string' },
          expected: { type: 'number' },
          examined: { type: 'number' },
          digest: NULLABLE_SHA,
        },
        additionalProperties: true,
      },
      measurement: { type: 'object' },
      limitations: STRINGS,
      uncertainty: STRINGS,
      evidenceRefs: STRINGS,
      binding: {
        type: 'object',
        required: ['planDigest', 'repositoryRevision', 'dirtyPatchDigest', 'blueprintGenerationId', 'blueprintManifestDigest', 'registryDigest'],
        properties: {
          planDigest: SHA,
          repositoryRevision: { type: 'string', minLength: 1 },
          dirtyPatchDigest: NULLABLE_SHA,
          blueprintGenerationId: { type: 'string', minLength: 1 },
          blueprintManifestDigest: SHA,
          registryDigest: SHA,
        },
        additionalProperties: false,
      },
    },
    additionalProperties: false,
  };
}
