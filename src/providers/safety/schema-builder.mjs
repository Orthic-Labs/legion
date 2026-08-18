// Code-owned builder for schemas/safety/hazard-model-v1.schema.json (B7-020).
// Mirrors the generation pattern in scripts/generate-security-schemas.mjs:
// the schema is generated from the same enums the runtime builder
// (./hazard-model.mjs) enforces, so schema and runtime can never drift.
// This lives under providers/safety/ (this lane's own path) rather than
// scripts/, which is outside this lane's Own paths.

import {
  CONFIRMATION_STATE,
  DEGRADED_MODE,
  EMERGENCY_STOP,
  FAILSAFE_DEFAULT,
  HAZARD_DISPOSITION,
  HAZARD_STATUS,
  HUMAN_OVERRIDE,
  INCIDENT_CONTROLS,
  INTERLOCK_STATE,
  OUTCOME_CLASS,
  RECOVERY_PATH,
  SEVERITY_HINTS,
} from './contracts.mjs';

const STRINGS = { type: 'array', items: { type: 'string' } };
const NON_EMPTY_STRINGS = { type: 'array', items: { type: 'string' }, minItems: 1 };

export function buildHazardModelSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/safety/hazard-model-v1.json',
    title: 'SafetyHazardV1',
    type: 'object',
    required: [
      'schemaVersion', 'kind', 'id', 'domain', 'outcomeClass', 'ruleId', 'claim',
      'severityHint', 'scope', 'hazards', 'assumptions', 'authorityLimits',
      'disposition', 'reasoningRequirement', 'certifiable', 'regulatoryClaim',
      'status', 'evidenceRefs', 'misuseScenarios',
    ],
    properties: {
      schemaVersion: { const: 1 },
      kind: { const: 'safety-hazard' },
      id: { type: 'string', pattern: '^sha256:' },
      domain: { type: 'string', minLength: 1 },
      outcomeClass: { enum: [...OUTCOME_CLASS] },
      ruleId: { type: 'string', minLength: 1 },
      claim: { type: 'string', minLength: 1 },
      severityHint: { enum: [...SEVERITY_HINTS] },
      scope: {
        type: 'object',
        required: ['static', 'runtime', 'description'],
        properties: {
          static: { type: 'boolean' },
          runtime: { type: 'boolean' },
          description: { type: 'string', minLength: 1 },
        },
        additionalProperties: false,
      },
      hazards: NON_EMPTY_STRINGS,
      assumptions: NON_EMPTY_STRINGS,
      authorityLimits: NON_EMPTY_STRINGS,
      disposition: { enum: [...HAZARD_DISPOSITION] },
      unsafeStates: STRINGS,
      interlock: { enum: [...INTERLOCK_STATE] },
      failsafeDefault: { enum: [...FAILSAFE_DEFAULT] },
      degradedMode: { enum: [...DEGRADED_MODE] },
      emergencyStop: { enum: [...EMERGENCY_STOP] },
      humanOverride: { enum: [...HUMAN_OVERRIDE] },
      confirmation: { enum: [...CONFIRMATION_STATE] },
      misuseScenarios: NON_EMPTY_STRINGS,
      recoveryPath: { enum: [...RECOVERY_PATH] },
      incidentControls: { enum: [...INCIDENT_CONTROLS] },
      // Every hazard in this model addresses a high-consequence outcome
      // class, so this is always 'human-decision' — never any other member
      // of the core REASONING_REQUIREMENT vocabulary (REASONING_REQUIREMENT
      // itself is asserted against at runtime in ./hazard-model.mjs).
      reasoningRequirement: { const: 'human-decision' },
      certifiable: { const: false },
      regulatoryClaim: { const: null },
      status: { enum: [...HAZARD_STATUS] },
      evidenceRefs: NON_EMPTY_STRINGS,
      detectorMetadata: { type: 'object' },
      uncertainty: STRINGS,
      closed: { type: 'boolean' },
    },
    additionalProperties: false,
  };
}
