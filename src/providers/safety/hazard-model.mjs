// Safety hazard-model builder and closure gate (B7-020).
//
// THE CRITICAL INVARIANT: every hazard emitted here addresses a
// high-consequence outcome class (see OUTCOME_CLASS in ./contracts.mjs), so
// every hazard unconditionally carries `reasoningRequirement: 'human-decision'`
// and can only ever be closed via closeHazard({ method: 'human-decision', ... }).
// Any other closure method throws. A hazard is never certifiable and never
// asserts compliance with a named regulatory/engineering standard.

import {
  CLOSURE_METHOD,
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
  REASONING_REQUIREMENT,
  SEVERITY_HINTS,
  assertEnum,
  digest,
  requireNonEmptyArray,
  requireObject,
  requireString,
  stableId,
} from './contracts.mjs';

function uniqueSorted(values) {
  return [...new Set(values ?? [])].sort();
}

// Builds one hazard candidate. Every hazard states its static/runtime scope,
// hazards (plural — the specific unsafe consequences), assumptions, and
// authority limits as explicit non-empty fields; the schema
// (schemas/safety/hazard-model-v1.schema.json) requires all four.
export function createHazardCandidate({
  domain,
  outcomeClass,
  ruleId,
  claim,
  severityHint,
  scope,
  hazards,
  assumptions,
  authorityLimits,
  disposition,
  unsafeStates = [],
  interlock = 'not-applicable',
  failsafeDefault = 'unknown',
  degradedMode = 'not-applicable',
  emergencyStop = 'not-applicable',
  humanOverride = 'not-applicable',
  confirmation = 'not-applicable',
  misuseScenarios = [],
  recoveryPath = 'not-applicable',
  incidentControls = 'not-applicable',
  evidenceRefs,
  detectorMetadata = {},
  uncertainty = [],
}) {
  requireString(domain, 'domain');
  assertEnum('outcome class', OUTCOME_CLASS, outcomeClass);
  requireString(ruleId, 'ruleId');
  requireString(claim, 'claim');
  if (!SEVERITY_HINTS.includes(severityHint)) throw new TypeError(`invalid severity hint ${severityHint}`);
  requireObject(scope, 'scope');
  requireString(scope.description, 'scope.description');
  if (typeof scope.static !== 'boolean' || typeof scope.runtime !== 'boolean') {
    throw new TypeError('scope.static and scope.runtime must be booleans');
  }
  requireNonEmptyArray(hazards, 'hazards');
  requireNonEmptyArray(assumptions, 'assumptions');
  requireNonEmptyArray(authorityLimits, 'authorityLimits');
  requireNonEmptyArray(misuseScenarios, 'misuseScenarios');
  assertEnum('hazard disposition', HAZARD_DISPOSITION, disposition);
  assertEnum('interlock state', INTERLOCK_STATE, interlock);
  assertEnum('failsafe default', FAILSAFE_DEFAULT, failsafeDefault);
  assertEnum('degraded mode', DEGRADED_MODE, degradedMode);
  assertEnum('emergency stop', EMERGENCY_STOP, emergencyStop);
  assertEnum('human override', HUMAN_OVERRIDE, humanOverride);
  assertEnum('confirmation state', CONFIRMATION_STATE, confirmation);
  assertEnum('recovery path', RECOVERY_PATH, recoveryPath);
  assertEnum('incident controls', INCIDENT_CONTROLS, incidentControls);
  const refs = requireNonEmptyArray(uniqueSorted(evidenceRefs), 'evidenceRefs');

  // Non-negotiable: every outcome class in this model is high-consequence,
  // so the reasoning requirement is always 'human-decision'. This is not a
  // per-hazard choice — it is asserted, not merely defaulted, so a future
  // edit cannot silently downgrade it.
  const reasoningRequirement = 'human-decision';
  assertEnum('reasoning requirement', REASONING_REQUIREMENT, reasoningRequirement);

  // Missing qualified domain evidence yields review-required or unproven —
  // never a clean claim, never a certification. A 'clean' disposition still
  // only ever reports 'review-required' (a human still owns the sign-off);
  // this model has no status that means "verified safe".
  const status = disposition === 'clean' && refs.length > 0 ? 'review-required' : 'review-required';
  if (!HAZARD_STATUS.includes(status)) throw new TypeError(`invalid hazard status ${status}`);

  const identity = { domain, outcomeClass, ruleId, disposition, evidenceRefs: refs, detectorMetadata };

  return Object.freeze({
    schemaVersion: 1,
    kind: 'safety-hazard',
    id: stableId('safety-hazard', identity),
    domain,
    outcomeClass,
    ruleId,
    claim,
    severityHint,
    scope: { static: scope.static, runtime: scope.runtime, description: scope.description },
    hazards: [...hazards],
    assumptions: [...assumptions],
    authorityLimits: [...authorityLimits],
    disposition,
    unsafeStates: uniqueSorted(unsafeStates),
    interlock,
    failsafeDefault,
    degradedMode,
    emergencyStop,
    humanOverride,
    confirmation,
    misuseScenarios: uniqueSorted(misuseScenarios),
    recoveryPath,
    incidentControls,
    reasoningRequirement,
    certifiable: false,
    regulatoryClaim: null,
    status,
    evidenceRefs: refs,
    detectorMetadata,
    uncertainty: uniqueSorted(uncertainty),
    closed: false,
  });
}

export function assertHazard(hazard) {
  requireObject(hazard, 'hazard');
  if (hazard.schemaVersion !== 1) throw new Error(`hazard schemaVersion must be 1; got ${hazard.schemaVersion}`);
  if (hazard.kind !== 'safety-hazard') throw new Error(`hazard kind must be safety-hazard; got ${hazard.kind}`);
  assertEnum('outcome class', OUTCOME_CLASS, hazard.outcomeClass);
  assertEnum('reasoning requirement', REASONING_REQUIREMENT, hazard.reasoningRequirement);
  if (hazard.reasoningRequirement !== 'human-decision') {
    throw new Error('every hazard in this model must require human-decision reasoning');
  }
  if (hazard.certifiable !== false) throw new Error('a hazard must never be marked certifiable');
  if (hazard.regulatoryClaim !== null) throw new Error('a hazard must never assert a regulatory claim');
  requireNonEmptyArray(hazard.hazards, 'hazard.hazards');
  requireNonEmptyArray(hazard.assumptions, 'hazard.assumptions');
  requireNonEmptyArray(hazard.authorityLimits, 'hazard.authorityLimits');
  requireNonEmptyArray(hazard.misuseScenarios, 'hazard.misuseScenarios');
  requireNonEmptyArray(hazard.evidenceRefs, 'hazard.evidenceRefs');
  requireObject(hazard.scope, 'hazard.scope');
  requireString(hazard.scope.description, 'hazard.scope.description');
  return true;
}

// THE CRITICAL GATE: closing a hazard is only ever valid via a human
// decision. A candidate generator (the hazard scanner) cannot close its own
// finding, and no model or automated verdict may close it either — the
// producer/closer separation and the reasoning-requirement gate are both
// enforced here, structurally, not by convention.
export function closeHazard({ hazard, method, decidedBy, decision, rationale }) {
  assertHazard(hazard);
  assertEnum('closure method', CLOSURE_METHOD, method);
  if (hazard.reasoningRequirement === 'human-decision' && method !== 'human-decision') {
    throw new Error(
      `hazard ${hazard.id} requires reasoningRequirement 'human-decision'; `
      + `closure method '${method}' is rejected — only a human-decision closure is accepted`,
    );
  }
  requireString(decidedBy, 'decidedBy');
  requireString(decision, 'decision');
  requireString(rationale, 'rationale');
  return Object.freeze({
    schemaVersion: 1,
    kind: 'safety-hazard-closure',
    hazardId: hazard.id,
    method,
    decidedBy,
    decision,
    rationale,
    // No wall-clock timestamp: determinism per lane rule 6. A caller wanting
    // an audit trail attaches its own binding/receipt timestamp externally.
    closureDigest: digest({ hazardId: hazard.id, method, decidedBy, decision }),
  });
}
