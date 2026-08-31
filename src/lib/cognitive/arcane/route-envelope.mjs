import { digestValue } from '../../contracts/arcane/canonical.mjs';

const ROUTE_STAGES = Object.freeze(['context', 'cognition', 'grounding', 'compute', 'challenge', 'verification', 'response']);
const CHALLENGE_RESULTS = new Set(['KEEP', 'NARROW', 'REVISE']);
const strongerTier = Object.freeze({ fast: 'balanced', balanced: 'strong', strong: 'strong' });

const available = (availability, stage) => availability?.[stage] !== false;
const required = (input, stage) => new Set(input?.requiredStages ?? []).has(stage);
const nonEmpty = (value) => typeof value === 'string' && value.trim().length > 0;

export function isTrivialArcaneRoute(input = {}) {
  const prompt = String(input.prompt ?? '').trim();
  return input.trivial === true || (
    prompt.length <= 80
    && !input.effect
    && !input.uncertain
    && !(input.claims?.length)
    && !(input.requiredStages?.length)
  );
}

/** Compile one ephemeral, minimum-sufficient cognitive route. */
export function compileArcaneRoute(input = {}, availability = {}) {
  const hasExplicitDegradation = Object.values(availability).some((state) => state === false);
  const trivial = isTrivialArcaneRoute(input) && !hasExplicitDegradation;
  if (trivial) return Object.freeze({
    schemaVersion: 1,
    kind: 'arcane-route-envelope',
    routeId: digestValue({ trivial: true, prompt: String(input.prompt ?? '').trim() }),
    mode: 'TRIVIAL',
    modelCalls: 0,
    stages: Object.freeze({ response: Object.freeze({ state: 'ACTIVE', policy: 'direct' }) }),
    degradation: Object.freeze([]),
  });

  const degradation = [];
  const stages = {};
  for (const stage of ROUTE_STAGES) {
    if (available(availability, stage)) {
      stages[stage] = Object.freeze({ state: 'ACTIVE', policy: input?.stagePolicy?.[stage] ?? 'proportional' });
      continue;
    }
    if (required(input, stage)) throw Object.assign(new Error(`required Arcane stage unavailable: ${stage}`), { code: 'ARC_STAGE_UNAVAILABLE', stage });
    stages[stage] = Object.freeze({ state: 'DEGRADED', reason: 'optional-stage-unavailable' });
    degradation.push(Object.freeze({ stage, reason: 'optional-stage-unavailable' }));
  }
  const uncertain = input.uncertain === true;
  const requestedTier = input.modelTier ?? 'balanced';
  return Object.freeze({
    schemaVersion: 1,
    kind: 'arcane-route-envelope',
    routeId: digestValue({ prompt: input.prompt ?? null, uncertain, requestedTier, stages }),
    mode: uncertain ? 'UNCERTAINTY_ESCALATION' : 'DIRECT',
    modelCalls: uncertain ? 1 : Number(input.modelCalls ?? 0),
    selectedModelTier: uncertain ? strongerTier[requestedTier] ?? 'strong' : requestedTier,
    stages: Object.freeze(stages),
    degradation: Object.freeze(degradation),
  });
}

function finalizeChallenge(outcome, evidence) {
  if (!CHALLENGE_RESULTS.has(outcome?.result)) throw Object.assign(new Error('challenge result must be KEEP, NARROW or REVISE'), { code: 'ARC_CHALLENGE_INVALID' });
  return Object.freeze({ result: outcome.result, reason: String(outcome.reason ?? ''), evidenceDigest: digestValue(evidence), passCount: 1, recursive: false });
}

/** One evidence-directed falsification pass. No recursive pass is representable. */
export function runFalsificationPass({ claim, evidence, evaluate, passCount = 0 } = {}) {
  if (passCount !== 0) throw Object.assign(new Error('falsification pass already consumed'), { code: 'ARC_CHALLENGE_RECURSION' });
  if (!nonEmpty(claim) || !Array.isArray(evidence) || evidence.length === 0 || typeof evaluate !== 'function') {
    throw Object.assign(new Error('claim, evidence & evaluator are required'), { code: 'ARC_CHALLENGE_INVALID' });
  }
  const frozenEvidence = Object.freeze([...evidence]);
  const outcome = evaluate(Object.freeze({ claim, evidence: frozenEvidence, pass: 1 }));
  return typeof outcome?.then === 'function'
    ? outcome.then((resolved) => finalizeChallenge(resolved, frozenEvidence))
    : finalizeChallenge(outcome, frozenEvidence);
}

export function routeEnvelopeContext(envelope) {
  if (envelope?.kind !== 'arcane-route-envelope') return null;
  return `ARCANE_ROUTE:${JSON.stringify(envelope)}`;
}
