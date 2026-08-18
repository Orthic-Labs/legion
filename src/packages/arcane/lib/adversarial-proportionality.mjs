// Deterministic architecture evaluators for proportionality & non-negotiable
// obligations.  Inputs are explicit structured facts; neither evaluator reads
// architecture-eval corpus expectations.
import { ArcaneError } from './errors.mjs';

export const ADVERSARIAL_PROPORTIONALITY_IDS = Object.freeze([
  'AE-ADVERSARIAL-001',
  'AE-ADVERSARIAL-002',
]);

const COMPLEXITY = Object.freeze(['minimal', 'modular', 'distributed']);
const SCALE = Object.freeze(['low', 'moderate', 'high']);
const OBLIGATION_DOMAINS = Object.freeze(['privacy', 'compliance', 'security', 'safety', 'retention', 'availability']);

const DEFAULT_INPUTS = Object.freeze({
  'AE-ADVERSARIAL-001': Object.freeze({
    deployment: 'greenfield', scale: 'low', proposedComplexity: 'distributed',
    drivers: Object.freeze({ independentScaling: false, isolationBoundary: false, multiRegionConsistency: false }),
    obligations: Object.freeze([]),
  }),
  'AE-ADVERSARIAL-002': Object.freeze({
    objective: 'minimize', proposedComplexity: 'minimal',
    obligations: Object.freeze([
      Object.freeze({ id: 'privacy-retention', domain: 'privacy', mandatory: true, status: 'missing' }),
      Object.freeze({ id: 'regulated-audit', domain: 'compliance', mandatory: true, status: 'missing' }),
    ]),
  }),
});

function schema(message, detail = {}) { throw new ArcaneError('ARC_SCHEMA_INVALID', message, detail); }
function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) schema(`${label} must be an object`);
  return value;
}
function fields(value, allowed, label) {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) schema(`unknown ${label} field: ${key}`);
}
function rank(complexity) { return COMPLEXITY.indexOf(complexity); }
function normalizeObligations(value) {
  if (!Array.isArray(value)) schema('obligations must be an array');
  const ids = new Set();
  return Object.freeze(value.map((entry, index) => {
    object(entry, `obligation ${index}`);
    fields(entry, ['id', 'domain', 'mandatory', 'status'], `obligation ${index}`);
    if (typeof entry.id !== 'string' || !entry.id.trim()) schema(`obligation ${index} id is required`);
    if (ids.has(entry.id)) schema(`duplicate obligation id: ${entry.id}`);
    ids.add(entry.id);
    if (!OBLIGATION_DOMAINS.includes(entry.domain)) schema(`obligation ${entry.id} domain is invalid`);
    if (typeof entry.mandatory !== 'boolean') schema(`obligation ${entry.id} mandatory must be boolean`);
    if (!['implemented', 'missing', 'not_applicable'].includes(entry.status)) schema(`obligation ${entry.id} status is invalid`);
    return Object.freeze({ id: entry.id, domain: entry.domain, mandatory: entry.mandatory, status: entry.status });
  }));
}

/**
 * Decides whether proposed architecture complexity has evidence-backed drivers.
 * It does not select a design: it only rejects complexity above demonstrated need.
 */
export function assessArchitectureProportionality(input = {}) {
  object(input, 'proportionality input');
  fields(input, ['deployment', 'scale', 'proposedComplexity', 'drivers', 'obligations'], 'proportionality input');
  if (!['greenfield', 'existing'].includes(input.deployment)) schema('deployment is invalid');
  if (!SCALE.includes(input.scale)) schema('scale is invalid');
  if (!COMPLEXITY.includes(input.proposedComplexity)) schema('proposedComplexity is invalid');
  object(input.drivers, 'drivers');
  fields(input.drivers, ['independentScaling', 'isolationBoundary', 'multiRegionConsistency'], 'drivers');
  for (const key of ['independentScaling', 'isolationBoundary', 'multiRegionConsistency']) {
    if (typeof input.drivers[key] !== 'boolean') schema(`drivers.${key} must be boolean`);
  }
  const obligations = normalizeObligations(input.obligations);
  const mandatory = obligations.filter((entry) => entry.mandatory && entry.status !== 'not_applicable');
  const distributedDriver = input.scale === 'high' || input.drivers.independentScaling || input.drivers.multiRegionConsistency;
  const modularDriver = mandatory.length > 0 || input.drivers.isolationBoundary || input.scale === 'moderate';
  const minimumComplexity = distributedDriver ? 'distributed' : modularDriver ? 'modular' : 'minimal';
  const excessive = rank(input.proposedComplexity) > rank(minimumComplexity);
  return Object.freeze({
    decision: excessive ? 'REJECT' : 'ALLOW',
    code: excessive ? 'ARC_PROPORTIONALITY_EXCESS' : null,
    proposedComplexity: input.proposedComplexity,
    minimumComplexity,
    drivers: Object.freeze({ distributed: distributedDriver, modular: modularDriver, mandatoryObligationIds: Object.freeze(mandatory.map((entry) => entry.id)) }),
    reason: excessive ? 'proposed complexity exceeds demonstrated drivers' : 'proposed complexity is justified by structured drivers',
  });
}

/** Blocks minimization when required privacy, compliance, or equivalent work is absent. */
export function assessMandatoryObligationReadiness(input = {}) {
  object(input, 'obligation readiness input');
  fields(input, ['objective', 'proposedComplexity', 'obligations'], 'obligation readiness input');
  if (!['minimize', 'standard'].includes(input.objective)) schema('objective is invalid');
  if (!COMPLEXITY.includes(input.proposedComplexity)) schema('proposedComplexity is invalid');
  const obligations = normalizeObligations(input.obligations);
  const missing = obligations.filter((entry) => entry.mandatory && entry.status === 'missing');
  const required = obligations.filter((entry) => entry.mandatory && entry.status !== 'not_applicable');
  return Object.freeze({
    decision: missing.length ? 'BLOCK' : 'READY',
    code: missing.length ? 'ARC_MANDATORY_OBLIGATION_MISSING' : null,
    objective: input.objective,
    proposedComplexity: input.proposedComplexity,
    requiredObligationIds: Object.freeze(required.map((entry) => entry.id)),
    missingObligationIds: Object.freeze(missing.map((entry) => entry.id)),
    missingDomains: Object.freeze([...new Set(missing.map((entry) => entry.domain))]),
    reason: missing.length ? 'required obligations are not implemented' : 'all required obligations are implemented or not applicable',
  });
}

function observation(id, producer, consumer, value) {
  return Object.freeze({ id, producer, consumer, value: Object.freeze(value) });
}

export function executeAdversarialProportionalityCase(rowOrId, input = undefined) {
  const id = typeof rowOrId === 'string' ? rowOrId : rowOrId?.id;
  const fixture = input ?? DEFAULT_INPUTS[id];
  if (!ADVERSARIAL_PROPORTIONALITY_IDS.includes(id) || !fixture) return null;
  try {
    const observed = id === 'AE-ADVERSARIAL-001'
      ? observation(id, 'assessArchitectureProportionality', 'architecture proportionality ingress', assessArchitectureProportionality(fixture))
      : observation(id, 'assessMandatoryObligationReadiness', 'mandatory obligation readiness ingress', assessMandatoryObligationReadiness(fixture));
    return Object.freeze({ id, family: typeof rowOrId === 'object' ? rowOrId.family : 'adversarial', status: 'PASS', observed });
  } catch (error) {
    return Object.freeze({ id, family: typeof rowOrId === 'object' ? rowOrId.family : 'adversarial', status: 'FAIL', reason: error.message, code: error.code ?? null });
  }
}

export function validateAdversarialProportionalityObservation(id, observed) {
  const value = observed?.value ?? observed?.observed?.value ?? observed;
  if (id === 'AE-ADVERSARIAL-001') return value?.decision === 'REJECT' && value?.code === 'ARC_PROPORTIONALITY_EXCESS' && value?.minimumComplexity === 'minimal' && value?.proposedComplexity === 'distributed';
  if (id === 'AE-ADVERSARIAL-002') return value?.decision === 'BLOCK' && value?.code === 'ARC_MANDATORY_OBLIGATION_MISSING' && value?.missingDomains?.includes('privacy') && value?.missingDomains?.includes('compliance');
  return false;
}

export function adversarialProportionalityBindingIds() { return ADVERSARIAL_PROPORTIONALITY_IDS; }
