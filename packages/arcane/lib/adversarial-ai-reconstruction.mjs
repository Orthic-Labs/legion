// Runtime controls for two adversarial architecture cases.  Both accept
// structured operator evidence, compute their own verdict, & expose an
// observation validator which recomputes it instead of trusting supplied
// output.

export const AI_RECONSTRUCTION_BINDING_IDS = Object.freeze([
  'AE-ADVERSARIAL-009',
  'AE-ADVERSARIAL-010',
]);

const AI_REQUIRED = Object.freeze(['provenance', 'evaluation', 'fallback', 'humanAuthority']);
const RECONSTRUCTION_REQUIRED = Object.freeze(['topology', 'runtime', 'deployment', 'ownership']);

const nonEmpty = (value) => typeof value === 'string' && value.trim().length > 0;
const isoTime = (value) => nonEmpty(value) && !Number.isNaN(Date.parse(value));
const unique = (values) => [...new Set(values)];

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (!value || typeof value !== 'object') return JSON.stringify(value);
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
}

function same(left, right) { return stable(left) === stable(right); }

function validProvenance(entry) {
  return entry && typeof entry === 'object' && nonEmpty(entry.sourceRef) && nonEmpty(entry.digest);
}

function validEvaluation(value) {
  return value && typeof value === 'object'
    && value.status === 'PASS' && nonEmpty(value.reportRef) && isoTime(value.evaluatedAt)
    && value.metrics && typeof value.metrics === 'object' && !Array.isArray(value.metrics);
}

function validFallback(value) {
  return value && typeof value === 'object'
    && nonEmpty(value.mode) && nonEmpty(value.owner) && isoTime(value.testedAt);
}

function validHumanAuthority(value) {
  return value && typeof value === 'object'
    && nonEmpty(value.role) && nonEmpty(value.authorityRef) && isoTime(value.approvedAt);
}

/**
 * Return a readiness verdict for an AI-containing system.  Readiness is
 * strictly conjunctive: provenance, evaluated behavior, tested fallback, &
 * a named human authority must each be present in caller supplied evidence.
 */
export function assessAiReadiness(input = {}) {
  const missing = [];
  const provenance = Array.isArray(input.provenance) ? input.provenance : [];
  if (!provenance.length || provenance.some((entry) => !validProvenance(entry))) missing.push('provenance');
  if (!validEvaluation(input.evaluation)) missing.push('evaluation');
  if (!validFallback(input.fallback)) missing.push('fallback');
  if (!validHumanAuthority(input.humanAuthority)) missing.push('humanAuthority');

  const readiness = missing.length === 0;
  return Object.freeze({
    systemId: nonEmpty(input.systemId) ? input.systemId : null,
    disposition: readiness ? 'READY' : 'NOT_READY',
    readiness,
    missing: Object.freeze(missing),
    evidence: Object.freeze({
      provenanceRecords: provenance.filter(validProvenance).length,
      evaluationVerified: validEvaluation(input.evaluation),
      fallbackTested: validFallback(input.fallback),
      humanAuthorityBound: validHumanAuthority(input.humanAuthority),
    }),
  });
}

function currentEvidence(entry, asOf) {
  return entry && typeof entry === 'object' && nonEmpty(entry.scope) && nonEmpty(entry.sourceRef)
    && isoTime(entry.observedAt) && isoTime(entry.expiresAt)
    && Date.parse(entry.observedAt) <= Date.parse(asOf) && Date.parse(entry.expiresAt) >= Date.parse(asOf);
}

/**
 * Assess a reconstruction from actual evidence coverage.  Any required scope
 * that is missing, malformed, or expired makes result explicitly uncertain;
 * callers cannot claim a broad clean conclusion from that result.
 */
export function assessArchitectureReconstruction(input = {}) {
  const asOf = isoTime(input.asOf) ? input.asOf : null;
  const requiredScopes = unique(Array.isArray(input.requiredScopes) && input.requiredScopes.length
    ? input.requiredScopes.filter(nonEmpty)
    : RECONSTRUCTION_REQUIRED);
  const evidence = Array.isArray(input.evidence) ? input.evidence : [];
  const freshScopes = new Set(asOf ? evidence.filter((entry) => currentEvidence(entry, asOf)).map((entry) => entry.scope) : []);
  const staleScopes = unique(evidence.filter((entry) => entry && nonEmpty(entry.scope) && asOf && isoTime(entry.expiresAt) && Date.parse(entry.expiresAt) < Date.parse(asOf)).map((entry) => entry.scope));
  const missingScopes = requiredScopes.filter((scope) => !freshScopes.has(scope));
  const uncertainty = !asOf || missingScopes.length > 0;

  return Object.freeze({
    asOf,
    disposition: uncertainty ? 'UNCERTAINTY_REPORTED' : 'RECONSTRUCTION_READY',
    conclusionAllowed: !uncertainty,
    cleanAllowed: !uncertainty,
    requiredScopes: Object.freeze(requiredScopes),
    observedScopes: Object.freeze([...freshScopes].sort()),
    missingScopes: Object.freeze(missingScopes),
    staleScopes: Object.freeze(staleScopes),
    uncertainty: Object.freeze({ present: uncertainty, reason: !asOf ? 'INVALID_AS_OF' : missingScopes.length ? 'INCOMPLETE_OR_STALE_EVIDENCE' : null }),
  });
}

function observation(id, input, value, producer, consumer) {
  return Object.freeze({ id, producer, consumer, input: Object.freeze(input), value });
}

/** Executor-friendly production binding. */
export function executeAdversarialAiReconstructionCase(id, input) {
  if (id === 'AE-ADVERSARIAL-009') {
    return observation(id, input ?? {}, assessAiReadiness(input), 'assessAiReadiness', 'AI readiness admission');
  }
  if (id === 'AE-ADVERSARIAL-010') {
    return observation(id, input ?? {}, assessArchitectureReconstruction(input), 'assessArchitectureReconstruction', 'architecture reconstruction conclusion gate');
  }
  return Object.freeze({ status: 'PENDING', id, reason: 'unknown AI/reconstruction adversarial case' });
}

/**
 * Validate output by recalculating it from recorded structured input.  This
 * rejects a forged verdict even if its text resembles expected corpus prose.
 */
export function validateAdversarialAiReconstructionObservation(id, observed) {
  if (!observed || observed.id !== id || !observed.input || !observed.value) return false;
  if (id === 'AE-ADVERSARIAL-009') {
    return observed.producer === 'assessAiReadiness'
      && observed.consumer === 'AI readiness admission'
      && same(observed.value, assessAiReadiness(observed.input));
  }
  if (id === 'AE-ADVERSARIAL-010') {
    return observed.producer === 'assessArchitectureReconstruction'
      && observed.consumer === 'architecture reconstruction conclusion gate'
      && same(observed.value, assessArchitectureReconstruction(observed.input));
  }
  return false;
}
