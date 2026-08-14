// Production admissions for two architecture hazards.  Both operate only on
// structured facts: no selection can be inferred from prose or an eval row.
import { ArcaneError, decision } from './errors.mjs';
import { compareEvidenceCandidates } from './evidence-registry.mjs';

export const ADVERSARIAL_OWNERSHIP_ECONOMICS_IDS = Object.freeze([
  'AE-ADVERSARIAL-006',
  'AE-ADVERSARIAL-007',
]);

export const REQUIRED_ADVERSE_ECONOMIC_METRICS = Object.freeze([
  'outageCost',
  'overageCost',
  'egressCost',
  'exitCost',
]);

function object(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', `${name} must be an object`, { name });
  }
  return value;
}

function nonEmptyString(value, name) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', `${name} must be a non-empty string`, { name });
  }
  return value.trim();
}

function nonEmptyStrings(value, name) {
  if (!Array.isArray(value) || value.length === 0 || value.some((entry) => typeof entry !== 'string' || !entry.trim())) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', `${name} must be a non-empty string array`, { name });
  }
  return [...new Set(value.map((entry) => entry.trim()))].sort();
}

function frozenConflict(authority, claims) {
  return Object.freeze({
    authority,
    sources: Object.freeze(claims.map((claim) => Object.freeze({ sourceId: claim.sourceId, owner: claim.owner }))),
    owners: Object.freeze([...new Set(claims.map((claim) => claim.owner))].sort()),
  });
}

/**
 * Detect incompatible ownership before an architecture selector can use its
 * inputs.  A duplicated authority is a conflict only when independent owners
 * claim it; multiple records owned by one authority may be replicas.
 */
export function assessSourceOfTruthOwnership({ sources } = {}) {
  if (!Array.isArray(sources) || sources.length === 0) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'sources must be a non-empty array', { name: 'sources' });
  }
  const claimsByAuthority = new Map();
  const sourceIds = new Set();
  for (const source of sources) {
    object(source, 'source');
    const sourceId = nonEmptyString(source.sourceId, 'source.sourceId');
    const owner = nonEmptyString(source.owner, 'source.owner');
    const authorities = nonEmptyStrings(source.authorities, 'source.authorities');
    if (sourceIds.has(sourceId)) {
      throw new ArcaneError('ARC_SCHEMA_INVALID', 'source.sourceId must be unique', { sourceId });
    }
    sourceIds.add(sourceId);
    for (const authority of authorities) {
      const claims = claimsByAuthority.get(authority) ?? [];
      claims.push(Object.freeze({ sourceId, owner }));
      claimsByAuthority.set(authority, claims);
    }
  }
  const conflicts = [...claimsByAuthority.entries()]
    .filter(([, claims]) => claims.length > 1 && new Set(claims.map((claim) => claim.owner)).size > 1)
    .map(([authority, claims]) => frozenConflict(authority, claims))
    .sort((left, right) => left.authority.localeCompare(right.authority));
  if (conflicts.length) {
    return decision({
      allowed: false,
      code: 'ARC_CLAIM_PREREQUISITE_UNMET',
      message: 'selection blocked by conflicting authority ownership',
      detail: { disposition: 'BLOCK_SELECTION', ownershipConflicts: Object.freeze(conflicts) },
    });
  }
  return decision({
    allowed: true,
    message: 'authority ownership is unambiguous for selection',
    detail: { disposition: 'ELIGIBLE_FOR_SELECTION', ownershipConflicts: Object.freeze([]) },
  });
}

function metricSet(value, name) {
  object(value, name);
  const missing = REQUIRED_ADVERSE_ECONOMIC_METRICS.filter((metric) => !Number.isFinite(value[metric]) || value[metric] < 0);
  return Object.freeze({ complete: missing.length === 0, missing: Object.freeze(missing) });
}

function normalizeVendor(candidate) {
  object(candidate, 'candidate');
  return Object.freeze({
    ...candidate,
    candidateId: nonEmptyString(candidate.candidateId, 'candidate.candidateId'),
    adverseCaseEconomics: candidate.adverseCaseEconomics ?? null,
  });
}

/**
 * Admit a vendor selection only after selected vendor supplies a complete,
 * non-negative adverse-case economic model.  Other candidate scores cannot
 * compensate for this missing hard-gate evidence.
 */
export function admitVendorSelection({ candidates, selectedCandidateId } = {}) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'candidates must be a non-empty array', { name: 'candidates' });
  }
  const selected = nonEmptyString(selectedCandidateId, 'selectedCandidateId');
  const normalized = candidates.map(normalizeVendor);
  const ids = normalized.map((candidate) => candidate.candidateId);
  if (new Set(ids).size !== ids.length) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'candidate.candidateId must be unique', { ids });
  }
  const selectedCandidate = normalized.find((candidate) => candidate.candidateId === selected);
  if (!selectedCandidate) {
    throw new ArcaneError('ARC_SCHEMA_INVALID', 'selectedCandidateId must identify a candidate', { selectedCandidateId: selected });
  }
  const economics = new Map(normalized.map((candidate) => [candidate.candidateId, metricSet(candidate.adverseCaseEconomics ?? {}, 'candidate.adverseCaseEconomics')]));
  const comparison = compareEvidenceCandidates({
    candidates: normalized,
    hardGates: [{
      id: 'adverse-case-economics-complete',
      evaluate: (candidate) => economics.get(candidate.candidateId)?.complete === true,
    }],
    score: (candidate) => Number.isFinite(candidate.score) ? candidate.score : 0,
  });
  const selectedEconomics = economics.get(selected);
  if (!selectedEconomics.complete) {
    return decision({
      allowed: false,
      code: 'ARC_EVIDENCE_INSUFFICIENT',
      message: 'selected vendor lacks adverse-case economic evidence',
      detail: {
        disposition: 'BLOCK_SELECTION',
        selectedCandidateId: selected,
        missingEconomicMetrics: selectedEconomics.missing,
        comparison,
      },
    });
  }
  return decision({
    allowed: true,
    message: 'selected vendor has complete adverse-case economic evidence',
    detail: { disposition: 'ELIGIBLE_FOR_SELECTION', selectedCandidateId: selected, comparison },
  });
}

function observed(id, producer, consumer, value) {
  return Object.freeze({ id, producer, consumer, value });
}

function ownershipFixture() {
  return assessSourceOfTruthOwnership({
    sources: [
      { sourceId: 'billing-cache', owner: 'platform', authorities: ['account-balance'] },
      { sourceId: 'ledger-db', owner: 'finance', authorities: ['account-balance'] },
    ],
  });
}

function economicsFixture() {
  return admitVendorSelection({
    candidates: [{ candidateId: 'vendor-a', score: 100, adverseCaseEconomics: { outageCost: 1000, overageCost: 25 } }],
    selectedCandidateId: 'vendor-a',
  });
}

const EVALUATORS = Object.freeze({
  'AE-ADVERSARIAL-006': () => observed('AE-ADVERSARIAL-006', 'assessSourceOfTruthOwnership', 'architecture selection admission', ownershipFixture()),
  'AE-ADVERSARIAL-007': () => observed('AE-ADVERSARIAL-007', 'admitVendorSelection', 'vendor selection admission', economicsFixture()),
});

export function adversarialOwnershipEconomicsBindingIds() {
  return ADVERSARIAL_OWNERSHIP_ECONOMICS_IDS;
}

export function executeAdversarialOwnershipEconomicsCase(rowOrId) {
  const id = typeof rowOrId === 'string' ? rowOrId : rowOrId?.id;
  const evaluate = EVALUATORS[id];
  if (!evaluate) return null;
  try {
    return Object.freeze({ id, status: 'PASS', observed: evaluate() });
  } catch (error) {
    return Object.freeze({ id, status: 'FAIL', reason: `ownership/economics evaluator failed: ${error.message}` });
  }
}

export function validateAdversarialOwnershipEconomicsObservation(id, observation) {
  const value = observation?.value ?? observation;
  if (id === 'AE-ADVERSARIAL-006') {
    return observation?.producer === 'assessSourceOfTruthOwnership'
      && value?.allowed === false
      && value.code === 'ARC_CLAIM_PREREQUISITE_UNMET'
      && value.detail?.disposition === 'BLOCK_SELECTION'
      && value.detail?.ownershipConflicts?.some((conflict) => conflict.authority === 'account-balance' && conflict.owners?.length === 2);
  }
  if (id === 'AE-ADVERSARIAL-007') {
    return observation?.producer === 'admitVendorSelection'
      && value?.allowed === false
      && value.code === 'ARC_EVIDENCE_INSUFFICIENT'
      && value.detail?.disposition === 'BLOCK_SELECTION'
      && value.detail?.selectedCandidateId === 'vendor-a'
      && value.detail?.missingEconomicMetrics?.includes('egressCost')
      && value.detail?.missingEconomicMetrics?.includes('exitCost');
  }
  return false;
}
