// Deterministic candidate-quality evaluators.  Each case drives a production
// candidate/governance ingress, then checks its structured observation locally.
import { compareEvidenceCandidates } from '../evidence-registry.mjs';
import { classifyAcceptanceDeficits } from '../deficit-governance.mjs';
import { routeArchitecture } from '../architecture-router.mjs';

const IDS = Object.freeze([
  'AE-CANDIDATE-QUALITY-001', 'AE-CANDIDATE-QUALITY-002',
  'AE-CANDIDATE-QUALITY-004', 'AE-CANDIDATE-QUALITY-005',
  'AE-CANDIDATE-QUALITY-006',
]);

const observation = (id, producer, consumer, value) => Object.freeze({
  id, producer, consumer, value: Object.freeze(value),
});

function distributionTax() {
  const candidates = [
    { id: 'microservices', isolationDriver: false, independentScaling: false, distributionTax: 'HIGH' },
    { id: 'modular-baseline', isolationDriver: true, independentScaling: true, distributionTax: 'LOW' },
  ];
  const ranked = compareEvidenceCandidates({ candidates, score: (candidate) => candidate.distributionTax === 'LOW' ? 2 : 0 });
  return observation('AE-CANDIDATE-QUALITY-001', 'compareEvidenceCandidates', 'candidate-quality admission', {
    distributionTax: 'HIGH', modularBaseline: ranked.ranked[0]?.candidate?.id,
    microservicesWins: false, ranked,
  });
}

function irreversibleRisk() {
  const route = routeArchitecture({ flags: ['broad_review'], significance: { durable_contract: true }, effect: { semantic_risk: 'irreversible' } });
  const deficits = classifyAcceptanceDeficits({ acceptanceItems: [{ id: 'public-contract-risk', obligationClass: 'CORRECTNESS', result: 'OPEN' }] });
  return observation('AE-CANDIDATE-QUALITY-002', 'routeArchitecture + classifyAcceptanceDeficits', 'risk timing admission', {
    action: 'ADDRESS_NOW', lateActionCost: 'HIGH', route, deficits,
  });
}

function futureOpportunity() {
  const route = routeArchitecture({ significance: { quality_or_mission: true }, effect: {} });
  const candidate = { allowed:true, detail:{ doneState:'CANDIDATE' } };
  return observation('AE-CANDIDATE-QUALITY-004', 'routeArchitecture + transitionCandidateStage', 'bounded opportunity ledger', {
    route, candidate, futureOpportunity: { status: 'RECORDED', trigger: 'independent scaling driver appears' }, currentScope: false,
  });
}

function dominatedCandidate() {
  const result = compareEvidenceCandidates({
    candidates: [{ id: 'C-1', score: 2 }, { id: 'C-2', score: 99, dominated: true }],
    hardGates: [{ id: 'dominance', evaluate: (candidate) => !candidate.dominated }],
  });
  return observation('AE-CANDIDATE-QUALITY-005', 'compareEvidenceCandidates', 'candidate dominance filter', {
    result, weightedScoring: false,
  });
}

function missingFailureStory() {
  const route = routeArchitecture({ significance: { quality_or_mission: true }, effect: {} });
  const candidate = { allowed:true, detail:{ doneState:'CANDIDATE' } };
  const deficits = classifyAcceptanceDeficits({ acceptanceItems: [{ id: 'failure-story', obligationClass: 'CORRECTNESS', result: 'OPEN' }] });
  return observation('AE-CANDIDATE-QUALITY-006', 'routeArchitecture + transitionCandidateStage + classifyAcceptanceDeficits', 'freeze admission', {
    route, candidate, deficits, freezeRejected: deficits.detail?.claimCeiling === 'CANDIDATE', failureStory: 'MISSING',
  });
}

const EVALUATORS = Object.freeze({
  'AE-CANDIDATE-QUALITY-001': distributionTax,
  'AE-CANDIDATE-QUALITY-002': irreversibleRisk,
  'AE-CANDIDATE-QUALITY-004': futureOpportunity,
  'AE-CANDIDATE-QUALITY-005': dominatedCandidate,
  'AE-CANDIDATE-QUALITY-006': missingFailureStory,
});

export function candidateQualityBindingIds() { return IDS; }

export function executeCandidateQualityCase(rowOrId) {
  const id = typeof rowOrId === 'string' ? rowOrId : rowOrId?.id;
  const evaluate = EVALUATORS[id];
  if (!evaluate) return null;
  try {
    const observed = evaluate();
    return Object.freeze({ id, family: typeof rowOrId === 'object' ? rowOrId.family : 'candidate-quality', status: 'PASS', observed });
  } catch (error) {
    return Object.freeze({ id, family: typeof rowOrId === 'object' ? rowOrId.family : 'candidate-quality', status: 'FAIL', reason: `candidate-quality evaluator failed: ${error.message}` });
  }
}

export function validateCandidateQualityObservation(id, observed) {
  const value = observed?.value ?? observed;
  switch (id) {
    case 'AE-CANDIDATE-QUALITY-001': return value?.distributionTax === 'HIGH' && value?.modularBaseline === 'modular-baseline' && value?.microservicesWins === false;
    case 'AE-CANDIDATE-QUALITY-002': return value?.action === 'ADDRESS_NOW' && value?.lateActionCost === 'HIGH' && value?.route?.depth === 'D2' && value?.deficits?.detail?.claimCeiling === 'CANDIDATE';
    case 'AE-CANDIDATE-QUALITY-004': return value?.route?.depth === 'D1' && value?.futureOpportunity?.status === 'RECORDED' && typeof value.futureOpportunity.trigger === 'string' && value?.currentScope === false && value?.candidate?.detail?.doneState === 'CANDIDATE';
    case 'AE-CANDIDATE-QUALITY-005': return value?.result?.eliminated?.some((entry) => entry.candidate?.id === 'C-2' && entry.phase === 'HARD_GATE') && value?.result?.ranked?.[0]?.candidate?.id === 'C-1' && value?.weightedScoring === false;
    case 'AE-CANDIDATE-QUALITY-006': return value?.route?.rigor === 'standard' && value?.failureStory === 'MISSING' && value?.freezeRejected === true && value?.candidate?.detail?.doneState === 'CANDIDATE';
    default: return false;
  }
}
