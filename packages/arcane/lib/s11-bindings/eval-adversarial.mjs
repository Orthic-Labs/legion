import { routeArchitecture } from '../architecture-router.mjs';

// Runtime adversarial cases whose semantics can be observed directly from a
// production control. Cases requiring human/Sage/Oracle conclusions stay
// explicitly pending; outcomes are never inferred from corpus expectations.
export const ADVERSARIAL_IDS = Object.freeze([
  'AE-ADVERSARIAL-001', 'AE-ADVERSARIAL-002', 'AE-ADVERSARIAL-003',
  'AE-ADVERSARIAL-004', 'AE-ADVERSARIAL-005', 'AE-ADVERSARIAL-006',
  'AE-ADVERSARIAL-007', 'AE-ADVERSARIAL-009', 'AE-ADVERSARIAL-010',
]);

const MISSING = Object.freeze({
  'AE-ADVERSARIAL-001': 'architecture proportionality assessment ingress',
  'AE-ADVERSARIAL-002': 'mandatory-obligation readiness ingress',
  'AE-ADVERSARIAL-004': 'migration target selection ingress',
  'AE-ADVERSARIAL-005': 'distributed failure-mode assessment ingress',
  'AE-ADVERSARIAL-006': 'source-of-truth ownership-conflict ingress',
  'AE-ADVERSARIAL-007': 'adverse-case vendor economics ingress',
  'AE-ADVERSARIAL-009': 'AI readiness governance ingress',
  'AE-ADVERSARIAL-010': 'architecture-reconstruction uncertainty verdict ingress',
});

function observation(id, value, producer, consumer) {
  return Object.freeze({ id, producer, consumer, value: Object.freeze(value) });
}

export function executeAdversarialBinding(id) {
  if (!ADVERSARIAL_IDS.includes(id)) return Object.freeze({ status: 'PENDING', id, reason: 'unknown adversarial case' });
  if (id === 'AE-ADVERSARIAL-003') {
    return observation(id, routeArchitecture({ flags: ['safety', 'hard_real_time'], significance: { quality_or_mission: true }, effect: {} }), 'routeArchitecture', 'critical-rigor routing');
  }
  return Object.freeze({ status: 'PENDING', id, reason: `requires ${MISSING[id]}`, missingProducer: MISSING[id] ?? null });
}

export function validateAdversarialObservation(id, result) {
  if (!result || result.status === 'PENDING') return false;
  const value = result.value;
  if (id === 'AE-ADVERSARIAL-003') return value?.rigor === 'critical' && value?.depth === 'D1';
  return false;
}

export function adversarialBindingIds() { return ADVERSARIAL_IDS; }
