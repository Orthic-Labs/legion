// Production-backed S11 adversarial evaluators for migration selection &
// distributed delivery.  Inputs are structured policy facts; corpus prose is
// never read, treated as authority, or echoed into results.

import { compareEvidenceCandidates } from './evidence-registry.mjs';
import { assessMigrationCutover, COEXISTENCE_FIELDS } from '../../cli/commands/governance/delivery/migration-cutover.mjs';
import { ReplayGuard } from '../../guard/compat/effects/replay.mjs';

export const ADVERSARIAL_MIGRATION_DISTRIBUTED_IDS = Object.freeze([
  'AE-ADVERSARIAL-004',
  'AE-ADVERSARIAL-005',
]);

const requiredCoexistence = (value) => COEXISTENCE_FIELDS.every((field) => {
  const item = value?.[field];
  return typeof item === 'string' ? item.length > 0 : Boolean(item && typeof item === 'object');
});

const observation = (id, producer, consumer, value) => Object.freeze({
  id,
  producer,
  consumer,
  value: Object.freeze(value),
});

/**
 * Prefer an executable migration target from facts about transition itself.
 * A high nominal score never bypasses a required transition control.
 */
export function selectMigrationTarget({ candidates = [], transitionRisk = {} } = {}) {
  const requiresBoundedCoexistence = transitionRisk.activeLegacyConsumers === true
    || transitionRisk.rollbackWindowRequired === true
    || transitionRisk.reconciliationRequired === true;
  const comparison = compareEvidenceCandidates({
    candidates,
    hardGates: [
      {
        id: 'transition-mode',
        evaluate: (candidate) => !requiresBoundedCoexistence || candidate?.mode === 'BOUNDED_COEXISTENCE',
      },
      {
        id: 'coexistence-contract',
        evaluate: (candidate) => !requiresBoundedCoexistence || requiredCoexistence(candidate?.coexistence),
      },
    ],
    score: (candidate) => Number.isFinite(candidate?.baseScore) ? candidate.baseScore : 0,
  });
  const selected = comparison.ranked[0]?.candidate ?? null;
  const readiness = selected?.mode === 'BOUNDED_COEXISTENCE'
    ? assessMigrationCutover({
      plan: { mode: selected.mode, bounded_coexistence: selected.coexistence },
      observations: { coexistence: selected.observations ?? {} },
    })
    : null;
  return Object.freeze({
    transitionRisk: Object.freeze({
      activeLegacyConsumers: transitionRisk.activeLegacyConsumers === true,
      rollbackWindowRequired: transitionRisk.rollbackWindowRequired === true,
      reconciliationRequired: transitionRisk.reconciliationRequired === true,
      requiresBoundedCoexistence,
    }),
    comparison,
    selected,
    readiness,
  });
}

/**
 * Observe duplicate, ordering, & consistency defenses independently.  A
 * replay guard makes duplicate/order outcomes real runtime decisions; typed
 * coexistence assessment makes reconciliation requirements executable.
 */
export function assessDistributedFailureModes({ scope, events, coexistence, now } = {}) {
  const timestamp = typeof now === 'string' ? now : '2026-08-15T00:00:00.000Z';
  const clock = Date.parse(timestamp);
  const guard = new ReplayGuard({
    clock: () => clock,
    freshnessWindowSeconds: 60,
    maxSkewSeconds: 0,
  });
  const [first, repeated, outOfOrder] = Array.isArray(events) ? events : [];
  const firstDecision = first ? guard.check({ ...first, scope, timestamp: first.timestamp ?? timestamp }) : null;
  const duplicateDecision = repeated ? guard.check({ ...repeated, scope, timestamp: repeated.timestamp ?? timestamp }) : null;
  const orderingDecision = outOfOrder ? guard.check({ ...outOfOrder, scope, timestamp: outOfOrder.timestamp ?? timestamp }) : null;
  const consistency = assessMigrationCutover({
    plan: { mode: 'BOUNDED_COEXISTENCE', bounded_coexistence: coexistence },
    observations: { coexistence: { reconciled: coexistence?.reconciled === true, telemetryActive: coexistence?.telemetryActive === true } },
  });
  return Object.freeze({
    duplicate: Object.freeze({
      firstAccepted: firstDecision?.allowed === true,
      replayDenied: duplicateDecision?.code === 'ARC_REPLAY_NONCE_SEEN',
      decision: duplicateDecision,
    }),
    ordering: Object.freeze({
      regressionDenied: orderingDecision?.code === 'ARC_REPLAY_SEQUENCE_REGRESSION',
      decision: orderingDecision,
    }),
    consistency: Object.freeze({
      reconciliationDeclared: requiredCoexistence(coexistence),
      ready: consistency.ready === true,
      assessment: consistency,
    }),
  });
}

function migrationTargetCase() {
  const coexistence = {
    owner: 'migration-owner',
    reconciliation: 'reconcile-by-version',
    telemetry: 'cutover-observability',
    expiry: '2026-09-01T00:00:00.000Z',
    rollback: 'restore-legacy-reader',
    trigger: 'all-readers-observed',
    reconciled: true,
    telemetryActive: true,
  };
  const value = selectMigrationTarget({
    transitionRisk: { activeLegacyConsumers: true, rollbackWindowRequired: true, reconciliationRequired: true },
    candidates: [
      { id: 'hard-cut', mode: 'HARD_CUT', baseScore: 100 },
      { id: 'bounded-coexistence', mode: 'BOUNDED_COEXISTENCE', baseScore: 20, coexistence, observations: { reconciled: true, telemetryActive: true } },
    ],
  });
  return observation('AE-ADVERSARIAL-004', 'selectMigrationTarget + assessMigrationCutover', 'migration target selector', value);
}

function distributedFailureModesCase() {
  const coexistence = {
    owner: 'workflow-owner',
    reconciliation: 'versioned-reconciler',
    telemetry: 'consistency-monitor',
    expiry: '2026-09-01T00:00:00.000Z',
    rollback: 'compensating-operation',
    trigger: 'reconciliation-lag',
    reconciled: true,
    telemetryActive: true,
  };
  const value = assessDistributedFailureModes({
    scope: { issuerId: 'workflow', sessionId: 's11', runId: 'distributed', workspaceId: 'arcane' },
    now: '2026-08-15T00:00:00.000Z',
    events: [
      { nonce: 'delivery-1', sequence: 10 },
      { nonce: 'delivery-1', sequence: 11 },
      { nonce: 'delivery-2', sequence: 9 },
    ],
    coexistence,
  });
  return observation('AE-ADVERSARIAL-005', 'ReplayGuard + assessMigrationCutover', 'distributed delivery policy', value);
}

const CASES = Object.freeze({
  'AE-ADVERSARIAL-004': migrationTargetCase,
  'AE-ADVERSARIAL-005': distributedFailureModesCase,
});

export function adversarialMigrationDistributedBindingIds() {
  return ADVERSARIAL_MIGRATION_DISTRIBUTED_IDS;
}

export function executeAdversarialMigrationDistributedCase(rowOrId) {
  const id = typeof rowOrId === 'string' ? rowOrId : rowOrId?.id;
  const evaluate = CASES[id];
  if (!evaluate) return null;
  try {
    return Object.freeze({
      id,
      family: typeof rowOrId === 'object' ? rowOrId.family : 'adversarial',
      status: 'PASS',
      observed: evaluate(),
    });
  } catch (error) {
    return Object.freeze({ id, family: typeof rowOrId === 'object' ? rowOrId.family : 'adversarial', status: 'FAIL', reason: error.message });
  }
}

export function validateAdversarialMigrationDistributedObservation(id, observed) {
  const value = observed?.value ?? observed;
  if (id === 'AE-ADVERSARIAL-004') {
    return value?.transitionRisk?.requiresBoundedCoexistence === true
      && value?.comparison?.eliminated?.some((entry) => entry.candidate?.id === 'hard-cut')
      && value?.selected?.id === 'bounded-coexistence'
      && value?.readiness?.ready === true;
  }
  if (id === 'AE-ADVERSARIAL-005') {
    return value?.duplicate?.firstAccepted === true
      && value?.duplicate?.replayDenied === true
      && value?.ordering?.regressionDenied === true
      && value?.consistency?.reconciliationDeclared === true
      && value?.consistency?.ready === true;
  }
  return false;
}
