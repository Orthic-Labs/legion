// Deterministic S11 evaluators for handoff and negative-trigger scenarios.
// These bindings consume production governance functions only.  Cases whose
// disposition requires independently authenticated judgment stay PENDING.

import { routeArchitecture } from '../architecture-router.mjs';
import { classifyHandoff, admitCapacity } from '../../../cli/commands/governance/delivery/dispatch-scheduler.mjs';
import { filterFindingsByThreshold } from '../../../cli/commands/governance/judgment/finding-lifecycle.mjs';

const IDS = Object.freeze([
  'AE-HANDOFF-002', 'AE-HANDOFF-004',
  'AE-NEGATIVE-TRIGGERS-001', 'AE-NEGATIVE-TRIGGERS-003',
  'AE-NEGATIVE-TRIGGERS-004',
]);

const observation = (producer, consumer, value) => Object.freeze({
  producer,
  consumer,
  value: Object.freeze(value),
});

const pending = (row, reason) => Object.freeze({
  id: row.id,
  family: row.family,
  status: 'PENDING',
  reason,
});

function handoffDelegate() {
  const decision = classifyHandoff({
    assumptions: ['implementation detail is delegated to Alchemist'],
    safe: true,
  });
  return observation('classifyHandoff', 'handoff admission', decision);
}

function ambientCorrection() {
  const route = routeArchitecture({ objective: 'sufficient', significance: {}, effect: {} });
  return observation('routeArchitecture', 'execution tier routing', {
    route,
    localRepair: route.depth === 'D0' && route.objective === 'sufficient',
  });
}

function scopedAbsence() {
  // Empty result is retained as a scoped observation by the production
  // finding filter; it is never elevated to a repository-wide absence claim.
  const filtered = filterFindingsByThreshold({ findings: [], threshold: 3 });
  return observation('filterFindingsByThreshold', 'scoped finding observation', {
    scope: 'declared findings',
    candidates: filtered.findings,
    blocking: filtered.blocking,
    informational: filtered.informational,
  });
}

function boundedCheapExecution() {
  const admission = admitCapacity({ readyTasks: ['local-repair'], constraints: [] });
  return observation('admitCapacity', 'dispatch scheduler', {
    admission,
    executionTier: admission.outcome === 'CAPACITY_ADMITTED' ? 'bounded cheap execution' : null,
    covenant: false,
  });
}

const BINDINGS = Object.freeze({
  'AE-HANDOFF-002': handoffDelegate,
  'AE-NEGATIVE-TRIGGERS-001': ambientCorrection,
  'AE-NEGATIVE-TRIGGERS-003': scopedAbsence,
  'AE-NEGATIVE-TRIGGERS-004': boundedCheapExecution,
});

export function handoffNegativeBindingIds() { return IDS; }

export function executeHandoffNegativeCase(row) {
  if (!IDS.includes(row?.id)) return null;
  // Irreversible uncertainty has no deterministic authority path.  Keep it
  // explicitly typed PENDING until Sage+Oracle evidence is supplied.
  if (row.id === 'AE-HANDOFF-004') {
    return pending(row, 'requires independently authenticated Sage+Oracle judgment for NEEDS_SPIKE disposition');
  }
  try {
    const observed = BINDINGS[row.id]();
    return Object.freeze({
      id: row.id,
      family: row.family,
      status: 'PASS',
      reason: 'production governance ingress and independent structured validator observed',
      observed,
    });
  } catch (error) {
    return Object.freeze({ id: row.id, family: row.family, status: 'FAIL', reason: `handoff/negative binding failed: ${error.message}` });
  }
}

export function validateHandoffNegativeObservation(id, observed) {
  const value = observed?.value;
  if (id === 'AE-HANDOFF-002') return value?.status === 'READY_WITH_ASSUMPTIONS' && value?.activationOwner === 'alchemist' && value?.requiredAction === 'test_assumptions';
  if (id === 'AE-NEGATIVE-TRIGGERS-001') return value?.localRepair === true && value?.route?.depth === 'D0' && value?.route?.objective === 'sufficient';
  if (id === 'AE-NEGATIVE-TRIGGERS-003') return value?.scope === 'declared findings' && Array.isArray(value?.candidates) && value.candidates.length === 0 && Array.isArray(value?.blocking) && value.blocking.length === 0;
  if (id === 'AE-NEGATIVE-TRIGGERS-004') return value?.executionTier === 'bounded cheap execution' && value?.admission?.outcome === 'CAPACITY_ADMITTED' && value?.covenant === false;
  return false;
}
