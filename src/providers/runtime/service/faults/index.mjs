import { SERVICE_RUNTIME_SCENARIOS } from '../../worker/index.mjs';

const FIXTURE_STATUS = Object.freeze({ clean: 'pass', defect: 'fail', partial: 'partial', 'stale-environment': 'unproven', 'unsupported-runtime': 'blocked' });

export function createServiceFixtureAdapter(fixture = 'clean', { onExecute = null } = {}) {
  const fixtureStatus = FIXTURE_STATUS[fixture] ?? 'blocked';
  return { async execute({ id, binding = {} } = {}) {
    if (!SERVICE_RUNTIME_SCENARIOS.includes(id)) return { status: 'error', terminal: true, coverageGaps: ['unsupported-runtime-scenario'] };
    if (typeof onExecute === 'function') onExecute({ id, binding });
    const restartable = id === 'worker-restart';
    return { status: fixtureStatus, terminal: true, restartable,
      evidence: { fixture, scenario: id, binding, restartable },
      cleanup: { status: 'pass', deployment: binding.deployment ?? null, region: binding.region ?? null, datastore: binding.datastore ?? null } };
  } };
}

export const createFaultAdapter = createServiceFixtureAdapter;
