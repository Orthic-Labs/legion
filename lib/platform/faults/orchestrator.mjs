import { validateFaultInjection } from './injectors.mjs';

export async function orchestrateFault({ fault, adapter, capability, scenarioId, controls = [] }) {
  const valid = validateFaultInjection(fault, capability);
  if (valid.status !== 'pass') return { schemaVersion: 1, kind: 'nemesis-fault-receipt', status: valid.status, scenarioId, controls, activation: null, recovery: null, residualDamage: null, coverageGaps: [valid.reason] };
  let activated = false;
  try { const activation = await adapter.inject(fault); activated = true; const observed = await adapter.observe(); const recovery = await adapter.recover();
    return { schemaVersion: 1, kind: 'nemesis-fault-receipt', status: recovery?.ok ? 'pass' : 'partial', scenarioId, controls, activation, observed, recovery, residualDamage: recovery?.residualDamage ?? null, coverageGaps: [] };
  } finally { if (activated) await adapter.cleanup?.(); }
}
