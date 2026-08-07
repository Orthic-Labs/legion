import { terminalScenarioReceipt, requireCapability } from '../contracts.mjs';
import { transition } from './state-machine.mjs';
import { evaluateInvariant } from './assertions.mjs';

export async function runJourney({ scenario, adapter, capability, binding = {} }) {
  const permitted = requireCapability(capability, { destructive: scenario?.destructive === true });
  if (!permitted.ok) return terminalScenarioReceipt({ scenarioId: scenario?.id, targetId: scenario?.targetId, status: 'blocked', binding, coverageGaps: [permitted] });
  let state = scenario.initialState;
  const steps = [];
  for (const step of scenario.steps ?? []) {
    const edge = transition(scenario.machine, state, step.event);
    if (edge.status !== 'pass') return terminalScenarioReceipt({ scenarioId: scenario.id, targetId: scenario.targetId, status: 'blocked', binding, steps, errors: [edge] });
    const result = await adapter.execute(step);
    const assertion = evaluateInvariant(step.invariant, result.observedState);
    steps.push({ id: step.id, action: step.action, status: assertion.status, expected: assertion.expected ?? null, actual: assertion.actual ?? null, observedState: result.observedState ?? null });
    if (assertion.status !== 'pass') return terminalScenarioReceipt({ scenarioId: scenario.id, targetId: scenario.targetId, status: assertion.status === 'fail' ? 'fail' : 'unproven', binding, steps, observedState: result.observedState, durableState: result.durableState ?? null });
    state = edge.to;
  }
  return terminalScenarioReceipt({ scenarioId: scenario.id, targetId: scenario.targetId, status: 'pass', binding, steps, observedState: { state } });
}
