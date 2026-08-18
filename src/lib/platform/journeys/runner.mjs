import { terminalScenarioReceipt, requireCapability } from '../contracts.mjs';
import { transition } from './state-machine.mjs';
import { evaluateInvariant } from './assertions.mjs';

export async function runJourney({ scenario, adapter, capability, binding = {} }) {
  const permitted = requireCapability(capability, { destructive: scenario?.destructive === true });
  if (!permitted.ok) return terminalScenarioReceipt({ scenarioId: scenario?.id, targetId: scenario?.targetId, status: 'blocked', binding, coverageGaps: [permitted] });
  if (!scenario || typeof scenario !== 'object' || !Array.isArray(scenario.steps) || scenario.steps.length === 0 || scenario.steps.some((step) => !step || typeof step !== 'object')) return terminalScenarioReceipt({ scenarioId: scenario?.id, targetId: scenario?.targetId, status: 'unproven', binding, coverageGaps: ['journey-steps-invalid'] });
  if (typeof adapter?.execute !== 'function') return terminalScenarioReceipt({ scenarioId: scenario.id, targetId: scenario.targetId, status: 'unproven', binding, coverageGaps: ['journey-adapter-missing'] });
  let state = scenario.initialState;
  const steps = [];
  let durableState = null;
  try {
    for (const step of scenario.steps) {
      const edge = transition(scenario.machine, state, step.event);
      if (edge.status !== 'pass') return terminalScenarioReceipt({ scenarioId: scenario.id, targetId: scenario.targetId, status: 'blocked', binding, steps, errors: [edge] });
      const result = await adapter.execute(step);
      if (!result || typeof result !== 'object') return terminalScenarioReceipt({ scenarioId: scenario.id, targetId: scenario.targetId, status: 'error', binding, steps, coverageGaps: ['journey-result-invalid'] });
      if (!['pass', 'fail', 'partial', 'unproven', 'blocked', 'error'].includes(result.status) || result.terminal !== true) return terminalScenarioReceipt({ scenarioId: scenario.id, targetId: scenario.targetId, status: 'error', binding, steps, coverageGaps: ['journey-result-nonterminal'] });
      durableState = result.durableState ?? null;
      const assertion = evaluateInvariant(step.invariant, result.observedState);
      const stepStatus = result.status !== 'pass' ? result.status : assertion.status;
      steps.push({ id: step.id, action: step.action, status: stepStatus, expected: assertion.expected ?? null, actual: assertion.actual ?? null, observedState: result.observedState ?? null, durableState });
      if (stepStatus !== 'pass') return terminalScenarioReceipt({ scenarioId: scenario.id, targetId: scenario.targetId, status: stepStatus === 'fail' ? 'fail' : stepStatus, binding, steps, observedState: result.observedState ?? null, durableState });
      if (durableState === null) return terminalScenarioReceipt({ scenarioId: scenario.id, targetId: scenario.targetId, status: 'unproven', binding, steps, observedState: result.observedState ?? null, coverageGaps: ['journey-durable-state-missing'] });
      state = edge.to;
    }
  } catch {
    return terminalScenarioReceipt({ scenarioId: scenario.id, targetId: scenario.targetId, status: 'error', binding, steps, errors: [{ name: 'JourneyExecutionError', message: 'journey execution failed' }], coverageGaps: ['journey-execution-error'] });
  }
  return terminalScenarioReceipt({ scenarioId: scenario.id, targetId: scenario.targetId, status: 'pass', binding, steps, observedState: { state }, durableState });
}
