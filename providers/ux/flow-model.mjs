export function createFlowModel({ flows = [], requiredGoalPolicy = [] } = {}) {
  if (!flows.length) return { provider: 'ux.flow-model', status: 'unproven', flows: [], requiredGoals: [], coverageGaps: ['zero-flow-denominator'] };
  const required = new Set(requiredGoalPolicy);
  const requiredGoals = flows.filter((flow) => !flow.goalInferred || required.has(flow.goal)).map((flow) => flow.goal);
  const coverageGaps = flows.flatMap((flow) => {
    const gaps = [];
    if (!flow.terminalState || flow.terminalState === 'unproven') gaps.push(`flow-unproven:${flow.id}`);
    if (!flow.steps.length) gaps.push(`flow-empty:${flow.id}`);
    return gaps;
  });
  return { provider: 'ux.flow-model', status: coverageGaps.length ? 'unproven' : 'pass', flows, requiredGoals, coverageGaps };
}
