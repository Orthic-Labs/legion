export function analyzeFriction({ flows = [] } = {}) {
  const findings = [];
  const candidates = [];
  const coverageGaps = flows.length ? [] : ['flow-denominator-missing'];
  for (const flow of flows) {
    for (const step of flow.steps ?? []) {
      if (step.loopTo === step.id || step.unreachableHelp || step.contradictsControl || step.requiredInfoAfterDecision || step.unreachableReport || step.unreachableAppeal) findings.push({ ruleId: 'ux.friction-deterministic', flowId: flow.id, stepId: step.id, policyContext: flow.policyContext ?? 'unknown', evidence: step.evidence ?? `step:${step.id}`, judgmentClass: 'deterministic' });
      if (step.memoryBurden || step.distracting || step.timePressure || step.tooltipDependence || step.repeatedEntry) candidates.push({ ruleId: 'ux.friction-interpretive', flowId: flow.id, stepId: step.id, policyContext: flow.policyContext ?? 'unknown', evidence: step.evidence ?? `step:${step.id}`, judgmentClass: 'interpretive' });
    }
  }
  return { provider: 'ux.friction', status: findings.length || candidates.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass', findings, candidates, coverageGaps, universalMaximumSteps: null };
}
