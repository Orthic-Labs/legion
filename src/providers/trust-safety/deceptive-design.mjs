export function analyzeDeceptiveDesign({ choices = [] } = {}) {
  const findings = [];
  const candidates = [];
  const coverageGaps = choices.length ? [] : ['choice-denominator-missing'];
  for (const choice of choices) {
    const base = { choiceId: choice.id, flowId: choice.flowId, policyContext: choice.policyContext ?? 'unknown', action: choice.action ?? choice.id, consequence: choice.consequence ?? null, evidence: choice.evidence ?? `choice:${choice.id}` };
    if (choice.preselected || choice.hiddenCost || choice.cancellationAsymmetry || choice.disguisedControl || choice.falselyLabeled || choice.ownerlessModeration || choice.policyInconsistent) findings.push({ ...base, ruleId: 'trust-safety.deceptive-design-deterministic', judgmentClass: 'deterministic' });
    if (choice.confirmshaming || choice.unsupportedUrgency || choice.intentConcern) candidates.push({ ...base, ruleId: 'trust-safety.deceptive-design-interpretive', judgmentClass: 'interpretive', reviewRequired: true });
  }
  return { provider: 'trust-safety.deceptive-design', status: findings.length || candidates.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass', findings, candidates, coverageGaps, legalConclusion: null };
}
