export function analyzeStacking({ contexts = [] } = {}) {
  const findings = [];
  const coverageGaps = contexts.length ? [] : ['stacking-contexts-missing'];
  for (const context of contexts) {
    const chain = context.zIndexChain ?? [];
    if (chain.some((value, index) => index && Math.abs(value - chain[index - 1]) > 1000)) findings.push({ ruleId: 'visual.stacking-fragile-chain', contextId: context.id, chain });
    if (context.overlap) findings.push({ ruleId: 'visual.stacking-overlap', contextId: context.id, elements: context.overlap });
  }
  return { provider: 'visual.stacking', status: findings.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass', complete: contexts.length > 0, denominator: { kind: 'stacking-contexts', expected: contexts.length, examined: contexts.length }, findings, coverageGaps };
}
