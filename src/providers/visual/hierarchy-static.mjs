export function analyzeHierarchy({ signals = [], renderedEvidence = null } = {}) {
  const coverageGaps = signals.length ? [] : ['hierarchy-signals-missing'];
  const findings = signals.filter((item) => Number.isFinite(item.semanticRank) && Number.isFinite(item.visualRank) && item.semanticRank !== item.visualRank)
    .map((item) => ({ ruleId: 'visual.hierarchy-rank-mismatch', component: item.component, source: item.source, semanticRank: item.semanticRank, visualRank: item.visualRank, judgmentClass: 'deterministic' }));
  const primaries = signals.filter((item) => item.strongPrimary);
  const candidates = primaries.map((item) => ({ ruleId: primaries.length > 1 ? 'visual.hierarchy-competing-primary' : 'visual.hierarchy-primary-review', component: item.component,
    source: item.source, copyItemId: item.copyItemId ?? null, judgmentClass: 'interpretive', evidenceLimitation: renderedEvidence ? null : 'rendered-evidence-missing' }));
  if (signals.some((item) => item.requiresPrimary) && !primaries.length) findings.push({ ruleId: 'visual.hierarchy-primary-missing', component: signals.find((item) => item.requiresPrimary).component, source: signals.find((item) => item.requiresPrimary).source, judgmentClass: 'deterministic' });
  for (const item of signals.filter((entry) => entry.hiddenDestructive || entry.repeatedStrongEmphasis)) candidates.push({ ruleId: item.hiddenDestructive ? 'visual.hierarchy-hidden-destructive' : 'visual.hierarchy-repeated-emphasis', component: item.component, source: item.source, copyItemId: item.copyItemId ?? null, judgmentClass: 'interpretive', evidenceLimitation: renderedEvidence ? null : 'rendered-evidence-missing' });
  return { provider: 'visual.hierarchy-static', status: findings.length || candidates.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass', complete: signals.length > 0, denominator: { kind: 'hierarchy-signals', expected: signals.length, examined: signals.length }, findings, candidates, coverageGaps, reviewRequired: candidates.length > 0 };
}
