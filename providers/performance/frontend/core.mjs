export function assessFrontendPerformance(measurements = [], budgets = {}) {
  const findings = measurements.flatMap((item) => Object.entries(budgets).filter(([metric, limit]) => Number.isFinite(item[metric]) && item[metric] > limit).map(([metric, limit]) => ({ surfaceId: item.surfaceId, metric, actual: item[metric], limit })));
  const gaps = measurements.filter((item) => !item.environment || !item.repeatCount).map((item) => `measurement-environment-missing:${item.surfaceId ?? 'unknown'}`);
  return { schemaVersion: 1, provider: 'performance.frontend', status: gaps.length ? 'partial' : findings.length ? 'candidates' : 'pass', findings, coverageGaps: gaps, measurements };
}
