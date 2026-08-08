export function analyzeMotion({ transitions = [], reducedMotionExercised = false } = {}) {
  const findings = [];
  for (const transition of transitions) {
    if (transition.blocksInteraction || transition.obscuresState) findings.push({ ruleId: 'visual.motion-blocking', transitionId: transition.id, from: transition.from, to: transition.to, timing: { durationMs: transition.durationMs }, evidenceClass: transition.frameEvidence ? 'runtime-frames' : 'runtime-timing' });
    if (Number.isFinite(transition.budgetMs) && transition.durationMs > transition.budgetMs) findings.push({ ruleId: 'visual.motion-budget', transitionId: transition.id, from: transition.from, to: transition.to, timing: { durationMs: transition.durationMs, budgetMs: transition.budgetMs }, performanceLink: true });
    if (transition.layoutShift) findings.push({ ruleId: 'visual.motion-layout-shift', transitionId: transition.id, from: transition.from, to: transition.to, timing: { durationMs: transition.durationMs }, performanceLink: true });
  }
  const coverageGaps = reducedMotionExercised ? [] : ['reduced-motion-unproven'];
  return { provider: 'visual.motion', status: findings.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass', findings, coverageGaps, decorativeRecommendations: [] };
}
