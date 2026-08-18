export function analyzeSystemStates({ surfaces = [] } = {}) {
  const findings = [];
  const coverageGaps = [];
  let denominator = 0;
  for (const surface of surfaces) {
    const declared = new Set(surface.declaredStates ?? []);
    const observed = new Set(surface.observedStates ?? []);
    for (const state of surface.expectedStates ?? []) {
      denominator += 1;
      if (!declared.has(state)) coverageGaps.push(`state-absent:${surface.id}:${state}`);
      else if (!observed.has(state)) coverageGaps.push(`state-untested:${surface.id}:${state}`);
    }
    if (surface.falseSuccess) findings.push({ ruleId: 'ux.system-state-false-success', surfaceId: surface.id, evidenceClass: surface.runtimeEvidence ? 'runtime' : 'source' });
    if (surface.errorWithoutRetry) findings.push({ ruleId: 'ux.system-state-retry-missing', surfaceId: surface.id, evidenceClass: surface.runtimeEvidence ? 'runtime' : 'source' });
    for (const [flag, ruleId] of Object.entries({ blankScreen: 'ux.system-state-blank', indefiniteSpinner: 'ux.system-state-indefinite-loading', genericSkeleton: 'ux.system-state-generic-skeleton', emptyActionMissing: 'ux.system-state-empty-action', offlineDeadEnd: 'ux.system-state-offline-dead-end', staleAmbiguity: 'ux.system-state-stale-ambiguity' })) if (surface[flag]) findings.push({ ruleId, surfaceId: surface.id, evidenceClass: surface.runtimeEvidence ? 'runtime' : 'source' });
  }
  if (!denominator) coverageGaps.push('state-denominator-missing');
  return { provider: 'ux.system-states', status: findings.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass', denominator, findings, coverageGaps };
}
