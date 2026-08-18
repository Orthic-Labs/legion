export function analyzeRuntimeAccessibility({ engine = null, requiredCases = [], runs = [], requiredExercises = [], exercised = [] } = {}) {
  if (!engine) return { provider: 'accessibility.runtime', status: 'unproven', complete: false, findings: [], coverageGaps: ['accessibility-engine-unavailable'] };
  if (!requiredCases.length && !requiredExercises.length) return { provider: 'accessibility.runtime', status: 'unproven', complete: false, findings: [], coverageGaps: ['zero-accessibility-denominator'] };
  const key = (item) => `${item.surfaceId}:${item.state}`;
  const observed = new Set(runs.map(key));
  const coverageGaps = requiredCases.filter((item) => !observed.has(key(item))).map((item) => `runtime-case-untested:${key(item)}`);
  const exercisedSet = new Set(exercised);
  coverageGaps.push(...requiredExercises.filter((name) => !exercisedSet.has(name)).map((name) => `runtime-exercise-untested:${name}`));
  const rootCauses = new Map();
  for (const run of runs) for (const violation of run.violations ?? []) {
    const root = violation.rootCause ?? `${violation.rule}:${(violation.nodes ?? []).join(',')}`;
    const current = rootCauses.get(root) ?? { ruleId: violation.rule, rootCause: root, nodes: [], evidenceSets: [], engineVersion: engine.version, impact: violation.impact ?? null,
      accessibleName: violation.accessibleName ?? null, role: violation.role ?? null, elementState: violation.state ?? null, domPath: violation.domPath ?? null, screenshot: violation.screenshot ?? null };
    current.nodes.push(...(violation.nodes ?? []));
    current.evidenceSets.push({ surfaceId: run.surfaceId, state: run.state, viewport: run.viewport ?? null });
    rootCauses.set(root, current);
  }
  const findings = [...rootCauses.values()];
  return { provider: 'accessibility.runtime', engine, status: findings.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass', complete: coverageGaps.length === 0, findings, coverageGaps };
}
