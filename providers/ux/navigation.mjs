export function analyzeNavigation({ routes = [], flows = [] } = {}) {
  const coverageGaps = routes.length ? [] : ['navigation-routes-missing'];
  const used = new Set(flows.flatMap((flow) => flow.routes ?? []));
  const findings = routes.filter((route) => !used.has(route.path)).map((route) => ({ ruleId: 'ux.navigation-unreachable', route: route.path, flowIds: [], evidenceRefs: [`route:${route.path}`] }));
  const labels = new Map();
  for (const route of routes) labels.set(route.label, [...(labels.get(route.label) ?? []), route.path]);
  for (const [label, paths] of labels) if (label && paths.length > 1) findings.push({ ruleId: 'ux.navigation-duplicate-label', label, routes: paths, evidenceRefs: paths.map((path) => `route:${path}`) });
  for (const route of routes) for (const [flag, ruleId] of Object.entries({ missingActiveState: 'ux.navigation-active-state-missing', misleadingBack: 'ux.navigation-back-misleading', hiddenCritical: 'ux.navigation-critical-hidden', orientationMissing: 'ux.navigation-orientation-missing' })) if (route[flag]) findings.push({ ruleId, route: route.path, evidenceRefs: [`route:${route.path}`] });
  for (const flow of flows) if ((flow.routes ?? []).length > 4) findings.push({ ruleId: 'ux.navigation-depth-candidate', flowId: flow.id, depth: flow.routes.length, evidenceRefs: [`flow:${flow.id}`], judgmentClass: 'candidate' });
  return { provider: 'ux.navigation', status: findings.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass', findings, coverageGaps, suggestions: [] };
}
