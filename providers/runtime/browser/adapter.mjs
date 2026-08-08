function redactValue(value, key = '') {
  if (/authorization|cookie|password|token|secret|api[-_]?key/i.test(key)) return '[REDACTED]';
  if (Array.isArray(value)) return value.map((item) => redactValue(item));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([childKey, child]) => [childKey, redactValue(child, childKey)]));
  return value;
}

export function buildBrowserSurfaceReceipt(spec = {}, observation = {}) {
  const allowedActions = new Set(spec.allowedActions ?? []);
  const allowedDestinations = new Set(spec.allowedDestinations ?? []);
  const undeclaredActions = (observation.actions ?? []).filter((action) => !allowedActions.has(action));
  const undeclaredDestinations = (observation.requests ?? []).map((request) => request.destination).filter((destination) => !allowedDestinations.has(destination));
  const shallow = observation.reachedMeaningfulState !== true;
  const blocked = undeclaredActions.length > 0 || undeclaredDestinations.length > 0 || observation.failedLaunch || observation.credentialsMissing;
  const status = blocked ? 'blocked' : observation.ready !== true || shallow ? 'unproven' : 'pass';
  return { schemaVersion: 1, kind: 'nemesis-runtime-receipt', provider: 'runtime.browser', surfaceId: spec.surfaceId, route: spec.route ?? null,
    state: observation.state ?? 'default', viewport: observation.viewport ?? null, locale: observation.locale ?? null, direction: observation.direction ?? null,
    status, complete: status === 'pass', shallow, undeclaredActions, undeclaredDestinations,
    console: redactValue(observation.console ?? []), requests: (observation.requests ?? []).map((request) => redactValue(request)),
    performance: observation.performance ?? null, processLifecycle: observation.processLifecycle ?? null, recovery: observation.recovery ?? null,
    coverageGaps: [observation.ready !== true ? 'readiness-unproven' : null, shallow ? 'shallow-traversal' : null].filter(Boolean), binding: spec.binding ?? {} };
}
