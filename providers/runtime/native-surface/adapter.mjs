export function buildNativeSurfaceReceipt(spec = {}, observation = {}) {
  const allowed = new Set(spec.allowedActions ?? []);
  const undeclaredActions = (observation.actions ?? []).filter((action) => !allowed.has(action));
  const blocked = observation.bridgeAvailable === false || observation.failedLaunch || undeclaredActions.length > 0;
  const shallow = observation.reachedMeaningfulState !== true;
  const status = blocked ? 'blocked' : observation.ready !== true || shallow ? 'unproven' : 'pass';
  return { schemaVersion: 1, kind: 'legion-runtime-receipt', provider: 'runtime.native-surface', surfaceId: spec.surfaceId, state: observation.state ?? 'default',
    status, complete: status === 'pass', shallow, undeclaredActions, processLifecycle: observation.processLifecycle ?? null, resourceUse: observation.resourceUse ?? null,
    recovery: observation.recovery ?? null, coverageGaps: [observation.bridgeAvailable === false ? 'native-bridge-unavailable' : null, shallow ? 'shallow-traversal' : null].filter(Boolean), binding: spec.binding ?? {} };
}
