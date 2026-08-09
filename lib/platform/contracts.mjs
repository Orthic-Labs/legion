import { createHash } from 'node:crypto';

export const PLATFORM_CAPABILITY_STATUS = Object.freeze(['available', 'unavailable', 'unsupported', 'permission-denied', 'stale', 'partial']);
export const SCENARIO_STATUS = Object.freeze(['pass', 'fail', 'partial', 'unproven', 'blocked', 'error']);
export const sha256 = (value) => `sha256:${createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex')}`;

export function capabilityReceipt(input = {}) {
  const status = input.status ?? 'unavailable';
  if (!PLATFORM_CAPABILITY_STATUS.includes(status)) throw new Error(`unknown platform capability status: ${status}`);
  return { schemaVersion: 1, kind: 'legion-platform-capability', id: input.id, status, isolation: input.isolation ?? null,
    resourceClaims: input.resourceClaims ?? {}, concurrencyKey: input.concurrencyKey ?? null,
    destructiveActionsAllowed: input.destructiveActionsAllowed === true, binding: input.binding ?? {}, checkedAt: input.checkedAt ?? null,
    limitations: input.limitations ?? [], receipt: input.receipt ?? null };
}

export function terminalScenarioReceipt(input = {}) {
  const status = input.status ?? 'unproven';
  if (!SCENARIO_STATUS.includes(status)) throw new Error(`unknown scenario status: ${status}`);
  const steps = input.steps ?? [];
  return { schemaVersion: 1, kind: 'legion-platform-scenario-receipt', scenarioId: input.scenarioId,
    targetId: input.targetId, status, terminal: true, binding: input.binding ?? {}, preState: input.preState ?? null,
    expectedInvariant: input.expectedInvariant ?? null, observedState: input.observedState ?? null, durableState: input.durableState ?? null,
    steps, errors: input.errors ?? [], recovery: input.recovery ?? null, artifacts: input.artifacts ?? [], coverageGaps: input.coverageGaps ?? [] };
}

export function requireCapability(capability, operation) {
  if (!capability || capability.status !== 'available') return { ok: false, reason: `capability-${capability?.status ?? 'missing'}`, operation };
  if (operation.destructive && capability.destructiveActionsAllowed !== true) return { ok: false, reason: 'destructive-action-forbidden', operation };
  return { ok: true };
}
