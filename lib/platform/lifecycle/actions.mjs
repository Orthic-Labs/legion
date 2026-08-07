import { requireCapability } from '../contracts.mjs';

const ACTIONS = new Set(['launch', 'foreground', 'background', 'suspend', 'resume', 'restart', 'terminate', 'install', 'uninstall', 'update', 'rollback']);

export async function runLifecycleAction({ action, adapter, capability, targetId, binding = {}, destructive = false } = {}) {
  if (!ACTIONS.has(action)) return lifecycleReceipt({ action, targetId, binding, status: 'blocked', coverageGaps: ['lifecycle-action-unsupported'] });
  const permitted = requireCapability(capability, { destructive });
  if (!permitted.ok) return lifecycleReceipt({ action, targetId, binding, status: 'blocked', coverageGaps: [permitted.reason] });
  if (typeof adapter?.[action] !== 'function') return lifecycleReceipt({ action, targetId, binding, status: 'unproven', coverageGaps: ['lifecycle-adapter-missing'] });
  try {
    const observed = await adapter[action]();
    return lifecycleReceipt({ action, targetId, binding, status: observed?.status ?? 'pass', observed, coverageGaps: observed?.coverageGaps ?? [] });
  } catch (error) {
    return lifecycleReceipt({ action, targetId, binding, status: 'error', errors: [{ name: error?.name ?? 'Error', message: error?.message ?? String(error) }], coverageGaps: ['lifecycle-action-error'] });
  }
}

export function lifecycleReceipt(input = {}) {
  return { schemaVersion: 1, kind: 'nemesis-lifecycle-receipt', action: input.action ?? null, targetId: input.targetId ?? null,
    binding: input.binding ?? {}, status: input.status ?? 'unproven', observed: input.observed ?? null, errors: input.errors ?? [], coverageGaps: input.coverageGaps ?? [] };
}
