const TIERS = new Set(['simulator', 'emulator', 'physical', 'device-farm', 'imported']);

const cleanupStep = async (fn, context) => {
  if (typeof fn !== 'function') return 'skipped';
  try { await fn(context); return 'pass'; } catch { return 'error'; }
};

export function createMobileDeviceAdapter({ id, tier, platform = null, exclusiveKey = null, operations = {}, metadata = {} } = {}) {
  if (!id || !TIERS.has(tier)) throw new TypeError('mobile device id and supported tier are required');
  return {
    capability: { id, tier, platform, exclusiveKey, simulated: tier === 'simulator' || tier === 'emulator', ...metadata },
    async execute({ target = {}, scenarioId = null, physicalOnly = false } = {}) {
      const binding = { deviceId: id, targetId: target.id ?? null, artifactDigest: target.artifactDigest ?? null,
        backendEnvironment: target.backendEnvironment ?? null, testAccountId: target.testAccountId ?? null };
      if (physicalOnly && tier !== 'physical') return { schemaVersion: 1, kind: 'nemesis-mobile-device-execution', status: 'blocked', terminal: true,
        tier, platform, binding, cleanup: {}, coverageGaps: [`physical-device-required:${scenarioId ?? 'unknown'}`] };
      const context = { id, tier, platform, exclusiveKey, target, scenarioId, binding };
      let status = 'pass'; let evidence = null; let error = null;
      const cleanup = {};
      try {
        if (typeof operations.acquire === 'function') await operations.acquire(context);
        if (typeof operations.install === 'function') await operations.install(context);
        evidence = typeof operations.execute === 'function' ? await operations.execute(context) : operations.receipt ?? null;
      } catch (cause) {
        status = 'fail'; error = cause?.code ?? cause?.message ?? 'device-execution-failed';
      } finally {
        cleanup.reset = await cleanupStep(operations.reset, context);
        cleanup.uninstall = await cleanupStep(operations.uninstall, context);
        cleanup.release = await cleanupStep(operations.release, context);
        if (Object.values(cleanup).includes('error') && status === 'pass') status = 'partial';
      }
      return { schemaVersion: 1, kind: 'nemesis-mobile-device-execution', status, terminal: true, tier, platform,
        simulated: tier === 'simulator' || tier === 'emulator', exclusiveKey, binding, evidence, error, cleanup,
        coverageGaps: status === 'pass' ? [] : [`device-execution-${status}:${scenarioId ?? 'unknown'}`] };
    },
  };
}
