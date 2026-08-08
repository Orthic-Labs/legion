const NETWORK_CASES = Object.freeze(['wifi-cellular-handoff', 'airplane-mode', 'vpn', 'proxy', 'captive-portal', 'invalid-certificate', 'hostname-mismatch', 'slow-tls', 'high-latency', 'packet-loss', 'low-bandwidth', 'ipv6-only', 'timeout', 'provider-outage', 'offline-online']);
const STORAGE_CASES = Object.freeze(['credentials', 'database', 'preferences', 'files', 'cache', 'logs', 'web-storage', 'backup', 'clipboard', 'app-switcher-snapshot']);

export function planMobileDataNetwork({ actorId = null, supportedSchemaVersions = [] } = {}) {
  const scenarios = [
    ...NETWORK_CASES.map((id) => ({ id: `network:${id}`, family: 'network', actorId, invariants: ['bounded-retry', 'request-cancellation', 'idempotent-effect', 'auth-refresh-race-safe'], status: 'unproven' })),
    { id: 'sync:offline-replay', family: 'sync', actorId, invariants: ['actor-scoped-queue', 'ordered-replay', 'expired-operation-dropped', 'optimistic-rollback', 'conflict-resolution', 'logout-clears-queue', 'unsynced-state-visible'], status: 'unproven' },
    ...STORAGE_CASES.map((id) => ({ id: `storage:${id}`, family: 'storage', actorId, requiresPlatformEvidence: true, invariants: ['account-isolation', 'sensitive-data-protected'], status: 'unproven' })),
    ...supportedSchemaVersions.map((version) => ({ id: `migration:${version}-to-current`, family: 'migration', fromVersion: version, invariants: ['preserve-user-data', 'interrupt-safe', 'corruption-bounded'], status: 'unproven' })),
    { id: 'pressure:low-disk-memory', family: 'pressure', actorId, invariants: ['preserve-user-data', 'orphan-cleanup', 'bounded-streaming'], status: 'unproven' },
    { id: 'cache:unchanged-content', family: 'cache', actorId, invariants: ['reuse-validated-content', 'bounded-growth'], status: 'unproven' },
  ];
  return { schemaVersion: 1, kind: 'nemesis-mobile-data-network-plan', status: 'unproven', terminal: true, actorId, scenarios,
    denominator: { total: scenarios.length, accounted: scenarios.length }, coverageGaps: scenarios.map((item) => `${item.id}:device-execution-missing`) };
}
