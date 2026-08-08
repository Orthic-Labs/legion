// Injected host capabilities for the deterministic core. Core functions receive
// clock, randomness, filesystem facade, process runner, artifact store, and
// capability receipts; they never read process.argv or write arbitrary files.

export function fixedHost(overrides = {}) {
  let counter = 0;
  return {
    ...overrides,
    clock: overrides.clock ?? { now: () => new Date('2026-08-06T00:00:00.000Z') },
    random: overrides.random ?? { uuid: () => `00000000-0000-4000-8000-${String(counter++).padStart(12, '0')}` },
    filesystem: overrides.filesystem ?? { state:'unavailable',receipt:null },
    processRunner: overrides.processRunner ?? { state:'unavailable',receipt:null },
    artifactStore: overrides.artifactStore ?? { state:'unavailable',receipt:null },
    reviewer: overrides.reviewer ?? { state:'unavailable',receipt:null },
    allowedExecutables: overrides.allowedExecutables ?? new Set(),
    capabilities: {
      networkSandbox: { active: false, receipt: null },
      mutation: false,
      browser: false,
      signing: false,
      filesystem:{active:false,receipt:null},process:{active:false,receipt:null},artifact:{active:false,receipt:null},reviewer:{active:false,receipt:null},
      ...(overrides.capabilities ?? {}),
    },
  };
}
