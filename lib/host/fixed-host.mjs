// Injected host capabilities for the deterministic core. Core functions receive
// clock, randomness, filesystem facade, process runner, artifact store, and
// capability receipts; they never read process.argv or write arbitrary files.

export function fixedHost(overrides = {}) {
  let counter = 0;
  return {
    clock: { now: () => new Date('2026-08-06T00:00:00.000Z') },
    random: { uuid: () => `00000000-0000-4000-8000-${String(counter++).padStart(12, '0')}` },
    capabilities: {
      networkSandbox: { active: false, receipt: null },
      mutation: false,
      browser: false,
      signing: false,
      ...(overrides.capabilities ?? {}),
    },
    ...overrides,
  };
}
