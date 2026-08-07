export function compileWebMatrix({ policy = {}, capabilities = [] } = {}) {
  const available = new Set(capabilities.filter((item) => item.status === 'available').map((item) => item.id));
  const expected = policy.combinations ?? (policy.browsers ?? []).flatMap((browser) => (policy.viewports ?? ['desktop']).map((viewport) => ({ browser, viewport })));
  const combinations = expected.map((item) => ({ ...item, status: available.has(item.browser) ? 'pending' : 'unproven' }));
  return { schemaVersion: 1, kind: 'nemesis-web-runtime-matrix', combinations, complete: combinations.every((item) => item.status !== 'unproven'), coverageGaps: combinations.filter((item) => item.status === 'unproven').map((item) => `browser-unavailable:${item.browser}`) };
}
