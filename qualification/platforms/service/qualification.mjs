export function qualifyServicePlatform({ receipts = [], fixtures = [] } = {}) {
  const rows = fixtures.map((fixture) => ({ id: fixture.id, expected: fixture.expected, actual: receipts.find((item) => item.id === fixture.id)?.status ?? 'unproven' }));
  const coverageGaps = rows.filter((item) => item.actual !== item.expected).map((item) => `fixture-mismatch:${item.id}:${item.expected}:${item.actual}`);
  return { schemaVersion: 1, kind: 'nemesis-service-platform-qualification', status: coverageGaps.length ? 'partial' : 'pass', terminal: true, provisional: true,
    denominator: { total: rows.length, accounted: rows.length }, fixtures: rows, coverageGaps };
}
