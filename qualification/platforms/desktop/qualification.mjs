export function qualifyDesktopPlatform({ targetId, fixtures = [] } = {}) {
  if (!Array.isArray(fixtures)) return { schemaVersion: 1, kind: 'legion-desktop-qualification', status: 'error', terminal: true, provisional: true, targetId, denominator: { total: 0, accounted: 0, missing: [] }, receipts: [], coverageGaps: ['fixtures-invalid'] };
  const ids = fixtures.map((item) => item.id);
  if (fixtures.length === 0) return { schemaVersion: 1, kind: 'legion-desktop-qualification', status: 'partial', terminal: true, provisional: true, claimLevel: 'source', targetId, denominator: { total: 0, accounted: 0, missing: [] }, receipts: [], coverageGaps: ['fixture-denominator-empty'] };
  const duplicates = [...new Set(ids.filter((id, index) => ids.indexOf(id) !== index))];
  const receipts = fixtures.filter((item) => item.targetId === targetId && item.family === 'desktop' && item.terminal === true);
  const present = new Set(receipts.map((item) => item.id));
  const missing = [...new Set(ids)].filter((id) => !present.has(id));
  const gaps = [...duplicates.map((id) => `fixture-duplicate:${id}`), ...missing.map((id) => `fixture-missing:${id}`), ...receipts.flatMap((item) => (item.coverageGaps ?? []).map((gap) => `${item.id}:${gap}`))];
  return { schemaVersion: 1, kind: 'legion-desktop-qualification', status: gaps.length ? 'partial' : 'pass', terminal: true, provisional: true, claimLevel: 'source', targetId,
    denominator: { total: new Set(ids).size, accounted: present.size, missing }, receipts, coverageGaps: [...new Set(gaps)].sort() };
}
