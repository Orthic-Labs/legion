export function qualifyMobilePlatform({ targetId = null, platform = null, fixtures = [] } = {}) {
  const coverageGaps = [];
  const receipts = [];
  let total = 0;
  for (const fixture of fixtures) {
    for (const control of fixture.controls ?? []) {
      total += 1;
      const candidates = (fixture.receipts ?? []).filter((item) => item.controlId === control.id && item.terminal === true);
      const satisfying = candidates.find((item) => item.status === 'pass' && (control.requiredTier !== 'physical' || item.tier === 'physical'));
      if (!satisfying) coverageGaps.push(control.requiredTier === 'physical' ? `physical-control-unproven:${control.id}` : `${control.requiredTier}-control-unproven:${control.id}`);
      receipts.push({ fixtureId: fixture.id, platform: fixture.platform, controlId: control.id, requiredTier: control.requiredTier, status: satisfying ? 'pass' : 'unproven', terminal: true });
    }
  }
  const platformStatus = (name) => { const rows = receipts.filter((item) => item.platform === name); return rows.length && rows.every((item) => item.status === 'pass') ? 'pass' : rows.some((item) => item.status === 'pass') ? 'partial' : 'unproven'; };
  return { schemaVersion: 1, kind: 'legion-mobile-platform-qualification', targetId, platform, status: coverageGaps.length ? 'partial' : 'pass', terminal: true, provisional: true, claimLevel: 'source',
    targets: { ios: { status: platformStatus('ios') }, android: { status: platformStatus('android') } }, receipts,
    denominator: { total, accounted: receipts.length }, coverageGaps: [...new Set(coverageGaps)].sort() };
}
