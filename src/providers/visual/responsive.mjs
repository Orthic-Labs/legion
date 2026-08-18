export function analyzeResponsive({ surfaces = [], requiredViewports = [] } = {}) {
  const tested = new Set(surfaces.map((item) => item.viewport));
  const coverageGaps = requiredViewports.filter((viewport) => !tested.has(viewport)).map((viewport) => `viewport-untested:${viewport}`);
  if (!surfaces.length) coverageGaps.push('responsive-surfaces-missing');
  const findings = [];
  for (const surface of surfaces) {
    if (surface.safeAreaMeasured !== true) coverageGaps.push(`safe-area-unmeasured:${surface.id}:${surface.viewport}`);
    for (const [condition, ruleId] of [['overflowX', 'visual.responsive-horizontal-overflow'], ['clipped', 'visual.responsive-clipped-content'], ['offscreenControl', 'visual.responsive-offscreen-control'], ['fixedChromeOverlap', 'visual.responsive-fixed-overlap'], ['unsafeProtectedRegion', 'visual.responsive-protected-region'], ['missingMobileAlternative', 'visual.responsive-mobile-alternative-missing']]) {
      if (surface[condition]) findings.push({ ruleId, surfaceId: surface.id, viewport: surface.viewport, state: surface.state ?? 'default', evidenceClass: surface.geometry ? 'rendered' : 'source-heuristic' });
    }
  }
  return { provider: 'visual.responsive', status: findings.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass', findings, coverageGaps, testedViewports: [...tested] };
}
