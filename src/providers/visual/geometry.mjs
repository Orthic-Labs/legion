import { intersectBounds } from '../../lib/design/geometry.mjs';

export function analyzeGeometryEvidence({ surfaceId, viewport, elements = [], tolerances = {}, intentionalOverlaps = [] } = {}) {
  const findings = [];
  const coverageGaps = [];
  const intentional = new Set(intentionalOverlaps.map((pair) => [...pair].sort().join(':')));
  const measurable = elements.filter((item) => !item.primitive);
  for (const element of elements) {
    if (['canvas', 'webgl', 'cross-origin'].includes(element.primitive)) coverageGaps.push(`unsupported-geometry:${element.id}:${element.primitive}`);
    if (!Number.isFinite(element.x) || !Number.isFinite(element.width)) continue;
    const overflowRight = Math.max(0, element.x + element.width - viewport.width - (tolerances.overflow ?? 0));
    const overflowBottom = Math.max(0, element.y + element.height - viewport.height - (tolerances.overflow ?? 0));
    if (overflowRight || overflowBottom) findings.push({ ruleId: 'visual.geometry-viewport-overflow', surfaceId, elementId: element.id, measurement: { overflowRight, overflowBottom }, sourceComponent: element.sourceComponent ?? null });
    if (element.clippedText) findings.push({ ruleId: 'visual.geometry-clipped-text', surfaceId, elementId: element.id, measurement: { bounds: { x: element.x, y: element.y, width: element.width, height: element.height } }, sourceComponent: element.sourceComponent ?? null });
    if (element.focusable && (overflowRight || overflowBottom || element.x < 0 || element.y < 0)) findings.push({ ruleId: 'visual.geometry-offscreen-focus', surfaceId, elementId: element.id, measurement: { x: element.x, y: element.y, overflowRight, overflowBottom }, sourceComponent: element.sourceComponent ?? null });
    const minimumTouch = tolerances.minimumTouchTarget ?? 24;
    if (element.touchTarget && (element.width < minimumTouch || element.height < minimumTouch)) findings.push({ ruleId: 'visual.geometry-touch-target', surfaceId, elementId: element.id, measurement: { width: element.width, height: element.height, minimum: minimumTouch }, sourceComponent: element.sourceComponent ?? null });
    if (Number.isFinite(element.layoutShift) && element.layoutShift > (tolerances.layoutShift ?? 0)) findings.push({ ruleId: 'visual.geometry-layout-shift', surfaceId, elementId: element.id, measurement: { layoutShift: element.layoutShift, tolerance: tolerances.layoutShift ?? 0 }, sourceComponent: element.sourceComponent ?? null });
  }
  for (const region of tolerances.protectedRegions ?? []) for (const element of measurable.filter((item) => item.fixed)) {
    const overlap = intersectBounds(region, element); if (overlap) findings.push({ ruleId: 'visual.geometry-protected-region', surfaceId, elementId: element.id, regionId: region.id ?? null, measurement: overlap });
  }
  for (let left = 0; left < measurable.length; left += 1) for (let right = left + 1; right < measurable.length; right += 1) {
    const a = measurable[left]; const b = measurable[right]; const overlap = intersectBounds(a, b); const key = [a.id, b.id].sort().join(':');
    if (overlap && !intentional.has(key) && (a.control || b.control)) findings.push({ ruleId: 'visual.geometry-control-overlap', surfaceId, elementIds: [a.id, b.id], measurement: overlap });
  }
  return { provider: 'visual.geometry', status: findings.length ? 'candidates' : coverageGaps.length ? 'unproven' : 'pass', findings, coverageGaps, tolerances };
}
