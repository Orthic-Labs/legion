import { baselineCompatibility, baselineIdentity } from '../../lib/design/baselines.mjs';

export function compareVisualEvidence({ baseline = null, actual = null, pixel = null, perceptual = null, geometry = null, text = null, masks = [] } = {}) {
  if (!baseline) return { provider: 'visual.diff', status: 'unproven', baselineAccepted: false, coverageGaps: ['baseline-missing'], components: {} };
  if (baseline.stale) return { provider: 'visual.diff', status: 'unproven', baselineAccepted: false, coverageGaps: ['baseline-stale'], components: {} };
  const compatibility = baselineCompatibility(baseline, actual ?? {});
  if (!compatibility.compatible) return { provider: 'visual.diff', status: 'unproven', baselineAccepted: false, coverageGaps: compatibility.mismatches.map((key) => `environment-mismatch:${key}`), components: {} };
  const approvedMasks = new Set((baseline.approvedMasks ?? []).map((mask) => mask.id));
  const unapprovedMasks = masks.filter((mask) => !mask.id || !approvedMasks.has(mask.id));
  if (unapprovedMasks.length) return { provider: 'visual.diff', status: 'unproven', baselineAccepted: false, coverageGaps: ['dynamic-mask-unapproved'], components: {} };
  const components = { pixel, perceptual, geometry, text };
  if (!Object.values(components).some((component) => component !== null)) return { provider: 'visual.diff', status: 'unproven', baselineAccepted: false, baselineIdentity: baselineIdentity(baseline), masks, components: {}, coverageGaps: ['comparison-components-missing'] };
  const changed = Object.values(components).some((component) => component && (component.changed > 0 || component.changedPixels > 0 || component.status === 'changed'));
  return { provider: 'visual.diff', status: changed ? 'candidates' : 'pass', baselineAccepted: false, baselineIdentity: baselineIdentity(baseline), masks, components, coverageGaps: [] };
}
