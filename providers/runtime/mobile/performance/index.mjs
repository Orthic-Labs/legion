const percentile = (values, rank) => values.length ? [...values].sort((a, b) => a - b)[Math.min(values.length - 1, Math.ceil(values.length * rank) - 1)] : null;
const REQUIRED_METRICS = Object.freeze(['cold-start', 'warm-start', 'resumed-start', 'interactive-time', 'responsiveness', 'memory', 'battery', 'thermal', 'network-per-session', 'binary-size', 'install-size']);
const REQUIRED_PROFILES = Object.freeze(['main-thread', 'idle-background', 'long-session', 'low-resource']);
const REQUIRED_ARTIFACT_INSPECTIONS = Object.freeze(['architecture-slices', 'resources-libraries', 'symbols-media-locales', 'delivery-update-size']);

export function assessMobilePerformance({ targetId = null, artifactDigest = null, measurements = [], budgets = {}, profiles = [], artifactInspection = {} } = {}) {
  const valid = measurements.filter((item) => item && Number.isFinite(item.value) && typeof item.metric === 'string');
  const physical = valid.filter((item) => item.tier === 'physical');
  const release = valid.filter((item) => item.buildType === 'release');
  const gaps = [];
  if (!physical.length) gaps.push('physical-device-measurement-missing');
  if (!release.length) gaps.push('release-build-measurement-missing');
  if (!physical.some((item) => item.metric === 'battery')) gaps.push('battery-measurement-missing');
  if (!physical.some((item) => item.metric === 'thermal')) gaps.push('thermal-measurement-missing');
  if (!artifactDigest) gaps.push('artifact-identity-missing');
  for (const metric of REQUIRED_METRICS) if (!valid.some((item) => item.metric === metric)) gaps.push(`metric-missing:${metric}`);
  for (const profile of REQUIRED_PROFILES) if (!profiles.includes(profile)) gaps.push(`profile-missing:${profile}`);
  for (const check of REQUIRED_ARTIFACT_INSPECTIONS) if (artifactInspection[check] !== true) gaps.push(`artifact-inspection-missing:${check}`);
  const metrics = Object.fromEntries([...new Set(valid.map((item) => item.metric))].sort().map((metric) => { const values = valid.filter((item) => item.metric === metric).map((item) => item.value); const worst = budgets[metric]?.direction === 'higher-is-better' ? Math.min(...values) : Math.max(...values); return [metric, { repeats: values.length, p50: percentile(values, .5), p95: percentile(values, .95), worst, budget: budgets[metric] ?? null }]; }));
  return { schemaVersion: 1, kind: 'nemesis-mobile-performance-evidence', targetId, artifactDigest, status: gaps.length ? 'partial' : 'pass', terminal: true,
    metrics, claims: { battery: gaps.includes('battery-measurement-missing') ? 'unproven' : 'measured', thermal: gaps.includes('thermal-measurement-missing') ? 'unproven' : 'measured', releaseArtifact: artifactDigest && release.length ? 'measured' : 'unproven' }, coverageGaps: gaps.sort() };
}
