const DIGEST = /^sha256:[a-f0-9]{64}$/;

export const PERFORMANCE_CASES = Object.freeze([
  'cold-start',
  'first-usable',
  'input',
  'background-job',
  'memory-idle',
  'memory-peak',
  'cpu-wakeups',
  'gpu-fallback',
  'disk-network',
  'energy',
  'duration',
  'low-end',
  'fault',
]);

const environmentGaps = (environment = {}) => {
  const gaps = [];
  if (!environment.os || !environment.hardware) gaps.push('measurement-environment-incomplete');
  if (!environment.hardwareClass) gaps.push('hardware-class-missing');
  if (!(environment.cpuCores >= 1) || !(environment.ramMb >= 1) || !environment.diskType) gaps.push('hardware-spec-incomplete');
  if (!environment.profilingTool) gaps.push('profiling-tool-missing');
  if (!Number.isFinite(environment.energyBudgetMw)) gaps.push('energy-budget-missing');
  return gaps;
};

const measurementEvidence = (item) => {
  const id = item.id ?? 'unknown';
  const gaps = [];
  const samples = Array.isArray(item.samples) ? item.samples.filter(Number.isFinite) : [];
  if (!item.id || !item.unit || samples.length < 3 || !Number.isFinite(item.percentiles?.p95)) gaps.push(`measurement-incomplete:${id}`);
  if (!Number.isFinite(item.budget) || !item.profileArtifact || !Number.isFinite(item.variance)) gaps.push(`measurement-budget-missing:${id}`);
  if (!(item.durationSeconds >= 1)) gaps.push(`measurement-duration-missing:${id}`);
  return { gaps, samples, repeatCount: samples.length };
};

export function evaluateDesktopPerformance({ artifact = {}, environment = {}, measurements = [], soak = null } = {}) {
  const gaps = environmentGaps(environment);
  if (artifact.build !== 'release' || !DIGEST.test(artifact.digest ?? '')) gaps.push('release-artifact-unproven');
  const normalized = measurements.map((item) => {
    const evidence = measurementEvidence(item);
    gaps.push(...evidence.gaps);
    return { ...item, samples: evidence.samples, repeatCount: evidence.repeatCount };
  });
  if (!measurements.length) gaps.push('measurement-denominator-empty');
  for (const id of PERFORMANCE_CASES) if (!measurements.some((item) => item.id === id)) gaps.push(`measurement-case-missing:${id}`);
  if (!soak) gaps.push('soak-evidence-missing');
  else if (soak.status === 'pass' && !(soak.hours >= 8)) gaps.push('soak-duration-incomplete');
  else if (soak.status !== 'pass') gaps.push(`soak-${soak.capabilityGap ?? soak.status ?? 'unproven'}`);
  const coverageGaps = [...new Set(gaps)].sort();
  return {
    schemaVersion: 1,
    kind: 'nemesis-desktop-performance',
    status: coverageGaps.length ? (coverageGaps.every((gap) => gap.startsWith('soak-')) ? 'partial' : 'unproven') : 'pass',
    terminal: true,
    artifact,
    environment,
    measurements: normalized,
    soak,
    denominator: {
      total: PERFORMANCE_CASES.length,
      accounted: normalized.length,
      hardwareClass: environment.hardwareClass ?? null,
      profilingTool: environment.profilingTool ?? null,
      soakHours: soak?.hours ?? null,
      budgetExceeded: soak?.budgetExceeded ?? null,
    },
    coverageGaps,
  };
}

export async function executeDesktopPerformance({ host, artifact, environment, budgets = {} } = {}) {
  if (!host?.measure || !host?.soak) return evaluateDesktopPerformance({ artifact, environment });
  const measurements = [];
  for (const id of PERFORMANCE_CASES) measurements.push(await host.measure({ id, budget: budgets[id] }));
  return evaluateDesktopPerformance({ artifact, environment, measurements, soak: await host.soak({ minimumHours: 8 }) });
}
