import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateDesktopPerformance, executeDesktopPerformance, PERFORMANCE_CASES } from '../../../../providers/runtime/desktop/performance/index.mjs';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const releaseArtifact = { build: 'release', digest: DIGEST };
const fullEnv = { os: 'windows-11', hardware: 'fixture-x64', hardwareClass: 'desktop', cpuCores: 8, ramMb: 16384, diskType: 'nvme', profilingTool: 'perfetto', energyBudgetMw: 15000 };

const fullMeasurement = (id) => ({
  id, unit: 'ms', samples: [10, 11, 12], percentiles: { p95: 12 },
  budget: 100, variance: 1, profileArtifact: `profiles/${id}.json`, durationSeconds: 300,
});

const fullSoak = { status: 'pass', hours: 10, durationMinutes: 600, budgetExceeded: false };

test('B4-021 binds measurements to release artifact, environment, repeats & soak', () => {
  const result = evaluateDesktopPerformance({
    artifact: releaseArtifact, environment: fullEnv,
    measurements: [fullMeasurement('cold-start'), fullMeasurement('idle-memory')],
    soak: { status: 'unavailable', requestedHours: 8, capabilityGap: 'long-duration-host-unavailable' },
  });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.includes('soak-long-duration-host-unavailable'));
  assert.equal(result.measurements[0].repeatCount, 3);
});

test('B4-021 executes required measurement/soak cases through host', async () => {
  const host = {
    measure: async ({ id, budget }) => ({ id, unit: 'ms', samples: [1, 2, 3], percentiles: { p95: 3 }, budget, variance: 1, profileArtifact: `profiles/${id}.json`, durationSeconds: 60 }),
    soak: async () => ({ status: 'pass', hours: 10, durationMinutes: 600, budgetExceeded: false }),
  };
  const budgets = Object.fromEntries(PERFORMANCE_CASES.map((id) => [id, 10]));
  const result = await executeDesktopPerformance({ host, artifact: releaseArtifact, environment: fullEnv, budgets });
  assert.equal(result.status, 'pass');
  assert.equal(result.denominator.accounted, PERFORMANCE_CASES.length);
  assert.equal(result.denominator.hardwareClass, 'desktop');
});

test('B4-021 refuses source or debug build performance claims', () => {
  const result = evaluateDesktopPerformance({ artifact: { build: 'debug' }, environment: {}, measurements: [] });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.includes('release-artifact-unproven'));
});

test('B4-021 requires budgets, profiling artifacts, variance & long soak duration', () => {
  const result = evaluateDesktopPerformance({
    artifact: releaseArtifact, environment: { os: 'windows', hardware: 'x64' },
    measurements: [{ id: 'cold-start', unit: 'ms', samples: [1, 2, 3], percentiles: { p95: 3 } }],
    soak: { status: 'pass', hours: 4, durationMinutes: 240, budgetExceeded: false },
  });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.includes('soak-duration-incomplete'));
  assert.ok(result.coverageGaps.includes('measurement-budget-missing:cold-start'));
});

test('B4-021 requires hardware class, spec, profiling tool, energy budget & duration per measurement', () => {
  const result = evaluateDesktopPerformance({
    artifact: releaseArtifact, environment: { os: 'windows', hardware: 'x64' },
    measurements: [fullMeasurement('cold-start')],
    soak: fullSoak,
  });
  assert.ok(result.coverageGaps.includes('hardware-class-missing'));
  assert.ok(result.coverageGaps.includes('hardware-spec-incomplete'));
  assert.ok(result.coverageGaps.includes('profiling-tool-missing'));
  assert.ok(result.coverageGaps.includes('energy-budget-missing'));
});

test('B4-021 soak denominator tracks duration, budget, and hardware context', () => {
  const result = evaluateDesktopPerformance({
    artifact: releaseArtifact, environment: fullEnv,
    measurements: PERFORMANCE_CASES.map(fullMeasurement),
    soak: fullSoak,
  });
  assert.equal(result.status, 'pass');
  assert.equal(result.denominator.total, PERFORMANCE_CASES.length);
  assert.equal(result.denominator.profilingTool, 'perfetto');
});

test('B4-021 all 13 performance cases (duration, low-end, fault) are required', () => {
  assert.ok(PERFORMANCE_CASES.includes('duration'));
  assert.ok(PERFORMANCE_CASES.includes('low-end'));
  assert.ok(PERFORMANCE_CASES.includes('fault'));
  assert.equal(PERFORMANCE_CASES.length, 13);
  const result = evaluateDesktopPerformance({
    artifact: releaseArtifact, environment: fullEnv,
    measurements: PERFORMANCE_CASES.filter((id) => id !== 'fault').map(fullMeasurement),
    soak: fullSoak,
  });
  assert.ok(result.coverageGaps.includes('measurement-case-missing:fault'));
});