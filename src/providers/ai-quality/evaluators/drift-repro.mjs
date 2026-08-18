// Model/provider/version drift and reproducibility.

function unproven(reason) {
  return { verdict: 'unproven', measurement: {}, limitations: [reason], uncertainty: [] };
}

export function scoreModelProviderVersionDrift(fixture) {
  const { baselineVersion, currentVersion, baselineScore, currentScore, driftThreshold } = fixture ?? {};
  if (typeof baselineScore !== 'number' || typeof currentScore !== 'number') {
    return unproven('no baseline/current score record recorded for this run');
  }
  const threshold = driftThreshold ?? 0.05;
  const delta = Math.abs(currentScore - baselineScore);
  return {
    verdict: delta <= threshold ? 'pass' : 'fail',
    measurement: { baselineVersion: baselineVersion ?? null, currentVersion: currentVersion ?? null, baselineScore, currentScore, delta, threshold },
    limitations: [],
    uncertainty: ['A single aggregate score delta can mask distributional drift on a specific eval slice.'],
  };
}

export function scoreReproducibility(fixture) {
  const runDigests = fixture?.runDigests;
  if (!Array.isArray(runDigests) || runDigests.length < 2) return unproven('fewer than 2 recorded run digests; reproducibility cannot be evaluated');
  const distinct = new Set(runDigests);
  return {
    verdict: distinct.size === 1 ? 'pass' : 'fail',
    measurement: { runCount: runDigests.length, distinctOutputCount: distinct.size },
    limitations: [],
    uncertainty: ['Digest equality checks exact-output reproducibility, not semantic equivalence across runs.'],
  };
}
