// Policy-selected subgroup/fairness evaluation. Fairness metrics are only
// ever computed over subgroups a policy has explicitly named — an absent or
// empty policy selection is not "no disparity found", it is "not evaluated",
// so it must score unproven rather than pass.

function unproven(reason) {
  return { verdict: 'unproven', measurement: {}, limitations: [reason], uncertainty: [] };
}

export function scoreSubgroupFairness(fixture) {
  const subgroups = fixture?.policySelectedSubgroups;
  const threshold = fixture?.parityThreshold;
  if (!Array.isArray(subgroups) || subgroups.length === 0) {
    return unproven('no policy-selected subgroup set recorded for this run; fairness is not applicable without an explicit policy selection');
  }
  if (typeof threshold !== 'number') return unproven('no parity threshold recorded for this run');
  const values = subgroups.map((s) => s.metricValue);
  const gap = Math.max(...values) - Math.min(...values);
  return {
    verdict: gap <= threshold ? 'pass' : 'fail',
    measurement: { subgroupCount: subgroups.length, gap, threshold, subgroups: subgroups.map((s) => s.name).sort() },
    limitations: [],
    uncertainty: ['Only the policy-selected subgroups and metric are evaluated; subgroups outside the policy selection are out of scope for this receipt.'],
  };
}
