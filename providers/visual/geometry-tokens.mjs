function observedScale(instances) {
  const counts = new Map();
  for (const item of instances) counts.set(item.value, (counts.get(item.value) ?? 0) + 1);
  return [...counts].filter(([, count]) => count > 1).map(([value]) => value);
}

export function analyzeGeometryTokens({ instances = [], declaredScale = null, exceptions = [] } = {}) {
  const scale = declaredScale?.length ? declaredScale : observedScale(instances);
  const excepted = new Set(exceptions.map((item) => `${item.component}:${item.property}:${item.value}`));
  const affected = instances.filter((item) => scale.length && !scale.includes(item.value) && !excepted.has(`${item.component}:${item.property}:${item.value}`));
  const candidates = affected.map((item) => ({
    ruleId: 'visual.geometry-token-off-scale', value: item.value, property: item.property,
    denominator: instances.filter((candidate) => candidate.property === item.property).length,
    affectedInstances: [item], evidenceClass: item.rendered ? 'source+rendered' : 'source-only',
    scaleSource: declaredScale?.length ? 'declared' : 'observed-candidate',
  }));
  for (const item of instances) for (const [flag, ruleId] of Object.entries({ nestedRadiusConflict: 'visual.geometry-nested-radius', inconsistentPadding: 'visual.geometry-padding-drift', misalignedBaseline: 'visual.geometry-baseline-misalignment', ambiguousElevation: 'visual.geometry-elevation-order' })) {
    if (item[flag]) candidates.push({ ruleId, value: item.value, property: item.property, denominator: instances.filter((candidate) => candidate.property === item.property).length,
      affectedInstances: [item], evidenceClass: item.rendered ? 'source+rendered' : 'source-only', scaleSource: declaredScale?.length ? 'declared' : 'observed-candidate' });
  }
  return { provider: 'visual.geometry-tokens', status: candidates.length ? 'candidates' : scale.length ? 'pass' : 'unproven', complete: scale.length > 0,
    denominator: instances.length, scale, inventedStandard: false, candidates, coverageGaps: scale.length ? [] : ['declared-or-clustered-scale-missing'] };
}
