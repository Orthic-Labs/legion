// Patch effect graph per SNIP-EFFECT-GRAPH-01. Maps finding → patch → affected
// symbols/contracts/public surfaces → tests/runtime/security evidence →
// residual risk.

export function patchEffectGraph({ patchDigest, findingIds, changedFiles, changedSymbols, publicSurfaceChanges, affectedProviders, requiredTests, runtimeSurfaces, securityPaths, residualRisks }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-patch-effect-graph',
    patchDigest,
    findingIds: [...(findingIds ?? [])].sort(),
    changedFiles: [...(changedFiles ?? [])].sort(),
    changedSymbols: [...(changedSymbols ?? [])].sort(),
    publicSurfaceChanges: [...(publicSurfaceChanges ?? [])].sort(),
    affectedProviders: [...(affectedProviders ?? [])].sort(),
    requiredTests: [...(requiredTests ?? [])].sort(),
    runtimeSurfaces: [...(runtimeSurfaces ?? [])].sort(),
    securityPaths: [...(securityPaths ?? [])].sort(),
    residualRisks: [...(residualRisks ?? [])].sort(),
  };
}

export function blocksAutoApply(effectGraph) {
  // Unplanned public-surface changes block automated apply.
  return (effectGraph.publicSurfaceChanges ?? []).length > 0;
}
