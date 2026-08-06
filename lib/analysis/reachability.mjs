// Reachability joins. Dependency vulnerabilities are joined to compiler/SCIP/
// CodeQL/OpenGrep call evidence using categorical states. Missing graph
// evidence is never inferred as safe.

export const REACHABILITY_STATES = Object.freeze([
  'reachable',
  'possibly-reachable',
  'not-reached-in-observed-graph',
  'unknown',
]);

export function joinReachability({ vulnerability, callEvidence, graphScope }) {
  if (!callEvidence || callEvidence.length === 0) {
    // No observed graph coverage for this package/entrypoint: unknown, never safe.
    return { ...vulnerability, reachability: 'unknown', graphScope: graphScope ?? null, evidenceRefs: [] };
  }
  const reached = callEvidence.some((evidence) => evidence.reached === true);
  const possibly = callEvidence.some((evidence) => evidence.reached === 'possibly');
  if (reached) return { ...vulnerability, reachability: 'reachable', graphScope, evidenceRefs: callEvidence.map((e) => e.id ?? null).filter(Boolean) };
  if (possibly) return { ...vulnerability, reachability: 'possibly-reachable', graphScope, evidenceRefs: callEvidence.map((e) => e.id ?? null).filter(Boolean) };
  // Every observed call site was examined and none reached the vulnerable sink.
  return { ...vulnerability, reachability: 'not-reached-in-observed-graph', graphScope, evidenceRefs: callEvidence.map((e) => e.id ?? null).filter(Boolean) };
}

export function reachabilityGap({ packageName, graphScope, reason }) {
  return {
    kind: 'reachability-unproven',
    packageName,
    graphScope: graphScope ?? null,
    reason: reason ?? 'no call evidence in observed graph',
  };
}
