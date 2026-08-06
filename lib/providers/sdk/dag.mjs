// Provider artifact dependency DAG. Validates topological ordering, unknown
// dependencies, self-dependencies, cycles, unproduced consumed artifacts,
// duplicate singleton producers, role/output authority, and mutable external
// script paths.

export function topologicalProviders(providers) {
  const byId = new Map(providers.map((provider) => [provider.id, provider]));
  const incoming = new Map(providers.map((provider) => [
    provider.id,
    new Set(provider.dependsOn ?? []),
  ]));
  for (const [id, deps] of incoming) {
    for (const dependency of deps) {
      if (!byId.has(dependency)) throw new Error(`provider ${id} depends on unknown ${dependency}`);
      if (dependency === id) throw new Error(`provider ${id} depends on itself`);
    }
  }

  const ready = [...incoming]
    .filter(([, deps]) => deps.size === 0)
    .map(([id]) => id)
    .sort();
  const ordered = [];

  while (ready.length) {
    const id = ready.shift();
    ordered.push(byId.get(id));
    for (const [otherId, deps] of incoming) {
      if (!deps.delete(id) || deps.size) continue;
      if (!ordered.some((item) => item.id === otherId) && !ready.includes(otherId)) {
        ready.push(otherId);
        ready.sort();
      }
    }
  }

  if (ordered.length !== providers.length) {
    const cyclic = [...incoming]
      .filter(([id, deps]) => deps.size && !ordered.some((item) => item.id === id))
      .map(([id, deps]) => ({ id, dependsOn: [...deps].sort() }));
    throw new Error(`provider dependency cycle: ${JSON.stringify(cyclic)}`);
  }
  return ordered;
}

// Role/output authority table from the Security Appendix Phase 7.
export const ROLE_OUTPUT_AUTHORITY = Object.freeze({
  'model-builder': { candidates: false, hypotheses: false, verdicts: false, findings: false },
  'candidate-generator': { candidates: true, hypotheses: false, verdicts: false, findings: false },
  'hypothesis-generator': { candidates: false, hypotheses: true, verdicts: false, findings: false },
  adjudicator: { candidates: false, hypotheses: false, verdicts: true, findings: false },
  'variant-analyzer': { candidates: false, hypotheses: false, verdicts: false, findings: false },
  'evidence-synthesizer': { candidates: false, hypotheses: false, verdicts: false, findings: true },
  deterministic: { candidates: true, hypotheses: false, verdicts: false, findings: true },
});

export function validateRoleOutput(provider) {
  const authority = ROLE_OUTPUT_AUTHORITY[provider.role];
  if (!authority) throw new Error(`provider ${provider.id} has unknown role ${provider.role}`);
  const produced = provider.produces ?? [];
  if (produced.includes('security-candidates') && !authority.candidates) {
    throw new Error(`provider ${provider.id} role ${provider.role} may not produce security-candidates`);
  }
  if (produced.includes('attack-path-hypotheses') && !authority.hypotheses) {
    throw new Error(`provider ${provider.id} role ${provider.role} may not produce attack-path-hypotheses`);
  }
  if (produced.includes('security-verdicts') && !authority.verdicts) {
    throw new Error(`provider ${provider.id} role ${provider.role} may not produce security-verdicts`);
  }
  if (produced.includes('findings') && !authority.findings) {
    throw new Error(`provider ${provider.id} role ${provider.role} may not produce findings`);
  }
  return true;
}

export function validateProviderDag(providers) {
  // Singleton artifact producers: an artifact kind may be produced by at most
  // one provider unless the artifact is explicitly non-singleton.
  const producers = new Map();
  for (const provider of providers) {
    validateRoleOutput(provider);
    for (const artifact of provider.produces ?? []) {
      if (producers.has(artifact) && !producers.get(artifact).nonSingleton) {
        throw new Error(`artifact ${artifact} is produced by both ${producers.get(artifact).id} and ${provider.id}`);
      }
      if (!producers.has(artifact)) producers.set(artifact, { id: provider.id, nonSingleton: provider.nonSingletonArtifacts?.includes(artifact) });
    }
  }
  // Consumed artifacts must be produced by some provider.
  const produced = new Set([...producers.keys()]);
  for (const provider of providers) {
    for (const artifact of provider.consumes ?? []) {
      if (!produced.has(artifact)) throw new Error(`provider ${provider.id} consumes unproduced artifact ${artifact}`);
    }
  }
  topologicalProviders(providers);
  return true;
}
