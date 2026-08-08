// Patch effect graphs (B7-033).
//
// A proposal is only as trustworthy as the blast radius you can name. The
// effect graph maps a proposal to every file, symbol, configuration key, public
// surface, content item, design state, flow, runtime surface and security path
// it can move — then closes over the plan graph to say which providers and
// families must be re-run before anyone may apply it.

import { createHash } from 'node:crypto';

export const EFFECT_GRAPH_SCHEMA_VERSION = 1;

function sorted(values) {
  return [...new Set(values ?? [])].sort();
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function digestOf(value) {
  return `sha256:${createHash('sha256').update(`effect-graph\0${JSON.stringify(canonical(value))}`).digest('hex')}`;
}

function matchesPath(pattern, path) {
  if (pattern === path) return true;
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, ' ').replace(/\*/g, '[^/]*').replace(/ /g, '.*');
  return new RegExp(`^${escaped}$`).test(path);
}

/**
 * Transitive closure over the plan's provider dependency graph: a provider that
 * consumes an affected provider is itself affected.
 */
export function computeClosure(planGraph, seeds) {
  const providers = planGraph.providers ?? [];
  const closure = new Set(seeds);
  let grew = true;
  while (grew) {
    grew = false;
    for (const provider of providers) {
      if (closure.has(provider.id)) continue;
      if ((provider.dependsOn ?? []).some((id) => closure.has(id))) {
        closure.add(provider.id);
        grew = true;
      }
    }
  }
  return [...closure].sort();
}

function seedProviders(planGraph, changedFiles) {
  return (planGraph.providers ?? [])
    .filter((provider) => (provider.paths ?? []).some((pattern) => changedFiles.some((file) => matchesPath(pattern, file))))
    .map((provider) => provider.id);
}

export function buildEffectGraph({
  proposal,
  planGraph,
  binding,
  observedPublicSurfaceChanges = [],
  contentItems = [],
  designStates = [],
  flows = [],
  runtimeSurfaces = [],
  securityPaths = [],
  residualRisks = [],
}) {
  if (!proposal?.patch?.digest) throw new Error('an effect graph requires the proposal patch digest');
  const changedFiles = sorted(proposal.targetPaths);
  if (changedFiles.length === 0) throw new Error('an effect graph requires at least one target path');

  const changes = proposal.changes ?? [];
  const declaredPublicSurfaceChanges = sorted(proposal.publicSurfaceChanges);
  const observed = sorted(observedPublicSurfaceChanges);

  const affectedProviders = computeClosure(planGraph, seedProviders(planGraph, changedFiles));
  const providerById = new Map((planGraph.providers ?? []).map((provider) => [provider.id, provider]));

  const body = {
    schemaVersion: EFFECT_GRAPH_SCHEMA_VERSION,
    kind: 'nemesis-patch-effect-graph',
    proposalId: proposal.id,
    findingIds: sorted(proposal.findingIds),
    patchDigest: proposal.patch.digest,
    changedFiles,
    changedSymbols: sorted(changes.flatMap((change) => change.symbols ?? [])),
    changedConfig: sorted(changes.filter((change) => change.kind === 'config').flatMap((change) => (change.keyPath ? [change.keyPath.join('.')] : []))),
    publicSurfaceChanges: sorted([...declaredPublicSurfaceChanges, ...observed]),
    unplannedPublicSurfaceChanges: observed.filter((item) => !declaredPublicSurfaceChanges.includes(item)),
    contentItems: sorted([...contentItems, ...changes.flatMap((change) => (change.contentItemId ? [change.contentItemId] : []))]),
    designStates: sorted(designStates),
    flows: sorted(flows),
    affectedProviders,
    affectedFamilies: sorted(affectedProviders.map((id) => providerById.get(id)?.family).filter(Boolean)),
    requiredProviders: affectedProviders.filter((id) => providerById.get(id)?.requiredForCleanClaim === true),
    requiredGates: sorted((planGraph.baselineGates ?? []).filter((gate) => gate.requiredForApply).map((gate) => gate.id)),
    runtimeSurfaces: sorted(runtimeSurfaces),
    securityPaths: sorted(securityPaths),
    residualRisks: sorted(residualRisks),
    complete: true,
    binding,
  };
  return { ...body, digest: digestOf(body) };
}

/**
 * Application is blocked by a public-surface change nobody planned for.
 * Accepts both the current effect graph and the legacy patchEffectGraph shape.
 */
export function blocksAutoApply(effectGraph) {
  if (Array.isArray(effectGraph?.unplannedPublicSurfaceChanges)) {
    return effectGraph.unplannedPublicSurfaceChanges.length > 0;
  }
  return (effectGraph?.publicSurfaceChanges ?? []).length > 0;
}

export function buildEffectGraphSchema() {
  const strings = { type: 'array', items: { type: 'string' } };
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/remediation/effect-graph-v1.json',
    title: 'RemediationEffectGraphV1',
    type: 'object',
    required: [
      'schemaVersion', 'kind', 'proposalId', 'findingIds', 'patchDigest', 'changedFiles',
      'changedSymbols', 'changedConfig', 'publicSurfaceChanges', 'unplannedPublicSurfaceChanges',
      'contentItems', 'designStates', 'flows', 'affectedProviders', 'affectedFamilies',
      'requiredProviders', 'requiredGates', 'runtimeSurfaces', 'securityPaths', 'residualRisks',
      'complete', 'binding', 'digest',
    ],
    properties: {
      schemaVersion: { const: EFFECT_GRAPH_SCHEMA_VERSION },
      kind: { const: 'nemesis-patch-effect-graph' },
      proposalId: { type: 'string' },
      findingIds: strings,
      patchDigest: { type: 'string', pattern: '^sha256:' },
      changedFiles: { ...strings, minItems: 1 },
      changedSymbols: strings,
      changedConfig: strings,
      publicSurfaceChanges: strings,
      unplannedPublicSurfaceChanges: strings,
      contentItems: strings,
      designStates: strings,
      flows: strings,
      affectedProviders: strings,
      affectedFamilies: strings,
      requiredProviders: strings,
      requiredGates: strings,
      runtimeSurfaces: strings,
      securityPaths: strings,
      residualRisks: strings,
      complete: { type: 'boolean' },
      binding: { type: 'object' },
      digest: { type: 'string', pattern: '^sha256:' },
    },
    additionalProperties: false,
  };
}

// ---------------------------------------------------------------------------
// Pre-existing helper retained for its existing callers.
// ---------------------------------------------------------------------------

export function patchEffectGraph({ patchDigest, findingIds, changedFiles, changedSymbols, publicSurfaceChanges, affectedProviders, requiredTests, runtimeSurfaces, securityPaths, residualRisks }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-patch-effect-graph',
    patchDigest,
    findingIds: sorted(findingIds),
    changedFiles: sorted(changedFiles),
    changedSymbols: sorted(changedSymbols),
    publicSurfaceChanges: sorted(publicSurfaceChanges),
    affectedProviders: sorted(affectedProviders),
    requiredTests: sorted(requiredTests),
    runtimeSurfaces: sorted(runtimeSurfaces),
    securityPaths: sorted(securityPaths),
    residualRisks: sorted(residualRisks),
  };
}
