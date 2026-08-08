import { fileDigest } from './release-manifest.mjs';

export function cyclonedxSbom({ components = [], serialNumber = null } = {}) {
  const normalized = components.map((component) => ({
    type: component.type ?? 'library', name: component.name, version: component.version,
    licenses: component.license ? [{ license: { id: component.license } }] : [],
    hashes: component.path && fileDigest(component.path) ? [{ alg: 'SHA-256', content: fileDigest(component.path).slice(7) }] : [],
  }));
  if (!normalized.length) throw new Error('SBOM cannot be empty');
  return { bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber, version: 1, components: normalized };
}

export function spdxSbom({ name, components = [] } = {}) {
  if (!name || !components.length) throw new Error('SPDX SBOM needs a package name and components');
  return { SPDXID: 'SPDXRef-DOCUMENT', spdxVersion: 'SPDX-2.3', name, dataLicense: 'CC0-1.0', packages: components };
}

export function generateSboms({ name, components = [], serialNumber = null } = {}) {
  return { cyclonedx: cyclonedxSbom({ components, serialNumber }), spdx: spdxSbom({ name, components }) };
}

export function inventoryRuntimeDependencies({ packageManifest = {}, provenance = {} } = {}) {
  return Object.entries(packageManifest.dependencies ?? {}).sort(([a], [b]) => a.localeCompare(b)).map(([name, version]) => ({
    type: 'library', name, version, source: provenance[name]?.source ?? 'npm', digest: provenance[name]?.digest ?? null,
    license: provenance[name]?.license ?? null, shipped: true, distributionStatus: provenance[name]?.distributionStatus ?? 'integrated',
  }));
}

export function inventoryDistribution({ runtime = [], externalTools = [], grammars = [], ruleMaterial = [], creatorMaterial = [] } = {}) {
  return [...runtime, ...externalTools, ...grammars, ...ruleMaterial, ...creatorMaterial]
    .map((component) => ({
      type: component.type ?? 'library', name: component.name, version: component.version ?? null,
      source: component.source ?? null, digest: component.digest ?? null, license: component.license ?? null,
      shipped: component.shipped === true, distributionStatus: component.distributionStatus ?? 'reference-only',
      redistributionGrant: component.redistributionGrant ?? null,
    }))
    .sort((a, b) => `${a.type}:${a.name}`.localeCompare(`${b.type}:${b.name}`));
}

export function reconcileDistributionContents(components = [], packageContents = []) {
  const shipped = components.filter(({ shipped }) => shipped);
  const content = new Set(packageContents.map((entry) => typeof entry === 'string' ? entry : entry.name));
  const blockers = shipped.flatMap((component) => {
    const missing = [];
    if (!content.has(component.name)) missing.push({ kind: 'shipped-component-absent', component: component.name });
    if (!component.digest || !component.license || !component.source) missing.push({ kind: 'component-metadata-incomplete', component: component.name });
    if (component.source === 'external' && component.redistributionGrant !== true) missing.push({ kind: 'redistribution-right-unresolved', component: component.name });
    return missing;
  });
  return { components: shipped, blockers, decision: blockers.length ? 'BLOCKED' : 'QUALIFIED' };
}
