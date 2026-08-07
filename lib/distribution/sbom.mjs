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
