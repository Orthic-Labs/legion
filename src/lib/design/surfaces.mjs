import { createHash } from 'node:crypto';
const id = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

export function buildSurfaceInventory({ artifacts = [], binding = {} } = {}) {
  const surfaces = artifacts.map((artifact) => ({ id: id([artifact.file, artifact.route ?? '', artifact.type ?? 'surface'].join('\0')), file: artifact.file,
    route: artifact.route ?? null, type: artifact.type ?? 'surface', framework: artifact.framework ?? null, states: artifact.states ?? ['default'],
    controls: artifact.controls ?? [], protectedRegions: artifact.protectedRegions ?? [], runtimeEligible: artifact.runtimeEligible !== false,
    visibility: artifact.visibility ?? 'user-facing' }));
  return { schemaVersion: 1, kind: 'legion-surface-inventory', binding, surfaces, denominatorDigest: id(JSON.stringify(surfaces)), complete: artifacts.every((artifact) => artifact.file), coverageGaps: artifacts.filter((artifact) => !artifact.file).map(() => 'surface-source-missing') };
}
