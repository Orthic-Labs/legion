import { createHash } from 'node:crypto';
const id = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
export function discoverWebSurfaces({ artifacts = [], targetId, componentId } = {}) {
  const surfaces = artifacts.map((artifact) => ({ id: id([targetId, artifact.path, artifact.kind ?? 'page'].join('\0')), targetId, componentId: artifact.componentId ?? componentId ?? null, path: artifact.path, kind: artifact.kind ?? 'page', url: artifact.url ?? null, access: artifact.access ?? 'unknown', dynamic: artifact.dynamic === true, generated: artifact.generated === true }));
  return { schemaVersion: 1, kind: 'legion-web-surface-inventory', targetId, surfaces, complete: surfaces.every((item) => item.componentId), coverageGaps: surfaces.filter((item) => !item.componentId).map((item) => `component-unbound:${item.id}`) };
}
