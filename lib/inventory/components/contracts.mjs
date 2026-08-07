import { createHash } from 'node:crypto';
export function componentId(kind, targetIds, evidence = []) { return `component:${createHash('sha256').update([kind,...targetIds,...evidence].sort().join('\0')).digest('hex').slice(0,20)}`; }
export function component(kind, targetIds, evidencePaths, extra = {}) { return { id: componentId(kind, targetIds, evidencePaths), kind, targetIds, evidencePaths, classificationBasis: 'observed', external: false, trustBoundaries: [], ...extra }; }
