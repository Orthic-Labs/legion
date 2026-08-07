import { component } from './contracts.mjs';
export function extractRuntimeComponents({ portfolio, projection = {} }) { return (projection.entrypoints ?? []).map((item) => component('helper-sidecar', portfolio.targets.map((target) => target.id), [item.path ?? item])); }
