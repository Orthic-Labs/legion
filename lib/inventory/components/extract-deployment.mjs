import { component } from './contracts.mjs';
export function extractDeploymentComponents({ portfolio, projection = {} }) { return (projection.deployments ?? []).map((item) => component('infrastructure-dns', portfolio.targets.map((target) => target.id), [item.path ?? item])); }
