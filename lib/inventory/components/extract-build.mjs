import { component } from './contracts.mjs';
export function extractBuildComponents({ portfolio, projection = {} }) { return (projection.buildOutputs ?? []).map((output) => component('build-sign-release', portfolio.targets.map((target) => target.id), [output.path ?? output])); }
