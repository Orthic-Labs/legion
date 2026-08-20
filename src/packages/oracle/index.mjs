import * as canonicalCore from '../../lib/index.mjs';

export { translateLegacyReport } from './lib/facade.mjs';
export { canonicalJson, wrapArtifact } from './lib/artifact.mjs';
export { traceDiffBlastRadius } from './lib/blueprint-impact.mjs';

import { createOracle as createFacade } from './lib/facade.mjs';

export function createOracle(options = {}) {
  const core = options.core ?? canonicalCore;
  return createFacade({ ...options, core });
}

export const oracle = createOracle();
