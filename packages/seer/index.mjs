import * as canonicalCore from '../../lib/index.mjs';

export { translateLegacyReport } from './lib/facade.mjs';
export { canonicalJson, wrapArtifact } from './lib/artifact.mjs';
export { traceDiffBlastRadius } from './lib/cortex-impact.mjs';

import { createSeer as createFacade } from './lib/facade.mjs';

export function createSeer(options = {}) {
  const core = options.core ?? canonicalCore;
  return createFacade({ ...options, core });
}

export const seer = createSeer();
