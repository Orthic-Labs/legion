import { discoverTargets } from '../inventory/product-targets/detectors/index.mjs';
import { buildPortfolio } from '../inventory/product-targets/build-portfolio.mjs';
import { extractComponents } from '../inventory/components/build-graph.mjs';
import { buildStackGraph } from '../inventory/stacks/build-graph.mjs';
import { discoverExternalSystems } from '../inventory/external-systems/discover.mjs';

export async function inspectProduct(options, host) {
  const candidates = await discoverTargets(options.projection ?? {}, options);
  const portfolio = buildPortfolio({ candidates, declarations: options.declarations ?? [], binding: options.binding ?? null });
  const components = extractComponents({ portfolio, projection: options.projection ?? {}, binding: options.binding ?? null });
  const stacks = buildStackGraph({ portfolio, components, projection: options.projection ?? {}, binding: options.binding ?? null });
  const externalSystems = discoverExternalSystems({ projection: options.projection ?? {}, components, binding: options.binding ?? null });
  return { schemaVersion: 1, kind: 'nemesis-product-inspection', portfolio, components, stacks, externalSystems };
}
