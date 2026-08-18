import { discoverTargets } from '../inventory/product-targets/detectors/index.mjs';
import { buildPortfolio } from '../inventory/product-targets/build-portfolio.mjs';
import { extractComponents } from '../inventory/components/build-graph.mjs';
import { buildStackGraph } from '../inventory/stacks/build-graph.mjs';
import { discoverExternalSystems } from '../inventory/external-systems/discover.mjs';
import { buildJourneys } from '../inventory/journeys/build.mjs';
import { loadControlPacks } from '../controls/packs/registry.mjs';
import { compileBaseline } from '../controls/baseline/compile.mjs';
import { evidenceCapabilities } from '../controls/evidence/capabilities.mjs';
import { capabilityImpacts } from '../controls/evidence/impacts.mjs';
import { compileScenarios } from '../controls/scenarios/compile.mjs';
import { mergeReleaseContract } from '../inventory/release-contract/merge.mjs';
import { buildProductContext } from '../inventory/product-context/actors.mjs';
import { digest } from './binding.mjs';
import { fileURLToPath } from 'node:url';

const ROOT=fileURLToPath(new URL('../..',import.meta.url));

export async function inspectProduct(options, host) {
  const candidates = await discoverTargets(options.projection ?? {}, options);
  let portfolio = buildPortfolio({ candidates, declarations: options.declarations ?? [],relations:options.targetRelations??[],conflicts:options.targetConflicts??[], materialDeliverables: options.projection?.buildOutputs ?? [], binding: options.binding ?? null });
  const components = extractComponents({ portfolio, projection: options.projection ?? {}, binding: options.binding ?? null });
  const stacks = buildStackGraph({ portfolio, components, projection: options.projection ?? {}, binding: options.binding ?? null });
  const targets=portfolio.targets.map((target)=>{const value={...target,componentIds:components.components.filter(({targetIds=[]})=>targetIds.includes(target.id)).map(({id})=>id).sort(),stackIds:stacks.stacks.filter(({targetIds=[]})=>targetIds.includes(target.id)).map(({id})=>id).sort()};delete value.digest;return{...value,digest:digest(value)};});const portfolioValue={...portfolio,targets};delete portfolioValue.digest;portfolio={...portfolioValue,digest:digest(portfolioValue)};
  const externalSystems = discoverExternalSystems({ projection: options.projection ?? {}, components, binding: options.binding ?? null });
  const releaseContract=options.releaseContract?.kind==='legion-release-contract'?options.releaseContract:mergeReleaseContract({...options.releaseContract,binding:options.binding??null});
  const productContext=buildProductContext(options.projection??{},releaseContract);
  const journeys=buildJourneys({portfolio,contract:releaseContract,projection:options.projection??{},binding:options.binding??null});
  const packs=options.packs??await loadControlPacks(ROOT);
  const baseline=compileBaseline({packs,portfolio,components,stacks:stacks.stacks,contract:options.releaseContract??{},binding:options.binding??null});
  const capabilities=evidenceCapabilities({...host,binding:options.binding??host?.binding??null});
  const claimImpact=capabilityImpacts(baseline,capabilities);
  const scenarios=compileScenarios({baseline,journeys:journeys.journeys,capabilities,binding:options.binding??null,dimensions:{environment:releaseContract.environments,role:releaseContract.roles,platform:releaseContract.supportedPlatforms}});
  const gaps=[...(releaseContract.missingDeclarations??[]).map((field)=>({kind:'release-contract-missing',field})),...(productContext.gaps??[]),...(journeys.gaps??[]),...(stacks.coverage.unknownStacks??[]).map((id)=>({kind:'unknown-stack',id}))];const reportSkeleton={targetIds:portfolio.targets.map(({id})=>id),componentIds:components.components.map(({id})=>id),stackIds:stacks.stacks.map(({id})=>id),externalSystemIds:externalSystems.systems.map(({id})=>id),controlIds:baseline.controls.map(({id})=>id),scenarioIds:scenarios.scenarios.map(({id})=>id),gaps};
  return { schemaVersion: 1, kind: 'legion-product-inspection', portfolio, components, stacks, externalSystems,releaseContract,productContext, journeys, baseline, capabilities, claimImpact, scenarios,reportSkeleton };
}
