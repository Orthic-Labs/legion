import { digest } from '../../core/binding.mjs';
import { component, validateComponentGraph } from './contracts.mjs';
import { extractPhysicalComponents } from './extract-build.mjs';
import { extractLogicalComponents } from './extract-logical.mjs';
import { extractDeploymentComponents } from './extract-deployment.mjs';
import { extractRuntimeComponents } from './extract-runtime.mjs';

const pathOf=(item)=>item.path??item;
export function extractComponents({ portfolio, projection = {}, binding = null }) {
  const input={portfolio,projection};const candidates=[...extractPhysicalComponents(input),...extractLogicalComponents(input),...extractDeploymentComponents(input),...extractRuntimeComponents(input)];
  const files=(projection.files??[]).map(pathOf);const ui=files.filter((path)=>/next\.config|vite\.config|react|views?|pages?|components?/i.test(path));if(ui.length)candidates.push(component('ui',portfolio.targets.map(({id})=>id),ui));
  return buildComponentGraph({portfolio,candidates,relations:projection.componentRelations??[],binding,expectedEntrypoints:(projection.entrypoints??[]).length,expectedOutputs:(projection.buildOutputs??[]).length,expectedStores:(projection.dataStores??[]).length,expectedExternalSystems:(projection.externalSystems??projection.externalEndpoints??[]).length,expectedReleaseMechanisms:(projection.releaseMechanisms??[]).length});
}
export function buildComponentGraph({portfolio,candidates=[],relations=[],binding=null,expectedEntrypoints=0,expectedOutputs=0,expectedStores=0,expectedExternalSystems=0,expectedReleaseMechanisms=0}) {
  const targetIds=new Set((portfolio.targets??[]).map(({id})=>id));
  const byId=new Map();for(const candidate of candidates){for(const targetId of candidate.targetIds??[])if(!targetIds.has(targetId))throw new Error(`unknown target for component ${candidate.id}: ${targetId}`);const prior=byId.get(candidate.id);if(prior&&JSON.stringify(prior)!==JSON.stringify(candidate))throw new Error(`component ID collision: ${candidate.id}`);byId.set(candidate.id,candidate);}
  const components=[...byId.values()].sort((a,b)=>a.id.localeCompare(b.id));const normalizedRelations=[...relations].sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
  const coveredTargets=new Set(components.flatMap(({targetIds=[]})=>targetIds));
  const value={schemaVersion:1,kind:'legion-component-graph',components,relations:normalizedRelations,binding,coverage:{expectedTargets:(portfolio.targets??[]).length,coveredTargets:coveredTargets.size,expectedEntrypoints,expectedOutputs,expectedStores,expectedExternalSystems,expectedReleaseMechanisms,coveredStores:components.filter(({kind})=>['data','cache-search','file-media'].includes(kind)).length,coveredExternalSystems:components.filter(({external})=>external).length,coveredReleaseMechanisms:components.filter(({kind})=>['installer','updater','build-sign-release','infrastructure-dns'].includes(kind)).length,unknownComponents:components.filter(({kind})=>kind==='unknown-material-component').map(({id})=>id),relationConfidence:normalizedRelations.map(({confidence='unknown'})=>confidence)}};
  validateComponentGraph(value);return{...value,digest:digest(value)};
}
