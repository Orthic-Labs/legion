import { createHash } from 'node:crypto';
const portable=(value)=>String(value).replaceAll('\\','/').replace(/^\.\//,'').replace(/\/{2,}/g,'/');
const COMPONENT_KINDS=new Set(['ui','domain','api','identity','data','cache-search','queue-job','sync-offline','file-media','integration','notification','commerce','telemetry','admin-support','native-bridge-ipc','helper-sidecar','installer','updater','build-sign-release','infrastructure-dns','privacy','content-community','ai','documentation-legal','unknown-material-component']);
const RELATION_KINDS=new Set(['authenticates-through','calls','contains','controls','crosses-trust-boundary','depends-on','deploys','emits','installs','invokes','observes','queues','reads','routes-to','runs-on','trusts','updates','writes']);
export function componentId(kind, targetIds, evidence = []) { const identity=[kind,[...targetIds].sort(),[...evidence].map(portable).sort()];return `component:${createHash('sha256').update(JSON.stringify(identity)).digest('hex').slice(0,20)}`; }
export function component(kind, targetIds, evidencePaths, extra = {}) { return { id: componentId(kind, targetIds, evidencePaths), kind, targetIds:[...new Set(targetIds)].sort(), rootPaths:[...new Set(evidencePaths)].sort(),evidencePaths:[...new Set(evidencePaths)].sort(), classificationBasis: 'observed',runtimeBoundary:null,privilege:null,identity:null,dataClassIds:[],stackIds:[], external: false, trustBoundaries: [], ...extra }; }
export function validateComponentGraph(graph) {
  if((graph.relations??[]).length && (graph.relations??[]).every(({kind})=>kind==='contains'))throw new Error('folder containment cannot be only relation evidence');
  const ids=new Set();
  for(const value of graph.components??[]){if(!value.id)throw new Error('component requires id');if(!COMPONENT_KINDS.has(value.kind))throw new Error(`unknown component kind: ${value.kind}`);if(ids.has(value.id))throw new Error(`duplicate component ID: ${value.id}`);ids.add(value.id);}
  for(const relation of graph.relations??[]){if(!RELATION_KINDS.has(relation.kind))throw new Error(`unknown relation kind: ${relation.kind}`);if(!ids.has(relation.from)||!ids.has(relation.to))throw new Error(`relation endpoint is unknown: ${relation.from}->${relation.to}`);}
  return graph;
}
