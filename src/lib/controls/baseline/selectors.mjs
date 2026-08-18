const KEYS=new Set(['op','targetKinds','componentKinds','facets','stackIds','environments','policyFlags']);
const overlap=(required,observed)=>!required||required.every((value)=>observed.includes(value));
export function matchesSelector(selector = {}, { target, component, stacks = [], contract = {} } = {}) {
  for(const key of Object.keys(selector))if(!KEYS.has(key))throw new Error(`unknown selector key: ${key}`);
  if(selector.op&&selector.op!=='always')throw new Error(`unknown selector operation: ${selector.op}`);
  if (selector.op === 'always') return true;
  if (selector.targetKinds && !selector.targetKinds.includes(target?.kind)) return false;
  if (selector.componentKinds && !selector.componentKinds.includes(component?.kind)) return false;
  if (selector.facets && !selector.facets.some((facet) => target?.facets?.includes(facet))) return false;
  if(!overlap(selector.stackIds,stacks.map(({id})=>id)))return false;
  if(!overlap(selector.environments,contract.environments??[]))return false;
  if(!overlap(selector.policyFlags,contract.policyFlags??[]))return false;
  return true;
}
