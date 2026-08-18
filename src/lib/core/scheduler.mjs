function equalDependencies(left,right){return JSON.stringify([...left].sort())===JSON.stringify([...right].sort());}
export function providerDependencies(provider){
  if(provider.dependencies&&provider.dependsOn&&!equalDependencies(provider.dependencies,provider.dependsOn))throw new TypeError(`provider ${provider.id} dependency fields disagree`);
  const dependencies=provider.dependencies??provider.dependsOn??[];
  if(!Array.isArray(dependencies)||dependencies.some((id)=>typeof id!=='string'))throw new TypeError(`provider ${provider.id} dependencies must be string IDs`);
  return [...new Set(dependencies)];
}

export function scheduleProviders(providers = [], { mode = 'auto', concurrency = 4, resources = null } = {}) {
  const normalized=providers.map((provider)=>({...provider,dependencies:providerDependencies(provider)}));
  const ids=new Set();for(const {id}of normalized){if(ids.has(id))throw new TypeError(`duplicate provider ID: ${id}`);ids.add(id);}
  const blocked=new Map();
  const block=(id,reason)=>{if(!blocked.has(id))blocked.set(id,{id,reason});};
  for(const provider of normalized)for(const dependency of provider.dependencies)if(!ids.has(dependency))block(provider.id,`unknown-dependency:${dependency}`);
  const propagate=()=>{let changed;do{changed=false;for(const provider of normalized)if(!blocked.has(provider.id)){const dependency=provider.dependencies.find((id)=>blocked.has(id));if(dependency){block(provider.id,`dependency-blocked:${dependency}`);changed=true;}}}while(changed);};
  propagate();
  if(!resources&&blocked.size)throw new TypeError([...blocked.values()][0].reason);
  const remaining=new Map(normalized.filter(({id})=>!blocked.has(id)).map((provider)=>[provider.id,provider]));
  const done=new Set();const waves=[];
  while(remaining.size){
    const ready=[...remaining.values()].filter((provider)=>provider.dependencies.every((id)=>done.has(id))).sort((a,b)=>a.id.localeCompare(b.id));
    if(!ready.length){if(!resources)throw new TypeError('provider dependency cycle');for(const id of remaining.keys())block(id,'dependency-cycle');break;}
    const wave=[];const used={};const locks=new Set();
    for(const provider of ready){
      const claims=Object.entries(provider.resources??{});
      const impossible=resources&&claims.some(([name,amount])=>typeof amount!=='number'||amount<0||amount>(resources[name]??Infinity));
      if(impossible){block(provider.id,'resource-ceiling');continue;}
      if(wave.length>=concurrency||(mode==='serial'&&wave.length))continue;
      if(provider.concurrencyKey&&locks.has(provider.concurrencyKey))continue;
      const fits=!resources||claims.every(([name,amount])=>(used[name]??0)+amount<=(resources[name]??Infinity));
      if(!fits)continue;
      wave.push(provider.id);if(provider.concurrencyKey)locks.add(provider.concurrencyKey);
      for(const[name,amount]of claims)used[name]=(used[name]??0)+amount;
    }
    for(const id of blocked.keys())remaining.delete(id);propagate();for(const id of blocked.keys())remaining.delete(id);
    if(!wave.length){if(!resources)throw new TypeError('scheduler cannot make progress');for(const {id}of ready)block(id,'resource-ceiling');propagate();break;}
    waves.push(wave);for(const id of wave){remaining.delete(id);done.add(id);}
  }
  if(!resources)return waves;
  const result={admitted:waves[0]??[],ready:waves.slice(1).flat(),blocked:[...blocked.values()].sort((a,b)=>a.id.localeCompare(b.id)),waves};
  result[Symbol.iterator]=function*(){yield* result.waves;};return result;
}
