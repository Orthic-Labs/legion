const stable=(value)=>JSON.stringify(value);
const allowed=(row,constraints)=>constraints.every((constraint)=>constraint(row));
export function pairwise(dimensions = {}, {constraints=[],mandatory=[]} = {}) {
  const keys=Object.keys(dimensions).sort();
  const values=Object.fromEntries(keys.map((key)=>[key,[...new Set(dimensions[key]??[])].sort((a,b)=>stable(a).localeCompare(stable(b)))]));
  for(const row of mandatory){const rowKeys=Object.keys(row).sort();if(stable(rowKeys)!==stable(keys)||keys.some((key)=>!values[key].some((value)=>stable(value)===stable(row[key]))))throw new TypeError('mandatory row must contain exactly one declared value for every dimension');}
  const witness=(fixed)=>{const row={...fixed};const remaining=keys.filter((key)=>!(key in row));const visit=(index)=>{if(index===remaining.length)return allowed(row,constraints)?{...row}:null;const key=remaining[index];for(const value of values[key]){row[key]=value;const found=visit(index+1);if(found)return found;}delete row[key];return null;};return visit(0);};
  const candidates=[],omitted=[];
  if(keys.length===1)for(const value of values[keys[0]]){const row={[keys[0]]:value};if(allowed(row,constraints))candidates.push(row);else omitted.push({row,reason:'constraint',mandatory:false});}
  for(let left=0;left<keys.length;left++)for(let right=left+1;right<keys.length;right++)for(const a of values[keys[left]])for(const b of values[keys[right]]){const pair={[keys[left]]:a,[keys[right]]:b};const row=witness(pair);if(row)candidates.push(row);else omitted.push({row:pair,reason:'constraint',mandatory:false});}
  for(const row of mandatory){if(allowed(row,constraints))candidates.push({...row});else omitted.push({row:{...row},reason:'constraint',mandatory:true});}
  const unique=[...new Map(candidates.map((row)=>[stable(row),row])).values()];
  const valid=unique;
  const uncovered=new Set();
  for(let left=0;left<keys.length;left++)for(let right=left+1;right<keys.length;right++)for(const a of values[keys[left]])for(const b of values[keys[right]])if(valid.some((row)=>row[keys[left]]===a&&row[keys[right]]===b))uncovered.add(stable([[keys[left],a],[keys[right],b]]));
  const rows=[];
  for(const required of mandatory)if(allowed(required,constraints)&&!rows.some((row)=>stable(row)===stable(required)))rows.push({...required});
  let pool=valid.filter((row)=>!rows.some((item)=>stable(item)===stable(row)));
  for(const row of rows)for(const pair of [...uncovered])if(JSON.parse(pair).every(([key,value])=>row[key]===value))uncovered.delete(pair);
  while(uncovered.size){let best=null,bestHits=[];for(const row of pool){const hits=[...uncovered].filter((pair)=>JSON.parse(pair).every(([key,value])=>row[key]===value));if(hits.length>bestHits.length){best=row;bestHits=hits;}}if(!best)break;rows.push(best);for(const hit of bestHits)uncovered.delete(hit);pool=pool.filter((row)=>row!==best);}
  if(keys.length===1)rows.push(...pool);
  rows.sort((a,b)=>stable(a).localeCompare(stable(b)));
  Object.defineProperties(rows,{rows:{value:rows},omitted:{value:omitted},complete:{value:uncovered.size===0&&!omitted.some(({mandatory})=>mandatory)},uncovered:{value:[...uncovered]},candidateCount:{value:rows.length}});
  return rows;
}
