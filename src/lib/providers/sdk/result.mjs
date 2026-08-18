import {createHash} from 'node:crypto';

const digest=(value)=>`sha256:${createHash('sha256').update(JSON.stringify(value??null)).digest('hex')}`;
const terminal=new Set(['pass','fail','partial','unproven','skipped','error','pending','missing','candidates','blocked']);

export function normalizeProviderResult(provider,result={}){
  const gaps=Array.isArray(result.coverageGaps)?result.coverageGaps:[];
  const requestedStatus=result.status==='measured'?'pass':result.status;
  const status=terminal.has(requestedStatus)?requestedStatus:'unproven';
  const complete=result.complete===true&&gaps.length===0&&['pass','fail','candidates'].includes(status);
  const denominator=result.denominator??result.coverage??{};
  const denominatorDigest=/^sha256:[a-f0-9]{64}$/.test(denominator.denominatorDigest??'')
    ?denominator.denominatorDigest:digest(denominator);
  return{
    schemaVersion:1,
    provider:provider.id,
    applicable:result.applicable!==false,
    required:result.required!==false,
    status:complete?status:'unproven',
    complete,
    coverage:{denominatorDigest,expected:Number.isInteger(denominator.expected)?denominator.expected:0,examined:Number.isInteger(denominator.examined)?denominator.examined:0},
    candidates:Array.isArray(result.candidates)?result.candidates:[],
    findings:Array.isArray(result.findings)?result.findings:[],
    coverageGaps:gaps,
    degradation:Array.isArray(result.degradation)?result.degradation:gaps,
    details:{family:provider.family,componentIds:result.componentIds??[],limitations:result.limitations??[],rawArtifacts:result.rawArtifacts??result.artifacts??[]}
  };
}
