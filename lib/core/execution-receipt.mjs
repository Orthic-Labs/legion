import {createHash} from 'node:crypto';

export const SPAWN_STATUS=Object.freeze(['completed','missing-executable','timeout','output-limit','signal','failed-exit','malformed-output','spawn-error','probe-error','unsealed-executable','blocked']);
const sha=(bytes)=>`sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const emptyArtifact=(provider,stream)=>({path:`raw/${provider}.${stream}`,digest:sha(Buffer.alloc(0)),bytes:0,immutable:false,storageReceipt:null,redaction:{applied:false,metadata:[]}});
export function executionReceipt({provider,binding=null,denominatorDigest=null,command,startedAt,completedAt,spawnStatus,exitCode=null,signal=null,timedOut=false,stdoutArtifact=null,stderrArtifact=null,environmentKeys=[],sandboxReceipt=null,processTreeReceipt=null,tool=null,parsed=null,providerResult=null}){
  if(!provider||!SPAWN_STATUS.includes(spawnStatus))throw new TypeError('execution receipt provider and spawn status required');
  const coverage={...(providerResult?.coverage??{}),denominatorDigest:providerResult?.coverage?.denominatorDigest??denominatorDigest};
  const normalizedResult={...providerResult,provider:providerResult?.provider??provider,complete:providerResult?.complete===true,coverage};
  return{schemaVersion:1,kind:'nemesis-execution-result',provider,binding,denominatorDigest,complete:normalizedResult.complete,command:command??{executable:null,args:[],cwd:null},startedAt:startedAt??null,completedAt:completedAt??null,durationMs:startedAt!=null&&completedAt!=null?Number(completedAt)-Number(startedAt):null,spawnStatus,exitCode,signal,timedOut,stdoutArtifact:stdoutArtifact??emptyArtifact(provider,'stdout'),stderrArtifact:stderrArtifact??emptyArtifact(provider,'stderr'),environmentKeys,sandboxReceipt,processTreeReceipt,tool:tool??{status:'not-applicable',name:'internal-module',version:'1',probe:null,executableDigest:null},parsed,providerResult:normalizedResult};
}
export function blocked(spec,reason){return executionReceipt({provider:spec?.provider??'unknown',binding:spec?.binding??null,denominatorDigest:spec?.denominatorDigest??null,command:{executable:spec?.executable??null,args:spec?.args??[],cwd:spec?.cwd??null},spawnStatus:'blocked',environmentKeys:spec?.environmentKeys??[],providerResult:{provider:spec?.provider??'unknown',status:'blocked',complete:false,coverageGaps:[{kind:'execution-blocked',reason}]}});}
