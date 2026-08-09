import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {isAbsolute} from 'node:path';
import {createOutputCollector} from './output-limit.mjs';
import {qualifyTool} from './tool-identity.mjs';

const DEFAULT_ALLOWED=new Set(['node','git','tsc','eslint','python3','python','ruff','cargo','go','dotnet','opengrep','ast-grep','sg','osv-scanner','gitleaks','syft','trivy','swift','clang','gcc','cmake','mvn','gradle','php','composer','ruby','bundle']);
const digest=(bytes)=>`sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const providerResult=(provider,status,complete,coverageGaps=[])=>({schemaVersion:1,provider,applicable:true,required:true,status,complete,coverage:{denominatorDigest:digest(Buffer.from(provider))},candidates:[],findings:[],coverageGaps,degradation:complete?[]:coverageGaps});
export function pickEnvironment(env,keys=[]){return Object.fromEntries(keys.filter((key)=>env[key]!==undefined).map((key)=>[key,env[key]]));}
const artifact=(provider,stream,bytes,storageReceipt=null)=>({path:`raw/${provider}.${stream}`,digest:digest(bytes),bytes:bytes.byteLength,immutable:storageReceipt?.immutable===true,storageReceipt,redaction:{applied:false,metadata:[]}});
export function blocked(spec,reason,state='blocked'){
  const empty=Buffer.alloc(0);const provider=spec?.provider??'process';
  return{schemaVersion:1,kind:'legion-execution-result',provider:spec?.provider??null,complete:false,command:{executable:spec?.executable??null,args:spec?.args??[],cwd:spec?.cwd??null},spawnStatus:state,exitCode:null,signal:null,timedOut:false,stdoutArtifact:artifact(provider,'stdout',empty),stderrArtifact:artifact(provider,'stderr',empty),environmentKeys:spec?.environmentKeys??[],tool:{status:'missing-executable',name:spec?.executable??null,version:null,probe:null,executableDigest:null},providerResult:providerResult(provider,state==='blocked'?'blocked':'unproven',false,[{kind:state,reason}])};
}
function execute(spec,env,host){return new Promise((resolve)=>{let child;let timer;let timedOut=false;let outputLimited=false;let settled=false;const hardKill=()=>host.processTree?.hardKill?host.processTree.hardKill(child.pid):child?.kill();const stdout=createOutputCollector(spec.maxOutputBytes??8388608,()=>{outputLimited=true;void hardKill();});const stderr=createOutputCollector(spec.maxOutputBytes??8388608,()=>{outputLimited=true;void hardKill();});const finish=(value)=>{if(settled)return;settled=true;clearTimeout(timer);resolve({...value,stdout:stdout.value(),stderr:stderr.value(),timedOut,outputLimited});};try{child=spawn(spec.executable,spec.args??[],{cwd:spec.cwd,env,shell:false,windowsHide:true,stdio:['ignore','pipe','pipe']});}catch(error){finish({error});return;}child.stdout.on('data',(chunk)=>stdout.push(chunk));child.stderr.on('data',(chunk)=>stderr.push(chunk));child.on('error',(error)=>finish({error}));child.on('close',(code,signal)=>finish({code,signal}));timer=setTimeout(()=>{timedOut=true;void hardKill();},spec.timeoutMs??120000);});}
export async function runExternal(spec,host={}){
  if(spec.shell===true)throw new Error('shell execution is forbidden');
  if(spec.projectExecution===true&&(host.capabilities?.networkSandbox?.active!==true||!host.capabilities.networkSandbox.receipt))return blocked(spec,'network-sandbox-receipt-missing');
  const allowed=host.allowedExecutables??DEFAULT_ALLOWED;
  if(!allowed.has(spec.executable))return blocked(spec,'executable-not-allowlisted');
  if(!isAbsolute(spec.executable))return blocked(spec,'executable-bytes-not-sealed','unsealed-executable');
  const environment=pickEnvironment(host.env??{},spec.environmentKeys??[]);
  const tool=await qualifyTool({executable:spec.executable,versionArgs:spec.versionArgs??['--version'],cwd:spec.cwd,env:environment,timeoutMs:Math.min(spec.timeoutMs??120000,5000)});
  if(tool.status==='missing-executable')return{...blocked(spec,'missing-executable','missing-executable'),tool};
  if(tool.status!=='available'||!tool.executableDigest)return{...blocked(spec,tool.status==='available'?'executable-digest-missing':tool.status,tool.status==='available'?'unsealed-executable':tool.status),tool};
  if(spec.executableDigest&&spec.executableDigest!==tool.executableDigest)return{...blocked(spec,'executable-digest-mismatch','unsealed-executable'),tool};
  const startedAt=host.clock?.now?.()??0;const result=await execute(spec,environment,host);const completedAt=host.clock?.now?.()??startedAt;
  if(result.error)return{...blocked(spec,result.error.code??result.error.message,result.error.code==='ENOENT'?'missing-executable':'spawn-error'),tool};
  let spawnStatus=result.outputLimited?'output-limit':result.timedOut?'timeout':result.code===null?'signal':result.code===0?'completed':'failed-exit';let parsed=null;
  if(spawnStatus==='completed'&&spec.parseOutput){try{parsed=spec.parseOutput(result.stdout);}catch{spawnStatus='malformed-output';}}
  const processComplete=spawnStatus==='completed';const outputLimited=spawnStatus==='output-limit';const gaps=processComplete?[]:[{kind:outputLimited?'execution-output-limit':spawnStatus}];const provider=spec.provider??'process';
  const stdoutPath=`raw/${provider}.stdout`;const stderrPath=`raw/${provider}.stderr`;const stdoutStorage=typeof host.artifactStore?.writeBytes==='function'?await host.artifactStore.writeBytes(stdoutPath,result.stdout,{immutable:true,digest:digest(result.stdout)}):null;const stderrStorage=typeof host.artifactStore?.writeBytes==='function'?await host.artifactStore.writeBytes(stderrPath,result.stderr,{immutable:true,digest:digest(result.stderr)}):null;const sealedOutputs=stdoutStorage?.immutable===true&&stderrStorage?.immutable===true;const sealedTree=Boolean(host.processTree?.hardKill&&host.processTree?.receipt);if(!sealedOutputs)gaps.push({kind:'immutable-raw-output-unavailable'});if(!sealedTree)gaps.push({kind:'process-tree-hard-kill-unavailable'});const complete=processComplete&&sealedOutputs&&sealedTree;
  return{schemaVersion:1,kind:'legion-execution-result',provider:spec.provider??null,complete,command:{executable:spec.executable,args:spec.args??[],cwd:spec.cwd??null},startedAt,completedAt,durationMs:completedAt-startedAt,spawnStatus,exitCode:result.code??null,signal:result.signal??null,timedOut:result.timedOut,stdoutArtifact:artifact(provider,'stdout',result.stdout,stdoutStorage),stderrArtifact:artifact(provider,'stderr',result.stderr,stderrStorage),environmentKeys:spec.environmentKeys??[],sandboxReceipt:host.capabilities?.networkSandbox?.receipt??null,processTreeReceipt:host.processTree?.receipt??null,tool,parsed,providerResult:providerResult(provider,complete?'pass':outputLimited?'partial':'unproven',complete,gaps)};
}
