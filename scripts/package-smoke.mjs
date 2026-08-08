import { execFileSync } from 'node:child_process';
import { cpSync,existsSync,mkdtempSync,readdirSync,readFileSync,rmSync,statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename,dirname,join,resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export function packageSmokeContract(){return['binary','library-import','cortex-projection','plan','schedule','serial-execution','auto-execution','audit','verify'];}
const walk=(root,current=root,out=[])=>{for(const name of readdirSync(current)){const path=join(current,name);if(statSync(path).isDirectory())walk(root,path,out);else out.push(path);}return out;};
export async function runPackageSmoke(root=resolve(import.meta.dirname,'..')){
  const pkg=JSON.parse(readFileSync(join(root,'package.json'),'utf8'));const manifest=JSON.parse(readFileSync(join(root,'MANIFEST.package.json'),'utf8'));const temp=mkdtempSync(join(tmpdir(),'nemesis-package-smoke-'));const assembled=join(temp,'package');
  try{
    for(const entry of pkg.files){const source=join(root,entry);if(!existsSync(source))throw new Error(`package entry missing: ${entry}`);const target=join(assembled,entry);cpSync(source,target,{recursive:true});}
    const files=walk(assembled);let forbiddenMarkers=0;for(const path of files){if(basename(path)==='MANIFEST.package.json'||!/\.(?:mjs|js|json|md|txt|ya?ml)$/i.test(path))continue;const text=readFileSync(path,'utf8');for(const marker of manifest.forbiddenContentMarkers)if(text.includes(marker))forbiddenMarkers++;}
    if(forbiddenMarkers)throw new Error(`assembled package contains ${forbiddenMarkers} forbidden markers`);
    const version=execFileSync(process.execPath,[join(assembled,pkg.bin.nemesis),'--version'],{cwd:assembled,encoding:'utf8'}).trim();if(version!==pkg.version)throw new Error('assembled binary version mismatch');
    const library=await import(`${pathToFileURL(join(assembled,'lib/index.mjs')).href}?smoke=${Date.now()}`);if(typeof library.buildPlan!=='function'||typeof library.reconcileRun!=='function')throw new Error('assembled library exports incomplete');
    const {loadPrecomputedProjection}=await import(pathToFileURL(join(assembled,'lib/adapters/cortex/precomputed.mjs')).href);const binding={repositoryRevision:'smoke',dirty:false,dirtyPatchDigest:'sha256:clean'};const projection=loadPrecomputedProjection({schemaVersion:1,binding,generation:'smoke',state:'ready',files:['package.json'],manifestDigest:'sha256:manifest',generationId:'smoke'},binding);
    const host=library.fixedHost({processRunner:{run:async()=>({exitCode:0,stdout:'',stderr:'',status:'completed'})}});const registry=library.loadProviderRegistry();const plan=await library.buildPlan({root:assembled,projection,repositoryBinding:binding,registry},host);const serialPlan={...plan,schedule:'serial'};const autoPlan={...plan,schedule:'auto'};const serial=await library.executePlan(serialPlan,host);const automatic=await library.executePlan(autoPlan,host);if(serial.receipts.length!==plan.providers.length||automatic.receipts.length!==plan.providers.length)throw new Error('assembled execution omitted selected providers');
    const facts=library.reconcileRun({plan,receipts:automatic.receipts,artifacts:{root:assembled}},host);const report=await library.finalizeRun({plan,facts,results:{securityCandidates:[],adjudication:{complete:true,verdicts:[]}}},host);const verification=await library.verifyRun({priorRun:{binding,controls:[],claims:{source:'pass'}},currentRepository:{binding,snapshot:{binding,controls:[],claims:{source:'pass'}}}},host);const audit=await library.audit({root:assembled,outDir:join(temp,'audit'),projection,binding,claimLevel:'inventory',providers:[]},host);
    return{binary:true,library:true,cortexProjection:projection.state==='ready',plan:Boolean(plan.seal?.digest),schedule:serial.receipts.length===automatic.receipts.length,serialExecution:true,autoExecution:true,audit:Boolean(audit.report),verify:verification.valid,report:Boolean(report),forbiddenMarkers,fileCount:files.length,version};
  }finally{rmSync(temp,{recursive:true,force:true});}
}
