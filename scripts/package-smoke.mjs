import { execFileSync } from 'node:child_process';
import { existsSync,mkdirSync,mkdtempSync,readdirSync,readFileSync,rmSync,statSync,writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename,dirname,isAbsolute,join,resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export function packageSmokeContract(){return['binary','library-import','blueprint-packet','plan','schedule','serial-execution','auto-execution','audit','verify','tasklist','dispatch','coder','qa','handoff','transcripts','decisions'];}
const walk=(root,current=root,out=[])=>{for(const name of readdirSync(current)){const path=join(current,name);if(statSync(path).isDirectory())walk(root,path,out);else out.push(path);}return out;};
const python=(args,options)=>process.platform==='win32'
  ? execFileSync('py',['-3.11',...args],options)
  : execFileSync('python3',args,options);
const pnpmCli=()=>{
  const homes=[process.env.PNPM_HOME,...String(process.env.PATH??'').split(process.platform==='win32'?';':':')].filter(Boolean);
  for(const home of homes){
    for(const name of ['pnpm','pnpm.CMD']){
      const shim=join(home,name);
      if(!existsSync(shim))continue;
      const source=readFileSync(shim,'utf8');
      const direct=source.match(/cmd-shim-target=(.+pnpm\.mjs)\s*$/im)?.[1]?.trim();
      if(direct&&existsSync(direct))return direct;
      const relative=source.match(/["'](%~dp0[^"']*pnpm\.mjs)["']/i)?.[1];
      if(relative){const resolved=resolve(dirname(shim),relative.replace(/^%~dp0[\\/]?/i,''));if(existsSync(resolved))return resolved;}
    }
  }
  throw new Error('pnpm runtime unavailable');
};
const pnpm=(args,options={})=>execFileSync(process.execPath,[pnpmCli(),...args],options);

// Builds a standalone .mjs file that a *separate* node process runs from inside
// a scratch consumer package. It must import the tarball-installed dependency
// purely by package specifier (never by file path), so that node's own
// package.json `exports` resolution is what gets exercised -- the same
// resolution a real downstream consumer of the published package goes through.
const buildConsumerCheckScript=(pkgName,subpaths)=>{
  const lines=[
    "import assert from 'node:assert/strict';",
    "import { existsSync } from 'node:fs';",
    "import { fileURLToPath } from 'node:url';",
    'const result={ok:true,failedSpecifier:null,error:null};',
    "let current='(unknown)';",
    'try{',
    `  current=${JSON.stringify(pkgName)};`,
    `  const root=await import(current);`,
    "  assert.equal(typeof root.buildPlan,'function','buildPlan export missing');",
    "  assert.equal(typeof root.reconcileRun,'function','reconcileRun export missing');",
    "  assert.equal(typeof root.resolveSkillInvocation,'function','resolveSkillInvocation export missing');",
    "  assert.equal(typeof root.validateCapabilitySelection,'function','validateCapabilitySelection export missing');",
    "  assert.equal(root.resolveSkillInvocation('/glass refine header').resolvedInvocation,'/designer glass refine header','installed alias arguments were dropped');",
    "  assert.equal(root.validateCapabilitySelection({ids:['architect'],source:'semantic'}).status,'resolved','installed semantic selection validation failed');",
  ];
  for(const key of subpaths){
    if(key.includes('*')){
      const sample=key.replace('*','core/binding-v1.schema.json').replace(/^\.\//,'');
      const specifier=`${pkgName}/${sample}`;
      lines.push(`  current=${JSON.stringify(specifier)};`);
      lines.push(`  { const resolvedUrl=import.meta.resolve(current); const resolvedPath=fileURLToPath(resolvedUrl); assert.ok(existsSync(resolvedPath), 'resolved path does not exist on disk: '+resolvedPath); }`);
    } else {
      const specifier=`${pkgName}/${key.replace(/^\.\//,'')}`;
      lines.push(`  current=${JSON.stringify(specifier)};`);
      lines.push(`  await import(current);`);
    }
  }
  lines.push('}catch(error){result.ok=false;result.failedSpecifier=current;result.error=String((error&&error.stack)||error);}');
  lines.push('process.stdout.write(JSON.stringify(result));');
  return lines.join('\n');
};

export async function runPackageSmoke(root=resolve(import.meta.dirname,'..')){
  const pkg=JSON.parse(readFileSync(join(root,'package.json'),'utf8'));
  const manifest=JSON.parse(readFileSync(join(root,'MANIFEST.package.json'),'utf8'));
  const temp=mkdtempSync(join(tmpdir(),'legion-package-smoke-'));
  const packDir=join(temp,'pack');
  mkdirSync(packDir,{recursive:true});
  try{
    // (a) build the actual publishable tarball. Ignoring scripts on THIS pack
    // call keeps package-smoke (wired into `prepack`) from recursing
    // into itself: package managers normally re-run `prepack`, which runs
    // this very script. Skipping lifecycle scripts here is correct on its own
    // merits too -- by the time prepack reaches this step it has already run
    // the full test suite and the naming/schema checks, so re-running them via
    // a nested pack would just be redundant work, not extra safety.
    const packOutputRaw=pnpm(['--config.ignore-scripts=true','pack','--json',`--pack-destination=${packDir}`],{cwd:root,encoding:'utf8'});
    const parsedPackInfo=JSON.parse(packOutputRaw);
    const packInfo=Array.isArray(parsedPackInfo)?parsedPackInfo[0]:parsedPackInfo;
    const tarballPath=isAbsolute(packInfo.filename)?packInfo.filename:join(packDir,packInfo.filename);
    if(!existsSync(tarballPath))throw new Error(`pnpm pack did not produce ${packInfo.filename}`);

    // (b) extract the tarball to a temp dir -- this is what actually ships,
    // including pnpm's interpretation of the "files" allowlist/denylist,
    // rather than a hand-rolled copy that can silently drift from reality.
    const extractDir=join(temp,'extracted');
    mkdirSync(extractDir,{recursive:true});
    execFileSync('tar',['-xzf',tarballPath,'-C',extractDir]);
    const assembled=join(extractDir,'package');
    if(!existsSync(assembled))throw new Error('tarball did not extract a package/ directory');

    const files=walk(assembled);let forbiddenMarkers=0;for(const path of files){if(basename(path)==='MANIFEST.package.json'||!/\.(?:mjs|js|json|md|txt|ya?ml)$/i.test(path))continue;const text=readFileSync(path,'utf8');for(const marker of manifest.forbiddenContentMarkers)if(text.includes(marker))forbiddenMarkers++;}
    if(forbiddenMarkers)throw new Error(`assembled package contains ${forbiddenMarkers} forbidden markers`);
    const version=execFileSync(process.execPath,[join(assembled,pkg.bin.legion),'--version'],{cwd:assembled,encoding:'utf8'}).trim();if(version!==pkg.version)throw new Error('assembled binary version mismatch');

    // (c) install the real tarball into a scratch consumer package, then
    // (d) import it THROUGH the package name and every declared subpath
    // export, from a child process whose module resolution starts at that
    // scratch package -- this is what actually catches an `exports` map
    // pointing at paths that don't exist inside the published tarball.
    const consumerDir=join(temp,'consumer');
    mkdirSync(consumerDir,{recursive:true});
    writeFileSync(join(consumerDir,'package.json'),JSON.stringify({name:'legion-package-smoke-consumer',version:'0.0.0',private:true,type:'module'}));
    pnpm(['add','--offline','--ignore-scripts',tarballPath],{cwd:consumerDir,encoding:'utf8'});
    const installedRoot=join(consumerDir,'node_modules',...pkg.name.split('/'));
    if(!existsSync(installedRoot))throw new Error(`npm install did not place ${pkg.name} in node_modules`);

    const subpaths=Object.keys(pkg.exports).filter((key)=>key!=='.');
    const checkerPath=join(consumerDir,'legion-smoke-check.mjs');
    writeFileSync(checkerPath,buildConsumerCheckScript(pkg.name,subpaths));
    let consumerResultRaw;
    try{
      consumerResultRaw=execFileSync(process.execPath,[checkerPath],{cwd:consumerDir,encoding:'utf8'});
    }catch(error){
      throw new Error(`published exports are broken: ${error.stderr||error.stdout||error.message}`);
    }
    const consumerResult=JSON.parse(consumerResultRaw);
    if(!consumerResult.ok)throw new Error(`published exports are broken for specifier "${consumerResult.failedSpecifier}": ${consumerResult.error}`);

    // The remaining checks exercise internal modules that are not part of the
    // public exports map (host/plan/audit orchestration, skill scripts). They
    // are addressed by file path inside the extracted tarball, same as before.
    const library=await import(`${pathToFileURL(join(assembled,'src/lib/index.mjs')).href}?smoke=${Date.now()}`);if(typeof library.buildPlan!=='function'||typeof library.reconcileRun!=='function')throw new Error('assembled library exports incomplete');
    const binding={repositoryRevision:'smoke',dirty:false,dirtyPatchDigest:'sha256:clean'};const projection={schema:'membrane.context-packet.v1',status:'ready',binding,files:['package.json'],packetDigest:'sha256:packet'};
    const host=library.fixedHost({processRunner:{run:async()=>({exitCode:0,stdout:'',stderr:'',status:'completed'})}});const {loadProviderRegistry}=await import(pathToFileURL(join(assembled,'src/registry/provider-registry.mjs')).href);const registry=loadProviderRegistry();const plan=await library.buildPlan({root:assembled,projection,repositoryBinding:binding,registry},host);const serialPlan={...plan,schedule:'serial'};const autoPlan={...plan,schedule:'auto'};const serial=await library.executePlan(serialPlan,host);const automatic=await library.executePlan(autoPlan,host);if(serial.receipts.length!==plan.providers.length||automatic.receipts.length!==plan.providers.length)throw new Error('assembled execution omitted selected providers');
    const facts=library.reconcileRun({plan,receipts:automatic.receipts,artifacts:{root:assembled}},host);const report=await library.finalizeRun({plan,facts,results:{securityCandidates:[],adjudication:{complete:true,verdicts:[]}}},host);const verification=await library.verifyRun({priorRun:{binding,controls:[],claims:{source:'pass'}},currentRepository:{binding,snapshot:{binding,controls:[],claims:{source:'pass'}}}},host);const audit=await library.audit({root:assembled,outDir:join(temp,'audit'),projection,binding,claimLevel:'inventory',providers:[]},host);
    const py=(script,args=['--help'])=>python([join(assembled,script),...args],{cwd:assembled,encoding:'utf8'});
    py('skills/tasklist/scripts/validate-tasklist.py');
    py('skills/dispatch/scripts/validate-dispatch.py');
    py('skills/coder/scripts/api-worker.py');
    py('skills/handoff/scripts/transcript-handoff.py');
    py('skills/handoff/scripts/validate-handoff.py');
    execFileSync(process.execPath,[join(assembled,'skills/qa/scripts/qa.mjs'),'--help'],{cwd:assembled,encoding:'utf8'});
    python(['-c',"from decision_provider import produce_candidate_set; assert produce_candidate_set('package smoke', {'repositoryId': '.', 'maxCandidates': 1}).candidates == ()"],{cwd:join(assembled,'src','lib'),encoding:'utf8'});
    return{binary:true,library:true,blueprintPacket:projection.status==='ready',plan:Boolean(plan.seal?.digest),schedule:serial.receipts.length===automatic.receipts.length,serialExecution:true,autoExecution:true,audit:Boolean(audit.report),verify:verification.valid,report:Boolean(report),tasklist:true,dispatch:true,coder:true,qa:true,handoff:true,transcripts:true,decisions:true,forbiddenMarkers,fileCount:files.length,version,publishedExports:true};
  }finally{rmSync(temp,{recursive:true,force:true});}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try{
    const result=await runPackageSmoke();
    console.log(JSON.stringify(result,null,2));
  }catch(error){
    console.error(`package-smoke failed: ${error.message}`);
    process.exitCode=1;
  }
}
