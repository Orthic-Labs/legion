import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { EXIT, LegionError } from '../../errors.mjs';

// CLI uses complete declarative provider runner. Native/host shells may expose a
// narrower compatibility Audit, but this package command never substitutes an
// empty provider list for repository evidence.
export async function runAudit(argv, { stdout, stderr, env, cwd, host, runner=null }) {
  let parsed;try{parsed = parseArgs({ args: argv, allowPositionals: true, strict: true,options:{out:{type:'string'},only:{type:'string',multiple:true},skip:{type:'string',multiple:true},'plan-only':{type:'boolean'},quiet:{type:'boolean'},url:{type:'string'},surfaces:{type:'string'},'visual-spec':{type:'string'},'visual-baselines':{type:'string'},width:{type:'string'},height:{type:'string'},'blueprint-out':{type:'string'},type:{type:'string'},base:{type:'string'},'base-commit':{type:'string'},dir:{type:'string'}} });}catch(error){throw new LegionError(error.message,{code:'USAGE',exitCode:EXIT.USAGE});}
  const root = resolve(parsed.positionals[0] ?? cwd);
  const api=runner??await import('../../../../tools/audit/audit-run.mjs');
  const scope={mode:['type','base','base-commit','dir'].some((name)=>parsed.values[name])?'diff':'whole-repo',type:parsed.values.type??'all',base:parsed.values.base??null,baseCommit:parsed.values['base-commit']??null,dir:parsed.values.dir??null};
  const result=await api.runAuditProviders({root,outDir:parsed.values.out,blueprintOut:parsed.values['blueprint-out'],only:parsed.values.only??[],skip:parsed.values.skip??[],planOnly:Boolean(parsed.values['plan-only']),quiet:Boolean(parsed.values.quiet),url:parsed.values.url,surfaces:parsed.values.surfaces,visualSpec:parsed.values['visual-spec'],visualBaselines:parsed.values['visual-baselines'],width:Number(parsed.values.width??1280),height:Number(parsed.values.height??800),scope,env,host});
  const payload={kind:'legion-audit-run',outDir:result.outDir,plan:result.planPath,facts:result.facts?`${result.outDir}/facts.json`:null,selectedProviders:result.plan?.denominator?.providerIds??[],requiredLenses:result.facts?.reasoning_lenses_required??result.plan?.denominator?.reasoningProviders??[],lensesRan:result.facts?.lenses_ran??[],incomplete:result.facts?.incomplete??true};
  stdout.write(`${JSON.stringify(payload)}\n`);
  return {exitCode:payload.incomplete?EXIT.INCOMPLETE:EXIT.PASS};
}
