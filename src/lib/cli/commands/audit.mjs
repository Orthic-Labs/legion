import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { EXIT, LegionError } from '../../errors.mjs';

// Audit runs the canonical pipeline. The complete deterministic core lands in
// PR06/PR07; this wires the existing audit-run.mjs entrypoint as the
// compatibility surface until then.
export async function runAudit(argv, { stdout, stderr, env, cwd, host, core=null }) {
  let parsed;try{parsed = parseArgs({ args: argv, allowPositionals: true, strict: true,options:{out:{type:'string'},'cortex-out':{type:'string'},only:{type:'string',multiple:true},skip:{type:'string',multiple:true},'plan-only':{type:'boolean'},quiet:{type:'boolean'},url:{type:'string'},surfaces:{type:'string'},'visual-spec':{type:'string'},'visual-baselines':{type:'string'},width:{type:'string'},height:{type:'string'}} });}catch(error){throw new LegionError(error.message,{code:'USAGE',exitCode:EXIT.USAGE});}
  const root = resolve(parsed.positionals[0] ?? cwd);
  const api=core??await import('../../index.mjs');const result=await api.audit({root,outDir:parsed.values.out,only:parsed.values.only??[],skip:parsed.values.skip??[],planOnly:Boolean(parsed.values['plan-only']),env},host);
  stdout.write(`${JSON.stringify({kind:'legion-audit-run',outDir:result.artifacts.runDir,report:result.artifacts.report?.path??null,incomplete:result.report?.incomplete??true})}\n`);
  return {exitCode:result.report?.incomplete?EXIT.INCOMPLETE:result.report?.audit_status==='fail'?EXIT.POLICY_FAIL:EXIT.PASS};
}
