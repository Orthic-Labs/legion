import { parseArgs } from 'node:util';
import { existsSync, statSync,readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { EXIT, LegionError } from '../../errors.mjs';

export async function runVerify(argv, { stdout, stderr, env, cwd,host,core=null }) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, strict: true });
  const [factsArg] = parsed.positionals;
  if (!factsArg) throw new LegionError('verify requires a run directory or facts.json path', { code: 'USAGE', exitCode: EXIT.USAGE });
  const supplied = resolve(cwd, factsArg);
  const runDirectory = existsSync(supplied) && statSync(supplied).isDirectory();
  const factsPath = runDirectory ? join(supplied, 'facts.json') : supplied;
  if (!existsSync(factsPath) || !statSync(factsPath).isFile()) {
    throw new LegionError(`verify facts artifact missing: ${factsPath}`, { code: 'VERIFY_RUN_ARTIFACT_MISSING', exitCode: EXIT.USAGE });
  }
  const planPath=runDirectory?join(supplied,'plan.json'):null;if(planPath&&(!existsSync(planPath)||!statSync(planPath).isFile()))throw new LegionError(`verify plan artifact missing: ${planPath}`,{code:'VERIFY_RUN_ARTIFACT_MISSING',exitCode:EXIT.USAGE});
  const prior=JSON.parse(readFileSync(factsPath,'utf8'));const api=core??await import('../../index.mjs');const currentBinding=await api.bindRepository(prior.workspace??cwd,{revision:prior.plan?.binding?.repositoryRevision??null});const receipt=await api.verifyRun({priorRun:prior,currentRepository:{binding:currentBinding}},host);stdout.write(`${JSON.stringify(receipt)}\n`);return{exitCode:receipt.valid?EXIT.PASS:EXIT.INCOMPLETE};
}
