import { inspectRepository } from './inspect.mjs';
export async function runControls(args,{stdout,cwd,host}){const result=await inspectRepository(args,{cwd,host});stdout.write(`${JSON.stringify({artifact:result.artifact.baseline,selectionTrace:result.artifact.baseline.selectionTrace})}\n`);return{exitCode:result.complete?0:2};}
