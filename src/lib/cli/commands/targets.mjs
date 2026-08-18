import { inspectRepository } from './inspect.mjs';
export async function runTargets(args,{stdout,cwd,host}){const result=await inspectRepository(args,{cwd,host});stdout.write(`${JSON.stringify({artifact:result.artifact.portfolio,selectionTrace:result.artifact.portfolio.coverage})}\n`);return{exitCode:result.complete?0:2};}
