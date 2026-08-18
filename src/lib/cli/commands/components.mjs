import { inspectRepository } from './inspect.mjs';
export async function runComponents(args,{stdout,cwd,host}){const result=await inspectRepository(args,{cwd,host});stdout.write(`${JSON.stringify({artifact:result.artifact.components,selectionTrace:result.artifact.components.coverage})}\n`);return{exitCode:result.complete?0:2};}
