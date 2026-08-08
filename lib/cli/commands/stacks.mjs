import { inspectRepository } from './inspect.mjs';
export async function runStacks(args,{stdout,cwd,host}){const result=await inspectRepository(args,{cwd,host});stdout.write(`${JSON.stringify({artifact:result.artifact.stacks,selectionTrace:result.artifact.stacks.coverage})}\n`);return{exitCode:result.complete?0:2};}
