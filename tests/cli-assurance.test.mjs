import assert from 'node:assert/strict';
import test from 'node:test';
import { runCli } from '../lib/cli/run.mjs';
const capture=()=>({buf:'',write(value){this.buf+=value;}});
test('EC603 CLI dispatcher exposes executable assurance, completion, host-event & proof routes',async()=>{for(const command of [['assurance','--help'],['completion','--help'],['host','events','help'],['authority','proof','help']]){const stdout=capture(),stderr=capture(),result=await runCli(command,{stdout,stderr,env:{},cwd:process.cwd()});assert.equal(result.exitCode,0,command.join(' '));assert.notEqual(stdout.buf,'');assert.equal(stderr.buf,'');}});
