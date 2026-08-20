import assert from 'node:assert/strict';
import test from 'node:test';
import { runCli } from '../src/lib/cli/run.mjs';
const capture=()=>({buf:'',write(value){this.buf+=value;}});
test('EC603 CLI exposes completion, host-event & proof routes without a Covenant/high-risk assurance gate',async()=>{for(const command of [['completion','--help'],['host','events','help'],['authority','proof','help']]){const stdout=capture(),stderr=capture(),result=await runCli(command,{stdout,stderr,env:{},cwd:process.cwd()});assert.equal(result.exitCode,0,command.join(' '));assert.notEqual(stdout.buf,'');assert.equal(stderr.buf,'');}const stdout=capture(),stderr=capture(),removed=await runCli(['assurance','--help'],{stdout,stderr,env:{},cwd:process.cwd()});assert.equal(removed.exitCode,4);assert.equal(stdout.buf,'');assert.match(stderr.buf,/unknown command/);});
