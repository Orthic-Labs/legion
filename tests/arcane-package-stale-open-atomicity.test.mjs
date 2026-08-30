import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runCli } from '../src/lib/cli/run.mjs';
import { seedStore } from './fixtures/arcane-package/runtime-binding-contract.mjs';
const capture=()=>({buf:'',write(value){this.buf+=value;}});
function snapshot(root){const walk=(dir)=>readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name)).flatMap(entry=>entry.isDirectory()?walk(join(dir,entry.name)).map(x=>entry.name+'/'+x):[entry.name+':'+readFileSync(join(dir,entry.name),'utf8')]);return walk(root);}
test('EC603 stale sealed source rejects run open before binding, lease, receipt, run-state, or filesystem mutation',async()=>{const root=mkdtempSync(join(tmpdir(),'arcane-stale-'));try{execFileSync('git',['init'],{cwd:root});execFileSync('git',['config','user.email','arcane@example.test'],{cwd:root});execFileSync('git',['config','user.name','Arcane'],{cwd:root});writeFileSync(join(root,'tracked.txt'),'base');execFileSync('git',['add','.'],{cwd:root});execFileSync('git',['commit','-m','base'],{cwd:root});seedStore(join(root,'.audit','arcane'));const before=snapshot(join(root,'.audit'));const stdout=capture(),stderr=capture(),result=await runCli(['run','open','--contract','EC-5','--version','1','--task','T-1','--session','stale-session'],{stdout,stderr,env:{},cwd:root});assert.equal(result.exitCode,2);assert.match(stderr.buf,/ARC_CONTRACT_SOURCE_STALE/);assert.deepEqual(snapshot(join(root,'.audit')),before);assert.equal(stdout.buf,'');}finally{rmSync(root,{recursive:true,force:true});}});
