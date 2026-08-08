import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export function currentSourceRevision(root){const head=execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim();const names=execFileSync('git',['ls-files','-m','-o','--exclude-standard'],{cwd:root,encoding:'utf8'}).split(/\r?\n/).filter(Boolean).map((path)=>path.replaceAll('\\','/')).filter((path)=>!path.startsWith('qualification/')&&path!=='architecture.md'&&path!=='pnpm-lock.yaml').sort();if(!names.length)return head;const hash=createHash('sha256');for(const name of names){hash.update(name);hash.update('\0');hash.update(readFileSync(resolve(root,name)));}return `${head}+dirty.sha256:${hash.digest('hex')}`;}
