import {readdir,readFile}from'node:fs/promises';
import { mkdirSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { compilePolicyFiles, PolicyRuleCompileError, renderPolicy } from '../../guard/compat/rules/policy-compiler.mjs';
async function files(url){const entries=await readdir(url,{withFileTypes:true});return(await Promise.all(entries.map((entry)=>entry.isDirectory()?files(new URL(`${entry.name}/`,url)):entry.name.endsWith('.json')?[new URL(entry.name,url)]:[]))).flat();}
async function packagedRules(){const rows=[];for(const url of await files(new URL('../../../registry/rules/',import.meta.url))){const value=JSON.parse(await readFile(url,'utf8'));for(const rule of value.rules??[])rows.push(rule.id??rule);}return[...new Set(rows)].sort();}
function compileArgs(argv) {
  if (argv.length < 2 || argv[0] !== 'compile') throw new PolicyRuleCompileError('Usage: legion rules compile <source> --base <policy> [--out <output>]');
  const source = argv[1]; const options = argv.slice(2);
  let base = null; let out = null;
  for (let index = 0; index < options.length; index += 2) {
    const flag = options[index]; const value = options[index + 1];
    if (!['--base', '--out'].includes(flag) || !value) throw new PolicyRuleCompileError('Usage: legion rules compile <source> --base <policy> [--out <output>]');
    if (flag === '--base' && base !== null) throw new PolicyRuleCompileError('duplicate --base');
    if (flag === '--out' && out !== null) throw new PolicyRuleCompileError('duplicate --out');
    if (flag === '--base') base = value; else out = value;
  }
  if (!base) throw new PolicyRuleCompileError('Usage: legion rules compile <source> --base <policy> [--out <output>]');
  return { source, base, out };
}
function writeAtomic(output, bytes) {
  mkdirSync(path.dirname(output), { recursive: true });
  const temporary = `${output}.tmp-${process.pid}`;
  writeFileSync(temporary, bytes, 'utf8');
  renameSync(temporary, output);
}
export async function runRules(argv, { stdout, stderr, cwd = process.cwd() }, registry = null) {
  if(argv.includes('--help')){stdout.write('Usage: legion rules [compile <source> --base <policy> [--out <output>]]\n');return{exitCode:0};}
  if (argv[0] === 'compile') {
    try {
      const { source, base, out } = compileArgs(argv);
      const bundle = compilePolicyFiles({ sourcePath: path.resolve(cwd, source), basePath: path.resolve(cwd, base) });
      const bytes = renderPolicy(bundle);
      if (out) writeAtomic(path.resolve(cwd, out), bytes);
      stdout.write(out ? `${JSON.stringify({ output: path.resolve(cwd, out) })}\n` : bytes);
      return { exitCode: 0 };
    } catch (error) {
      stderr.write(`${error instanceof PolicyRuleCompileError ? error.message : String(error.message ?? error)}\n`);
      return { exitCode: 4 };
    }
  }
  if(argv.length){stderr.write(`unknown option: ${argv[0]}\n`);return{exitCode:4};}registry??=await packagedRules();stdout.write(`${JSON.stringify({ rules: registry })}\n`); return { exitCode: 0 };
}
