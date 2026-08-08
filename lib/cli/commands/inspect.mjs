import { parseArgs } from 'node:util';
import { readdir,readFile } from 'node:fs/promises';
import { resolve,relative } from 'node:path';
import { productTopologyStage } from '../../core/plan-stages/product-topology.mjs';

const EXCLUDED=new Set(['.git','.audit','node_modules']);
async function files(root,path=root,output=[]){for(const entry of await readdir(path,{withFileTypes:true})){if(EXCLUDED.has(entry.name))continue;const absolute=resolve(path,entry.name);if(entry.isDirectory())await files(root,absolute,output);else output.push(relative(root,absolute).replaceAll('\\','/'));}return output;}
async function projection(root){const listed=(await files(root)).sort();let manifest={};if(listed.includes('package.json'))try{manifest=JSON.parse(await readFile(resolve(root,'package.json'),'utf8'));}catch{}return{files:listed,manifests:listed.includes('package.json')?[{path:'package.json',...manifest}]:[],dependencies:{...(manifest.dependencies??{}),...(manifest.devDependencies??{})},entrypoints:[...(typeof manifest.bin==='string'?[manifest.bin]:Object.values(manifest.bin??{}))],buildOutputs:[]};}
export async function inspectRepository(args,{cwd,host={clock:{now:()=>new Date(0)}}}={}){const parsed=parseArgs({args,allowPositionals:true,strict:true,options:{json:{type:'boolean'}}});if(parsed.positionals.length>1)throw new TypeError('inspect accepts at most one repository root');const root=resolve(cwd,parsed.positionals[0]??'.');return productTopologyStage.run({root,projection:await projection(root)},host);}
export async function runInspect(args, { stdout, cwd,host }) { const result=await inspectRepository(args,{cwd,host});stdout.write(`${JSON.stringify(result)}\n`);return { exitCode: result.complete ? 0 : 2 }; }
