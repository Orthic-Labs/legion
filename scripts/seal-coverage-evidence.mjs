import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {mkdirSync,readFileSync,readdirSync,statSync,writeFileSync} from 'node:fs';
import {dirname,join,relative,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const indexPath=join(root,'registry/coverage/index.json');
const registry=JSON.parse(readFileSync(indexPath,'utf8'));
const providers=JSON.parse(readFileSync(join(root,'registry/providers.json'),'utf8')).providers;
const sha=(bytes)=>`sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const tests={
  'language.javascript':'tests/providers/javascript/javascript.test.mjs','language.python':'tests/providers/python/python.test.mjs',
  'language.rust':'tests/providers/rust/rust.test.mjs','language.go':'tests/providers/go/go.test.mjs','language.jvm':'tests/providers/jvm/jvm.test.mjs',
  'language.dotnet':'tests/providers/dotnet/dotnet.test.mjs','language.c-family':'tests/providers/c-family/c-family.test.mjs',
  'language.php-ruby':'tests/providers/php-ruby/php-ruby.test.mjs','language.mobile':'tests/providers/mobile/mobile.test.mjs',
  'language.long-tail':'tests/coverage-long-tail.test.mjs','framework.frontend':'tests/framework-suite.test.mjs',
  'framework.backend':'tests/framework-suite.test.mjs','framework.data':'tests/generic-source-suite.test.mjs'
};
function files(path){return readdirSync(path,{withFileTypes:true}).flatMap((entry)=>entry.isDirectory()?files(join(path,entry.name)):[join(path,entry.name)]).sort();}
function corpusBytes(path){const selected=files(path).filter((file)=>!file.endsWith('qualification.json'));if(selected.length<4)throw new Error(`${relative(root,path)} requires positive negative unsupported and denominator fixtures`);return Buffer.concat(selected.flatMap((file)=>[Buffer.from(relative(path,file).replaceAll('\\','/')),Buffer.from([0]),readFileSync(file),Buffer.from([0])]));}
for(const record of registry.records){
  const stem=record.id.replace(/[^a-z0-9.-]/gi,'-');
  const corpusRoot=record.id.startsWith('framework.')?`bench/corpora/frameworks/${record.id.slice(10)}`:`bench/corpora/${record.id.slice(9)}`;
  const corpusPath=`${corpusRoot}/qualification.json`;
  const testPath=tests[record.id];if(!testPath)throw new Error(`no qualification test for ${record.id}`);
  const run=spawnSync(process.execPath,['--test',testPath],{cwd:root,encoding:'utf8',env:{...process.env,FORCE_COLOR:'0',NO_COLOR:'1'}});
  const raw=Buffer.from(`${run.stdout}${run.stderr}`);if(run.status!==0)throw new Error(`${record.id} qualification failed`);
  const logPath=`bench/qualifications/book-3/coverage/${stem}.test.log`;mkdirSync(dirname(join(root,logPath)),{recursive:true});writeFileSync(join(root,logPath),raw);
  const corpusDigest=sha(corpusBytes(join(root,corpusRoot)));
  const corpusQualification=JSON.parse(readFileSync(join(root,corpusPath),'utf8'));const casesRequired=(corpusQualification.cases??[]).map(({id})=>id);if(!casesRequired.length)throw new Error(`${record.id} corpus declares no cases`);
  const providerVersions=Object.fromEntries(record.providers.map((id)=>{const provider=providers.find((item)=>item.id===id);if(!provider)throw new Error(`${record.id} references unknown provider ${id}`);return[id,provider.providerVersion];}));
  const qualificationPath=`bench/qualifications/book-3/coverage/${stem}.qualification.json`;
  const artifactPath=`bench/qualifications/book-3/coverage/${stem}.artifact.json`;
  const artifact=Buffer.from(`${JSON.stringify({schemaVersion:1,kind:'nemesis-coverage-test-artifact',recordId:record.id,testPath,status:'pass',rawLog:{path:logPath,digest:sha(raw),bytes:raw.byteLength},providerVersions},null,2)}\n`);
  const qualification=Buffer.from(`${JSON.stringify({schemaVersion:1,kind:'nemesis-coverage-qualification',recordId:record.id,corpusRoot,corpusDigest,artifactDigest:sha(artifact),providerVersions,casesRequired,command:['node','--test',testPath],decision:'source-measured-runtime-unproven'},null,2)}\n`);
  for(const [path,bytes]of [[qualificationPath,qualification],[artifactPath,artifact]])writeFileSync(join(root,path),bytes);
  Object.assign(record,{corpusPath,corpusRoot,corpusDigest,providerVersions,qualificationPath,qualificationDigest:sha(qualification),artifactPath,artifactDigest:sha(artifact)});
}
writeFileSync(indexPath,`${JSON.stringify(registry,null,2)}\n`);
