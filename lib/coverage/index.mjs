import {createHash} from 'node:crypto';
import {readFileSync,readdirSync} from 'node:fs';
import {join,relative,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const ROOT=resolve(fileURLToPath(new URL('../..',import.meta.url)));
const TIERS=['inventory','parser','native','cross-file','measured-pack','runtime','remediation'];
const sha=(bytes)=>`sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const files=(path)=>readdirSync(path,{withFileTypes:true}).flatMap((entry)=>entry.isDirectory()?files(join(path,entry.name)):[join(path,entry.name)]).sort();
const corpusDigest=(path)=>sha(Buffer.concat(files(path).filter((file)=>!file.endsWith('qualification.json')).flatMap((file)=>[Buffer.from(relative(path,file).replaceAll('\\','/')),Buffer.from([0]),readFileSync(file),Buffer.from([0])])));

const equalJson=(left,right)=>JSON.stringify(left)===JSON.stringify(right);
export function validateCoverageEvidence(record,{qualification,artifact,corpus}){
  if(qualification?.recordId!==record.id||artifact?.recordId!==record.id)throw new Error(`${record.id} qualification record mismatch`);
  if(qualification.corpusRoot!==record.corpusRoot||qualification.corpusDigest!==record.corpusDigest||qualification.artifactDigest!==record.artifactDigest)throw new Error(`${record.id} qualification digest binding mismatch`);
  if(!equalJson(qualification.providerVersions,record.providerVersions)||!equalJson(artifact.providerVersions,record.providerVersions))throw new Error(`${record.id} qualification provider versions mismatch`);
  const required=[...(qualification.casesRequired??[])].sort();const cases=[...(corpus?.cases??[]).map(({id})=>id)].sort();if(!required.length||!equalJson(required,cases))throw new Error(`${record.id} qualification cases mismatch`);
  if(artifact.status!=='pass'||!artifact.testPath||!artifact.rawLog?.path||!/^sha256:[a-f0-9]{64}$/.test(artifact.rawLog.digest??'')||!Number.isInteger(artifact.rawLog.bytes))throw new Error(`${record.id} qualification test artifact invalid`);
  return true;
}

export function validateCoverageRegistry(registry,{root=ROOT,providerRegistry=null}={}){
  if(registry.schemaVersion!==2)throw new Error('coverage v2 required');
  const providers=providerRegistry?.providers??JSON.parse(readFileSync(resolve(root,'registry/providers.json'),'utf8')).providers;
  const ids=new Set();
  for(const record of registry.records??[]){
    if(ids.has(record.id))throw new Error(`duplicate coverage: ${record.id}`);ids.add(record.id);
    for(const tier of TIERS)if(!Number.isInteger(record.tiers?.[tier])||record.tiers[tier]<0)throw new Error(`invalid tier ${record.id}:${tier}`);
    if(Object.keys(record.tiers).sort().join(',')!==[...TIERS].sort().join(','))throw new Error(`${record.id} tier schema parity mismatch`);
    if(record.tiers.parser>record.tiers.inventory||record.tiers.native>record.tiers.parser||record.tiers['cross-file']>record.tiers.native||record.tiers.runtime>record.tiers['measured-pack']||record.tiers.remediation>record.tiers.runtime)throw new Error(`${record.id} coverage tiers must be monotone`);
    if(record.tiers['measured-pack']){
      if(!record.corpusRoot||!record.corpusDigest||!record.artifactPath||!record.artifactDigest||!record.qualificationPath||!record.qualificationDigest||record.corpusDigest===record.artifactDigest)throw new Error('measured tier requires independent corpus artifact and qualification proof');
      if(corpusDigest(resolve(root,record.corpusRoot))!==record.corpusDigest)throw new Error(`${record.id} corpus digest mismatch`);
      if(sha(readFileSync(resolve(root,record.artifactPath)))!==record.artifactDigest)throw new Error(`${record.id} artifact digest mismatch`);
      if(sha(readFileSync(resolve(root,record.qualificationPath)))!==record.qualificationDigest)throw new Error(`${record.id} qualification digest mismatch`);
      const qualification=JSON.parse(readFileSync(resolve(root,record.qualificationPath),'utf8'));const artifact=JSON.parse(readFileSync(resolve(root,record.artifactPath),'utf8'));const corpus=JSON.parse(readFileSync(resolve(root,record.corpusPath),'utf8'));validateCoverageEvidence(record,{qualification,artifact,corpus});
      if(!existsFile(root,artifact.testPath)||sha(readFileSync(resolve(root,artifact.rawLog.path)))!==artifact.rawLog.digest||readFileSync(resolve(root,artifact.rawLog.path)).byteLength!==artifact.rawLog.bytes)throw new Error(`${record.id} qualification test/log binding mismatch`);
      for(const providerId of record.providers??[]){const provider=providers.find(({id})=>id===providerId);if(!provider||record.providerVersions?.[providerId]!==provider.providerVersion)throw new Error(`${record.id} provider version mismatch: ${providerId}`);}
    }
    if(record.tiers.runtime&&!record.qualificationVersion)throw new Error('runtime tier requires qualification');
  }
  return registry;
}
function existsFile(root,path){try{return readFileSync(resolve(root,path)).byteLength>=0;}catch{return false;}}
export function accountCoverage(detected,registry){const byAlias=new Map((registry.records??[]).flatMap((record)=>[record.id,...record.aliases??[],...record.extensions??[]].map((value)=>[value,record])));return detected.map((value)=>byAlias.get(value)??{id:`unknown.${value}`,kind:'unknown',tiers:Object.fromEntries(TIERS.map((tier)=>[tier,0])),limitations:['unaccounted format'],cleanClaim:'never'});}
