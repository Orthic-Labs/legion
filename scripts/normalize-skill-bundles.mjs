import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { transformSkillText } from '../lib/skills/transform.mjs';
import { digestBytes } from '../lib/artifacts/digests.mjs';

const root=resolve(new URL('..',import.meta.url).pathname.replace(/^\/(?:[A-Za-z]:)/,(value)=>value.slice(1)));
for(const bundle of ['designer','writing']){
  const manifestPath=resolve(root,'skills/manifests',`${bundle}.json`);const manifest=JSON.parse(readFileSync(manifestPath,'utf8'));
  manifest.licenseState='unresolved';manifest.rightsReceipt=null;
  manifest.profiles.authoring={...manifest.profiles.authoring,externalOnly:true};
  for(const record of manifest.files){const path=resolve(root,'skills',bundle,record.path);const sourcePath=resolve(root,'..',bundle,record.path);const sourceBytes=readFileSync(sourcePath);const output=transformSkillText(sourceBytes.toString('utf8'),{bundle,path:record.path,profile:'audit',rules:[{from:'the operator',to:'the approving human'}]});writeFileSync(path,output);record.sourceDigest=digestBytes(sourceBytes);record.outputDigest=digestBytes(Buffer.from(output));record.transformations=[...new Set([...(record.transformations??[]),'package-relative-links','audit-capability-strip'])];}
  writeFileSync(manifestPath,`${JSON.stringify(manifest,null,2)}\n`);
}
