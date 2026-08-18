const digestPattern=/^sha256:[a-f0-9]{64}$/;
const sameBinding=(actual,expected)=>actual&&expected&&actual.repositoryRevision===expected.repositoryRevision&&actual.digest===expected.digest;
export function validateEvidenceRefs(refs,{root,evidenceIndex={},binding,now}={}){
  const errors=[];const instant=Date.parse(now??'');
  if(!Array.isArray(refs)||refs.length===0)return['evidence-refs-empty'];
  for(const ref of refs){const record=evidenceIndex[ref];if(!record){errors.push(`evidence-ref-missing:${ref}`);continue;}if(!digestPattern.test(record.digest??''))errors.push(`evidence-digest-invalid:${ref}`);if(!sameBinding(record.binding,binding))errors.push(`evidence-binding-mismatch:${ref}`);if(record.expiresAt&&(!Number.isFinite(instant)||Date.parse(record.expiresAt)<=instant))errors.push(`evidence-expired:${ref}`);if(!root||!record.path){errors.push(`evidence-path-missing:${ref}`);}else{try{const bytes=readFileSync(resolve(root,record.path));const actual=`sha256:${createHash('sha256').update(bytes).digest('hex')}`;if(actual!==record.digest)errors.push(`evidence-bytes-mismatch:${ref}`);}catch{errors.push(`evidence-bytes-missing:${ref}`);}}if(record.storageReceipt?.immutable!==true)errors.push(`evidence-storage-unproven:${ref}`);if(record.toolReceipt?.complete!==true||!digestPattern.test(record.toolReceipt?.tool?.executableDigest??''))errors.push(`evidence-tool-unproven:${ref}`);}
  return errors;
}
import{createHash}from'node:crypto';import{readFileSync}from'node:fs';import{resolve}from'node:path';
