import {buildJudgmentPacket} from './judgment-packets.mjs';
import {reviewerPolicy} from './reviewer-policy.mjs';
import {sameBinding} from './binding.mjs';

export function prepareAdjudication(subjects,policy){return subjects.map((subject,index)=>({policy:reviewerPolicy({...policy,contextId:`${policy.contextPrefix??'review'}-${index}`}),packet:buildJudgmentPacket({subject,reviewerRole:policy.reviewer,budget:policy.budget,evidence:subject.evidence})}));}
const MODES=new Set(['auto','disabled','required']);
export async function adjudicateSubjects(subjects=[],policy={},host={}){
  const mode=policy.mode??'auto';if(!MODES.has(mode))throw new TypeError(`unknown reasoning mode: ${mode}`);
  const binding=host.binding??policy.binding??null;const review=host.reviewer?.review??host.reviewer?.run;const reviewerAvailable=host.reviewer?.state!=='unavailable'&&typeof review==='function';
  if(mode==='disabled'||!reviewerAvailable){const required=mode==='required';const receipts=subjects.map((subject,index)=>({schemaVersion:1,kind:'nemesis-judgment-receipt',subjectId:subject.id,status:required?'unproven':'skipped',complete:false,binding,contextId:`${policy.contextPrefix??'review'}-${index}`,reviewer:null,verdict:null,evidenceRefs:[...(subject.evidence??[])],gaps:[{kind:required?'required-reviewer-unavailable':'reasoning-disabled'}]}));return{complete:subjects.length===0||(!required&&mode==='disabled'),receipts,packets:[]};}
  const packets=prepareAdjudication(subjects,{...policy,reviewer:policy.reviewer??host.reviewer.id});const receipts=[];
  for(const {policy:reviewPolicy,packet} of packets){const value=await review.call(host.reviewer,packet,reviewPolicy);const receipt={schemaVersion:1,kind:'nemesis-judgment-receipt',subjectId:packet.subject?.id,status:value?.status??'unproven',complete:value?.complete===true,binding,contextId:reviewPolicy.contextId,reviewer:reviewPolicy.reviewer,verdict:value?.verdict??null,evidenceRefs:packet.evidence,gaps:value?.gaps??[]};validateJudgmentReceipt(receipt,binding);receipts.push(receipt);}
  return{complete:receipts.every(({complete})=>complete),receipts,packets};
}
export function validateJudgmentReceipt(receipt,expectedBinding){if(receipt?.schemaVersion!==1||receipt.kind!=='nemesis-judgment-receipt')throw new TypeError('invalid judgment receipt');if(!sameBinding(receipt.binding,expectedBinding))throw new TypeError('judgment receipt binding mismatch');if(receipt.complete===true&&!['confirmed','rejected','unproven','needs-human'].includes(receipt.verdict))throw new TypeError('complete judgment receipt requires verdict');if(!Array.isArray(receipt.evidenceRefs)||!Array.isArray(receipt.gaps))throw new TypeError('judgment receipt evidence contract invalid');return receipt;}
