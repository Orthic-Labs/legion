import { digest, sameBinding } from './binding.mjs';
import { semanticProjection } from '../verification/projection.mjs';

function integrityGaps(snapshot) {
  const gaps=[];const providers=new Map((snapshot?.plan?.providers??[]).map((provider)=>[provider.id,provider]));const order=new Map((snapshot?.receipts??[]).map((receipt,index)=>[receipt.provider,index]));
  for(const [id,provider] of providers)for(const dependency of provider.dependencies??provider.dependsOn??[])if(order.has(id)&&(!order.has(dependency)||order.get(dependency)>order.get(id)))gaps.push({kind:'dependency-order',provider:id,dependency});
  const intervals=(snapshot?.receipts??[]).filter(({concurrencyKey,startedAt,completedAt})=>concurrencyKey&&startedAt&&completedAt);for(let left=0;left<intervals.length;left++)for(let right=left+1;right<intervals.length;right++){const a=intervals[left],b=intervals[right];if(a.concurrencyKey===b.concurrencyKey&&Date.parse(a.startedAt)<Date.parse(b.completedAt)&&Date.parse(b.startedAt)<Date.parse(a.completedAt))gaps.push({kind:'exclusive-lock-overlap',providers:[a.provider,b.provider],concurrencyKey:a.concurrencyKey});}
  const contexts=new Set();for(const judgment of snapshot?.judgments??[]){if(!judgment.contextId)continue;if(contexts.has(judgment.contextId))gaps.push({kind:'reasoning-context-reuse',contextId:judgment.contextId});contexts.add(judgment.contextId);}
  return gaps;
}

export async function verifySealedRun({ priorRun, currentRepository }, host) {
  const prior = typeof priorRun === 'string' ? JSON.parse(await host.fs.readFile(priorRun, 'utf8')) : priorRun;
  const currentBinding = currentRepository?.binding ?? currentRepository?.snapshot?.binding ?? currentRepository ?? null;
  const expectedBinding = prior?.binding ?? prior?.plan?.binding ?? null;
  const current=currentRepository?.snapshot??currentRepository?.run??null;const gaps=[];
  if(!prior||!expectedBinding||!sameBinding(expectedBinding,currentBinding))gaps.push({kind:'binding-drift'});
  if(!current)gaps.push({kind:'semantic-replay-unavailable'});
  const priorSemantic=digest(semanticProjection(prior??null));const currentSemantic=current?digest(semanticProjection(current)):null;
  if(current&&priorSemantic!==currentSemantic)gaps.push({kind:'semantic-drift',priorDigest:priorSemantic,currentDigest:currentSemantic});
  if(current)gaps.push(...integrityGaps(current));
  const valid=gaps.length===0;
  return { schemaVersion: 1, kind: 'nemesis-verification-receipt', valid, priorDigest: priorSemantic,currentDigest:currentSemantic, binding: currentBinding, status: valid ? 'pass' : 'unproven', gaps, verifiedAt: host.clock.now().toISOString() };
}
