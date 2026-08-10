import { mkdirSync, openSync, readFileSync, closeSync, fsyncSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { digestValue } from './canonical.mjs';
import { ArcaneError } from './errors.mjs';
const MAP={sage:'sage',alchemist:'alchemist',oracle:'oracle','covenant-seat':'covenant'};
const dig=(domain,values)=>digestValue({domain,values});
export class AuthorityBindingStore {
  constructor({root,clock=()=>new Date().toISOString()}){this.root=root;this.clock=clock;}
  key(adapter,sessionId,agentId=null){return dig('arcane.authority.binding-key.v1',[adapter,sessionId,agentId]).slice(7);}
  path(adapter,sessionId,agentId=null){return join(this.root,`${this.key(adapter,sessionId,agentId)}.json`);}
  observe({adapter,sessionId,agentId=null,agentType,eventId}){
    if(agentId==null)return {bound:false,reason:'missing-identity'}; if(!MAP[agentType])return {bound:false,reason:'unsupported-agent-type'};
    const key=this.key(adapter,sessionId,agentId), path=join(this.root,`${key}.json`), record={schemaVersion:1,kind:'arcane-authority-binding',adapter,sessionIdDigest:dig('arcane.authority.session.v1',[adapter,sessionId]),agentIdDigest:dig('arcane.authority.agent.v1',[adapter,sessionId,agentId]),agentType,authority:MAP[agentType],observedEventId:eventId,observedAt:this.clock()};
    mkdirSync(this.root,{recursive:true}); const text=`${JSON.stringify(record)}\n`;
    try { const fd=openSync(path,'wx',0o600); try{writeSync(fd,text);fsyncSync(fd);}finally{closeSync(fd);} return {bound:true,created:true,record}; }
    catch(error){if(error.code!=='EEXIST')throw error; const existing=this.get({adapter,sessionId,agentId}); if(!existing)throw new ArcaneError('ARC_STORE_CORRUPT','binding record corrupt'); if(['adapter','sessionIdDigest','agentIdDigest','agentType','authority'].some(k=>existing[k]!==record[k]))throw new ArcaneError('ARC_BINDING_MISMATCH','binding identity conflict'); return {bound:true,created:false,record:existing};}
  }
  get({adapter,sessionId,agentId=null}){try{const r=JSON.parse(readFileSync(this.path(adapter,sessionId,agentId),'utf8'));return r?.kind==='arcane-authority-binding'?r:null;}catch(e){if(e.code==='ENOENT')return null;throw new ArcaneError('ARC_STORE_CORRUPT','binding record corrupt');}}
  assertForTurn({adapter,sessionId,agentId,turnId,authorityLedger,keyId,authority}){if(authority)throw new ArcaneError('ARC_AUTHORITY_MODEL_CLAIMED','caller authority forbidden');if(!keyId)throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE','key required');const record=this.get({adapter,sessionId,agentId});if(!record)throw new ArcaneError('ARC_AUTHORITY_NOT_ASSERTED','binding missing');return authorityLedger.assertForTurn({turnId,authority:record.authority,source:'host',assertedBy:`${adapter}:${record.agentIdDigest}`,verificationMethod:'capability-signature',perMessage:true,keyId});}
}
