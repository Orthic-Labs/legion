import { mkdirSync, openSync, readFileSync, readdirSync, closeSync, fsyncSync, writeSync, existsSync, renameSync, unlinkSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { digestValue } from './canonical.mjs';
import { ArcaneError } from './errors.mjs';
const MAP={legion:'legion',sage:'sage',alchemist:'alchemist',oracle:'oracle'};
const dig=(domain,values)=>digestValue({domain,values});
const refresh=(path,record)=>{const tmp=`${path}.refresh-${process.pid}-${randomBytes(6).toString('hex')}`,fd=openSync(tmp,'w',0o600);try{writeSync(fd,`${JSON.stringify(record)}\n`);fsyncSync(fd);}finally{closeSync(fd);}try{renameSync(tmp,path);}catch(error){if(error.code!=='EEXIST')throw error;unlinkSync(path);renameSync(tmp,path);}};
export class AuthorityBindingStore {
  constructor({root,clock=()=>new Date().toISOString()}){this.root=root;this.clock=clock;}
  key(adapter,sessionId,agentId=null){return dig('arcane.authority.binding-key.v1',[adapter,sessionId,agentId]).slice(7);}
  path(adapter,sessionId,agentId=null){return join(this.root,`${this.key(adapter,sessionId,agentId)}.json`);}
  observe({adapter,sessionId,agentId=null,agentType,eventId,sessionRoot=false}){
    if(agentId==null)return {bound:false,reason:'missing-identity'}; if(!MAP[agentType]||(agentType==='legion'&&!sessionRoot))return {bound:false,reason:'unsupported-agent-type'};
    const key=this.key(adapter,sessionId,agentId), path=join(this.root,`${key}.json`), record={schemaVersion:1,kind:'arcane-authority-binding',adapter,sessionIdDigest:dig('arcane.authority.session.v1',[adapter,sessionId]),agentIdDigest:dig('arcane.authority.agent.v1',[adapter,sessionId,agentId]),agentType,authority:MAP[agentType],observedEventId:eventId,observedAt:this.clock()};
    mkdirSync(this.root,{recursive:true}); const text=`${JSON.stringify(record)}\n`;
    try { const fd=openSync(path,'wx',0o600); try{writeSync(fd,text);fsyncSync(fd);}finally{closeSync(fd);} return {bound:true,created:true,record}; }
    catch(error){if(error.code!=='EEXIST')throw error; const existing=this.get({adapter,sessionId,agentId}); if(!existing)throw new ArcaneError('ARC_STORE_CORRUPT','binding record corrupt'); if(['adapter','sessionIdDigest','agentIdDigest','agentType','authority'].some(k=>existing[k]!==record[k]))throw new ArcaneError('ARC_BINDING_MISMATCH','binding identity conflict'); if(existing.observedEventId!==eventId){const refreshed={...existing,observedEventId:eventId,observedAt:this.clock()};refresh(path,refreshed);return {bound:true,created:false,record:refreshed};} return {bound:true,created:false,record:existing};}
  }
  observeLegionSession({adapter,sessionId,eventId}){const agentId='legion-session-root';return this.observe({adapter,sessionId,agentId,agentType:'legion',eventId,sessionRoot:true});}
  get({adapter,sessionId,agentId=null}){try{const r=JSON.parse(readFileSync(this.path(adapter,sessionId,agentId),'utf8'));return r?.kind==='arcane-authority-binding'?r:null;}catch(e){if(e.code==='ENOENT')return null;throw new ArcaneError('ARC_STORE_CORRUPT','binding record corrupt');}}
  // A binding is routing metadata, never authority. On a read-only Stop it is
  // safe to quarantine one unreadable binding: this removes a bad lookup but
  // cannot mint an authority assertion or widen a later mutation.
  recover({adapter,sessionId,agentId=null}){const path=this.path(adapter,sessionId,agentId);if(!existsSync(path))return false;try{renameSync(path,`${path}.corrupt-${randomBytes(6).toString('hex')}`);return true;}catch{return false;}}
  // Resolve a binding without knowing the raw agentId. `path()` hashes the raw
  // id, and only the digest is ever stored, so an agent cannot look up its own
  // binding — which left `contract seal` unrunnable by anyone. Scanning by the
  // session digest (derivable from the sessionId the caller already has) is the
  // supported way back in. It never widens authority: only bindings a real
  // SubagentStart or authenticated root SessionStart wrote are visible, and
  // the requested authority must match.
  findLatest({adapter,sessionId,authority}){
    const want=dig('arcane.authority.session.v1',[adapter,sessionId]); let best=null;
    let names; try{names=readdirSync(this.root);}catch(e){if(e.code==='ENOENT')return null;throw e;}
    for(const name of names){
      if(!name.endsWith('.json'))continue; let r;
      try{r=JSON.parse(readFileSync(join(this.root,name),'utf8'));}catch{continue;}
      if(r?.kind!=='arcane-authority-binding'||r.adapter!==adapter||r.sessionIdDigest!==want)continue;
      if(authority&&r.authority!==authority)continue;
      if(!best||String(r.observedAt)>String(best.observedAt))best=r;
    }
    return best;
  }
  assertForTurn({adapter,sessionId,agentId,turnId,authorityLedger,keyId,authority,record=null}){if(authority)throw new ArcaneError('ARC_AUTHORITY_MODEL_CLAIMED','caller authority forbidden');if(!keyId)throw new ArcaneError('ARC_AUTH_KEY_UNAVAILABLE','key required');if(record&&(record.adapter!==adapter||record.sessionIdDigest!==dig('arcane.authority.session.v1',[adapter,sessionId])))throw new ArcaneError('ARC_BINDING_MISMATCH','binding identity conflict');const rec=record??this.get({adapter,sessionId,agentId});if(!rec)throw new ArcaneError('ARC_AUTHORITY_NOT_ASSERTED','binding missing');return authorityLedger.assertForTurn({turnId,authority:rec.authority,source:'host',assertedBy:`${adapter}:${rec.agentIdDigest}`,verificationMethod:'capability-signature',perMessage:true,keyId});}
}
