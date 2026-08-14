import { randomBytes } from 'node:crypto';
import { digestValue, isDigest } from './canonical.mjs';
import { decision } from './errors.mjs';
import { HOST_EVENT_LEDGER_FIELDS } from './host-event-ledger.mjs';
import { signRecord, verifyRecord } from './receipt-auth.mjs';

const DOMAIN='arcane.current-user-scope-amendment.v1';
const TTL_MS=300000;
export const CURRENT_USER_SCOPE_AMENDMENT_BOUND_FIELDS=Object.freeze(['schemaVersion','kind','amendmentId','acceptanceId','oldAcceptanceFingerprint','newAcceptanceFingerprint','sourceSetDigest','integratedStateIdentity','userPromptEventDigest','amendmentChallengeDigest','issuedAt','expiresAt','nonce']);
const INGRESS_FIELDS=Object.freeze(['acceptanceId','oldAcceptanceFingerprint','newAcceptanceFingerprint','sourceSetDigest','integratedStateIdentity','challengeToken','hostEvent','hostEventPayload']);
const EXPECTED_FIELDS=Object.freeze(['acceptanceId','oldAcceptanceFingerprint','newAcceptanceFingerprint','sourceSetDigest','integratedStateIdentity','userPromptEventDigest','challengeToken']);
const exactKeys=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every((key)=>Object.hasOwn(value,key));
const deny=(code,message,detail={})=>decision({allowed:false,code,message,detail});
const missing=()=>deny('ARC_APPROVAL_REQUIRED','frozen acceptance scope amendment is OUT_OF_SCOPE without a current signed user challenge',{disposition:'OUT_OF_SCOPE'});
const storeRecords=(store)=>store?.list?.()??[];
const exactPrompt=(payload)=>typeof(payload?.prompt??payload?.user_prompt)==='string'?(payload.prompt??payload.user_prompt):null;
const fresh=(record,now)=>{const issued=Date.parse(record.issuedAt),expires=Date.parse(record.expiresAt),current=now instanceof Date?now.valueOf():Number(now);return Number.isFinite(issued)&&Number.isFinite(expires)&&Number.isFinite(current)&&issued<=current&&expires>current&&expires-issued<=TTL_MS;};
const identity=(record)=>digestValue(Object.fromEntries(Object.entries(record).filter(([key])=>!['amendmentId','authentication'].includes(key))));
const currentUserPrompt=(ledgerStore,event,keyRing)=>Boolean(ledgerStore?.verify?.().allowed)&&digestValue(ledgerStore.records().at(-1))===digestValue(event)&&verifyRecord(event,event.authentication,{keyRing,boundFields:HOST_EVENT_LEDGER_FIELDS}).allowed&&event.eventType==='UserPromptSubmit'&&event.observedAuthority==='current-user';
const valid=(record)=>exactKeys(record,[...CURRENT_USER_SCOPE_AMENDMENT_BOUND_FIELDS,'authentication'])&&record.schemaVersion===1&&record.kind==='arcane-current-user-scope-amendment'&&typeof record.acceptanceId==='string'&&record.acceptanceId.length>0&&['amendmentId','oldAcceptanceFingerprint','newAcceptanceFingerprint','sourceSetDigest','integratedStateIdentity','userPromptEventDigest','amendmentChallengeDigest'].every((field)=>isDigest(record[field]))&&record.oldAcceptanceFingerprint!==record.newAcceptanceFingerprint&&/^[0-9a-f]{32}$/.test(record.nonce);

export const scopeAmendmentChallengeDigestFor=(acceptanceId,oldAcceptanceFingerprint,newAcceptanceFingerprint,sourceSetDigest,integratedStateIdentity,challengeToken)=>digestValue({domain:'arcane.current-user-scope-amendment-challenge.v1',acceptanceId,oldAcceptanceFingerprint,newAcceptanceFingerprint,sourceSetDigest,integratedStateIdentity,challengeToken});

/** Host ingress only: an amendment exists solely through current user intent. */
export function mintCurrentUserScopeAmendment(input,{ledgerStore,receiptStore,keyRing,keyId,clock=()=>new Date().toISOString()}={}) {
  if(!exactKeys(input,INGRESS_FIELDS))throw Object.assign(new TypeError('invalid current-user scope amendment ingress'),{code:'ARC_SCHEMA_INVALID'});
  const {acceptanceId,oldAcceptanceFingerprint,newAcceptanceFingerprint,sourceSetDigest,integratedStateIdentity,challengeToken,hostEvent,hostEventPayload}=input;
  if(typeof acceptanceId!=='string'||!acceptanceId||typeof challengeToken!=='string'||!challengeToken||![oldAcceptanceFingerprint,newAcceptanceFingerprint,sourceSetDigest,integratedStateIdentity].every(isDigest)||oldAcceptanceFingerprint===newAcceptanceFingerprint)throw Object.assign(new TypeError('invalid frozen acceptance amendment binding'),{code:'ARC_SCHEMA_INVALID'});
  if(!currentUserPrompt(ledgerStore,hostEvent,keyRing))throw Object.assign(new TypeError('current authenticated user prompt is unavailable'),{code:'ARC_AUTHORITY_NOT_ASSERTED'});
  if(hostEvent.payloadDigest!==digestValue(hostEventPayload)||exactPrompt(hostEventPayload)!==challengeToken)throw Object.assign(new TypeError('user amendment challenge does not match authenticated prompt'),{code:'ARC_BINDING_MISMATCH'});
  const userPromptEventDigest=digestValue(hostEvent);
  if(storeRecords(receiptStore).some((record)=>record.kind==='arcane-current-user-scope-amendment'&&record.acceptanceId===acceptanceId&&record.oldAcceptanceFingerprint===oldAcceptanceFingerprint&&record.newAcceptanceFingerprint===newAcceptanceFingerprint&&record.sourceSetDigest===sourceSetDigest&&record.integratedStateIdentity===integratedStateIdentity))throw Object.assign(new TypeError('frozen acceptance amendment already exists'),{code:'ARC_REPLAY_NONCE_SEEN'});
  const issuedAt=clock(),expiresAt=new Date(Date.parse(issuedAt)+TTL_MS).toISOString();
  const unsigned={schemaVersion:1,kind:'arcane-current-user-scope-amendment',acceptanceId,oldAcceptanceFingerprint,newAcceptanceFingerprint,sourceSetDigest,integratedStateIdentity,userPromptEventDigest,amendmentChallengeDigest:scopeAmendmentChallengeDigestFor(acceptanceId,oldAcceptanceFingerprint,newAcceptanceFingerprint,sourceSetDigest,integratedStateIdentity,challengeToken),issuedAt,expiresAt,nonce:randomBytes(16).toString('hex')};
  const record={...unsigned,amendmentId:digestValue(unsigned)},signed={...record,authentication:signRecord(record,{keyRing,keyId,boundFields:CURRENT_USER_SCOPE_AMENDMENT_BOUND_FIELDS,macDomain:DOMAIN})};
  receiptStore?.append?.(signed);return signed;
}

/** Consumer seam: reviewer hardening remains OUT_OF_SCOPE unless this verifies. */
export function verifyCurrentUserScopeAmendment(expected,{ledgerStore,receiptStore,keyRing,now=new Date()}={}) {
  if(!receiptStore?.verifyChain?.().ok)return deny('ARC_STORE_CORRUPT','scope amendment receipt chain is unavailable');
  if(!exactKeys(expected,EXPECTED_FIELDS)||typeof expected.acceptanceId!=='string'||!expected.acceptanceId||typeof expected.challengeToken!=='string'||!expected.challengeToken||!['oldAcceptanceFingerprint','newAcceptanceFingerprint','sourceSetDigest','integratedStateIdentity','userPromptEventDigest'].every((field)=>isDigest(expected[field]))||expected.oldAcceptanceFingerprint===expected.newAcceptanceFingerprint)return missing();
  const matches=storeRecords(receiptStore).filter((record)=>record.kind==='arcane-current-user-scope-amendment'&&record.acceptanceId===expected.acceptanceId&&record.oldAcceptanceFingerprint===expected.oldAcceptanceFingerprint&&record.newAcceptanceFingerprint===expected.newAcceptanceFingerprint&&record.sourceSetDigest===expected.sourceSetDigest&&record.integratedStateIdentity===expected.integratedStateIdentity);
  if(!matches.length)return missing();const record=matches.at(-1);
  if(!valid(record)||record.amendmentId!==identity(record))return deny('ARC_AUTH_FORGED','scope amendment record is malformed');
  const auth=verifyRecord(record,record.authentication,{keyRing,boundFields:CURRENT_USER_SCOPE_AMENDMENT_BOUND_FIELDS,macDomain:DOMAIN});if(!auth.allowed)return auth;
  if(!fresh(record,now))return deny('ARC_REPLAY_STALE','scope amendment is stale');
  for(const [field,value] of Object.entries({oldAcceptanceFingerprint:expected.oldAcceptanceFingerprint,newAcceptanceFingerprint:expected.newAcceptanceFingerprint,sourceSetDigest:expected.sourceSetDigest,integratedStateIdentity:expected.integratedStateIdentity,userPromptEventDigest:expected.userPromptEventDigest,amendmentChallengeDigest:scopeAmendmentChallengeDigestFor(expected.acceptanceId,expected.oldAcceptanceFingerprint,expected.newAcceptanceFingerprint,expected.sourceSetDigest,expected.integratedStateIdentity,expected.challengeToken)}))if(record[field]!==value)return deny('ARC_BINDING_MISMATCH','scope amendment differs from current frozen acceptance',{field});
  const promptEvent=ledgerStore?.records?.().find((event)=>digestValue(event)===record.userPromptEventDigest);
  if(!currentUserPrompt(ledgerStore,promptEvent,keyRing))return deny('ARC_AUTHORITY_NOT_ASSERTED','current signed user prompt is unavailable');
  if(storeRecords(receiptStore).some((entry)=>entry.kind==='arcane-current-user-scope-amendment-consumption'&&entry.amendmentId===record.amendmentId))return deny('ARC_REPLAY_NONCE_SEEN','scope amendment was already consumed');
  return decision({allowed:true,detail:{amendmentId:record.amendmentId,acceptanceId:record.acceptanceId,oldAcceptanceFingerprint:record.oldAcceptanceFingerprint,newAcceptanceFingerprint:record.newAcceptanceFingerprint,userPromptEventDigest:record.userPromptEventDigest}});
}

/** Verify first, then consume only when exact frozen-acceptance mutation commits. */
export function consumeCurrentUserScopeAmendment(expected,{ledgerStore,receiptStore,keyRing,now=new Date()}={}) {
  const verified=verifyCurrentUserScopeAmendment(expected,{ledgerStore,receiptStore,keyRing,now});if(!verified.allowed)return verified;
  const record=storeRecords(receiptStore).find((entry)=>entry.kind==='arcane-current-user-scope-amendment'&&entry.amendmentId===verified.detail.amendmentId);if(!record)return missing();
  receiptStore.append({kind:'arcane-current-user-scope-amendment-consumption',amendmentId:record.amendmentId,acceptanceId:record.acceptanceId,oldAcceptanceFingerprint:record.oldAcceptanceFingerprint,newAcceptanceFingerprint:record.newAcceptanceFingerprint,sourceSetDigest:record.sourceSetDigest,integratedStateIdentity:record.integratedStateIdentity,consumedAt:now instanceof Date?now.toISOString():new Date(now).toISOString()});return verified;
}
export { DOMAIN as CURRENT_USER_SCOPE_AMENDMENT_MAC_DOMAIN, TTL_MS as CURRENT_USER_SCOPE_AMENDMENT_TTL_MS };
