import { randomBytes } from 'node:crypto';
import { digestValue, isDigest } from '../../contracts/arcane/canonical.mjs';
import { decision } from '../../contracts/arcane/errors.mjs';
import { HOST_EVENT_LEDGER_FIELDS } from '../../host/arcane/host-event-ledger.mjs';
import { signRecord, verifyRecord } from '../../guard/compat/audit/receipt-auth.mjs';

const DOMAIN = 'arcane.current-user-risk-acceptance.v1';
const TTL_MS = 300000;
export const CURRENT_USER_RISK_ACCEPTANCE_BOUND_FIELDS = Object.freeze(['schemaVersion','kind','acceptanceId','riskId','riskDigest','acceptanceLedgerFingerprint','integratedStateIdentity','sourceSetDigest','userPromptEventDigest','acceptanceChallengeDigest','disposition','issuedAt','expiresAt','nonce']);
const INGRESS_FIELDS = Object.freeze(['riskId','riskDigest','acceptanceLedgerFingerprint','integratedStateIdentity','sourceSetDigest','challengeToken','hostEvent','hostEventPayload','disposition']);
const EXPECTED_FIELDS = Object.freeze(['riskId','riskDigest','acceptanceLedgerFingerprint','integratedStateIdentity','sourceSetDigest','userPromptEventDigest','challengeToken']);
const deny = (code, message, detail = {}) => decision({ allowed: false, code, message, detail });
const missing = () => Object.freeze({ allowed:false, code:'ACCEPTANCE_AUTHORITY_MISSING', message:'current-user risk acceptance is missing', detail:Object.freeze({}), failClosed:false, enforcementHealth:'strong' });
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
export const acceptanceChallengeDigestFor = (riskId, challengeToken) => digestValue({ domain:'arcane.current-user-risk-challenge.v1', riskId, challengeToken });
const fresh = (record, now) => { const issued=Date.parse(record.issuedAt), expires=Date.parse(record.expiresAt), current=now instanceof Date ? now.valueOf() : Number(now); return Number.isFinite(issued)&&Number.isFinite(expires)&&Number.isFinite(current)&&issued<=current&&expires>current&&expires-issued<=TTL_MS; };
const valid = (record) => exactKeys(record,[...CURRENT_USER_RISK_ACCEPTANCE_BOUND_FIELDS,'authentication']) && record.schemaVersion===1 && record.kind==='arcane-current-user-risk-acceptance' && typeof record.riskId==='string' && record.riskId.length>0 && ['riskDigest','acceptanceLedgerFingerprint','integratedStateIdentity','sourceSetDigest','userPromptEventDigest','acceptanceChallengeDigest','acceptanceId'].every((field)=>isDigest(record[field])) && ['ACCEPT','REJECT'].includes(record.disposition) && /^[0-9a-f]{32}$/.test(record.nonce);
const identity = (record) => digestValue(Object.fromEntries(Object.entries(record).filter(([key])=>!['acceptanceId','authentication'].includes(key))));
const storeRecords = (store) => store?.list?.() ?? [];
const exactPrompt = (payload) => typeof (payload?.prompt ?? payload?.user_prompt) === 'string' ? (payload.prompt ?? payload.user_prompt) : null;
const currentUserPrompt = (ledgerStore,event,keyRing) => Boolean(ledgerStore?.verify?.().allowed) && digestValue(ledgerStore.records().at(-1))===digestValue(event) && verifyRecord(event,event.authentication,{keyRing,boundFields:HOST_EVENT_LEDGER_FIELDS}).allowed && event.eventType==='UserPromptSubmit' && event.observedAuthority==='current-user';

/** Host ingress only: agent roles cannot create a current-user prompt event. */
export function mintCurrentUserRiskAcceptance(input,{ledgerStore,receiptStore,keyRing,keyId,clock=()=>new Date().toISOString()}={}) {
  if (!exactKeys(input,INGRESS_FIELDS)) throw Object.assign(new TypeError('invalid current-user risk acceptance ingress'),{code:'ARC_SCHEMA_INVALID'});
  const {riskId,riskDigest,acceptanceLedgerFingerprint,integratedStateIdentity,sourceSetDigest,challengeToken,hostEvent,hostEventPayload,disposition}=input;
  if (typeof riskId!=='string'||!riskId||typeof challengeToken!=='string'||!challengeToken||![riskDigest,acceptanceLedgerFingerprint,integratedStateIdentity,sourceSetDigest].every(isDigest)||!['ACCEPT','REJECT'].includes(disposition)) throw Object.assign(new TypeError('invalid current-user risk acceptance binding'),{code:'ARC_SCHEMA_INVALID'});
  if (!currentUserPrompt(ledgerStore,hostEvent,keyRing)) throw Object.assign(new TypeError('current authenticated user prompt is unavailable'),{code:'ARC_AUTHORITY_NOT_ASSERTED'});
  if (hostEvent.payloadDigest!==digestValue(hostEventPayload)||exactPrompt(hostEventPayload)!==challengeToken) throw Object.assign(new TypeError('user challenge does not match authenticated prompt'),{code:'ARC_BINDING_MISMATCH'});
  const userPromptEventDigest=digestValue(hostEvent);
  if (storeRecords(receiptStore).some((record)=>record.kind==='arcane-current-user-risk-acceptance'&&record.riskId===riskId&&record.integratedStateIdentity===integratedStateIdentity&&record.acceptanceLedgerFingerprint===acceptanceLedgerFingerprint&&record.sourceSetDigest===sourceSetDigest)) throw Object.assign(new TypeError('risk/state/ledger/source acceptance already exists'),{code:'ARC_REPLAY_NONCE_SEEN'});
  const issuedAt=clock(), expiresAt=new Date(Date.parse(issuedAt)+TTL_MS).toISOString();
  const unsigned={schemaVersion:1,kind:'arcane-current-user-risk-acceptance',riskId,riskDigest,acceptanceLedgerFingerprint,integratedStateIdentity,sourceSetDigest,userPromptEventDigest,acceptanceChallengeDigest:acceptanceChallengeDigestFor(riskId,challengeToken),disposition,issuedAt,expiresAt,nonce:randomBytes(16).toString('hex')};
  const record={...unsigned,acceptanceId:digestValue(unsigned)};
  const signed={...record,authentication:signRecord(record,{keyRing,keyId,boundFields:CURRENT_USER_RISK_ACCEPTANCE_BOUND_FIELDS,macDomain:DOMAIN})};
  receiptStore?.append?.(signed); return signed;
}

/** Completion-gate integration seam; missing records block with ACCEPTANCE_AUTHORITY_MISSING. */
export function verifyCurrentUserRiskAcceptance(expected,{ledgerStore,receiptStore,keyRing,now=new Date()}={}) {
  if (!receiptStore?.verifyChain?.().ok) return deny('ARC_STORE_CORRUPT','risk acceptance receipt chain is unavailable');
  if (!exactKeys(expected,EXPECTED_FIELDS)||typeof expected.riskId!=='string'||!expected.riskId||typeof expected.challengeToken!=='string'||!expected.challengeToken||!['riskDigest','acceptanceLedgerFingerprint','integratedStateIdentity','sourceSetDigest','userPromptEventDigest'].every((field)=>isDigest(expected[field]))) return missing();
  const matches=storeRecords(receiptStore).filter((record)=>record.kind==='arcane-current-user-risk-acceptance'&&record.riskId===expected.riskId&&record.integratedStateIdentity===expected.integratedStateIdentity&&record.acceptanceLedgerFingerprint===expected.acceptanceLedgerFingerprint&&record.sourceSetDigest===expected.sourceSetDigest);
  if (!matches.length) return missing(); const record=matches.at(-1);
  if (!valid(record)||record.acceptanceId!==identity(record)) return deny('ARC_AUTH_FORGED','risk acceptance record is malformed');
  const auth=verifyRecord(record,record.authentication,{keyRing,boundFields:CURRENT_USER_RISK_ACCEPTANCE_BOUND_FIELDS,macDomain:DOMAIN}); if(!auth.allowed)return auth;
  if (!fresh(record,now)) return deny('ARC_REPLAY_STALE','risk acceptance is stale');
  for (const [field,value] of Object.entries({riskDigest:expected.riskDigest,acceptanceLedgerFingerprint:expected.acceptanceLedgerFingerprint,integratedStateIdentity:expected.integratedStateIdentity,sourceSetDigest:expected.sourceSetDigest,userPromptEventDigest:expected.userPromptEventDigest,acceptanceChallengeDigest:acceptanceChallengeDigestFor(expected.riskId,expected.challengeToken)})) if(record[field]!==value)return deny('ARC_BINDING_MISMATCH','risk acceptance differs from current state',{field});
  const promptEvent=ledgerStore?.records?.().find((event)=>digestValue(event)===record.userPromptEventDigest);
  if (!currentUserPrompt(ledgerStore,promptEvent,keyRing)) return deny('ARC_AUTHORITY_NOT_ASSERTED','current signed user prompt is unavailable');
  if(record.disposition!=='ACCEPT') return missing();
  if(storeRecords(receiptStore).some((entry)=>entry.kind==='arcane-current-user-risk-acceptance-consumption'&&entry.acceptanceId===record.acceptanceId)) return deny('ARC_REPLAY_NONCE_SEEN','risk acceptance was already consumed');
  return decision({allowed:true,detail:{acceptanceId:record.acceptanceId,userPromptEventDigest:record.userPromptEventDigest,acceptanceChallengeDigest:record.acceptanceChallengeDigest}});
}

/**
 * Structured close-admission seam for material residual risk.  Completion
 * consumers can distinguish a human admission from ordinary gate evidence;
 * no agent role, stale prompt, or altered state can produce this result.
 */
export function evaluateResidualRiskCloseAdmission(expected, options = {}) {
  const verified=verifyCurrentUserRiskAcceptance(expected,options);
  if(!verified.allowed)return Object.freeze({allowed:false,code:verified.code,message:verified.message,closeDisposition:'BLOCKED',residualRisk:Object.freeze({riskId:expected?.riskId??null,riskDigest:expected?.riskDigest??null}),detail:verified.detail??Object.freeze({})});
  return Object.freeze({allowed:true,closeDisposition:'ADMIT_RESIDUAL_RISK',residualRisk:Object.freeze({riskId:expected.riskId,riskDigest:expected.riskDigest}),acceptance:Object.freeze({acceptanceId:verified.detail.acceptanceId,userPromptEventDigest:verified.detail.userPromptEventDigest,acceptanceChallengeDigest:verified.detail.acceptanceChallengeDigest}),detail:verified.detail});
}

/** Verify first, then consume only after a completion gate succeeds. */
export function consumeCurrentUserRiskAcceptance(expected,{ledgerStore,receiptStore,keyRing,now=new Date()}={}) {
  const verified=verifyCurrentUserRiskAcceptance(expected,{ledgerStore,receiptStore,keyRing,now});
  if(!verified.allowed)return verified;
  const record=storeRecords(receiptStore).find((entry)=>entry.kind==='arcane-current-user-risk-acceptance'&&entry.acceptanceId===verified.detail.acceptanceId);
  if(!record)return missing();
  receiptStore.append({kind:'arcane-current-user-risk-acceptance-consumption',acceptanceId:record.acceptanceId,riskId:record.riskId,integratedStateIdentity:record.integratedStateIdentity,acceptanceLedgerFingerprint:record.acceptanceLedgerFingerprint,sourceSetDigest:record.sourceSetDigest,consumedAt:now instanceof Date?now.toISOString():new Date(now).toISOString()});
  return verified;
}
export { DOMAIN as CURRENT_USER_RISK_ACCEPTANCE_MAC_DOMAIN, TTL_MS as CURRENT_USER_RISK_ACCEPTANCE_TTL_MS };
