import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { validateSchema } from '../../../lib/qualification/schema-validator.mjs';
import { digestValue } from './canonical.mjs';
import { decision } from './errors.mjs';
import { signRecord, verifyRecord } from './receipt-auth.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'schemas');
const requestSchema = JSON.parse(readFileSync(join(root, 'high-risk-assurance-request-v1.schema.json'), 'utf8'));
const receiptSchema = JSON.parse(readFileSync(join(root, 'high-risk-assurance-receipt-v1.schema.json'), 'utf8'));
export const HIGH_RISK_REQUEST_BOUND_FIELDS = Object.freeze(['schemaVersion','kind','runId','taskId','contractId','contractVersion','contractDigest','sourceRevision','intentRestatement','blastRadius','whySafe','invocationProofDigest','binding','issuedAt','expiresAt','nonce']);
export const HIGH_RISK_ASSURANCE_BOUND_FIELDS = Object.freeze(['schemaVersion','kind','receiptId','requestDigest','invocationProofDigest','runId','taskId','contractId','contractVersion','contractDigest','sourceRevision','binding','verdict','issuedAt']);
export function mintAssuranceRequest(request, { keyRing, keyId }) {
  if (request && Object.hasOwn(request, 'authentication')) throw Object.assign(new TypeError('caller authentication is forbidden'), { code: 'ARC_AUTHORITY_MODEL_CLAIMED' });
  const signed = { ...request, authentication: signRecord(request, { keyRing, keyId, boundFields: HIGH_RISK_REQUEST_BOUND_FIELDS }) };
  if (validateSchema(requestSchema, signed).length) throw Object.assign(new TypeError('invalid high-risk assurance request'), { code: 'ARC_SCHEMA_INVALID' });
  return signed;
}
export function mintAssuranceReceipt(receipt, { keyRing, keyId }) {
  // Authentication is deliberately absent from caller input; validate only
  // after the kernel has attached its MAC so callers cannot supply one.
  if (receipt && Object.hasOwn(receipt, 'authentication')) throw Object.assign(new TypeError('caller authentication is forbidden'), { code: 'ARC_AUTHORITY_MODEL_CLAIMED' });
  const signed = { ...receipt, authentication: signRecord(receipt, { keyRing, keyId, boundFields: HIGH_RISK_ASSURANCE_BOUND_FIELDS }) };
  if (validateSchema(receiptSchema, signed).length) throw Object.assign(new TypeError('invalid high-risk assurance receipt'), { code: 'ARC_SCHEMA_INVALID' });
  return signed;
}
export function verifyAssurance({ request, receipt, expected }, { keyRing, authorityBindingStore, now = new Date(), freshnessMs = 86400000 } = {}) {
  if (!keyRing || !authorityBindingStore || !expected || validateSchema(requestSchema, request).length || validateSchema(receiptSchema, receipt).length || receipt.requestDigest !== digestValue(request)) return decision({allowed:false,code:'ARC_CLAIM_PREREQUISITE_UNMET',message:'sealed Sage request and Covenant receipt must validate',detail:{}});
  for (const field of ['runId','taskId','contractId','contractVersion','contractDigest','sourceRevision']) {
    if (request[field] !== expected[field] || receipt[field] !== expected[field]) return decision({allowed:false,code:'ARC_BINDING_MISMATCH',message:'assurance does not match exact execution binding',detail:{field}});
  }
  const requestIssued=Date.parse(request.issuedAt), requestExpires=Date.parse(request.expiresAt), receiptIssued=Date.parse(receipt.issuedAt);
  if (!Number.isFinite(requestIssued) || !Number.isFinite(requestExpires) || requestIssued > now.valueOf() || requestExpires < now.valueOf() || requestExpires - requestIssued > freshnessMs || !Number.isFinite(receiptIssued) || receiptIssued > now.valueOf() || receiptIssued + freshnessMs < now.valueOf()) return decision({allowed:false,code:'ARC_CLAIM_PREREQUISITE_UNMET',message:'Sage request or Covenant receipt is stale or from the future',detail:{}});
  const sageBinding=authorityBindingStore.findLatest({adapter:request.binding.adapter,sessionId:request.binding.sessionId,authority:'sage'});
  if(!sageBinding || digestValue(sageBinding)!==request.binding.bindingDigest) return decision({allowed:false,code:'ARC_CLAIM_PREREQUISITE_UNMET',message:'Sage authority binding is invalid',detail:{}});
  const sageAuth=verifyRecord(request,request.authentication,{keyRing,boundFields:HIGH_RISK_REQUEST_BOUND_FIELDS,expectedBinding:{runId:expected.runId,taskId:expected.taskId,contractId:expected.contractId}});
  if(!sageAuth.allowed)return sageAuth;
  const binding = authorityBindingStore?.findLatest({adapter:receipt.binding.adapter,sessionId:receipt.binding.sessionId,authority:'covenant'});
  if (!binding || digestValue(binding) !== receipt.binding.bindingDigest) return decision({allowed:false,code:'ARC_CLAIM_PREREQUISITE_UNMET',message:'Covenant authority binding is invalid',detail:{}});
  const auth = verifyRecord(receipt, receipt.authentication, {keyRing,boundFields:HIGH_RISK_ASSURANCE_BOUND_FIELDS,expectedBinding:{runId:expected.runId,taskId:expected.taskId,contractId:expected.contractId}});
  return auth.allowed ? decision({allowed:true,detail:{covenantVerdict:'SUPPORTED',fields:{intentRestatement:request.intentRestatement,blastRadius:request.blastRadius,whySafe:request.whySafe}}}) : auth;
}
