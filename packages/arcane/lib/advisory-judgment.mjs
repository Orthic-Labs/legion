import { randomBytes } from 'node:crypto';
import { digestValue, isDigest } from './canonical.mjs';
import { decision } from './errors.mjs';
import { signRecord, verifyRecord } from './receipt-auth.mjs';

// `authority` is host-asserted through `binding.bindingDigest`, not a
// self-asserted payload claim. receipt-auth therefore must never inspect it.
export const ADVISORY_JUDGMENT_BOUND_FIELDS = Object.freeze(['schemaVersion','kind','receiptId','agentIdDigest','runId','taskId','contractId','contractVersion','contractDigest','stateDigest','sourceDigest','sourceRevision','judgment','reviewOfReceiptDigest','binding','issuedAt','expiresAt','nonce']);
const KEYS = Object.freeze([...ADVISORY_JUDGMENT_BOUND_FIELDS, 'authority', 'authentication']);
const DOMAIN = 'arcane.advisory-judgment.v1';
const deny = (code, message, detail = {}) => decision({ allowed: false, code, message, detail });
const text = (v) => typeof v === 'string' && v.length > 0;
const exact = (v, keys) => v && typeof v === 'object' && Object.keys(v).length === keys.length && keys.every((key) => Object.hasOwn(v, key));
const execution = (r) => text(r.runId) && text(r.taskId) && text(r.contractId) && Number.isInteger(r.contractVersion) && r.contractVersion > 0 && isDigest(r.contractDigest);
const binding = (v) => exact(v, ['adapter','sessionId','bindingDigest']) && text(v.adapter) && text(v.sessionId) && isDigest(v.bindingDigest);
const judgment = (v) => exact(v, ['subjectDigest','disposition','rationaleDigest']) && isDigest(v.subjectDigest) && isDigest(v.rationaleDigest) && ['ACCEPT','REJECT','DENY','NEEDS_SPIKE','BLOCKED_EXTERNAL'].includes(v.disposition);
const authSubject = (receipt) => { const subject = { ...receipt }; delete subject.authority; return subject; };
function valid(r) { return exact(r, KEYS) && r.schemaVersion === 1 && r.kind === 'arcane-advisory-judgment' && ['sage','oracle'].includes(r.authority) && isDigest(r.receiptId) && isDigest(r.agentIdDigest) && execution(r) && isDigest(r.stateDigest) && isDigest(r.sourceDigest) && text(r.sourceRevision) && judgment(r.judgment) && (r.reviewOfReceiptDigest === null || isDigest(r.reviewOfReceiptDigest)) && binding(r.binding) && text(r.issuedAt) && text(r.expiresAt) && /^[0-9a-f]{32}$/.test(r.nonce); }
function hostBinding(store, adapter, sessionId, authority) { const found = store?.findLatest({ adapter, sessionId, authority }); if (!found || !isDigest(found.agentIdDigest)) throw Object.assign(new TypeError(`host ${authority} binding is unavailable`), { code: 'ARC_AUTHORITY_NOT_ASSERTED' }); return found; }
function fresh(r, now, freshnessMs) { const issued = Date.parse(r.issuedAt), expires = Date.parse(r.expiresAt), current = now instanceof Date ? now.valueOf() : Number(now); return Number.isFinite(issued) && Number.isFinite(expires) && Number.isFinite(current) && issued <= current && expires > current && expires - issued <= freshnessMs; }
const EXPECTED_FIELDS = Object.freeze(['runId','taskId','contractId','contractVersion','contractDigest','stateDigest','sourceDigest','sourceRevision','subjectDigest','disposition']);
function expectedMatch(r, expected) {
  for (const key of EXPECTED_FIELDS) {
    if (!Object.hasOwn(expected ?? {}, key)) continue;
    const actual = key === 'subjectDigest' ? r.judgment.subjectDigest : key === 'disposition' ? r.judgment.disposition : r[key];
    if (actual !== expected[key]) return key;
  }
  return null;
}
function sameJudgmentContext(sage, oracle) {
  return oracle.reviewOfReceiptDigest === digestValue(sage)
    && oracle.agentIdDigest !== sage.agentIdDigest
    && oracle.runId === sage.runId && oracle.taskId === sage.taskId
    && oracle.contractId === sage.contractId && oracle.contractVersion === sage.contractVersion
    && oracle.contractDigest === sage.contractDigest && oracle.stateDigest === sage.stateDigest
    && oracle.sourceDigest === sage.sourceDigest && oracle.sourceRevision === sage.sourceRevision
    && oracle.judgment.subjectDigest === sage.judgment.subjectDigest
    && oracle.judgment.disposition === sage.judgment.disposition;
}

export function mintAdvisoryJudgment(input, { keyRing, keyId, authorityBindingStore, clock = () => new Date().toISOString(), freshnessMs = 86400000 } = {}) {
  for (const field of ['authentication','receiptId','agentIdDigest','binding','authority']) if (Object.hasOwn(input ?? {}, field)) throw Object.assign(new TypeError(`caller field '${field}' is forbidden`), { code: 'ARC_AUTHORITY_MODEL_CLAIMED' });
  if (!exact(input, ['role','runId','taskId','contractId','contractVersion','contractDigest','stateDigest','sourceDigest','sourceRevision','judgment','reviewOfReceiptDigest','adapter','sessionId']) || !['sage','oracle'].includes(input.role) || !execution(input) || !isDigest(input.stateDigest) || !isDigest(input.sourceDigest) || !text(input.sourceRevision) || !judgment(input.judgment) || (input.reviewOfReceiptDigest !== null && !isDigest(input.reviewOfReceiptDigest)) || !text(input.adapter) || !text(input.sessionId)) throw Object.assign(new TypeError('invalid advisory judgment input'), { code: 'ARC_SCHEMA_INVALID' });
  if ((input.role === 'sage') !== (input.reviewOfReceiptDigest === null)) throw Object.assign(new TypeError('Sage originates judgments; Oracle reviews a Sage receipt'), { code: 'ARC_BINDING_MISMATCH' });
  const found = hostBinding(authorityBindingStore, input.adapter, input.sessionId, input.role); const issuedAt = clock();
  const unsigned = { schemaVersion: 1, kind: 'arcane-advisory-judgment', authority: input.role, agentIdDigest: found.agentIdDigest, runId: input.runId, taskId: input.taskId, contractId: input.contractId, contractVersion: input.contractVersion, contractDigest: input.contractDigest, stateDigest: input.stateDigest, sourceDigest: input.sourceDigest, sourceRevision: input.sourceRevision, judgment: input.judgment, reviewOfReceiptDigest: input.reviewOfReceiptDigest, binding: { adapter: input.adapter, sessionId: input.sessionId, bindingDigest: digestValue(found) }, issuedAt, expiresAt: new Date(Date.parse(issuedAt) + freshnessMs).toISOString(), nonce: randomBytes(16).toString('hex') };
  const receipt = { ...unsigned, receiptId: digestValue(unsigned) }; return { ...receipt, authentication: signRecord(authSubject(receipt), { keyRing, keyId, boundFields: ADVISORY_JUDGMENT_BOUND_FIELDS, macDomain: DOMAIN }) };
}
export function verifyAdvisoryJudgment(receipt, expected = {}, { keyRing, authorityBindingStore, now = new Date(), freshnessMs = 86400000 } = {}) {
  if (!valid(receipt)) return deny('ARC_SCHEMA_INVALID', 'advisory judgment is invalid');
  if (receipt.receiptId !== digestValue(Object.fromEntries(Object.entries(receipt).filter(([key]) => !['receiptId','authentication'].includes(key))))) return deny('ARC_AUTH_FORGED', 'advisory judgment identifier does not match content');
  if (!fresh(receipt, now, freshnessMs)) return deny('ARC_REPLAY_STALE', 'advisory judgment is stale or from the future');
  const found = authorityBindingStore?.findLatest({ adapter: receipt.binding.adapter, sessionId: receipt.binding.sessionId, authority: receipt.authority });
  if (!found || found.agentIdDigest !== receipt.agentIdDigest || digestValue(found) !== receipt.binding.bindingDigest) return deny('ARC_AUTHORITY_NOT_ASSERTED', 'host role binding is unavailable');
  const auth = verifyRecord(authSubject(receipt), receipt.authentication, { keyRing, boundFields: ADVISORY_JUDGMENT_BOUND_FIELDS, expectedBinding: expected, macDomain: DOMAIN }); if (!auth.allowed) return auth;
  const key = expectedMatch(receipt, expected); return key ? deny('ARC_BINDING_MISMATCH', 'judgment differs from expected binding', { field: key }) : decision({ allowed: true, detail: { receiptId: receipt.receiptId, authority: receipt.authority } });
}
export function persistAdvisoryJudgment(receipt, { receiptStore, ...options } = {}) {
  const checked = verifyAdvisoryJudgment(receipt, {}, options); if (!checked.allowed) return checked;
  if (!receiptStore?.verifyChain?.().ok) return deny('ARC_STORE_CORRUPT', 'receipt store is unavailable or corrupt');
  const existing = receiptStore.list().filter((r) => r.kind === receipt.kind);
  if (existing.some((r) => r.receiptId === receipt.receiptId || (r.agentIdDigest === receipt.agentIdDigest && r.nonce === receipt.nonce))) return deny('ARC_REPLAY_NONCE_SEEN', 'advisory judgment was already persisted');
  if (receipt.authority === 'oracle') {
    const sage = existing.find((record) => record.authority === 'sage' && digestValue(record) === receipt.reviewOfReceiptDigest);
    if (!sage || !verifyAdvisoryJudgment(sage, {}, options).allowed || !sameJudgmentContext(sage, receipt)) return deny('ARC_BINDING_MISMATCH', 'Oracle judgment does not independently review a current Sage judgment');
  }
  return decision({ allowed: true, detail: receiptStore.append(receipt) });
}
export function findCurrentAdvisoryJudgment({ receiptStore, expected = {} }, options = {}) { if (!receiptStore?.verifyChain?.().ok) return deny('ARC_STORE_CORRUPT', 'receipt store is unavailable or corrupt'); const records = receiptStore.list().filter((r) => r.kind === 'arcane-advisory-judgment'); const sages = records.filter((r) => r.authority === 'sage').reverse(); const oracles = records.filter((r) => r.authority === 'oracle').reverse(); for (const sage of sages) { const s = verifyAdvisoryJudgment(sage, expected, options); if (!s.allowed) continue; for (const oracle of oracles) { if (!sameJudgmentContext(sage, oracle)) continue; const o = verifyAdvisoryJudgment(oracle, expected, options); if (o.allowed) return decision({ allowed: true, detail: { sageReceiptId: sage.receiptId, oracleReceiptId: oracle.receiptId, judgment: sage.judgment } }); } } return deny('ARC_EVIDENCE_INSUFFICIENT', 'current independent Sage/Oracle judgment is unavailable'); }
export function validateAdvisoryJudgmentCase(value) {
  if (!exact(value, ['case','expected','sage','oracle']) || !text(value.case) || !exact(value.expected, EXPECTED_FIELDS) || !execution(value.expected) || !isDigest(value.expected.stateDigest) || !isDigest(value.expected.sourceDigest) || !text(value.expected.sourceRevision) || !isDigest(value.expected.subjectDigest) || !['ACCEPT','REJECT','DENY','NEEDS_SPIKE','BLOCKED_EXTERNAL'].includes(value.expected.disposition)) return false;
  const shape = (r, role, review) => exact(r, ['role','adapter','sessionId','judgment','review']) && r.role === role && text(r.adapter) && text(r.sessionId) && judgment(r.judgment) && r.review === review;
  return shape(value.sage, 'sage', null) && shape(value.oracle, 'oracle', 'sage') && value.sage.judgment.subjectDigest === value.expected.subjectDigest && value.oracle.judgment.subjectDigest === value.expected.subjectDigest && value.sage.judgment.disposition === value.expected.disposition && value.oracle.judgment.disposition === value.expected.disposition;
}
