import { randomBytes } from 'node:crypto';

import { digestValue, isDigest } from '../../contracts/arcane/canonical.mjs';
import { decision } from '../../contracts/arcane/errors.mjs';
import { signRecord, verifyRecord } from '../../guard/compat/audit/receipt-auth.mjs';

export const ADVISORY_ARTIFACT_BOUND_FIELDS = Object.freeze([
  'schemaVersion', 'kind', 'receiptId', 'artifactDigest', 'briefDigest', 'bundleId', 'bundleVersion',
  'profileId', 'manifestDigest', 'profileDigest', 'producerAgentIdDigest', 'runId', 'taskId',
  'contractId', 'contractVersion', 'contractDigest', 'sourceRevision', 'binding', 'issuedAt',
  'expiresAt', 'nonce',
]);

export const ADVISORY_CERTIFICATION_BOUND_FIELDS = Object.freeze([
  'schemaVersion', 'kind', 'receiptId', 'artifactReceiptDigest', 'artifactDigest', 'briefDigest',
  'bundleId', 'bundleVersion', 'profileId', 'manifestDigest', 'profileDigest', 'producerAgentIdDigest',
  'certifierAgentIdDigest', 'runId', 'taskId', 'contractId', 'contractVersion', 'contractDigest',
  'sourceRevision', 'checklistEvidence', 'verdict', 'binding', 'issuedAt', 'expiresAt', 'nonce',
]);

const ARTIFACT_DOMAIN = 'arcane.advisory-artifact-receipt.v1';
const CERTIFICATION_DOMAIN = 'arcane.advisory-certification-receipt.v1';
const EXECUTION_FIELDS = Object.freeze(['runId', 'taskId', 'contractId', 'contractVersion', 'contractDigest', 'sourceRevision']);
const INPUT_FIELDS = Object.freeze(['artifactDigest', 'briefDigest', 'bundleId', 'bundleVersion', 'profileId', 'manifestDigest', 'profileDigest']);

const deny = (code, message, detail = {}) => decision({ allowed: false, code, message, detail });
const nonempty = (value) => typeof value === 'string' && value.length > 0;
const exactKeys = (value, keys) => value && typeof value === 'object'
  && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const validExecution = (value) => nonempty(value.runId) && nonempty(value.taskId) && nonempty(value.contractId)
  && Number.isInteger(value.contractVersion) && value.contractVersion > 0 && isDigest(value.contractDigest)
  && nonempty(value.sourceRevision);
const validInputs = (value) => isDigest(value.artifactDigest) && isDigest(value.briefDigest)
  && nonempty(value.bundleId) && nonempty(value.bundleVersion) && nonempty(value.profileId)
  && isDigest(value.manifestDigest) && isDigest(value.profileDigest);
const validBinding = (value) => exactKeys(value, ['adapter', 'sessionId', 'bindingDigest']) && nonempty(value.adapter) && nonempty(value.sessionId)
  && isDigest(value.bindingDigest);
const validChecklist = (value) => Array.isArray(value) && value.length > 0
  && value.every((item) => exactKeys(item, ['criterionId', 'evidenceDigest']) && nonempty(item.criterionId) && isDigest(item.evidenceDigest))
  && new Set(value.map((item) => item.criterionId)).size === value.length;
const ARTIFACT_KEYS = Object.freeze([...ADVISORY_ARTIFACT_BOUND_FIELDS, 'authentication']);
const CERTIFICATION_KEYS = Object.freeze([...ADVISORY_CERTIFICATION_BOUND_FIELDS, 'authentication']);
const ARTIFACT_INPUT_KEYS = Object.freeze([...INPUT_FIELDS, ...EXECUTION_FIELDS, 'adapter', 'sessionId']);

function rejectCallerAuthority(value) {
  for (const field of ['authentication', 'receiptId', 'producerAgentIdDigest', 'certifierAgentIdDigest', 'binding']) {
    if (Object.hasOwn(value ?? {}, field)) throw Object.assign(new TypeError(`caller field '${field}' is forbidden`), { code: 'ARC_AUTHORITY_MODEL_CLAIMED' });
  }
}

function requireBinding(authorityBindingStore, { adapter, sessionId, authority }) {
  const binding = authorityBindingStore?.findLatest({ adapter, sessionId, authority });
  if (!binding || !isDigest(binding.agentIdDigest)) throw Object.assign(new TypeError(`host ${authority} binding is unavailable`), { code: 'ARC_AUTHORITY_NOT_ASSERTED' });
  return binding;
}

function freshness(receipt, now, freshnessMs) {
  const issued = Date.parse(receipt.issuedAt);
  const expires = Date.parse(receipt.expiresAt);
  const current = now instanceof Date ? now.valueOf() : Number(now);
  return Number.isFinite(issued) && Number.isFinite(expires) && Number.isFinite(current)
    && issued <= current && expires > current && expires - issued <= freshnessMs;
}

function verifyStoredBinding(receipt, authority, authorityBindingStore) {
  const binding = receipt.binding;
  if (!validBinding(binding)) return false;
  const stored = authorityBindingStore?.findLatest({ adapter: binding.adapter, sessionId: binding.sessionId, authority });
  return Boolean(stored && digestValue(stored) === binding.bindingDigest && stored.agentIdDigest === receipt[`${authority === 'oracle' ? 'certifier' : 'producer'}AgentIdDigest`]);
}

function commonReceipt(core, { binding, clock, freshnessMs }) {
  const issuedAt = clock();
  const expiresAt = new Date(Date.parse(issuedAt) + freshnessMs).toISOString();
  const unsigned = {
    schemaVersion: 1,
    ...core,
    binding: { adapter: core.adapter, sessionId: core.sessionId, bindingDigest: digestValue(binding) },
    issuedAt,
    expiresAt,
    nonce: randomBytes(16).toString('hex'),
  };
  delete unsigned.adapter;
  delete unsigned.sessionId;
  return { ...unsigned, receiptId: digestValue(unsigned) };
}

export function mintAdvisoryArtifactReceipt(input, {
  keyRing, keyId, authorityBindingStore, producerAuthority = 'alchemist', clock = () => new Date().toISOString(), freshnessMs = 86400000,
} = {}) {
  rejectCallerAuthority(input);
  if (!exactKeys(input, ARTIFACT_INPUT_KEYS) || !validInputs(input) || !validExecution(input) || !nonempty(input.adapter) || !nonempty(input.sessionId)) throw Object.assign(new TypeError('invalid advisory artifact input'), { code: 'ARC_SCHEMA_INVALID' });
  const binding = requireBinding(authorityBindingStore, { adapter: input.adapter, sessionId: input.sessionId, authority: producerAuthority });
  const receipt = commonReceipt({ kind: 'arcane-advisory-artifact-receipt', ...input, producerAgentIdDigest: binding.agentIdDigest }, { binding, clock, freshnessMs });
  return { ...receipt, authentication: signRecord(receipt, { keyRing, keyId, boundFields: ADVISORY_ARTIFACT_BOUND_FIELDS, macDomain: ARTIFACT_DOMAIN }) };
}

export function verifyAdvisoryArtifactReceipt(receipt, expected, {
  keyRing, authorityBindingStore, producerAuthority = 'alchemist', now = new Date(), freshnessMs = 86400000,
} = {}) {
  if (!exactKeys(receipt, ARTIFACT_KEYS) || receipt.schemaVersion !== 1 || receipt.kind !== 'arcane-advisory-artifact-receipt' || !validInputs(receipt) || !validExecution(receipt) || !validBinding(receipt.binding) || !isDigest(receipt.receiptId) || !isDigest(receipt.producerAgentIdDigest) || !/^[0-9a-f]{32}$/.test(receipt.nonce)) return deny('ARC_SCHEMA_INVALID', 'advisory artifact receipt is invalid');
  if (receipt.receiptId !== digestValue(Object.fromEntries(Object.entries(receipt).filter(([field]) => !['receiptId', 'authentication'].includes(field))))) return deny('ARC_AUTH_FORGED', 'advisory artifact receipt identifier does not match content');
  if (!freshness(receipt, now, freshnessMs)) return deny('ARC_REPLAY_STALE', 'advisory artifact receipt is stale or from the future');
  if (!verifyStoredBinding(receipt, producerAuthority, authorityBindingStore)) return deny('ARC_AUTHORITY_NOT_ASSERTED', 'artifact producer binding is unavailable');
  const auth = verifyRecord(receipt, receipt.authentication, { keyRing, boundFields: ADVISORY_ARTIFACT_BOUND_FIELDS, expectedBinding: expected ?? {}, macDomain: ARTIFACT_DOMAIN });
  if (!auth.allowed) return auth;
  for (const field of [...INPUT_FIELDS, ...EXECUTION_FIELDS]) if (Object.hasOwn(expected ?? {}, field) && receipt[field] !== expected[field]) return deny('ARC_BINDING_MISMATCH', 'artifact receipt differs from expected input', { field });
  return decision({ allowed: true, detail: { receiptId: receipt.receiptId, artifactDigest: receipt.artifactDigest, producerAgentIdDigest: receipt.producerAgentIdDigest } });
}

export function mintAdvisoryCertificationReceipt({ artifactReceipt, checklistEvidence, adapter, sessionId }, {
  keyRing, keyId, authorityBindingStore, now = new Date(), clock = () => new Date().toISOString(), freshnessMs = 86400000,
} = {}) {
  const artifact = verifyAdvisoryArtifactReceipt(artifactReceipt, {}, { keyRing, authorityBindingStore, now, freshnessMs });
  if (!artifact.allowed) throw Object.assign(new TypeError(artifact.message), { code: artifact.code });
  if (!validChecklist(checklistEvidence) || !nonempty(adapter) || !nonempty(sessionId)) throw Object.assign(new TypeError('certification requires checklist evidence and host session'), { code: 'ARC_SCHEMA_INVALID' });
  const binding = requireBinding(authorityBindingStore, { adapter, sessionId, authority: 'oracle' });
  if (binding.agentIdDigest === artifactReceipt.producerAgentIdDigest) throw Object.assign(new TypeError('producer cannot certify its own artifact'), { code: 'ARC_CLAIM_PREREQUISITE_UNMET' });
  const copied = Object.fromEntries([...INPUT_FIELDS, ...EXECUTION_FIELDS].map((field) => [field, artifactReceipt[field]]));
  const receipt = commonReceipt({
    kind: 'arcane-advisory-certification-receipt', ...copied, artifactReceiptDigest: digestValue(artifactReceipt),
    producerAgentIdDigest: artifactReceipt.producerAgentIdDigest, certifierAgentIdDigest: binding.agentIdDigest,
    checklistEvidence: checklistEvidence.map((item) => ({ criterionId: item.criterionId, evidenceDigest: item.evidenceDigest })), verdict: 'PASS', adapter, sessionId,
  }, { binding, clock, freshnessMs });
  return { ...receipt, authentication: signRecord(receipt, { keyRing, keyId, boundFields: ADVISORY_CERTIFICATION_BOUND_FIELDS, macDomain: CERTIFICATION_DOMAIN }) };
}

export function verifyAdvisoryCertification({ artifactReceipt, certificationReceipt, expected = {} }, {
  keyRing, authorityBindingStore, producerAuthority = 'alchemist', now = new Date(), freshnessMs = 86400000,
} = {}) {
  const artifact = verifyAdvisoryArtifactReceipt(artifactReceipt, expected, { keyRing, authorityBindingStore, producerAuthority, now, freshnessMs });
  if (!artifact.allowed) return artifact;
  const receipt = certificationReceipt;
  if (!exactKeys(receipt, CERTIFICATION_KEYS) || receipt.schemaVersion !== 1 || receipt.kind !== 'arcane-advisory-certification-receipt' || !validInputs(receipt) || !validExecution(receipt) || !validBinding(receipt.binding) || !validChecklist(receipt.checklistEvidence) || receipt.verdict !== 'PASS' || !isDigest(receipt.receiptId) || !isDigest(receipt.certifierAgentIdDigest) || !isDigest(receipt.producerAgentIdDigest) || !isDigest(receipt.artifactReceiptDigest) || !/^[0-9a-f]{32}$/.test(receipt.nonce)) return deny('ARC_EVIDENCE_INSUFFICIENT', 'independent advisory certification is missing or invalid');
  if (receipt.receiptId !== digestValue(Object.fromEntries(Object.entries(receipt).filter(([field]) => !['receiptId', 'authentication'].includes(field))))) return deny('ARC_AUTH_FORGED', 'advisory certification identifier does not match content');
  if (!freshness(receipt, now, freshnessMs)) return deny('ARC_REPLAY_STALE', 'advisory certification is stale or from the future');
  if (!verifyStoredBinding(receipt, 'oracle', authorityBindingStore)) return deny('ARC_AUTHORITY_NOT_ASSERTED', 'Oracle certifier binding is unavailable');
  const auth = verifyRecord(receipt, receipt.authentication, { keyRing, boundFields: ADVISORY_CERTIFICATION_BOUND_FIELDS, expectedBinding: expected, macDomain: CERTIFICATION_DOMAIN });
  if (!auth.allowed) return auth;
  if (receipt.producerAgentIdDigest === receipt.certifierAgentIdDigest) return deny('ARC_CLAIM_PREREQUISITE_UNMET', 'producer cannot certify its own artifact');
  if (receipt.artifactReceiptDigest !== digestValue(artifactReceipt)) return deny('ARC_BINDING_MISMATCH', 'certification targets a different artifact receipt', { field: 'artifactReceiptDigest' });
  for (const field of [...INPUT_FIELDS, ...EXECUTION_FIELDS, 'producerAgentIdDigest']) if (receipt[field] !== artifactReceipt[field]) return deny('ARC_BINDING_MISMATCH', 'certification differs from artifact receipt', { field });
  return decision({ allowed: true, detail: { artifactReceiptId: artifactReceipt.receiptId, certificationReceiptId: receipt.receiptId, artifactDigest: receipt.artifactDigest } });
}

export function findCurrentAdvisoryCertification({ receiptStore, artifactDigest, expected = {} }, options = {}) {
  if (!receiptStore || !isDigest(artifactDigest)) return deny('ARC_EVIDENCE_INSUFFICIENT', 'receipt store and artifact digest are required');
  const continuity = typeof receiptStore.verifyChain === 'function' ? receiptStore.verifyChain() : null;
  if (!continuity?.ok) return deny('ARC_STORE_CORRUPT', 'advisory receipt chain is unavailable or corrupt');
  const records = receiptStore.list({ runId: expected.runId });
  const artifacts = records.filter((record) => record.kind === 'arcane-advisory-artifact-receipt' && record.artifactDigest === artifactDigest).reverse();
  const certifications = records.filter((record) => record.kind === 'arcane-advisory-certification-receipt' && record.artifactDigest === artifactDigest).reverse();
  for (const artifactReceipt of artifacts) for (const certificationReceipt of certifications) {
    const result = verifyAdvisoryCertification({ artifactReceipt, certificationReceipt, expected }, options);
    if (result.allowed) return result;
  }
  return deny('ARC_EVIDENCE_INSUFFICIENT', 'current independent advisory certification is unavailable', { artifactDigest });
}
