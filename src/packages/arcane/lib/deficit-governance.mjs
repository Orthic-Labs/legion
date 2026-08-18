// Deterministic deficit & outcome governance.  This module only accepts
// explicit structured classification fields; it never infers debt from prose.
import { decision } from './errors.mjs';

const DEBT_SAFE_CLASSES = new Set(['OPTIONAL', 'QUALITY', 'PERFORMANCE', 'USABILITY']);
const PROTECTED_CLASSES = new Set(['CORRECTNESS', 'SAFETY']);
const PASS = 'PASS';
const nonEmpty = (value) => typeof value === 'string' && value.length > 0;
const freeze = (value) => Object.freeze(value);
const deny = (code, message, detail = {}) => decision({ allowed: false, code, message, detail });

function normalizeAcceptance(item, index) {
  const id = item?.acceptanceId ?? item?.acceptance_id ?? item?.id;
  const obligationClass = item?.obligationClass ?? item?.obligation_class;
  const result = item?.result;
  if (!nonEmpty(id) || !nonEmpty(obligationClass) || !nonEmpty(result)) {
    return null;
  }
  return freeze({ id, obligationClass, result, canonicalDeficitId: `deficit:${id}` });
}

// Classify every non-passing acceptance item.  Only explicit optional/quality
// classes may become debt; correctness & safety always retain their gate.
export function classifyAcceptanceDeficits({ acceptanceItems = [] } = {}) {
  if (!Array.isArray(acceptanceItems)) return deny('ARC_SCHEMA_INVALID', 'acceptanceItems must be an array');
  const normalized = acceptanceItems.map(normalizeAcceptance);
  if (normalized.some((item) => item === null)) return deny('ARC_SCHEMA_INVALID', 'every acceptance item requires id, obligationClass, and result');
  const deficits = normalized.filter((item) => item.result !== PASS).map((item) => freeze({
    ...item,
    debtEligible: DEBT_SAFE_CLASSES.has(item.obligationClass),
    protected: PROTECTED_CLASSES.has(item.obligationClass),
    disposition: DEBT_SAFE_CLASSES.has(item.obligationClass) ? 'DEBT' : 'BLOCKING',
  }));
  const blocking = deficits.filter((item) => item.disposition === 'BLOCKING');
  const debt = deficits.filter((item) => item.disposition === 'DEBT');
  const claimCeiling = blocking.length ? 'CANDIDATE' : debt.length ? 'COMPLETE_WITH_DEBT' : 'COMPLETE';
  return decision({
    allowed: true,
    message: 'acceptance deficits classified',
    detail: freeze({ deficits: freeze(deficits), claimCeiling, outcomeState: claimCeiling === 'COMPLETE' ? 'COMPLETE' : claimCeiling === 'COMPLETE_WITH_DEBT' ? 'COMPLETE_WITH_DEBT' : 'CANDIDATE' }),
  });
}

// Debt is a conversion, not a label.  This guard rejects any protected or
// required class before a caller can expose a downgraded completion claim.
export function convertDeficitsToDebt(input = {}) {
  const classified = classifyAcceptanceDeficits(input);
  if (!classified.allowed) return classified;
  const protectedDeficits = classified.detail.deficits.filter((deficit) => deficit.protected);
  if (protectedDeficits.length) {
    return deny('ARC_CLAIM_PREREQUISITE_UNMET', 'correctness or safety deficit cannot convert to debt', freeze({
      outcomeState: 'CANDIDATE', claimCeiling: 'CANDIDATE',
      protectedDeficitIds: freeze(protectedDeficits.map((deficit) => deficit.canonicalDeficitId)),
    }));
  }
  const blocking = classified.detail.deficits.filter((deficit) => deficit.disposition === 'BLOCKING');
  if (blocking.length) return deny('ARC_CLAIM_PREREQUISITE_UNMET', 'required acceptance deficit cannot convert to debt', freeze({ outcomeState: 'CANDIDATE', claimCeiling: 'CANDIDATE', blockingDeficitIds: freeze(blocking.map((deficit) => deficit.canonicalDeficitId)) }));
  return decision({ allowed: true, message: 'eligible acceptance deficits converted to canonical debt', detail: freeze({ outcomeState: classified.detail.outcomeState, claimCeiling: classified.detail.claimCeiling, debts: freeze(classified.detail.deficits) }) });
}

// A consumer may proceed with degraded behavior only by acknowledging a
// producer's canonical debt identity.  Locally copied debt objects are not an
// acknowledgement and cannot cross a dispatch boundary.
export function acknowledgeDownstreamDeficits({ canonicalDeficits = [], acknowledgements = [] } = {}) {
  if (!Array.isArray(canonicalDeficits) || !Array.isArray(acknowledgements)) return deny('ARC_SCHEMA_INVALID', 'canonicalDeficits and acknowledgements must be arrays');
  const canonicalIds = new Set(canonicalDeficits.map((deficit) => deficit?.canonicalDeficitId).filter(nonEmpty));
  if (canonicalIds.size !== canonicalDeficits.length) return deny('ARC_SCHEMA_INVALID', 'each canonical deficit requires canonicalDeficitId');
  const acknowledged = new Set();
  for (const acknowledgement of acknowledgements) {
    if (!nonEmpty(acknowledgement?.canonicalDeficitId) || acknowledgement?.canonical !== true || !nonEmpty(acknowledgement?.consumerId)) return deny('ARC_SCHEMA_INVALID', 'acknowledgement requires canonical identity, canonical marker, and consumerId');
    if (!canonicalIds.has(acknowledgement.canonicalDeficitId)) return deny('ARC_BINDING_MISMATCH', 'downstream acknowledgement does not reference canonical debt', { canonicalDeficitId: acknowledgement.canonicalDeficitId });
    acknowledged.add(acknowledgement.canonicalDeficitId);
  }
  const missing = [...canonicalIds].filter((id) => !acknowledged.has(id));
  if (missing.length) return deny('ARC_CLAIM_PREREQUISITE_UNMET', 'dispatch rejected until canonical debt is acknowledged', freeze({ dispatch: 'REJECTED', missingCanonicalDeficitIds: freeze(missing) }));
  return decision({ allowed: true, message: 'downstream acknowledged canonical deficits', detail: freeze({ dispatch: 'ALLOWED', acknowledgedCanonicalDeficitIds: freeze([...acknowledged].sort()) }) });
}

// Internal tests are supporting evidence only.  A complete outcome requires a
// structured, authenticated observation at its declared acceptance surface.
export function evaluateOutcomeClosure({ acceptanceSurface } = {}) {
  const observed = acceptanceSurface?.observed === true;
  const authenticated = acceptanceSurface?.authenticated === true;
  const stateIdentity = acceptanceSurface?.integratedState;
  if (!observed || !authenticated || stateIdentity === null || stateIdentity === undefined) {
    return deny('ARC_EVIDENCE_INSUFFICIENT', 'outcome remains CANDIDATE until acceptance surface is observed', freeze({ outcomeState: 'CANDIDATE', claimCeiling: 'CANDIDATE', acceptanceSurface: observed ? 'UNAUTHENTICATED' : 'UNOBSERVED' }));
  }
  return decision({ allowed: true, message: 'outcome acceptance surface observed', detail: freeze({ outcomeState: 'COMPLETE', claimCeiling: 'COMPLETE', integratedState: stateIdentity }) });
}
