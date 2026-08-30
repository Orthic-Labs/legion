import { ArcaneError } from '../../contracts/arcane/errors.mjs';

export const DECISION_ENFORCEMENT_HEALTH = Object.freeze(['strong', 'observed', 'read_only', 'advisory', 'unsupported', 'degraded']);
export const DECISION_TERMINATION = Object.freeze(['terminate', 'continue']);
export const DECISION_CERTIFICATION = Object.freeze(['not_claimed', 'genuine', 'certified', 'rejected']);

const PUBLIC_REASONS = Object.freeze({
  ARC_SCHEMA_INVALID: 'Arcane rejected invalid structured input.', ARC_ID_INVALID: 'Arcane rejected an invalid identifier.', ARC_CANONICALIZATION_FAILED: 'Arcane could not canonicalize required data.',
  ARC_POLICY_UNAVAILABLE: 'Arcane policy is unavailable.', ARC_POLICY_MALFORMED: 'Arcane policy is invalid.', ARC_POLICY_UNKNOWN_FIELD: 'Arcane policy contains an unknown field.',
  ARC_AUTHORITY_NOT_ASSERTED: 'Required host authority was not asserted.', ARC_AUTHORITY_MODEL_CLAIMED: 'Authority cannot be claimed by model input.', ARC_CLAIM_PREREQUISITE_UNMET: 'Completion prerequisites are unmet.',
  ARC_AUTH_FORGED: 'Authentication verification failed.', ARC_AUTH_UNAUTHENTICATED: 'Authenticated host evidence is missing.', ARC_AUTH_KEY_UNAVAILABLE: 'Host authentication key is unavailable.', ARC_AUTH_LEGACY_DIGEST: 'A legacy digest is not authentication.',
  ARC_REPLAY_NONCE_SEEN: 'Replay nonce was already consumed.', ARC_REPLAY_SEQUENCE_REGRESSION: 'Replay sequence is not increasing.', ARC_REPLAY_STALE: 'Host event is outside the freshness window.', ARC_BINDING_MISMATCH: 'Runtime binding does not match authorization.',
  ARC_CAPABILITY_EXPIRED: 'Capability expired.', ARC_CAPABILITY_EXHAUSTED: 'Capability was already consumed.', ARC_CAPABILITY_REVOKED: 'Capability was revoked.', ARC_CAPABILITY_UNKNOWN: 'Capability is missing.',
  ARC_HOST_EVENT_INVALID: 'Host event is invalid.', ARC_HOST_EVENT_UNTRUSTED: 'Host event is not authenticated.', ARC_MODEL_SELF_REPORT: 'Model self-report cannot become a receipt.', ARC_INGEST_CORRELATION_MISSING: 'Matching pre-effect authorization is missing.',
  ARC_EVIDENCE_STALE: 'Evidence is stale.', ARC_EVIDENCE_INSUFFICIENT: 'Required evidence is missing.', ARC_DEPENDENCY_UNKNOWN: 'Evidence dependency is unknown.', ARC_STORE_CORRUPT: 'Arcane state is unavailable or corrupt.',
  ARC_GATE_UNAVAILABLE: 'Pre-effect gate is unavailable.', ARC_NO_CONTRACT: 'No sealed execution contract is bound.', ARC_CONTRACT_NOT_EXECUTABLE: 'Execution contract has unresolved questions.', ARC_CONTRACT_VERSION_MISMATCH: 'Bound contract version or digest does not match.', ARC_PATH_NOT_OWNED: 'Target is outside contract-owned scope.', ARC_PATH_FORBIDDEN: 'Target is forbidden by contract.', ARC_EFFECT_CLASS_UNAUTHORIZED: 'Effect class is not authorized.', ARC_LATITUDE_VIOLATION: 'Requested latitude is not allowed.', ARC_APPROVAL_REQUIRED: 'Required approval evidence is missing.', ARC_KERNEL_PRIMITIVE_UNAVAILABLE: 'Required Kernel primitive is unavailable.',
  ARC_ESCALATION_UNEVIDENCED: 'Escalation needs two documented self-attempts and the error each one hit, in the prompt body.', ARC_STOP_SHAPE: '[non-authoritative stop feedback] Complete latest user-requested scope; this feedback cannot authorize or restore scope.',
});

const REMEDIATION = Object.freeze({
  deterministic: Object.freeze({ responsibleProducer: 'legion run close', remediationRoutes: Object.freeze(['legion run close --help']) }),
  'terminal-operation-claim': Object.freeze({ responsibleProducer: 'legion completion claim', remediationRoutes: Object.freeze(['legion completion claim --help']) }),
  'host-event-ledger': Object.freeze({ responsibleProducer: 'authenticated host ingress', remediationRoutes: Object.freeze(['legion host events inspect']) }),
});

export function publicReason(code) {
  if (code === null) return 'ARCANE_OK: No denial.';
  const resolved = Object.hasOwn(PUBLIC_REASONS, code) ? code : 'ARC_SCHEMA_INVALID';
  return `${resolved}: ${PUBLIC_REASONS[resolved]}`;
}

export function actionableMissingEvidence(missingClasses = []) {
  const classes = [...new Set(Array.isArray(missingClasses) ? missingClasses : [])];
  return classes.map((missingClass) => {
    const remediation = REMEDIATION[missingClass];
    if (!remediation) throw new ArcaneError('ARC_SCHEMA_INVALID', 'missing evidence class has no public remediation', { missingClass });
    return Object.freeze({ missingClass, responsibleProducer: remediation.responsibleProducer, remediationRoutes: [...remediation.remediationRoutes] });
  });
}

export function createDecisionEnvelope({ allowed, code = null, detail = {}, enforcementHealth = 'strong' } = {}) {
  const missingEvidence = actionableMissingEvidence(detail.missingClasses);
  const first = missingEvidence[0] ?? null;
  const termination = detail.termination?.allowed === true || detail.termination === 'terminate' ? 'terminate' : 'continue';
  const certification = DECISION_CERTIFICATION.includes(detail.certification) ? detail.certification : (allowed ? 'certified' : 'rejected');
  return Object.freeze({
    schemaVersion: 1,
    kind: 'arcane-decision-envelope',
    allowed: Boolean(allowed),
    code: typeof code === 'string' ? code : null,
    publicReason: publicReason(typeof code === 'string' ? code : null),
    enforcementHealth: DECISION_ENFORCEMENT_HEALTH.includes(enforcementHealth) ? enforcementHealth : 'unsupported',
    retrySignature: typeof detail.retrySignature === 'string' ? detail.retrySignature : null,
    termination,
    certification,
    missingClasses: missingEvidence.map((entry) => entry.missingClass),
    responsibleProducer: first?.responsibleProducer ?? null,
    remediationRoutes: first ? [...first.remediationRoutes] : [],
    missingEvidence,
  });
}
