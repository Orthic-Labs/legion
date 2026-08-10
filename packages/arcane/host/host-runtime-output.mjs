import { RuntimeSchemaSet } from '../lib/runtime-schema.mjs';

const schema = new RuntimeSchemaSet();

export const PUBLIC_REASON = Object.freeze({
  ARC_SCHEMA_INVALID: 'Arcane rejected invalid structured input.',
  ARC_ID_INVALID: 'Arcane rejected an invalid identifier.',
  ARC_CANONICALIZATION_FAILED: 'Arcane could not canonicalize required data.',
  ARC_POLICY_UNAVAILABLE: 'Arcane policy is unavailable.',
  ARC_POLICY_MALFORMED: 'Arcane policy is invalid.',
  ARC_POLICY_UNKNOWN_FIELD: 'Arcane policy contains an unknown field.',
  ARC_AUTHORITY_NOT_ASSERTED: 'Required host authority was not asserted.',
  ARC_AUTHORITY_MODEL_CLAIMED: 'Authority cannot be claimed by model input.',
  ARC_CLAIM_PREREQUISITE_UNMET: 'Completion prerequisites are unmet.',
  ARC_AUTH_FORGED: 'Authentication verification failed.',
  ARC_AUTH_UNAUTHENTICATED: 'Authenticated host evidence is missing.',
  ARC_AUTH_KEY_UNAVAILABLE: 'Host authentication key is unavailable.',
  ARC_AUTH_LEGACY_DIGEST: 'A legacy digest is not authentication.',
  ARC_REPLAY_NONCE_SEEN: 'Replay nonce was already consumed.',
  ARC_REPLAY_SEQUENCE_REGRESSION: 'Replay sequence is not increasing.',
  ARC_REPLAY_STALE: 'Host event is outside the freshness window.',
  ARC_BINDING_MISMATCH: 'Runtime binding does not match authorization.',
  ARC_CAPABILITY_EXPIRED: 'Capability expired.',
  ARC_CAPABILITY_EXHAUSTED: 'Capability was already consumed.',
  ARC_CAPABILITY_REVOKED: 'Capability was revoked.',
  ARC_CAPABILITY_UNKNOWN: 'Capability is missing.',
  ARC_HOST_EVENT_INVALID: 'Host event is invalid.',
  ARC_HOST_EVENT_UNTRUSTED: 'Host event is not authenticated.',
  ARC_MODEL_SELF_REPORT: 'Model self-report cannot become a receipt.',
  ARC_INGEST_CORRELATION_MISSING: 'Matching pre-effect authorization is missing.',
  ARC_EVIDENCE_STALE: 'Evidence is stale.',
  ARC_EVIDENCE_INSUFFICIENT: 'Required evidence is missing.',
  ARC_DEPENDENCY_UNKNOWN: 'Evidence dependency is unknown.',
  ARC_STORE_CORRUPT: 'Arcane state is unavailable or corrupt.',
  ARC_GATE_UNAVAILABLE: 'Pre-effect gate is unavailable.',
  ARC_NO_CONTRACT: 'No sealed execution contract is bound.',
  ARC_CONTRACT_NOT_EXECUTABLE: 'Execution contract has unresolved questions.',
  ARC_CONTRACT_VERSION_MISMATCH: 'Bound contract version or digest does not match.',
  ARC_PATH_NOT_OWNED: 'Target is outside contract-owned scope.',
  ARC_PATH_FORBIDDEN: 'Target is forbidden by contract.',
  ARC_EFFECT_CLASS_UNAUTHORIZED: 'Effect class is not authorized.',
  ARC_LATITUDE_VIOLATION: 'Requested latitude is not allowed.',
  ARC_APPROVAL_REQUIRED: 'Required approval evidence is missing.',
  ARC_KERNEL_PRIMITIVE_UNAVAILABLE: 'Required Kernel primitive is unavailable.',
  // Unlike the codes above, this one states the remedy. The reasons here are
  // deliberately generic so internals never leak, but nothing about the
  // escalation bar is internal — and a refusal that does not say what would
  // satisfy it just gets retried verbatim.
  ARC_ESCALATION_UNEVIDENCED: 'Escalation needs two documented self-attempts and the error each one hit, in the prompt body.',
});

export function publicReason(code) {
  const resolved = Object.hasOwn(PUBLIC_REASON, code) ? code : 'ARC_SCHEMA_INVALID';
  return `${resolved}: ${PUBLIC_REASON[resolved]}`;
}

export function renderHostRuntimeOutput({ eventType, allowed, code = null }) {
  if (allowed) return null;
  const reason = publicReason(code);
  let output;
  if (eventType === 'PreToolUse') {
    output = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } };
  } else if (eventType === 'Stop') {
    output = { decision: 'block', reason };
  } else {
    output = { hookSpecificOutput: { hookEventName: eventType, additionalContext: `Arcane: ${reason}` } };
  }
  schema.assert('arcane-host-runtime-output-v1', output);
  return output;
}

export function serializeHostRuntimeOutput(output) {
  if (output === null) return '';
  schema.assert('arcane-host-runtime-output-v1', output);
  return `${JSON.stringify(output)}\n`;
}
