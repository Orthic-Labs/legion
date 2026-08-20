// Legion shared-contract wire enums.
//
// This module is the single code-owned source of truth for every enumerated
// value used by the JSON Schemas in packages/contracts/schemas/. Schemas do
// not hand-duplicate these arrays independently of this file; smoke.test.mjs
// asserts each schema's enum property is set-equal to the corresponding
// export here. If you need to change an enum, change it here first, then
// update the schema(s) that reference it, then update smoke.test.mjs if a
// new enum-bearing field was added.
//
// docs/LEGION-CANONICAL-SSOT.md owns semantics; this module projects only
// current contract/runtime vocabulary.

/** Runtime identities permitted in authority-bearing contract fields. Covenant is advisory. */
export const AUTHORITY_ID = Object.freeze([
  'legion', // always-on orchestrator
  'sage', // exceptional adjudication authority
  'alchemist', // transformation authority
  'oracle', // independent assurance authority
  'arcane', // deterministic enforcement identity
  'kernel', // deterministic substrate under Legion
]);

/** Decision latitude on an artifact/task. */
export const LATITUDE = Object.freeze(['EXACT', 'BOUNDED', 'OPEN']);

/**
 * Alchemist terminal/intermediate execution states, reused as domain outcome.
 */
export const ALCHEMIST_STATE = Object.freeze([
  'REPAIR',
  'BLOCKED_DECISION',
  'NEEDS_AMENDMENT',
  'OUT_OF_SCOPE',
  'BUDGET_STOP',
  'FAILED_CONTRACT',
  'COMPLETE',
]);

/** Domain outcome of an operation/run — reuses ALCHEMIST_STATE (see above). */
export const DOMAIN_OUTCOME = ALCHEMIST_STATE;

/**
 * Runtime invocation lifecycle, orthogonal to domain outcome & claim boundary.
 */
export const INVOCATION_STATE = Object.freeze([
  'ACCEPTED',
  'RUNNING',
  'INPUT_REQUIRED',
  'CANCELLED',
  'EXPIRED',
  'FAILED_INVOCATION',
  'COMPLETED',
]);

/**
 * Claim boundary is distinct from invocation state & domain outcome.
 */
export const CLAIM_BOUNDARY = Object.freeze([
  'CLEAN_WITHIN_DECLARED_SCOPE',
  'PARTIALLY_PROVEN',
  'UNPROVEN',
  'EVIDENCE_INSUFFICIENT',
  'NOT_APPLICABLE',
]);

/** Sage claims are limited to actual exceptional adjudication. */
export const SAGE_CLAIM = Object.freeze([
  'ADJUDICATION_MADE',
  'SEMANTIC_CONFLICT_RESOLVED',
  'ACCEPTANCE_SEMANTICS_SEALED',
  'ADJUDICATED_CONTRACT_SEALED',
]);

/** Alchemist-owned transformation claims. */
export const ALCHEMIST_CLAIM = Object.freeze([
  'EFFECT_APPLIED',
  'CANDIDATE_READY',
  'DECLARED_CHECKS_PASSED',
  'IMPLEMENTATION_MATCHES_CONTRACT',
  'LOCAL_EXECUTION_VERIFIED',
]);

/** Oracle claims are limited to independent Completion Validation. */
export const ORACLE_CLAIM = Object.freeze([
  'COMPLETION_VALIDATED',
  'COMPLETION_BLOCKED',
  'UNKNOWN',
  'NOT_APPLICABLE',
  'EVIDENCE_INSUFFICIENT',
]);

/** Every claim name across all authorities; Arcane validates but does not invent them. */
export const CLAIM_NAME = Object.freeze([...SAGE_CLAIM, ...ALCHEMIST_CLAIM, ...ORACLE_CLAIM]);

/** Which claim names a given authority is permitted to assert. */
export const CLAIMS_BY_AUTHORITY = Object.freeze({
  sage: SAGE_CLAIM,
  alchemist: ALCHEMIST_CLAIM,
  oracle: ORACLE_CLAIM,
});

/** Authority context supplied by an explicit Covenant caller. */
export const CALLER_AUTHORITY = Object.freeze(['SAGE', 'ALCHEMIST', 'USER_OVERRIDE']);

/**
 * Covenant advisory modes. DISPUTE_REVIEW is exceptional; its presence does
 * not make Covenant a routine Oracle route or release gate.
 */
export const COVENANT_MODE = Object.freeze([
  'DECISION_CHALLENGE',
  'BLOCKER_CONSULT',
  'PACKET_ONLY',
  'DISPUTE_REVIEW',
]);

/**
 * Covenant outcomes across all modes.
 * Not every value applies to every mode; see ids.md / schema descriptions.
 */
export const COVENANT_OUTCOME = Object.freeze([
  'SUPPORTED',
  'REVISE',
  'UNRESOLVED',
  'CONTRACT_SAFE',
  'AMENDMENT_REQUIRED',
  'INSUFFICIENT_EVIDENCE',
]);

/** Originating decision owner disposition of a Covenant finding. */
export const DISPOSITION_VALUE = Object.freeze([
  'ACCEPT',
  'REJECT',
  'DEFER_TO_PHASE',
  'NEEDS_EVIDENCE',
  'SUPERSEDED',
]);

/** Covenant finding scope classification. */
export const FINDING_SCOPE_CLASS = Object.freeze([
  'IN_SCOPE_DEFECT',
  'LATER_PHASE',
  'OUT_OF_SCOPE',
  'MISSING_EVIDENCE',
  'OPTIONAL_VALUE',
]);

/**
 * Runtime effect classes Arcane authorizes & gates. Canonical semantic effect
 * classes remain owned by docs/LEGION-CANONICAL-SSOT.md; this is a deliberately
 * narrower compatibility vocabulary at the enforcement boundary.
 */
export const EFFECT_CLASS = Object.freeze([
  'FILE_WRITE',
  'FILE_DELETE',
  'FILE_MOVE',
  'COMMAND_EXEC',
  'NETWORK_EGRESS',
  'PROCESS_SPAWN',
  'CREDENTIAL_ACCESS',
  'DEPENDENCY_INSTALL',
  'VCS_COMMIT',
  'VCS_PUSH',
  'PUBLISH',
  'EXTERNAL_SIDE_EFFECT',
]);

/**
 * Abstract runtime model tiers. Role identity sources own tier selection;
 * generated host projections may map them to host-specific model names.
 */
export const MODEL_TIER = Object.freeze(['FRONTIER', 'MID', 'CHEAP_STRICT', 'NONE']);

/** Worker execution profiles. */
export const WORKER_PROFILE = Object.freeze(['strict', 'standard', 'advanced']);

/**
 * Effect/evidence authentication method. Imported historical records remain
 * explicitly unauthenticated; connection trust never masquerades as per-message proof.
 */
export const AUTHENTICATION_METHOD = Object.freeze([
  'host-connection-trust',
  'capability-signature',
  'unauthenticated',
]);

/** Advisory contract-safety outcome from Covenant blocker challenge. */
export const BLOCKER_CONSULT_OUTCOME = Object.freeze([
  'CONTRACT_SAFE',
  'AMENDMENT_REQUIRED',
  'INSUFFICIENT_EVIDENCE',
]);

/** Whether a blocker is clearly semantic or possibly contract-safe. */
export const BLOCKER_CLASS = Object.freeze(['CLEARLY_SEMANTIC', 'POSSIBLY_CONTRACT_SAFE']);

/** Blocker lifecycle status. */
export const BLOCKER_STATUS = Object.freeze([
  'OPEN',
  'COVENANT_CONSULTED',
  'AMENDED',
  'RESOLVED',
]);

/** Claim object lifecycle status; Arcane owns validation transitions. */
export const CLAIM_STATUS = Object.freeze(['PENDING', 'VALIDATED', 'REJECTED']);

/**
 * Evidence class for an evidence-capability receipt. Values are duplicated
 * inline (not imported) from legion's existing EVIDENCE_CLASS convention
 * (lib/contracts, providers/security/contracts.mjs) to avoid this package
 * taking a runtime dependency on legion's internal provider pipeline.
 * Judgment call J-5, see FREEZE.md.
 */
export const EVIDENCE_CLASS = Object.freeze(['deterministic', 'measured', 'interpretive', 'external', 'human']);

export function assertEnum(label, values, value) {
  if (!values.includes(value)) throw new TypeError(`unknown ${label}: ${value}`);
  return value;
}

export function assertSchemaVersion(label, version, supported = [1]) {
  if (!supported.includes(version)) {
    throw new TypeError(`${label} unsupported schema version: ${version}`);
  }
  return version;
}
