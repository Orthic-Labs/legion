// Legion shared-contract enums — WP2 freeze.
//
// This module is the single code-owned source of truth for every enumerated
// value used by the JSON Schemas in packages/contracts/schemas/. Schemas do
// not hand-duplicate these arrays independently of this file; smoke.test.mjs
// asserts each schema's enum property is set-equal to the corresponding
// export here. If you need to change an enum, change it here first, then
// update the schema(s) that reference it, then update smoke.test.mjs if a
// new enum-bearing field was added.
//
// Naming is canonical per docs/plans/legion/00-CANON.md: Sage, Alchemist,
// Seer, Arcane, Covenant, Legion, Kernel. The archive's "Sorcerer" and
// "Sentinel" are superseded and must never appear here.

/** Legion authority identities (ARCHITECTURE.md Part I-VI, VI-A). */
export const AUTHORITY_ID = Object.freeze([
  'legion', // orchestrator — routes, never decides (ARCHITECTURE §3a, G21)
  'sage', // engineering decision authority
  'alchemist', // transformation authority
  'seer', // independent assurance authority
  'arcane', // control/evidence/claim authority (no model — ARCHITECTURE Part XI-A)
  'covenant', // deliberation subsystem, not a peer authority
  'kernel', // deterministic substrate under Legion
]);

/** Decision latitude on an artifact/task (ARCHITECTURE §12). */
export const LATITUDE = Object.freeze(['EXACT', 'BOUNDED', 'OPEN']);

/**
 * Alchemist terminal/intermediate execution states (ARCHITECTURE §18).
 * ARCHITECTURE §18 explicitly instructs these become "part of Legion's
 * shared state vocabulary, not duplicated ad hoc in prompts" — this array
 * is also reused verbatim as the DOMAIN_OUTCOME enum (see below) rather
 * than inventing a parallel vocabulary. See FREEZE.md judgment call J-6.
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
 * Operation/task invocation lifecycle state — the Kernel-owned axis,
 * orthogonal to domain outcome and claim boundary per ARCHITECTURE I-09
 * (archive numbering; carried into ARCHITECTURE.md's status-orthogonality
 * invariant referenced at §33/§34). Grounded in IMPLEMENTATION-PLAN
 * Workstream D deliverables (cancellation, resumption, expiry,
 * input-required handling) and Phase 9's durable terminal states.
 * Not given a literal enum anywhere in source docs — judgment call J-7.
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
 * Claim boundary — what the result is actually licensed to claim, distinct
 * from whether the operation ran (INVOCATION_STATE) and whether the
 * engineering outcome succeeded (DOMAIN_OUTCOME). Grounded in
 * IMPLEMENTATION-PLAN §7.11 Seer report ("safe/prohibited claims"), I-12
 * ("no false clean"), and ARCHITECTURE §26 Seer claims. No literal enum is
 * given in source docs for this specific axis — judgment call J-7.
 */
export const CLAIM_BOUNDARY = Object.freeze([
  'CLEAN_WITHIN_DECLARED_SCOPE',
  'PARTIALLY_PROVEN',
  'UNPROVEN',
  'EVIDENCE_INSUFFICIENT',
  'NOT_APPLICABLE',
]);

/** Sage-owned claims (ARCHITECTURE §26). */
export const SAGE_CLAIM = Object.freeze([
  'ROOT_CAUSE_ESTABLISHED',
  'DECISION_MADE',
  'ARCHITECTURE_SEALED',
  'CONTRACT_SEALED',
  'IMPLEMENTATION_SPEC_COMPLETE',
]);

/** Alchemist-owned claims (ARCHITECTURE §26). */
export const ALCHEMIST_CLAIM = Object.freeze([
  'EFFECT_APPLIED',
  'TASK_COMPLETED',
  'DECLARED_CHECKS_PASSED',
  'IMPLEMENTATION_MATCHES_CONTRACT',
  'LOCAL_EXECUTION_VERIFIED',
]);

/** Seer-owned claims (ARCHITECTURE §26). */
export const SEER_CLAIM = Object.freeze([
  'FINDING_CONFIRMED',
  'CONTROL_PASS',
  'CONTROL_FAIL',
  'UNKNOWN',
  'NOT_APPLICABLE',
  'EVIDENCE_INSUFFICIENT',
  'CLEAN_WITHIN_DECLARED_SCOPE',
]);

/** Every claim name across all authorities — Arcane validates, does not invent, these (ARCHITECTURE §26). */
export const CLAIM_NAME = Object.freeze([...SAGE_CLAIM, ...ALCHEMIST_CLAIM, ...SEER_CLAIM]);

/** Which claim names a given authority is permitted to assert (ARCHITECTURE §26). */
export const CLAIMS_BY_AUTHORITY = Object.freeze({
  sage: SAGE_CLAIM,
  alchemist: ALCHEMIST_CLAIM,
  seer: SEER_CLAIM,
});

/** Covenant caller authority (COVENANT.md §11). */
export const CALLER_AUTHORITY = Object.freeze(['SAGE', 'ALCHEMIST', 'USER_OVERRIDE']);

/**
 * Covenant modes (COVENANT.md Part III + §9). DISPUTE_REVIEW is the
 * exceptional mode (§9) — included because CovenantRequest.mode must be
 * able to express it, not because it is a routine Seer route.
 */
export const COVENANT_MODE = Object.freeze([
  'DECISION_CHALLENGE',
  'BLOCKER_CONSULT',
  'PACKET_ONLY',
  'DISPUTE_REVIEW',
]);

/**
 * Covenant outcomes across all modes (COVENANT.md §12 CovenantRecord.outcome).
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

/** Caller disposition of a Covenant finding — Sage/Alchemist owned (COVENANT.md §14). */
export const DISPOSITION_VALUE = Object.freeze([
  'ACCEPT',
  'REJECT',
  'DEFER_TO_PHASE',
  'NEEDS_EVIDENCE',
  'SUPERSEDED',
]);

/** Covenant finding scope classification (COVENANT.md §13). */
export const FINDING_SCOPE_CLASS = Object.freeze([
  'IN_SCOPE_DEFECT',
  'LATER_PHASE',
  'OUT_OF_SCOPE',
  'MISSING_EVIDENCE',
  'OPTIONAL_VALUE',
]);

/**
 * Effect classes Arcane authorizes/gates (ARCHITECTURE §24, §24a; COVENANT
 * §17; IMPLEMENTATION-PLAN Workstream E and Phase 5 tasks). No source
 * document gives a literal closed enum — this list is synthesized from the
 * containment/policy nouns those sections name. Judgment call J-8.
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
 * Model tiers (ARCHITECTURE Part XI-A). The table names concrete
 * model-class examples (Opus-class, MiMo/DeepSeek-flash/Luna-class) rather
 * than a closed tier enum; these four tier names are a judgment-call
 * normalization of that table. Judgment call J-9.
 */
export const MODEL_TIER = Object.freeze(['FRONTIER', 'MID', 'CHEAP_STRICT', 'NONE']);

/** Worker execution profiles (IMPLEMENTATION-PLAN Phase 8 task 13). */
export const WORKER_PROFILE = Object.freeze(['strict', 'standard', 'advanced']);

/**
 * Effect/evidence authentication method. Grounded in the S00 Forge semantic
 * baseline (docs/plans/legion/s00-baseline/legacy-semantic-inventory.json,
 * report §"What S03/S04/S05 will need to preserve or must NOT inherit as-is"
 * findings 1-2): Forge's `signature_or_mac` field
 * (hooks/claude-code/tool-receipt.js:80) is a self-hash by the same
 * untrusted process that built the receipt, not real authentication; the one
 * genuine trust primitive found is `lib/host.js`'s process-identity /
 * code-signing check, and it authenticates a *connection* once at MCP
 * startup, not each message. This enum lets a receipt/request say honestly
 * which of these it actually has. 'unauthenticated' is the correct value for
 * an imported legacy record; S03 owns designing real per-message
 * authentication ('capability-signature' is the forward-looking target this
 * freeze reserves a slot for, not something S03 is required to name this).
 * Judgment call, added mid-freeze at coordinator direction — see FREEZE.md.
 */
export const AUTHENTICATION_METHOD = Object.freeze([
  'host-connection-trust',
  'capability-signature',
  'unauthenticated',
]);

/** Contract-safety test outcome for a Covenant blocker suggestion (COVENANT.md §17) — subset of COVENANT_OUTCOME relevant to Alchemist. */
export const BLOCKER_CONSULT_OUTCOME = Object.freeze([
  'CONTRACT_SAFE',
  'AMENDMENT_REQUIRED',
  'INSUFFICIENT_EVIDENCE',
]);

/** Blocker classification — whether a blocker is clearly semantic or possibly contract-safe (ARCHITECTURE §15, §38). */
export const BLOCKER_CLASS = Object.freeze(['CLEARLY_SEMANTIC', 'POSSIBLY_CONTRACT_SAFE']);

/** Blocker lifecycle status. */
export const BLOCKER_STATUS = Object.freeze([
  'OPEN',
  'COVENANT_CONSULTED',
  'AMENDED',
  'RESOLVED',
]);

/** Claim object lifecycle status — Arcane owns the transition to VALIDATED/REJECTED (ARCHITECTURE §26). */
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
