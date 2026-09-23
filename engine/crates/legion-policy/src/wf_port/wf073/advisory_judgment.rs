//! Port of `src/lib/verification/arcane/s11-bindings/advisory-judgment.mjs`.
//!
//! Evidence-only policy stub: every row in `ADVISORY_IDS` is bound to a
//! constant `PENDING` refusal until a future live consumer replaces it with
//! authenticated, case-bound record loading (externally authenticated
//! Sage+Oracle judgments). A pending observation is never valid completion
//! evidence — `validate_advisory_judgment_observation` always returns
//! `false`.
//!
//! Not to be confused with `legion_arcane::advisory_judgment`
//! (`find_current_advisory_judgment`/`persist_advisory_judgment`), which is
//! a different, already-native module: a receipt-store Sage/Oracle
//! consensus reader/writer. This module is the S11-architecture-evaluator
//! *binding table* that reports every one of its 35 case ids as
//! unconditionally pending — the two are not the same surface and this port
//! does not attempt to unify them (see the wf073 report).

pub const ADVISORY_IDS: [&str; 35] = [
    "AE-ADR-ADMISSION-001",
    "AE-ADR-ADMISSION-002",
    "AE-ADVERSARIAL-001",
    "AE-ADVERSARIAL-002",
    "AE-ADVERSARIAL-003",
    "AE-ADVERSARIAL-004",
    "AE-ADVERSARIAL-005",
    "AE-ADVERSARIAL-006",
    "AE-ADVERSARIAL-007",
    "AE-ADVERSARIAL-009",
    "AE-ADVERSARIAL-010",
    "AE-CANDIDATE-QUALITY-001",
    "AE-CANDIDATE-QUALITY-002",
    "AE-CANDIDATE-QUALITY-004",
    "AE-CANDIDATE-QUALITY-005",
    "AE-CANDIDATE-QUALITY-006",
    "AE-CANON-DRIFT-001",
    "AE-CANON-DRIFT-002",
    "AE-CLARIFICATION-CONVERGENCE-001",
    "AE-CLARIFICATION-CONVERGENCE-002",
    "AE-CONCURRENCY-ATTENTION-002",
    "AE-CONCURRENCY-ATTENTION-006",
    "AE-CONTROL-PLANE-BUDGETS-002",
    "AE-CONVERGENCE-001",
    "AE-CONVERGENCE-003",
    "AE-HANDOFF-002",
    "AE-HANDOFF-004",
    "AE-NEGATIVE-TRIGGERS-001",
    "AE-NEGATIVE-TRIGGERS-003",
    "AE-NEGATIVE-TRIGGERS-004",
    "AE-REVIEW-ADMISSION-001",
    "AE-REVIEW-VERDICT-SECURITY-002",
    "AE-REVIEW-VERDICT-SECURITY-005",
    "AE-REVIEW-VERDICT-SECURITY-006",
    "AE-SCOPE-AUTHORITY-001",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDecision {
    pub allowed: bool,
    pub code: &'static str,
    pub disposition: &'static str,
    pub reason: &'static str,
    pub case_id: Option<String>,
}

/// The JS binding table maps each id to a `pending(row)` closure; this port
/// exposes the equivalent evaluation function directly, keyed by id.
pub fn advisory_judgment_bindings(id: &str, row_id: Option<&str>) -> Option<PendingDecision> {
    if !ADVISORY_IDS.contains(&id) {
        return None;
    }
    Some(PendingDecision {
        allowed: false,
        code: "ARC_EVIDENCE_INSUFFICIENT",
        disposition: "PENDING",
        reason: "requires pre-existing externally authenticated Sage+Oracle judgments",
        case_id: row_id.map(str::to_string),
    })
}

pub fn advisory_judgment_runtime_ids() -> &'static [&'static str] {
    &ADVISORY_IDS
}

/// A pending observation is never valid completion evidence. A future live
/// consumer must replace this with authenticated, case-bound record
/// loading.
pub fn validate_advisory_judgment_observation() -> bool {
    false
}
