//! wf074 — Rust port of `src/lib/verification/arcane/s11-bindings/{
//! eval-adr-canon-clarify,eval-adversarial,eval-concurrency-convergence,
//! eval-review-security,evidence-closure}.mjs`.
//!
//! Additive only: the JS remains the source of truth until CI parity is
//! proven and a later packet deletes it. See the wf074 report at
//! `/private/tmp/claude-501/-Volumes-D-claude-heardright/27c99660-46fe-472a-bd29-43596bb3bc77/scratchpad/loss/wf/wf074.md`
//! for per-file status, what was ported faithfully, and what could not be
//! (with the reason and the dependency this module would need once other
//! wf packets land it).
//!
//! NOTE for the integration owner: not yet wired into the crate root. Add
//! `pub mod wf_port;` to `engine/crates/legion-policy/src/lib.rs` (if not
//! already present from another wf packet) and `pub mod wf074;` to
//! `engine/crates/legion-policy/src/wf_port/mod.rs` before running
//! `cargo test` against it.

mod canonical;
pub mod eval_adr_canon_clarify;
pub mod eval_adversarial;
pub mod eval_concurrency_convergence;
pub mod eval_review_security;
pub mod evidence_closure;

pub use eval_adr_canon_clarify::{
    adr_canon_clarify_binding_ids, adr_canon_clarify_runtime_ids, evaluate_adr_admission,
    evaluate_canon_owner_drift, evaluate_clarification_convergence, evaluate_fog_metadata,
    evaluate_generated_source_drift, execute_adr_canon_clarify_binding,
    execute_adr_canon_clarify_case, validate_adr_canon_clarify_observation, AdrAdmissionInput,
    ClarificationImpact, EvalOutcome,
};
pub use eval_adversarial::{
    adversarial_binding_ids, execute_adversarial_binding, validate_adversarial_observation,
    AdversarialResult, ADVERSARIAL_IDS,
};
pub use eval_concurrency_convergence::{
    concurrency_convergence_binding_ids, execute_concurrency_convergence_case,
    validate_concurrency_convergence_observation, ConcurrencyConvergenceResult,
};
pub use eval_review_security::{
    execute_review_security_binding, review_security_runtime_ids,
    validate_review_security_observation, ReviewSecurityResult,
};
pub use evidence_closure::{
    evidence_closure_runtime_policy_ids, execute_evidence_closure_runtime_case,
    EvidenceClosureResult,
};
pub use canonical::{digest_value, canonical_json, Json};
