//! wf073 — port of `src/lib/verification/arcane/{invalidation,
//! pending-terminal-operation-store,provider-capability,
//! review-disposition-policy}.mjs` and `s11-bindings/advisory-judgment.mjs`.
//!
//! Owned exclusively by this porting chunk. JS remains source of truth
//! until CI parity is proven. Not yet wired into `legion-policy`'s public
//! surface: the integrator adds `pub mod wf_port;` to `src/lib.rs` and
//! `pub mod wf073;` to `src/wf_port/mod.rs`.
//!
//! Cargo.toml patch needed from the integrator (same one wf068 already
//! flags): promote `serde_json` from `[dev-dependencies]` to
//! `[dependencies]` — this module's decision/claim payloads use
//! `serde_json::Value`/`Map` for the untyped JS `detail`/record shapes.
//! No other new dependency is needed; everything else uses `serde`,
//! `sha2`, and `hex`, all already declared.
//!
//! See each submodule's header for the specific ported-behaviour gaps
//! (file-backed ledger persistence, receipt-auth MAC construction, event-id
//! scheme) and the wf073 report for the full method notes.

pub mod advisory_judgment;
pub mod errors;
pub mod invalidation;
pub mod pending_terminal_operation_store;
pub mod provider_capability;
pub mod review_disposition_policy;

pub use advisory_judgment::{
    advisory_judgment_bindings, advisory_judgment_runtime_ids, validate_advisory_judgment_observation,
    PendingDecision, ADVISORY_IDS,
};
pub use errors::ArcaneError;
pub use invalidation::{
    ChangedDigest, Dependency, DependencyLedger, EligibilityStatus, EvidenceView, InvalidationEvent,
    LedgerSnapshot, ProofEligibility, QuarantineEntry, StaleEvent,
};
pub use pending_terminal_operation_store::{
    PendingTerminalOperationStore, PENDING_TERMINAL_OPERATION_FIELDS,
};
pub use provider_capability::{
    verify_external_provider_capability, AdapterCapability, CapabilityDecision,
    InMemoryProviderCapabilityStore, ProviderCapabilityRegistry, ProviderCapabilityRecord,
    ProviderCapabilityStore,
};
pub use review_disposition_policy::{
    evaluate_review_disposition_case, review_disposition_policy_ids, validate_review_disposition_decision,
    CaseEvidence, Coverage, CoverageDisposition, ExploitChainEvidence, ExploitLink, Finding, HandoffEvidence,
    ReviewDispositionDecision, ReviewReopenEvidence, Status, REVIEW_DISPOSITION_POLICY_IDS,
};
