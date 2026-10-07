#![forbid(unsafe_code)]

pub mod advisory_certification;
pub mod advisory_judgment;
pub mod authority_invocation;
pub mod budget;
pub mod command_verifier;
pub mod continuity;
pub mod contract_lifecycle;
pub mod control_lifecycle;
pub mod control_recovery;
pub mod decision;
pub mod deficit_governance;
pub mod delivery_dispatch;
pub mod delivery_scheduler;
pub mod durable_packet;
pub mod error;
pub mod evidence_authority;
pub mod execution_dispatch;
pub mod execution_governance;
pub mod finding_lifecycle;
pub mod judgment_dispatch;
pub mod key_ring;
pub mod migration_cutover;
pub mod receipt_auth;
pub mod receipt_store;
pub mod scope_amendment;
pub mod session_binding;
pub mod state_paths;

pub use authority_invocation::AuthorityInvocationProofIssuer;
pub use budget::{
    inspect_projection, BudgetGovernanceStore, TaskBudgetSealStore, AMENDED_BUDGET_BOUND_FIELDS,
    BUDGET_AMENDMENT_BOUND_FIELDS, BUDGET_BOUND_FIELDS, TASK_BUDGET_SEAL_BOUND_FIELDS,
};
pub use command_verifier::verify_command_result;
pub use continuity::rehydrate_untrusted_data;
pub use contract_lifecycle::ContractLifecycle;
pub use control_lifecycle::assess_control_retirement;
pub use control_recovery::recover_control_state;
pub use delivery_dispatch::{
    dispatch_delivery_governance, DeliveryGovernanceDispatcher, TrustedDeliveryEvidenceCapability,
};
pub use delivery_scheduler::{
    admit_capacity, admit_task_phase, assess_realization, classify_handoff,
};
pub use durable_packet::DurablePacketAdmissionStore;
pub use error::ArcaneError;
pub use evidence_authority::{
    classify_technology_requirement, resolve_latency_target, EvidenceAuthorityRegistry,
};
pub use execution_dispatch::{
    dispatch_execution_control, ExecutionControlCapability, ExecutionSnapshot,
    EXECUTION_CONTROL_OPERATIONS,
};
pub use execution_governance::{
    admit_convergence_pass, admit_retry, classify_rehydrated_input, classify_retry_failure,
    deny_stale_continuation, record_attempt, require_diagnosis_delta, settle_flaky_retry,
    EventStoreAccept,
};
pub use judgment_dispatch::{
    auth_unavailable_result, dispatch_governance_judgment, requires_authenticated_stores,
    JudgmentControlCapability,
};
pub use key_ring::KeyRing;
pub use migration_cutover::assess_migration_cutover;
pub use receipt_auth::sign_record;
pub use receipt_store::ReceiptStore;
pub use session_binding::SessionBindingStore;
pub use state_paths::state_root;
