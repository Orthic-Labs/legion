#![forbid(unsafe_code)]

pub mod budget;
pub mod engine;
pub mod error;
pub mod escalation;
pub mod p7_host;
pub mod grant;
pub mod l4_platform;
pub mod l5_skills;
pub mod plan;
pub mod profile;
pub mod release_binding;
pub mod route;
pub mod scheduler;
pub mod task;
pub mod p5_core;
pub mod l3_inventory;
pub mod l6_designer_checks;
pub mod p9_skills;
pub mod p8_designer;

pub use budget::{BudgetAccount, BudgetReservation};
pub use engine::{
    adjudicate, Adjudication, CandidateEvidence, DrainReport, EffectPolicy, EngineOutcome,
    Invocation, LegionEngine, RuntimeAdmission, RuntimeState,
};
pub use error::RuntimeError;
pub use escalation::{validate_target, EscalationGrant};
pub use grant::EffectiveGrant;
pub use legion_contracts::{
    AgentDefinition, BudgetCeiling, InvocationGrant as CapabilityGrant, TaskSpec,
};
pub use plan::{compile_plan, FrozenPlan};
pub use profile::AgentProfile;
pub use release_binding::{
    load_release_manifest, verify_release_binding, DeclarativeAssets, DevelopmentExecutionContext,
    ReleaseBindingError, ReleaseBindingInputs, ReleaseManifest, RightkitAxIdentity,
    RuntimeIdentity, VerifiedReleaseBinding, REPAIR_COMMAND,
};
pub use route::{select_route, RouteCandidate, SelectedRoute};
pub use scheduler::{
    replan_remaining, ExecutionJournal, ExecutorActionEnvelope, PauseDecisionReceipt,
    RunLedgerEntry, Scheduler, SchedulerEvent, SchedulerOutput, SchedulerPolicy, TrajectoryRecord,
};
pub use task::{validate_task, ContextRequest};

// LEG-026 owns validation.rs; this declaration is intentionally reserved.
pub mod validation;
pub mod p6_inventory;
pub mod wf_port;
