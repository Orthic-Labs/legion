#![forbid(unsafe_code)]

pub mod budget;
pub mod engine;
pub mod error;
pub mod escalation;
pub mod grant;
pub mod plan;
pub mod profile;
pub mod release_binding;
pub mod route;
pub mod scheduler;
pub mod task;

pub use budget::{BudgetAccount, BudgetReservation};
pub use engine::{
    adjudicate, Adjudication, CandidateEvidence, EffectPolicy, EngineOutcome, Invocation,
    LegionEngine,
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
pub use scheduler::{Scheduler, SchedulerEvent, SchedulerOutput, SchedulerPolicy};
pub use task::{validate_task, ContextRequest};

// LEG-026 owns validation.rs; this declaration is intentionally reserved.
pub mod validation;
