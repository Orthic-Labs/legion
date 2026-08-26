#![forbid(unsafe_code)]

pub mod budget;
pub mod error;
pub mod evidence;
pub mod receipt;
pub mod report;
pub mod source;
pub mod workflow;

pub use budget::{BudgetAccount, BudgetLimits, BudgetSnapshot, BudgetUsage};
pub use error::ResearchError;
pub use evidence::{Claim, EvidenceKind, EvidenceLedger, EvidenceRecord};
pub use receipt::ResearchReceipt;
pub use report::{ReportClaim, ReportStatus, ResearchReport};
pub use source::{InjectedSource, SourceClient, SourceHit, SourceKind, SourceRecord};
pub use workflow::{
    Cancellation, NullableString, ResearchAuthorization, ResearchNumber, ResearchPatient,
    ResearchRoute, ResearchSubject, ResearchValue, ResearchWorkflow, SourceFailure, StageRecord,
    WorkflowOutcome, WorkflowRequest, WorkflowStage, WorkflowStatus,
};
