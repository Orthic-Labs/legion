#![forbid(unsafe_code)]

mod error;
pub mod migrate_jsonl;
pub mod model;
pub mod query;
pub mod store;

pub use error::DecisionError;
pub use migrate_jsonl::{
    migrate_jsonl, migrate_reader, MigrationDiagnostic, MigrationDisposition, MigrationReport,
};
pub use model::{
    derive_decision_id, DecisionQuery, DecisionRecord, DecisionStatus, DECISION_ID_PREFIX,
    SCHEMA_VERSION,
};
pub use query::RankedDecision;
pub use store::{DecisionStore, InsertDisposition};
