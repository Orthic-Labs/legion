use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::SourceError;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordCategory {
    ProtectedObligation,
    ActiveTask,
    Decision,
    Artifact,
    UnresolvedRisk,
    Memory,
    Event,
}

impl RecordCategory {
    pub fn priority(&self) -> u8 {
        match self {
            Self::ProtectedObligation => 0,
            Self::ActiveTask => 1,
            Self::Decision => 2,
            Self::Artifact => 3,
            Self::UnresolvedRisk => 4,
            Self::Memory => 5,
            Self::Event => 6,
        }
    }
    pub fn protected(&self) -> bool {
        matches!(
            self,
            Self::ProtectedObligation | Self::ActiveTask | Self::UnresolvedRisk
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    pub id: String,
    pub category: RecordCategory,
    pub text: String,
    pub sequence: u64,
    pub occurred_at_ms: i64,
    pub source_ref: String,
    pub source_hash: String,
    pub provenance: String,
    pub authority: String,
    pub recoverable: bool,
    #[serde(default)]
    pub external_ref: Option<String>,
}

impl Record {
    pub fn new(id: impl Into<String>, category: RecordCategory, text: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            category,
            text: text.into(),
            sequence: 0,
            occurred_at_ms: 0,
            source_ref: "injected".into(),
            source_hash: "unknown".into(),
            provenance: "injected".into(),
            authority: "record".into(),
            recoverable: true,
            external_ref: None,
        }
    }
    pub fn protected(&self) -> bool {
        self.category.protected()
    }
}

pub type RecordKind = RecordCategory;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandoffQuery {
    pub session_id: String,
    pub repository_id: String,
    pub task_id: Option<String>,
    pub source_generation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventCursor {
    pub stream: String,
    pub sequence: u64,
    pub source_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventPage {
    pub records: Vec<Record>,
    pub cursor: EventCursor,
    pub complete: bool,
}

#[async_trait]
pub trait RecordSource: Send + Sync {
    async fn records(&self, query: &HandoffQuery) -> std::result::Result<Vec<Record>, SourceError>;
}

#[async_trait]
pub trait MemorySearch: Send + Sync {
    async fn search(&self, query: &HandoffQuery) -> std::result::Result<Vec<Record>, SourceError>;
}

#[async_trait]
pub trait SessionEventReader: Send + Sync {
    async fn events(
        &self,
        query: &HandoffQuery,
        after: Option<&EventCursor>,
    ) -> std::result::Result<EventPage, SourceError>;
}

#[async_trait]
pub trait ArtifactReader: Send + Sync {
    async fn artifacts(
        &self,
        query: &HandoffQuery,
    ) -> std::result::Result<Vec<Record>, SourceError>;
}

#[derive(Clone, Default)]
pub struct SourceSet {
    pub records: Option<Arc<dyn RecordSource>>,
    pub memory: Option<Arc<dyn MemorySearch>>,
    pub events: Option<Arc<dyn SessionEventReader>>,
    pub artifacts: Option<Arc<dyn ArtifactReader>>,
}

impl std::fmt::Debug for SourceSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceSet")
            .field("records", &self.records.is_some())
            .field("memory", &self.memory.is_some())
            .field("events", &self.events.is_some())
            .field("artifacts", &self.artifacts.is_some())
            .finish()
    }
}
