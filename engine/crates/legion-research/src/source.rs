use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc, time::Instant};

use crate::{error::ResearchError, workflow::Cancellation};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Web,
    Scholarly,
    Authority,
    LocalCorpus,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRecord {
    pub schema_version: u32,
    pub source_id: String,
    pub kind: SourceKind,
    pub provider: String,
    pub uri: String,
    pub title: Option<String>,
    pub retrieved_at: Option<String>,
    pub content_digest: String,
    pub byte_length: u64,
    /// Source material is opaque data. It is never interpreted as workflow instructions.
    pub text: String,
    pub metadata: BTreeMap<String, String>,
}

impl SourceRecord {
    pub fn validate(&self) -> Result<(), ResearchError> {
        if self.schema_version != 1 {
            return Err(ResearchError::InvalidSource(
                "unsupported source schema version".into(),
            ));
        }
        for (field, value) in [
            ("source_id", &self.source_id),
            ("provider", &self.provider),
            ("uri", &self.uri),
            ("content_digest", &self.content_digest),
        ] {
            if value.trim().is_empty() {
                return Err(ResearchError::InvalidSource(format!(
                    "{field} must be non-empty"
                )));
            }
        }
        let actual = self.text.as_bytes().len() as u64;
        if actual != self.byte_length {
            return Err(ResearchError::InvalidSource(format!(
                "byte_length {0} does not match source text length {actual}",
                self.byte_length
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceHit {
    pub source_id: String,
    pub uri: String,
    pub title: Option<String>,
    pub provider: String,
    pub relevance: Option<u32>,
}

impl SourceHit {
    pub fn validate(&self) -> Result<(), ResearchError> {
        if self.source_id.trim().is_empty()
            || self.uri.trim().is_empty()
            || self.provider.trim().is_empty()
        {
            return Err(ResearchError::InvalidSource(
                "source hit requires id, uri, and provider".into(),
            ));
        }
        Ok(())
    }
}

/// Injected external source client. Implementations own transport; this crate owns bounds and provenance.
pub trait SourceClient: Send + Sync {
    fn provider(&self) -> &str;
    /// Upper bound reserved before `open` is called. Zero means the workflow uses one byte.
    fn estimated_bytes(&self, _hit: &SourceHit) -> u64 {
        0
    }
    fn estimated_call_cost_micros(&self) -> u64 {
        0
    }
    fn search(
        &self,
        query: &str,
        limit: u32,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> Result<Vec<SourceHit>, ResearchError>;
    fn open(
        &self,
        hit: &SourceHit,
        deadline: Instant,
        cancellation: &Cancellation,
    ) -> Result<SourceRecord, ResearchError>;
}

pub type InjectedSource = Arc<dyn SourceClient>;
