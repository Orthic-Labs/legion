use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
        let actual = self.text.len() as u64;
        if actual != self.byte_length {
            return Err(ResearchError::InvalidSource(format!(
                "byte_length {0} does not match source text length {actual}",
                self.byte_length
            )));
        }
        let actual_digest = format!("sha256:{:x}", Sha256::digest(self.text.as_bytes()));
        if self.content_digest != actual_digest {
            return Err(ResearchError::InvalidSource(
                "content_digest does not match source text".into(),
            ));
        }
        if self.text.trim().is_empty() {
            return Err(ResearchError::InvalidSource(
                "source text must be non-empty".into(),
            ));
        }
        if matches!(
            self.kind,
            SourceKind::Web | SourceKind::Scholarly | SourceKind::Authority
        ) {
            if self.retrieved_at.as_deref().is_none_or(str::is_empty) {
                return Err(ResearchError::InvalidSource(
                    "external source requires retrieved_at".into(),
                ));
            }
            if self
                .metadata
                .get("request_receipt")
                .map(String::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(ResearchError::InvalidSource(
                    "external source requires request_receipt provenance".into(),
                ));
            }
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
