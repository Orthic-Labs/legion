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
    /// The smallest stable locator supplied by a host for this opened source.
    ///
    /// Hosts may provide a passage locator in metadata.  A source URI remains a
    /// valid whole-document locator for host records that do not expose a more
    /// precise passage.
    pub fn evidence_locator(&self) -> Option<String> {
        self.metadata
            .get("locator")
            .filter(|locator| !locator.trim().is_empty())
            .cloned()
            .or_else(|| (!self.uri.trim().is_empty()).then(|| self.uri.clone()))
    }

    /// Search hits, snippets, model answers, and NotebookLM answers are leads.
    /// They cannot be promoted to opened-source evidence by this boundary.
    pub fn is_lead(&self) -> bool {
        let status = self
            .metadata
            .get("evidence_status")
            .or_else(|| self.metadata.get("status"))
            .map(|value| value.trim().to_ascii_lowercase());
        let source_type = self
            .metadata
            .get("source_type")
            .map(|value| value.trim().to_ascii_lowercase());
        matches!(
            self.provider.trim().to_ascii_lowercase().as_str(),
            "notebooklm"
        ) || matches!(status.as_deref(), Some("lead" | "snippet" | "summary"))
            || matches!(
                source_type.as_deref(),
                Some(
                    "search-hit"
                        | "search-snippet"
                        | "snippet"
                        | "ai-summary"
                        | "provider-answer"
                        | "notebooklm-answer"
                )
            )
    }

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
        if self.is_lead() {
            return Err(ResearchError::InvalidSource(
                "lead-only source records cannot enter evidence".into(),
            ));
        }
        if self.evidence_locator().is_none() {
            return Err(ResearchError::InvalidSource(
                "opened source requires a locator".into(),
            ));
        }
        if self
            .metadata
            .get("instruction_policy")
            .map(|policy| policy != "data_only")
            .unwrap_or(false)
        {
            return Err(ResearchError::InvalidSource(
                "source instruction_policy must be data_only".into(),
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
            if let Some(retrieved_at) = self.retrieved_at.as_deref() {
                let date = retrieved_at.get(..10).unwrap_or_default();
                let valid_date = date.len() == 10
                    && date.as_bytes()[4] == b'-'
                    && date.as_bytes()[7] == b'-'
                    && date
                        .bytes()
                        .enumerate()
                        .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit());
                if !valid_date {
                    return Err(ResearchError::InvalidSource(
                        "external source retrieved_at must begin with an ISO date".into(),
                    ));
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> SourceRecord {
        let text = "opened source text";
        SourceRecord {
            schema_version: 1,
            source_id: "source-1".into(),
            kind: SourceKind::Web,
            provider: "browser".into(),
            uri: "https://example.test/source".into(),
            title: Some("Source".into()),
            retrieved_at: Some("2026-08-26T00:00:00Z".into()),
            content_digest: format!("sha256:{:x}", Sha256::digest(text.as_bytes())),
            byte_length: text.len() as u64,
            text: text.into(),
            metadata: BTreeMap::from([("request_receipt".into(), "request-1".into())]),
        }
    }

    #[test]
    fn lead_source_is_rejected_before_ledger_admission() {
        let mut lead = source();
        lead.metadata
            .insert("evidence_status".into(), "lead".into());
        assert!(lead.validate().is_err());
    }

    #[test]
    fn opened_source_exposes_locator() {
        let mut opened = source();
        opened.metadata.insert(
            "locator".into(),
            "https://example.test/source#passage-1".into(),
        );
        assert_eq!(
            opened.evidence_locator().as_deref(),
            Some("https://example.test/source#passage-1")
        );
    }
}
