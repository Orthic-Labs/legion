use serde::{Deserialize, Serialize};

use crate::{
    source::{EventCursor, Record, RecordCategory},
    token::TokenAccounting,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandoffEntry {
    pub id: String,
    pub category: RecordCategory,
    pub text: String,
    pub sequence: u64,
    pub occurred_at_ms: i64,
    pub source_ref: String,
    pub source_hash: String,
    pub provenance: String,
    pub authority: String,
    pub externalized: bool,
}

impl HandoffEntry {
    pub fn from_record(record: &Record) -> Self {
        Self {
            id: record.id.clone(),
            category: record.category.clone(),
            text: record.text.clone(),
            sequence: record.sequence,
            occurred_at_ms: record.occurred_at_ms,
            source_ref: record.source_ref.clone(),
            source_hash: record.source_hash.clone(),
            provenance: record.provenance.clone(),
            authority: record.authority.clone(),
            externalized: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Omission {
    pub id: String,
    pub category: RecordCategory,
    pub reason: String,
    pub recoverable: bool,
    pub source_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandoffSection {
    pub category: RecordCategory,
    pub entries: Vec<HandoffEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandoffPacket {
    pub schema_version: u32,
    pub handoff_id: String,
    pub session_id: String,
    pub repository_id: String,
    pub source_generation: String,
    pub sections: Vec<HandoffSection>,
    pub cursor: Option<EventCursor>,
    pub source_provenance: Vec<String>,
    pub omissions: Vec<Omission>,
    pub accounting: TokenAccounting,
    pub partial: bool,
    pub blocked: bool,
    pub receipt_digest: String,
}
