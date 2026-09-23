//! Ported dataclasses and `Provider` protocol from
//! `src/lib/research-core/providers/base.py`.

use serde_json::{Map, Value};

use super::support::WfError;

/// Port of `base.SearchHit`.
#[derive(Clone, Debug, PartialEq)]
pub struct SearchHit {
    pub id: String,
    pub url: String,
    pub title: String,
    pub publisher: String,
    pub snippet: String,
    pub suggested_by: String,
    pub seed_chain: Vec<String>,
    pub provider: String,
    pub metadata: Map<String, Value>,
}

impl SearchHit {
    /// Port of `SearchHit.to_dict`: adds `evidence_status: "lead"`.
    pub fn to_dict(&self) -> Value {
        let mut out = Map::new();
        out.insert("id".into(), self.id.clone().into());
        out.insert("url".into(), self.url.clone().into());
        out.insert("title".into(), self.title.clone().into());
        out.insert("publisher".into(), self.publisher.clone().into());
        out.insert("snippet".into(), self.snippet.clone().into());
        out.insert("suggested_by".into(), self.suggested_by.clone().into());
        out.insert(
            "seed_chain".into(),
            Value::Array(self.seed_chain.iter().cloned().map(Value::from).collect()),
        );
        out.insert("provider".into(), self.provider.clone().into());
        out.insert("metadata".into(), Value::Object(self.metadata.clone()));
        out.insert("evidence_status".into(), "lead".into());
        Value::Object(out)
    }
}

/// Port of `base.OpenedSource`.
#[derive(Clone, Debug, PartialEq)]
pub struct OpenedSource {
    pub url: String,
    pub title: String,
    pub publisher: String,
    pub retrieved_at: String,
    pub content: String,
    pub content_sha256: String,
    pub instruction_policy: String,
    pub provider: String,
    pub metadata: Map<String, Value>,
}

impl OpenedSource {
    /// Port of `OpenedSource.to_dict`: renames `instruction_policy` to
    /// `instructionPolicy`.
    pub fn to_dict(&self) -> Value {
        let mut out = Map::new();
        out.insert("url".into(), self.url.clone().into());
        out.insert("title".into(), self.title.clone().into());
        out.insert("publisher".into(), self.publisher.clone().into());
        out.insert("retrieved_at".into(), self.retrieved_at.clone().into());
        out.insert("content".into(), self.content.clone().into());
        out.insert("content_sha256".into(), self.content_sha256.clone().into());
        out.insert("instructionPolicy".into(), self.instruction_policy.clone().into());
        out.insert("provider".into(), self.provider.clone().into());
        out.insert("metadata".into(), Value::Object(self.metadata.clone()));
        Value::Object(out)
    }
}

/// Port of `base.LocatedPassage`.
#[derive(Clone, Debug, PartialEq)]
pub struct LocatedPassage {
    pub url: String,
    pub locator: String,
    pub text: String,
    pub is_paraphrase: bool,
    pub provider: String,
    pub metadata: Map<String, Value>,
}

impl LocatedPassage {
    /// Port of `LocatedPassage.to_dict` (plain `asdict`).
    pub fn to_dict(&self) -> Value {
        let mut out = Map::new();
        out.insert("url".into(), self.url.clone().into());
        out.insert("locator".into(), self.locator.clone().into());
        out.insert("text".into(), self.text.clone().into());
        out.insert("is_paraphrase".into(), self.is_paraphrase.into());
        out.insert("provider".into(), self.provider.clone().into());
        out.insert("metadata".into(), Value::Object(self.metadata.clone()));
        Value::Object(out)
    }
}

/// Port of `base.Provider` (a `Protocol` in Python).
pub trait Provider {
    fn name(&self) -> &str;
    fn search(
        &self,
        query: &str,
        limit: usize,
        seed_chain: &[String],
    ) -> Result<Vec<SearchHit>, WfError>;
    fn open(&self, url: &str) -> Result<OpenedSource, WfError>;
    fn find(&self, opened: &OpenedSource, pattern: &str) -> Result<Option<LocatedPassage>, WfError>;
}
