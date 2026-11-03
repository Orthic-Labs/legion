//! Port of `src/lib/verification/projection.mjs` and
//! `src/lib/verification/receipt.mjs` (packet P5c).
//!
//! `semanticProjection` recursively strips a fixed set of non-semantic keys
//! (`generatedAt`, `timestamp`, `outputDir`, `temporaryPath`,
//! `presentationOrder`, `scheduleOrder`) from a JSON value, sorts arrays of
//! objects that carry an `id` field by that id (string compare), and then
//! canonicalizes the result. `verificationReceipt` compares the digest of
//! the projected `prior` and `current` values.
//!
//! Needs `serde_json` as a `legion-runtime` dependency (see packet report).

use serde_json::{Map, Value};

use rightkit_evidence_contracts::canonical_digest;

const OMIT: [&str; 6] = [
    "generatedAt",
    "timestamp",
    "outputDir",
    "temporaryPath",
    "presentationOrder",
    "scheduleOrder",
];

fn is_id_bearing_object(value: &Value) -> bool {
    matches!(value, Value::Object(map) if map.contains_key("id"))
}

fn id_sort_key(value: &Value) -> String {
    match value.get("id") {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

fn project(value: Value) -> Value {
    match value {
        Value::Array(items) => {
            let projected: Vec<Value> = items.into_iter().map(project).collect();
            if !projected.is_empty() && projected.iter().all(is_id_bearing_object) {
                let mut sorted = projected;
                sorted.sort_by_key(id_sort_key);
                Value::Array(sorted)
            } else {
                Value::Array(projected)
            }
        }
        Value::Object(map) => {
            let mut output = Map::new();
            for (key, item) in map {
                if OMIT.contains(&key.as_str()) {
                    continue;
                }
                output.insert(key, project(item));
            }
            Value::Object(output)
        }
        other => other,
    }
}

/// Port of `semanticProjection(value)`. Returns the projected (but not yet
/// digested) canonical value; callers that need the digest itself should use
/// `rightkit_evidence_contracts::canonical_digest` on the result, matching how the JS
/// `canonicalize()` call was only ever used to feed a digest in this repo.
pub fn semantic_projection(value: Value) -> Value {
    project(value)
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationReceiptError {
    #[error("digest computation failed: {0}")]
    Digest(String),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub valid: bool,
    pub prior_digest: String,
    pub current_digest: String,
}

/// Port of `verificationReceipt(prior, current)`.
pub fn verification_receipt(
    prior: Value,
    current: Value,
) -> Result<VerificationReceipt, VerificationReceiptError> {
    let prior_digest = canonical_digest(&semantic_projection(prior))
        .map_err(|error| VerificationReceiptError::Digest(error.to_string()))?;
    let current_digest = canonical_digest(&semantic_projection(current))
        .map_err(|error| VerificationReceiptError::Digest(error.to_string()))?;
    Ok(VerificationReceipt {
        schema_version: 1,
        kind: "legion-verification-receipt".to_string(),
        valid: prior_digest == current_digest,
        prior_digest,
        current_digest,
    })
}
