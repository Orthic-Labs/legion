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

use legion_contracts::canonical_digest;

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
                sorted.sort_by(|a, b| id_sort_key(a).cmp(&id_sort_key(b)));
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
/// `legion_contracts::canonical_digest` on the result, matching how the JS
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn omitted_keys_are_stripped_at_any_depth() {
        let value = json!({
            "generatedAt": "2026-01-01T00:00:00Z",
            "nested": {"timestamp": 1, "keep": "yes"},
        });
        let projected = semantic_projection(value);
        assert_eq!(projected, json!({"nested": {"keep": "yes"}}));
    }

    #[test]
    fn id_bearing_arrays_are_sorted_by_id() {
        let value = json!([{"id": "b"}, {"id": "a"}]);
        let projected = semantic_projection(value);
        assert_eq!(projected, json!([{"id": "a"}, {"id": "b"}]));
    }

    #[test]
    fn non_id_arrays_keep_original_order() {
        let value = json!([3, 1, 2]);
        let projected = semantic_projection(value);
        assert_eq!(projected, json!([3, 1, 2]));
    }

    #[test]
    fn receipt_is_valid_when_only_omitted_fields_differ() {
        let prior = json!({"generatedAt": "t1", "data": 1});
        let current = json!({"generatedAt": "t2", "data": 1});
        let receipt = verification_receipt(prior, current).unwrap();
        assert!(receipt.valid);
        assert_eq!(receipt.kind, "legion-verification-receipt");
    }

    #[test]
    fn receipt_is_invalid_when_semantic_data_differs() {
        let prior = json!({"data": 1});
        let current = json!({"data": 2});
        let receipt = verification_receipt(prior, current).unwrap();
        assert!(!receipt.valid);
        assert_ne!(receipt.prior_digest, receipt.current_digest);
    }
}
