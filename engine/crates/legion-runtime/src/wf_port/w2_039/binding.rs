//! Faithful port of `src/lib/core/binding.mjs`.
//!
//! `canonicalize` recursively sorts object keys and normalizes backslashes to
//! forward slashes in strings so that a value's JSON serialization is stable
//! across platforms; `digest` hashes that canonical form; `same_binding`
//! compares two bindings by digest equality (so `null`/`None` bindings match
//! each other); `assert_artifact_binding` is the guard `execute-plan`/`audit`
//! callers use to reject an artifact whose binding drifted from the sealed
//! plan's binding.

use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// Mirrors `canonicalize(value)`: arrays map element-wise, objects have their
/// keys sorted (matching JS `Object.keys(...).sort()`, i.e. UTF-16 code-unit
/// order — equivalent to Rust's default `&str` ordering for BMP text), and
/// strings have `\` replaced with `/` (JS `String.prototype.replaceAll`).
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::with_capacity(map.len());
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        Value::String(s) => Value::String(s.replace('\\', "/")),
        other => other.clone(),
    }
}

/// Mirrors `digest(value)`: `sha256:` followed by the hex SHA-256 of
/// `JSON.stringify(canonicalize(value))`.
pub fn digest(value: &Value) -> String {
    let canonical = canonicalize(value);
    // serde_json's Map is a BTreeMap by default (or IndexMap with the
    // `preserve_order` feature); canonicalize() already sorted every key
    // above, and serde_json::to_string on a Map serializes in key order for
    // BTreeMap, so this matches JSON.stringify on a key-sorted object.
    let serialized = serde_json::to_string(&canonical).expect("json values always serialize");
    let hash = Sha256::digest(serialized.as_bytes());
    format!("sha256:{}", hex::encode(hash))
}

/// Mirrors `sameBinding(left, right)`: `digest(left ?? null) === digest(right ?? null)`.
/// `None` stands in for JS `null`/`undefined`.
pub fn same_binding(left: Option<&Value>, right: Option<&Value>) -> bool {
    let null = Value::Null;
    digest(left.unwrap_or(&null)) == digest(right.unwrap_or(&null))
}

/// Error mirroring `IntegrityError` as thrown by `assertArtifactBinding`.
#[derive(Debug, thiserror::Error)]
#[error("{label} binding does not match sealed plan")]
pub struct BindingMismatch {
    pub label: String,
}

/// An artifact carrying a `binding` field, as `assertArtifactBinding` expects.
pub trait BoundArtifact {
    fn binding(&self) -> Option<&Value>;
}

/// Mirrors `assertArtifactBinding(artifact, expectedBinding, label = 'artifact')`.
/// JS treats a falsy `artifact` (e.g. `null`/`undefined`) as a mismatch too;
/// callers here pass `Option<&T>` to represent that.
pub fn assert_artifact_binding<'a, T: BoundArtifact>(
    artifact: Option<&'a T>,
    expected_binding: Option<&Value>,
    label: &str,
) -> Result<&'a T, BindingMismatch> {
    match artifact {
        Some(artifact) if same_binding(artifact.binding(), expected_binding) => Ok(artifact),
        _ => Err(BindingMismatch {
            label: label.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalize_sorts_object_keys() {
        let value = json!({"b": 1, "a": 2});
        assert_eq!(canonicalize(&value), json!({"a": 2, "b": 1}));
    }

    #[test]
    fn canonicalize_normalizes_backslashes_in_strings() {
        let value = json!({"path": "a\\b\\c"});
        assert_eq!(canonicalize(&value), json!({"path": "a/b/c"}));
    }

    #[test]
    fn canonicalize_recurses_into_arrays_and_nested_objects() {
        let value = json!([{"z": "x\\y"}, {"a": 1, "b": [3, 2, 1]}]);
        assert_eq!(
            canonicalize(&value),
            json!([{"z": "x/y"}, {"a": 1, "b": [3, 2, 1]}])
        );
    }

    #[test]
    fn digest_is_stable_regardless_of_input_key_order() {
        let a = json!({"a": 1, "b": 2});
        let b = json!({"b": 2, "a": 1});
        assert_eq!(digest(&a), digest(&b));
    }

    #[test]
    fn digest_has_sha256_prefix_and_length() {
        let d = digest(&json!({"a": 1}));
        assert!(d.starts_with("sha256:"));
        assert_eq!(d.len(), "sha256:".len() + 64);
    }

    #[test]
    fn digest_changes_when_value_changes() {
        assert_ne!(digest(&json!({"a": 1})), digest(&json!({"a": 2})));
    }

    #[test]
    fn same_binding_treats_none_as_null() {
        assert!(same_binding(None, None));
        assert!(same_binding(Some(&Value::Null), None));
        assert!(!same_binding(Some(&json!({"a": 1})), None));
    }

    #[test]
    fn same_binding_ignores_key_order_and_backslashes() {
        let left = json!({"root": "C:\\repo", "rev": "abc"});
        let right = json!({"rev": "abc", "root": "C:/repo"});
        assert!(same_binding(Some(&left), Some(&right)));
    }

    struct Artifact {
        binding: Option<Value>,
    }
    impl BoundArtifact for Artifact {
        fn binding(&self) -> Option<&Value> {
            self.binding.as_ref()
        }
    }

    #[test]
    fn assert_artifact_binding_passes_when_bindings_match() {
        let artifact = Artifact {
            binding: Some(json!({"rev": "abc"})),
        };
        let expected = json!({"rev": "abc"});
        let result = assert_artifact_binding(Some(&artifact), Some(&expected), "plan");
        assert!(result.is_ok());
    }

    #[test]
    fn assert_artifact_binding_rejects_mismatched_binding() {
        let artifact = Artifact {
            binding: Some(json!({"rev": "abc"})),
        };
        let expected = json!({"rev": "different"});
        let err = assert_artifact_binding(Some(&artifact), Some(&expected), "plan").unwrap_err();
        assert_eq!(err.label, "plan");
        assert_eq!(err.to_string(), "plan binding does not match sealed plan");
    }

    #[test]
    fn assert_artifact_binding_rejects_missing_artifact() {
        let expected = json!({"rev": "abc"});
        let err: BindingMismatch =
            assert_artifact_binding::<Artifact>(None, Some(&expected), "artifact").unwrap_err();
        assert_eq!(err.label, "artifact");
    }

    #[test]
    fn assert_artifact_binding_default_label_matches_js_default() {
        // JS default is 'artifact'; Rust callers must pass it explicitly, but
        // this test documents the expected literal so a caller who forgets
        // the JS default doesn't silently diverge.
        let err: BindingMismatch =
            assert_artifact_binding::<Artifact>(None, None, "artifact").unwrap_err();
        assert_eq!(err.to_string(), "artifact binding does not match sealed plan");
    }
}
