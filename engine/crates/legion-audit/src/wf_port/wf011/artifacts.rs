//! Port of `src/lib/providers/sdk/artifacts.mjs`.

use std::collections::BTreeMap;

use serde_json::Value;

use super::SdkError;

fn string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Faithful port of:
/// ```js
/// export function validateArtifactAuthority(providers) {
///   const owners = new Map();
///   for (const provider of providers) for (const artifact of provider.produces ?? []) {
///     if (owners.has(artifact)) throw new TypeError(`duplicate artifact producer: ${artifact}`);
///     owners.set(artifact, provider.id);
///   }
///   for (const provider of providers) for (const artifact of provider.consumes ?? [])
///     if (!owners.has(artifact)) throw new TypeError(`unproduced artifact: ${artifact}`);
///   return owners;
/// }
/// ```
///
/// Returns the artifact -> owning-provider-id map (JS `Map`, here a
/// `BTreeMap` for a deterministic, testable iteration order — the JS `Map`'s
/// insertion order is never observed by any caller of this function).
pub fn validate_artifact_authority(providers: &[Value]) -> Result<BTreeMap<String, String>, SdkError> {
    let mut owners: BTreeMap<String, String> = BTreeMap::new();
    for provider in providers {
        let id = provider.get("id").and_then(Value::as_str).unwrap_or("");
        for artifact in string_array(provider, "produces") {
            if owners.contains_key(&artifact) {
                return Err(SdkError::new(format!("duplicate artifact producer: {artifact}")));
            }
            owners.insert(artifact, id.to_owned());
        }
    }
    for provider in providers {
        for artifact in string_array(provider, "consumes") {
            if !owners.contains_key(&artifact) {
                return Err(SdkError::new(format!("unproduced artifact: {artifact}")));
            }
        }
    }
    Ok(owners)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn p(id: &str, produces: Vec<&str>, consumes: Vec<&str>) -> Value {
        json!({"id": id, "produces": produces, "consumes": consumes})
    }

    #[test]
    fn owners_map_records_producer_per_artifact() {
        let owners = validate_artifact_authority(&[
            p("a", vec!["x"], vec![]),
            p("b", vec!["y"], vec!["x"]),
        ])
        .unwrap();
        assert_eq!(owners.get("x").map(String::as_str), Some("a"));
        assert_eq!(owners.get("y").map(String::as_str), Some("b"));
    }

    #[test]
    fn duplicate_producer_is_rejected() {
        let err = validate_artifact_authority(&[p("a", vec!["x"], vec![]), p("b", vec!["x"], vec![])])
            .unwrap_err();
        assert_eq!(err.0, "duplicate artifact producer: x");
    }

    #[test]
    fn unproduced_consumed_artifact_is_rejected() {
        let err = validate_artifact_authority(&[p("a", vec![], vec!["ghost"])]).unwrap_err();
        assert_eq!(err.0, "unproduced artifact: ghost");
    }

    #[test]
    fn missing_produces_and_consumes_default_to_empty() {
        let owners = validate_artifact_authority(&[json!({"id": "a"})]).unwrap();
        assert!(owners.is_empty());
    }
}
