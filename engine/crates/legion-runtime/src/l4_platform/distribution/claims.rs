//! Port of `src/lib/distribution/claims.mjs`.

use serde_json::{json, Value};

const STATES: &[&str] =
    &["deterministic-measured", "interpretive-measured", "experimental", "unproven", "unavailable"];

/// `generateClaims(qualifications)`. Panics (mirrors the JS `throw`) on an
/// unknown claim state.
pub fn generate_claims(qualifications: &[Value]) -> Vec<Value> {
    qualifications
        .iter()
        .map(|item| {
            let state = item.get("state").and_then(Value::as_str).unwrap_or("unproven");
            if !STATES.contains(&state) {
                panic!("unknown claim state: {state}");
            }
            let artifact_digest = item.get("artifactDigest").cloned().unwrap_or(Value::Null);
            let corpus_digest = item.get("corpusDigest").cloned().unwrap_or(Value::Null);
            let provider_digest = item.get("providerDigest").cloned().unwrap_or(Value::Null);
            let expected = item.get("expectedIdentity").filter(|v| !v.is_null());

            let qualified = expected
                .map(|expected| {
                    !artifact_digest.is_null()
                        && !corpus_digest.is_null()
                        && !provider_digest.is_null()
                        && expected.get("artifactDigest") == Some(&artifact_digest)
                        && expected.get("corpusDigest") == Some(&corpus_digest)
                        && expected.get("providerDigest") == Some(&provider_digest)
                })
                .unwrap_or(false);

            let final_state = if qualified { state.to_string() } else { "unproven".to_string() };
            let qualification = if qualified {
                json!({"artifactDigest": artifact_digest, "corpusDigest": corpus_digest, "providerDigest": provider_digest})
            } else {
                Value::Null
            };
            let limitations = item.get("limitations").filter(|v| v.is_array()).cloned().unwrap_or_else(|| {
                if qualified {
                    json!([])
                } else if expected.is_some() {
                    json!(["qualification identity mismatch"])
                } else {
                    json!(["qualification identity incomplete"])
                }
            });

            json!({
                "id": item.get("id").cloned().unwrap_or(Value::Null),
                "subject": item.get("subject").cloned().unwrap_or(Value::Null),
                "state": final_state,
                "qualification": qualification,
                "limitations": limitations,
                "hostCapabilities": item.get("hostCapabilities").cloned().unwrap_or_else(|| json!([])),
                "resourceConstraints": item.get("resourceConstraints").cloned().unwrap_or_else(|| json!({})),
                "reasoningRequirements": item.get("reasoningRequirements").cloned().unwrap_or_else(|| json!([])),
                "authorityLimits": item.get("authorityLimits").cloned().unwrap_or_else(|| json!([])),
            })
        })
        .collect()
}

/// `renderSupportMarkdown(claims)`.
pub fn render_support_markdown(claims: &[Value]) -> String {
    let lines: Vec<String> = claims
        .iter()
        .map(|claim| {
            let subject = claim.get("subject").and_then(Value::as_str)
                .or_else(|| claim.get("id").and_then(Value::as_str))
                .unwrap_or("");
            let state = claim.get("state").and_then(Value::as_str).unwrap_or("");
            let limitations = claim.get("limitations").and_then(Value::as_array).cloned().unwrap_or_default();
            let limitations_suffix = if limitations.is_empty() {
                String::new()
            } else {
                let joined: Vec<String> =
                    limitations.iter().map(|l| l.as_str().unwrap_or("").to_string()).collect();
                format!("; limitations: {}", joined.join(", "))
            };
            format!("- **{subject}** — {state}{limitations_suffix}")
        })
        .collect();
    format!("# Generated support claims\n\n{}\n", lines.join("\n"))
}

/// `generateClaimsFromQualification(qualification, expectedIdentity)`.
pub fn generate_claims_from_qualification(qualification: Option<&Value>, expected_identity: Option<&Value>) -> Value {
    let records = qualification
        .and_then(|q| q.get("claims").or_else(|| q.get("features")))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let with_expected: Vec<Value> = records
        .into_iter()
        .map(|mut record| {
            if let (Some(obj), Some(expected)) = (record.as_object_mut(), expected_identity) {
                obj.insert("expectedIdentity".to_string(), expected.clone());
            }
            record
        })
        .collect();
    json!({
        "schemaVersion": 1,
        "kind": "legion-generated-claims",
        "qualificationIdentity": expected_identity.cloned().unwrap_or(Value::Null),
        "claims": generate_claims(&with_expected),
        "knownGaps": if expected_identity.is_some() { json!([]) } else { json!(["exact qualification identity is absent"]) },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn qualifies_matching_identity() {
        let claims = generate_claims(&[json!({
            "id": "js", "subject": "JavaScript", "state": "deterministic-measured",
            "artifactDigest": "sha256:a", "corpusDigest": "sha256:c", "providerDigest": "sha256:p",
            "expectedIdentity": {"artifactDigest": "sha256:a", "corpusDigest": "sha256:c", "providerDigest": "sha256:p"},
            "hostCapabilities": ["process"], "authorityLimits": ["source-only"], "resourceConstraints": {"maxConcurrency": 1},
        })]);
        assert_eq!(claims[0]["state"], "deterministic-measured");
        assert_eq!(claims[0]["authorityLimits"], json!(["source-only"]));
        assert!(render_support_markdown(&claims).contains("deterministic-measured"));
    }

    #[test]
    fn downgrades_on_identity_mismatch() {
        let claims = generate_claims(&[json!({
            "id": "bad", "subject": "Bad", "state": "deterministic-measured",
            "artifactDigest": "sha256:x", "corpusDigest": "sha256:c", "providerDigest": "sha256:p",
            "expectedIdentity": {"artifactDigest": "sha256:a", "corpusDigest": "sha256:c", "providerDigest": "sha256:p"},
        })]);
        assert_eq!(claims[0]["state"], "unproven");
    }

    #[test]
    fn unproven_without_expected_identity() {
        let claims = generate_claims(&[json!({
            "id": "self", "state": "deterministic-measured",
            "artifactDigest": "sha256:x", "corpusDigest": "sha256:y", "providerDigest": "sha256:z",
        })]);
        assert_eq!(claims[0]["state"], "unproven");
        let result = generate_claims_from_qualification(Some(&json!({"claims": [{"id": "self", "state": "deterministic-measured"}]})), None);
        assert_eq!(result["claims"][0]["state"], "unproven");
    }
}
