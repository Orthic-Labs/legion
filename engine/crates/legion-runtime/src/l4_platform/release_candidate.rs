//! Port of `src/lib/platform/release-candidate.mjs`.

use super::contracts::sha256;
use serde_json::{json, Map, Value};

/// `createReleaseCandidate(input)`.
pub fn create_release_candidate(input: &Value) -> Value {
    let raw_artifacts = input.get("artifacts").and_then(Value::as_array).cloned().unwrap_or_default();
    let artifacts: Vec<Value> = raw_artifacts
        .iter()
        .map(|artifact| {
            let mut obj: Map<String, Value> = artifact.as_object().cloned().unwrap_or_default();
            if !obj.contains_key("digest") || obj["digest"].is_null() {
                obj.insert("digest".to_string(), Value::Null);
            }
            Value::Object(obj)
        })
        .collect();

    let missing: Vec<String> = artifacts
        .iter()
        .filter(|artifact| {
            let path_missing = artifact.get("path").map(|p| p.is_null()).unwrap_or(true)
                || artifact.get("path").and_then(Value::as_str) == Some("");
            let digest_missing = artifact.get("digest").map(Value::is_null).unwrap_or(true);
            path_missing || digest_missing
        })
        .map(|artifact| {
            artifact.get("path").and_then(Value::as_str).unwrap_or("unknown").to_string()
        })
        .collect();

    let source_revision = input.get("sourceRevision").cloned().unwrap_or(Value::Null);
    let build_id = input.get("buildId").cloned().unwrap_or(Value::Null);
    let digest_input = json!({
        "sourceRevision": source_revision,
        "buildId": build_id,
        "artifacts": artifacts,
    });

    json!({
        "schemaVersion": 1,
        "kind": "legion-release-candidate",
        "sourceRevision": source_revision,
        "buildId": build_id,
        "version": input.get("version").cloned().unwrap_or(Value::Null),
        "toolchain": input.get("toolchain").cloned().unwrap_or_else(|| json!({})),
        "configuration": input.get("configuration").cloned().unwrap_or_else(|| json!({})),
        "dependencies": input.get("dependencies").cloned().unwrap_or_else(|| json!({})),
        "backendEnvironment": input.get("backendEnvironment").cloned().unwrap_or(Value::Null),
        "artifacts": artifacts,
        "signatures": input.get("signatures").cloned().unwrap_or_else(|| json!([])),
        "storeIdentity": input.get("storeIdentity").cloned().unwrap_or(Value::Null),
        "promotionChannel": input.get("promotionChannel").cloned().unwrap_or(Value::Null),
        "binding": input.get("binding").cloned().unwrap_or_else(|| json!({})),
        "complete": missing.is_empty(),
        "coverageGaps": missing.iter().map(|path| json!({"kind": "artifact-digest-missing", "path": path})).collect::<Vec<_>>(),
        "digest": sha256(&digest_input),
    })
}

/// `verifyCandidateArtifact(candidate, artifact)`.
pub fn verify_candidate_artifact(candidate: &Value, artifact: &Value) -> Value {
    let empty: Vec<Value> = Vec::new();
    let candidate_artifacts = candidate.get("artifacts").and_then(Value::as_array).unwrap_or(&empty);
    let path = artifact.get("path");
    let id = artifact.get("id");
    let expected = candidate_artifacts.iter().find(|item| {
        (path.is_some() && item.get("path") == path) || (id.is_some() && item.get("id") == id)
    });
    let expected = match expected {
        None => return json!({"status": "unproven", "reason": "artifact-not-in-candidate"}),
        Some(e) => e,
    };
    let expected_digest = expected.get("digest").cloned().unwrap_or(Value::Null);
    let actual_digest = artifact.get("digest").cloned().unwrap_or(Value::Null);
    if expected_digest.is_null() || expected_digest != actual_digest {
        return json!({
            "status": "fail",
            "reason": "artifact-digest-mismatch",
            "expected": expected_digest,
            "actual": actual_digest,
        });
    }
    json!({"status": "pass", "artifact": expected.get("path").cloned().unwrap_or(Value::Null)})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn complete_when_all_artifacts_have_path_and_digest() {
        let candidate = create_release_candidate(&json!({
            "sourceRevision": "abc",
            "artifacts": [{"path": "dist/pkg", "digest": "sha256:x"}],
        }));
        assert_eq!(candidate["complete"], true);
        assert_eq!(candidate["coverageGaps"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn incomplete_when_digest_missing() {
        let candidate = create_release_candidate(&json!({
            "artifacts": [{"path": "dist/pkg"}],
        }));
        assert_eq!(candidate["complete"], false);
        assert_eq!(candidate["coverageGaps"][0]["path"], "dist/pkg");
    }

    #[test]
    fn verify_candidate_artifact_matches_digest() {
        let candidate = create_release_candidate(&json!({
            "artifacts": [{"path": "dist/pkg", "digest": "sha256:x"}],
        }));
        let ok = verify_candidate_artifact(&candidate, &json!({"path": "dist/pkg", "digest": "sha256:x"}));
        assert_eq!(ok["status"], "pass");
        let bad = verify_candidate_artifact(&candidate, &json!({"path": "dist/pkg", "digest": "sha256:y"}));
        assert_eq!(bad["status"], "fail");
        let unproven = verify_candidate_artifact(&candidate, &json!({"path": "dist/other"}));
        assert_eq!(unproven["status"], "unproven");
    }
}
