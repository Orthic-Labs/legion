//! Port of `src/lib/platform/promotion-equivalence.mjs`.

use serde_json::{json, Value};

/// `promotionEquivalence({ qaCandidate, promotedArtifacts })`.
pub fn promotion_equivalence(qa_candidate: Option<&Value>, promoted_artifacts: &[Value]) -> Value {
    let source_artifacts = qa_candidate
        .and_then(|c| c.get("artifacts"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let checks: Vec<Value> = promoted_artifacts
        .iter()
        .map(|artifact| {
            let source_artifact_id = artifact.get("sourceArtifactId");
            let source_path = artifact.get("sourcePath");
            let source = source_artifacts.iter().find(|item| {
                (source_artifact_id.is_some() && item.get("id") == source_artifact_id)
                    || (source_path.is_some() && item.get("path") == source_path)
            });
            let expected_digest = source.and_then(|s| s.get("digest")).cloned().unwrap_or(Value::Null);
            let actual_digest = artifact.get("digest").cloned().unwrap_or(Value::Null);
            let status = if !expected_digest.is_null() && expected_digest == actual_digest {
                "pass"
            } else if source.is_some() {
                "fail"
            } else {
                "unproven"
            };
            json!({
                "artifact": artifact.get("path").or_else(|| artifact.get("id")).cloned().unwrap_or(Value::Null),
                "expectedDigest": expected_digest,
                "actualDigest": actual_digest,
                "status": status,
            })
        })
        .collect();

    let status = if !checks.is_empty() && checks.iter().all(|c| c["status"] == "pass") {
        "pass"
    } else if checks.iter().any(|c| c["status"] == "fail") {
        "fail"
    } else {
        "unproven"
    };

    json!({
        "schemaVersion": 1,
        "kind": "legion-promotion-equivalence",
        "qaCandidateDigest": qa_candidate.and_then(|c| c.get("digest")).cloned().unwrap_or(Value::Null),
        "checks": checks,
        "status": status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn passes_when_digests_match() {
        let qa = json!({"digest": "sha256:qa", "artifacts": [{"id": "a1", "digest": "sha256:x"}]});
        let promoted = vec![json!({"sourceArtifactId": "a1", "path": "out/a", "digest": "sha256:x"})];
        let result = promotion_equivalence(Some(&qa), &promoted);
        assert_eq!(result["status"], "pass");
    }

    #[test]
    fn fails_on_mismatch_and_unproven_when_missing() {
        let qa = json!({"artifacts": [{"id": "a1", "digest": "sha256:x"}]});
        let promoted = vec![
            json!({"sourceArtifactId": "a1", "digest": "sha256:y"}),
            json!({"sourceArtifactId": "missing", "digest": "sha256:z"}),
        ];
        let result = promotion_equivalence(Some(&qa), &promoted);
        assert_eq!(result["status"], "fail");
        assert_eq!(result["checks"][0]["status"], "fail");
        assert_eq!(result["checks"][1]["status"], "unproven");
    }
}
