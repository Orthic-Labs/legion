//! Port of `src/providers/runtime/web/integration/index.mjs`
//! (`integrateWebEvidence`).

use serde_json::Value;
use std::collections::HashSet;

use super::shared::{canonicalize, denominator, exact_binding, finalize, is_canonical_base64, safe_path, same_binding, sort_by_id};

const ACCEPTED: &[&str] = &["pass", "fail", "partial", "unproven", "blocked", "error"];

fn valid_artifact(artifact: &Value, binding: &Value, control_id: &str) -> bool {
    let Some(_) = artifact.as_object() else { return false };
    if !safe_path(&artifact["path"]) {
        return false;
    }
    if artifact.get("family").and_then(Value::as_str) != Some("web") {
        return false;
    }
    if artifact.get("targetId") != binding.get("targetId") {
        return false;
    }
    if artifact.get("environment") != binding.get("environment") {
        return false;
    }
    if artifact.get("sourceRevision") != binding.get("sourceRevision") {
        return false;
    }
    if artifact.get("controlId").and_then(Value::as_str) != Some(control_id) {
        return false;
    }
    if !same_binding(binding, artifact.get("binding").unwrap_or(&Value::Null)) {
        return false;
    }
    let sensitive_fields = artifact.get("sensitiveFields").cloned().unwrap_or(Value::Array(Vec::new()));
    let (_, sensitive, _) = super::shared::sanitize_artifact_content(artifact, &sensitive_fields);
    if sensitive {
        return false;
    }
    let has_content = artifact.get("content").and_then(Value::as_str).is_some();
    let has_bytes = artifact.get("bytesBase64").and_then(Value::as_str).is_some();
    if has_content == has_bytes {
        return false;
    }
    let bytes: Option<Vec<u8>> = if has_content {
        Some(artifact.get("content").and_then(Value::as_str).unwrap().as_bytes().to_vec())
    } else {
        let b64 = artifact.get("bytesBase64").and_then(Value::as_str).unwrap();
        if is_canonical_base64(b64) {
            super::shared::base64_decode(b64)
        } else {
            None
        }
    };
    let Some(bytes) = bytes else { return false };
    if bytes.is_empty() {
        return false;
    }
    let expected = format!("sha256:{}", sha256_hex(&bytes));
    artifact.get("digest").and_then(Value::as_str) == Some(expected.as_str())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn artifact_key(artifact: &Value) -> String {
    let shaped = if let Some(path) = artifact.as_str() {
        serde_json::json!({ "binding": Value::Null, "digest": Value::Null, "family": Value::Null, "id": Value::Null, "path": path })
    } else {
        serde_json::json!({
            "binding": artifact.get("binding").cloned().unwrap_or(Value::Null),
            "digest": artifact.get("digest").cloned().unwrap_or(Value::Null),
            "family": artifact.get("family").cloned().unwrap_or(Value::Null),
            "id": artifact.get("id").cloned().unwrap_or(Value::Null),
            "path": artifact.get("path").cloned().unwrap_or(Value::Null),
        })
    };
    serde_json::to_string(&canonicalize(&shaped)).unwrap_or_default()
}

struct NormalizedArtifacts {
    artifacts: Vec<Value>,
    duplicates: Vec<String>,
}

fn normalize_artifacts(values: Option<&[Value]>) -> NormalizedArtifacts {
    let Some(values) = values else {
        return NormalizedArtifacts { artifacts: Vec::new(), duplicates: Vec::new() };
    };
    let mut rows: Vec<(Value, String, String)> = values
        .iter()
        .map(|artifact| {
            let key = artifact_key(artifact);
            let value = serde_json::to_string(&canonicalize(artifact)).unwrap_or_default();
            (artifact.clone(), key, value)
        })
        .collect();
    rows.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2)));
    let mut duplicates = Vec::new();
    let mut artifacts: Vec<Value> = Vec::new();
    let mut last_key: Option<String> = None;
    for (artifact, key, _) in rows {
        if last_key.as_deref() == Some(key.as_str()) {
            duplicates.push(key);
            continue;
        }
        last_key = Some(key.clone());
        artifacts.push(artifact);
    }
    let mut unique_duplicates: Vec<String> = duplicates;
    unique_duplicates.sort();
    unique_duplicates.dedup();
    NormalizedArtifacts { artifacts, duplicates: unique_duplicates }
}

/// Port of `integrateWebEvidence` in `integration/index.mjs`.
///
/// # Panics / errors
/// The JS throws `Error(\`cross-target evidence rejected: ${controlId}\`)`
/// when a receipt's `targetId` does not match the binding, and
/// `Error(\`duplicate terminal receipt: ${controlId}\`)` for a second
/// terminal receipt on the same expected control. This port surfaces both
/// as `Err(String)` with the identical message rather than panicking, since
/// callers of the JS function are expected to catch these.
pub fn integrate_web_evidence(binding: Value, applicable_controls: Vec<Value>, receipts: Vec<Value>) -> Result<Value, String> {
    if receipts.iter().any(|item| item.as_object().is_none()) {
        return Ok(finalize(
            "legion-web-integrated-evidence",
            serde_json::json!({
                "status": "error",
                "terminal": true,
                "provisional": true,
                "claimLevel": "source",
                "binding": binding,
                "denominator": denominator(&[], &[], &[]).to_value(),
                "receipts": [],
                "rawArtifacts": [],
                "coverageGaps": ["integration-collections-invalid"],
            }),
        ));
    }

    let mut expected: Vec<String> = applicable_controls.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    expected.sort();
    expected.dedup();

    for receipt in &receipts {
        if receipt.get("targetId") != binding.get("targetId") {
            let control_id = receipt.get("controlId").and_then(Value::as_str).unwrap_or("");
            return Err(format!("cross-target evidence rejected: {control_id}"));
        }
    }

    let mut by_control: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    for receipt in sort_by_id(&receipts) {
        let control_id = receipt.get("controlId").and_then(Value::as_str).unwrap_or("").to_string();
        if !expected.contains(&control_id) {
            continue;
        }
        if by_control.contains_key(&control_id) {
            return Err(format!("duplicate terminal receipt: {control_id}"));
        }
        by_control.insert(control_id, receipt);
    }

    let mut duplicate_artifact_keys: Vec<String> = Vec::new();
    let terminal: Vec<Value> = expected
        .iter()
        .map(|control_id| {
            let Some(receipt) = by_control.get(control_id) else {
                return serde_json::json!({
                    "controlId": control_id,
                    "targetId": binding.get("targetId").cloned().unwrap_or(Value::Null),
                    "status": "unproven",
                    "terminal": true,
                    "binding": binding.clone(),
                    "artifacts": [],
                    "synthesized": true,
                });
            };
            let terminal_ok = receipt.get("terminal") == Some(&Value::Bool(true))
                && receipt.get("status").and_then(Value::as_str).map(|s| ACCEPTED.contains(&s)).unwrap_or(false);
            if !terminal_ok {
                let mut out = receipt.as_object().cloned().unwrap_or_default();
                out.insert("status".to_string(), Value::String("unproven".to_string()));
                out.insert("terminal".to_string(), Value::Bool(true));
                out.insert("invalidTerminal".to_string(), Value::Bool(true));
                out.insert(
                    "bindingMismatch".to_string(),
                    Value::Bool(!same_binding(&binding, receipt.get("binding").unwrap_or(&Value::Null))),
                );
                return Value::Object(out);
            }
            if !same_binding(&binding, receipt.get("binding").unwrap_or(&Value::Null)) {
                let mut out = receipt.as_object().cloned().unwrap_or_default();
                out.insert("status".to_string(), Value::String("unproven".to_string()));
                out.insert("terminal".to_string(), Value::Bool(true));
                out.insert("bindingMismatch".to_string(), Value::Bool(true));
                return Value::Object(out);
            }
            let candidates: Vec<Value> = match receipt.get("artifacts") {
                None => Vec::new(),
                Some(Value::Array(items)) => items.clone(),
                Some(other) => vec![other.clone()],
            };
            let control_id_str = receipt.get("controlId").and_then(Value::as_str).unwrap_or("");
            let admitted: Vec<Value> = candidates.iter().filter(|a| valid_artifact(a, &binding, control_id_str)).cloned().collect();
            let artifact_invalid = admitted.len() != candidates.len();
            let normalized = normalize_artifacts(Some(&admitted));
            duplicate_artifact_keys.extend(normalized.duplicates.iter().map(|key| format!("{control_id_str}:{key}")));
            let mut out = receipt.as_object().cloned().unwrap_or_default();
            out.insert("artifacts".to_string(), Value::Array(normalized.artifacts));
            if artifact_invalid {
                out.insert("artifactInvalid".to_string(), Value::Bool(true));
            }
            Value::Object(out)
        })
        .collect();

    let counts = denominator(&expected, &terminal, &[]);
    let mut gaps: Vec<String> = exact_binding(&binding).gaps.iter().map(|g| format!("binding-missing:{g}")).collect();
    if expected.is_empty() {
        gaps.push("integration-denominator-empty".to_string());
    }
    for item in receipts.iter().filter(|item| !expected.contains(&item.get("controlId").and_then(Value::as_str).unwrap_or("").to_string())) {
        gaps.push(format!("non-applicable-receipt:{}", item.get("controlId").and_then(Value::as_str).unwrap_or("")));
    }
    for receipt in &terminal {
        let control_id = receipt.get("controlId").and_then(Value::as_str).unwrap_or("");
        if receipt.get("synthesized") == Some(&Value::Bool(true)) {
            gaps.push(format!("missing-terminal-receipt:{control_id}"));
        }
        if receipt.get("bindingMismatch") == Some(&Value::Bool(true)) {
            gaps.push(format!("binding-mismatch:{control_id}"));
        }
        if receipt.get("invalidTerminal") == Some(&Value::Bool(true)) {
            gaps.push(format!("invalid-terminal-receipt:{control_id}"));
        }
        if receipt.get("artifactInvalid") == Some(&Value::Bool(true)) {
            gaps.push(format!("artifact-invalid:{control_id}"));
        }
    }

    let flattened: Vec<Value> = terminal
        .iter()
        .filter(|item| {
            item.get("synthesized") != Some(&Value::Bool(true))
                && item.get("bindingMismatch") != Some(&Value::Bool(true))
                && item.get("invalidTerminal") != Some(&Value::Bool(true))
        })
        .flat_map(|item| item.get("artifacts").and_then(Value::as_array).cloned().unwrap_or_default())
        .collect();
    let aggregate = normalize_artifacts(Some(&flattened));
    duplicate_artifact_keys.extend(aggregate.duplicates.clone());
    let mut unique_dup_keys: Vec<String> = duplicate_artifact_keys;
    unique_dup_keys.sort();
    unique_dup_keys.dedup();
    gaps.extend(unique_dup_keys.into_iter().map(|key| format!("artifact-identity-duplicate:{key}")));

    let statuses: HashSet<&str> = terminal.iter().filter_map(|item| item.get("status").and_then(Value::as_str)).collect();
    let status = if statuses.len() == 1 && statuses.contains("pass") && gaps.is_empty() {
        "pass"
    } else if statuses.contains("error") {
        "error"
    } else {
        "partial"
    };
    let final_status = if !gaps.is_empty() && status == "pass" { "partial" } else { status };

    let mut gaps_sorted = gaps;
    gaps_sorted.sort();

    Ok(finalize(
        "legion-web-integrated-evidence",
        serde_json::json!({
            "status": final_status,
            "terminal": true,
            "provisional": true,
            "claimLevel": "source",
            "binding": binding,
            "denominator": counts.to_value(),
            "receipts": terminal,
            "rawArtifacts": aggregate.artifacts,
            "coverageGaps": gaps_sorted,
        }),
    ))
}
