use crate::error::MinimizeError;
use crate::git::canonical_locator;
use crate::json_util::{read_json, sha256_file};
use crate::review::{MinimizePaths, RUNGS};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;

pub const DECISION_SCHEMA: &str = "minimize-decision.v1";
pub const DECISION_RECEIPT_SCHEMA: &str = "minimize-decision-receipt.v1";

pub fn validate_decision(
    value: &Value,
    new_files: &[String],
    new_dependencies: &[String],
) -> Result<Value, MinimizeError> {
    if value.get("schema").and_then(Value::as_str) != Some(DECISION_SCHEMA) {
        return Err(MinimizeError::new(format!(
            "decision schema must be {}",
            DECISION_SCHEMA
        )));
    }
    let selected = value
        .get("selected_rung")
        .and_then(Value::as_str)
        .ok_or_else(|| MinimizeError::new(format!("selected_rung must be one of: {}", RUNGS.join(", "))))?;
    if !RUNGS.contains(&selected) {
        return Err(MinimizeError::new(format!(
            "selected_rung must be one of: {}",
            RUNGS.join(", ")
        )));
    }
    let prior = value
        .get("prior_rungs")
        .and_then(Value::as_array)
        .ok_or_else(|| MinimizeError::new("prior_rungs must be a list"))?;
    let selected_index = RUNGS
        .iter()
        .position(|rung| *rung == selected)
        .unwrap_or(0);
    let required = RUNGS[..selected_index].to_vec();
    let observed = prior
        .iter()
        .filter(|row| row.is_object())
        .filter_map(|row| row.get("rung").and_then(Value::as_str))
        .collect::<Vec<_>>();
    if observed != required {
        let missing = required
            .iter()
            .find(|rung| !observed.contains(rung))
            .map(|rung| (*rung).to_string())
            .unwrap_or_else(|| "ordered prior rung".to_string());
        return Err(MinimizeError::new(format!(
            "missing or unordered prior rung: {missing}"
        )));
    }
    for row in prior {
        if row.get("verdict").and_then(Value::as_str) != Some("REJECTED")
            || row
                .get("evidence")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
        {
            let rung = row
                .get("rung")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            return Err(MinimizeError::new(format!(
                "prior rung {rung} needs REJECTED verdict and evidence"
            )));
        }
    }
    for key in ["decision_id", "state_a", "state_b"] {
        if value
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            return Err(MinimizeError::new(format!("{key} is required")));
        }
    }
    let allowed_files = value
        .get("allowed_new_files")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let allowed_deps = value
        .get("allowed_new_dependencies")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut denied_files = new_files
        .iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|name| !allowed_files.contains(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    denied_files.sort();
    let mut denied_deps = new_dependencies
        .iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|name| !allowed_deps.contains(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    denied_deps.sort();
    if !denied_files.is_empty() {
        return Err(MinimizeError::new(format!(
            "new file not allowed by decision: {}",
            denied_files.join(", ")
        )));
    }
    if !denied_deps.is_empty() {
        return Err(MinimizeError::new(format!(
            "new dependency not allowed by decision: {}",
            denied_deps.join(", ")
        )));
    }
    Ok(value.clone())
}

pub fn decision_receipt(source_path: &Path, paths: &MinimizePaths) -> Result<Value, MinimizeError> {
    let value = validate_decision(&read_json(source_path)?, &[], &[])?;
    Ok(json!({
        "schema": DECISION_RECEIPT_SCHEMA,
        "decision": canonical_locator(source_path),
        "decision_sha256": sha256_file(source_path)?,
        "policy_sha256": sha256_file(&paths.policy_path)?,
        "validator_sha256": sha256_file(&paths.validator_path)?,
        "decision_id": value.get("decision_id").cloned().unwrap_or(Value::Null),
        "selected_rung": value.get("selected_rung").cloned().unwrap_or(Value::Null),
    }))
}

pub fn verify_decision(
    source_path: &Path,
    receipt_path: &Path,
    paths: &MinimizePaths,
) -> Result<Value, MinimizeError> {
    let expected = decision_receipt(source_path, paths)?;
    let actual = read_json(receipt_path)?;
    for key in [
        "decision_sha256",
        "policy_sha256",
        "validator_sha256",
        "decision_id",
        "selected_rung",
    ] {
        if actual.get(key) != expected.get(key) {
            return Err(MinimizeError::new(format!(
                "stale decision receipt: {key} mismatch"
            )));
        }
    }
    Ok(actual)
}
