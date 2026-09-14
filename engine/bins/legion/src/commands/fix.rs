use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use serde_json::{json, Value};
use std::path::PathBuf;

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if argv.iter().any(|value| value == "--help") {
        return Ok(json!({
            "__raw": "Usage: legion fix --plan <sealed-remediation-plan>\n"
        }));
    }
    let plan_index = argv.iter().position(|value| value == "--plan");
    let plan_path = match plan_index {
        Some(index) => argv.get(index + 1),
        None => None,
    };
    if argv.len() != 2 || plan_path.is_none() {
        return Err(CommandError::usage(
            "fix requires exactly --plan <sealed-remediation-plan>",
        ));
    }
    let plan_path = PathBuf::from(plan_path.unwrap());
    let bytes = std::fs::read(&plan_path).map_err(|error| {
        CommandError::usage(format!("cannot read remediation plan: {error}"))
    })?;
    let plan: Value = serde_json::from_slice(&bytes).map_err(|error| {
        CommandError::usage(format!("invalid remediation plan: {error}"))
    })?;
    validate_remediation_plan(&plan)?;
    let action_count = plan
        .get("actions")
        .and_then(Value::as_array)
        .map(|actions| actions.len())
        .unwrap_or(0);
    let plan_digest = plan
        .get("planDigest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(json!({
        "status": "validated",
        "plan": plan_path,
        "planDigest": plan_digest,
        "actionCount": action_count,
        "mutationApplied": false
    }))
}

fn validate_remediation_plan(plan: &Value) -> Result<(), CommandError> {
    let schema_version = plan.get("schemaVersion").and_then(Value::as_u64);
    let kind = plan.get("kind").and_then(Value::as_str);
    if schema_version != Some(1)
        || !matches!(kind, Some("legion-remediation-plan") | Some("legion-sealed-remediation-plan"))
    {
        return Err(CommandError::usage("invalid remediation plan contract"));
    }
    if !plan.get("binding").is_some()
        || !plan.get("actions").and_then(Value::as_array).is_some()
        || plan.get("planDigest").and_then(Value::as_str).is_none()
    {
        return Err(CommandError::usage(
            "remediation plan requires binding actions and digest",
        ));
    }
    let digest = plan
        .get("planDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| CommandError::usage("remediation plan requires digest"))?;
    let mut subject = plan.clone();
    if let Some(object) = subject.as_object_mut() {
        object.remove("planDigest");
    }
    let expected = legion_contracts::canonical_digest(&subject)
        .map_err(|error| CommandError::usage(error.to_string()))?;
    if digest != expected {
        return Err(CommandError::usage("remediation plan digest mismatch"));
    }
    Ok(())
}
