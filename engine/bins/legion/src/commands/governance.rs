use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use legion_arcane::{
    auth_unavailable_result, dispatch_delivery_governance, dispatch_execution_control,
    dispatch_governance_judgment, requires_authenticated_stores, JudgmentControlCapability,
    KeyRing,
};
use serde_json::Value;
use std::path::PathBuf;

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let domain = argv.first().map(String::as_str);
    if matches!(domain, Some("--help") | Some("help") | None) {
        return Ok(json_raw(
            "Usage: legion governance execution|delivery|judgment --json <structured-request> [--key-dir <dir>]\n",
        ));
    }
    if !matches!(domain, Some("execution") | Some("delivery") | Some("judgment")) {
        return Err(CommandError::usage(format!(
            "governance requires execution, delivery, or judgment (got {})",
            domain.unwrap_or("<none>")
        )));
    }
    let (request, key_dir) = parse_json_request(&argv[1..])?;
    if domain == Some("execution") {
        return Ok(dispatch_execution_control(&request, None));
    }
    if domain == Some("delivery") {
        return Ok(dispatch_delivery_governance(&request));
    }
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if requires_authenticated_stores(operation) {
        let resolved_key_dir = key_dir
            .clone()
            .or_else(|| std::env::var_os("ARCANE_KEY_DIR").map(PathBuf::from))
            .filter(|path| !path.as_os_str().is_empty());
        if resolved_key_dir.is_none() {
            return Ok(auth_unavailable_result());
        }
        if KeyRing::load_dir(resolved_key_dir.as_ref().expect("checked")).is_err() {
            return Ok(auth_unavailable_result());
        }
    }
    let cwd = std::env::current_dir().map_err(super::io_error)?;
    let key_ring = key_dir
        .or_else(|| std::env::var_os("ARCANE_KEY_DIR").map(PathBuf::from))
        .filter(|path| !path.as_os_str().is_empty())
        .and_then(|path| KeyRing::load_dir(&path).ok());
    let capability = JudgmentControlCapability::from_cwd(&cwd, key_ring)
        .map_err(|error| CommandError::incomplete(error))?;
    Ok(dispatch_governance_judgment(&request, Some(&capability)))
}

fn parse_json_request(argv: &[String]) -> Result<(Value, Option<PathBuf>), CommandError> {
    let mut index = 0;
    let mut json_payload: Option<String> = None;
    let mut key_dir: Option<PathBuf> = None;
    while index < argv.len() {
        match argv[index].as_str() {
            "--json" => {
                index += 1;
                json_payload = argv.get(index).cloned();
            }
            "--key-dir" => {
                index += 1;
                key_dir = argv.get(index).map(PathBuf::from);
            }
            flag => return Err(CommandError::usage(format!("unknown governance option: {flag}"))),
        }
        index += 1;
    }
    let json_payload = json_payload.filter(|value| !value.is_empty()).ok_or_else(|| {
        CommandError::usage("governance requires --json <structured-request>")
    })?;
    let request = serde_json::from_str(&json_payload).map_err(|_| {
        CommandError::usage("governance --json must be valid JSON")
    })?;
    Ok((request, key_dir))
}

fn json_raw(text: &str) -> Value {
    serde_json::json!({ "__raw": text })
}
