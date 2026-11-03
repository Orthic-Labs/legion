//! Read-only Apple tool preflight.
//!
//! This is a native port of the iOS tool catalog helper.  It only inspects
//! explicit PATH entries; it never executes a candidate, reads configuration,
//! uses a network, installs anything, or edits a project.

use serde_json::{json, Map, Value};
use std::env;
use std::fs;
use std::path::Path;

const CATALOG_JSON: &str =
    include_str!("../../../../skills/ios-development/config/tool-catalog.json");

/// Parse and return catalog metadata, including its tool setup records.
pub fn catalog_metadata() -> Value {
    serde_json::from_str(CATALOG_JSON).expect("bundled Apple tool catalog must be valid JSON")
}

/// Return catalog IDs in source order, without probing the host.
pub fn catalog_ids() -> Vec<String> {
    catalog_metadata()
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tool| tool.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

/// Inspect selected catalog IDs or list catalog IDs.
///
/// `tool`, `tools`, and `selectedIDs` accept a string or array of strings. A
/// `path` argument is an optional PATH string useful to deterministic callers;
/// otherwise the process PATH is used. An `environment` argument may select
/// Darwin, Linux, or Windows for a host-independent inspection.
pub fn invoke(arguments: &Value) -> Result<Value, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;
    let list = match object.get("list") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| "list must be a boolean".to_string())?,
    };
    if list {
        return Ok(json!({ "tools": catalog_ids() }));
    }

    let ids = selected_ids(object)?;
    let system = object
        .get("environment")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(host_system);
    validate_system(&system)?;
    let path = object
        .get("path")
        .or_else(|| object.get("PATH"))
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "path must be a string".to_string())
        })
        .transpose()?
        .unwrap_or_else(|| env::var("PATH").unwrap_or_default());
    let catalog = catalog_metadata();
    let tools = inspect_selected(&catalog, &ids, &system, &path)?;
    Ok(json!({
        "readOnly": true,
        "environment": system,
        "tools": tools,
        "note": "PATH evidence only; no compatibility, MCP, authorization or native-validation pass is implied."
    }))
}

fn host_system() -> String {
    match env::consts::OS {
        "macos" => "Darwin".to_string(),
        "windows" => "Windows".to_string(),
        "linux" => "Linux".to_string(),
        other => other.to_string(),
    }
}

fn validate_system(system: &str) -> Result<(), String> {
    match system {
        "Darwin" | "Linux" | "Windows" => Ok(()),
        other => Err(format!("unsupported environment: {other}")),
    }
}

fn selected_ids(object: &Map<String, Value>) -> Result<Vec<String>, String> {
    let mut provided = Vec::new();
    for key in ["tool", "tools", "selectedIDs"] {
        if let Some(value) = object.get(key) {
            let values = match value {
                Value::String(id) => vec![id.clone()],
                Value::Array(values) => values
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| format!("{key} entries must be strings"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err(format!("{key} must be a string or array of strings")),
            };
            provided.extend(values);
        }
    }
    if provided.is_empty() {
        return Err("select at least one tool; do not probe every tool".to_string());
    }
    let mut unique = Vec::new();
    for id in provided {
        if !unique.contains(&id) {
            unique.push(id);
        }
    }
    Ok(unique)
}

/// Inspect IDs against a supplied catalog and PATH string. Kept public so
/// native CLI/MCP adapters can test the policy without touching process state.
pub fn inspect_selected(
    catalog: &Value,
    ids: &[String],
    system: &str,
    path: &str,
) -> Result<Vec<Value>, String> {
    let tools = catalog
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| "catalog tools must be an array".to_string())?;
    let mut indexed = std::collections::BTreeMap::new();
    for tool in tools {
        let id = tool
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| "catalog tool is missing string id".to_string())?;
        indexed.insert(id, tool);
    }
    let mut unknown: Vec<&str> = ids
        .iter()
        .filter(|id| !indexed.contains_key(id.as_str()))
        .map(String::as_str)
        .collect();
    unknown.sort_unstable();
    unknown.dedup();
    if !unknown.is_empty() {
        return Err(format!("Unknown tool ids: {}", unknown.join(", ")));
    }
    let mut unique_ids = Vec::new();
    for id in ids {
        if !unique_ids.contains(id) {
            unique_ids.push(id.clone());
        }
    }
    unique_ids
        .iter()
        .map(|id| inspect_tool(indexed[id.as_str()], system, path))
        .collect()
}

fn inspect_tool(tool: &Value, system: &str, path: &str) -> Result<Value, String> {
    let executables = tool
        .get("executables")
        .and_then(Value::as_array)
        .ok_or_else(|| "catalog tool executables must be an array".to_string())?;
    let mut found = Vec::new();
    for executable in executables.iter().filter_map(Value::as_str) {
        if let Some(candidate) = locate(executable, path, system) {
            found.push(json!({ "command": executable, "path": candidate }));
        }
    }
    let (state, next_step) = if !found.is_empty() {
        (
            "installed-candidate",
            "Verify version/schema and reuse if compatible; do not reinstall.",
        )
    } else if !tool
        .get("platforms")
        .and_then(Value::as_array)
        .map(|platforms| {
            platforms
                .iter()
                .any(|platform| platform.as_str() == Some(system))
        })
        .unwrap_or(false)
    {
        (
            "unsupported-environment",
            "Use a supported authorized environment; do not install here.",
        )
    } else if executables.is_empty() {
        (
            "manual-check",
            "Inspect the existing project/app/source integration before proposing setup.",
        )
    } else {
        (
            "not-on-path",
            "Check connected MCP tools and alternate existing locations, then follow the setup recipe if genuinely missing.",
        )
    };
    Ok(json!({
        "id": tool.get("id").cloned().unwrap_or(Value::Null),
        "state": state,
        "found": found,
        "nextStep": next_step,
        "scope": tool.get("scope").cloned().unwrap_or(Value::Null),
        "recipe": tool.get("recipeReference").cloned().unwrap_or(Value::Null),
        "versionVerified": false,
        "mcpRegistrationVerified": false
    }))
}

fn locate(command: &str, path: &str, system: &str) -> Option<String> {
    for directory in env::split_paths(path) {
        let candidate = directory.join(command);
        if is_candidate(&candidate, system, false) {
            return Some(candidate.to_string_lossy().into_owned());
        }
        if system == "Windows" && Path::new(command).extension().is_none() {
            let pathext = env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
            for extension in pathext.split(';').filter(|extension| !extension.is_empty()) {
                let candidate = directory.join(format!("{command}{extension}"));
                if is_candidate(&candidate, system, true) {
                    return Some(candidate.to_string_lossy().into_owned());
                }
            }
        }
    }
    None
}

fn is_candidate(path: &Path, system: &str, _windows_extension: bool) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    if system == "Windows" {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn fixture_catalog() -> Value {
        json!({"tools": [
            {"id":"asc","executables":["asc"],"platforms":["Darwin","Linux","Windows"],"scope":"binary","recipeReference":"r#asc"},
            {"id":"manual","executables":[],"platforms":["Darwin"],"scope":"source","recipeReference":"r#manual"}
        ]})
    }

    #[test]
    fn list_is_offline_and_catalog_preserves_order() {
        assert_eq!(
            invoke(&json!({"list":true})).unwrap()["tools"][0],
            "legion-apple"
        );
    }

    #[test]
    fn selection_deduplicates_and_reports_path_candidate_without_execution() {
        let root = std::env::temp_dir().join(format!("legion-preflight-{}", std::process::id()));
        let _ = fs::create_dir_all(&root);
        #[cfg(windows)]
        let (system, file) = ("Windows", root.join("asc.EXE"));
        #[cfg(not(windows))]
        let (system, file) = ("Darwin", root.join("asc"));
        fs::write(&file, b"this is not executable code").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&file).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&file, permissions).unwrap();
        }
        let result = inspect_selected(
            &fixture_catalog(),
            &["asc".into(), "asc".into()],
            system,
            &root.to_string_lossy(),
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["state"], "installed-candidate");
        let _ = fs::remove_file(file);
        let _ = fs::remove_dir(root);
    }

    #[test]
    fn unknown_ids_are_sorted_and_manual_or_unsupported_states_are_distinct() {
        let error = inspect_selected(&fixture_catalog(), &["z".into(), "a".into()], "Darwin", "")
            .unwrap_err();
        assert_eq!(error, "Unknown tool ids: a, z");
        let manual =
            inspect_selected(&fixture_catalog(), &["manual".into()], "Darwin", "").unwrap();
        assert_eq!(manual[0]["state"], "manual-check");
        let root =
            std::env::temp_dir().join(format!("legion-preflight-windows-{}", std::process::id()));
        let _ = fs::create_dir_all(&root);
        fs::write(root.join("asc.EXE"), b"not executed").unwrap();
        let installed = inspect_selected(
            &fixture_catalog(),
            &["asc".into()],
            "Windows",
            &root.to_string_lossy(),
        )
        .unwrap();
        assert_eq!(installed[0]["state"], "installed-candidate");
        let _ = fs::remove_file(root.join("asc.EXE"));
        let _ = fs::remove_dir(root);
        let unsupported =
            inspect_selected(&fixture_catalog(), &["manual".into()], "Linux", "").unwrap();
        assert_eq!(unsupported[0]["state"], "unsupported-environment");
    }

    #[test]
    fn malformed_requests_are_rejected_without_host_probing() {
        assert!(invoke(&json!({"list":"yes"})).is_err());
        assert!(invoke(&json!({"tool":["asc",3]})).is_err());
        assert!(invoke(&json!({"tool":"missing"})).is_err());
    }
}
