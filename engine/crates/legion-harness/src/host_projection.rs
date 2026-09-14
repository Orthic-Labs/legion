use crate::assets::host_projection_path;
use crate::error::HarnessError;
use serde_json::Value;
use std::path::Path;

pub fn load_host_projection(legion_root: &Path) -> Result<Value, HarnessError> {
    let path = host_projection_path(legion_root);
    if !path.is_file() {
        return Err(HarnessError::internal(format!(
            "host projection missing at {}; run: node scripts/generate-host-projection.mjs",
            path.display()
        )));
    }
    let bytes = std::fs::read(&path).map_err(|error| HarnessError::internal(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| HarnessError::internal(error.to_string()))
}

pub fn capability_catalog_block(legion_root: &Path) -> Result<String, HarnessError> {
    let projection = load_host_projection(legion_root)?;
    let capabilities = projection
        .get("capabilities")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let public = capabilities
        .into_iter()
        .filter(|capability| {
            capability.get("kind").and_then(Value::as_str) == Some("domain-capability")
                && capability.get("discoverability").and_then(Value::as_str) == Some("public")
        })
        .collect::<Vec<_>>();
    if public.is_empty() {
        return Ok(String::new());
    }
    let mut lines = vec!["## Legion capabilities".to_string(), String::new()];
    for capability in public {
        let name = capability
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let description = capability
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("");
        lines.push(format!("- **{name}** — {description}"));
    }
    Ok(lines.join("\n"))
}

pub fn canonical_skill_ids(legion_root: &Path) -> Result<Vec<String>, HarnessError> {
    let projection = load_host_projection(legion_root)?;
    let mut ids = projection
        .get("capabilities")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|capability| {
                    (capability.get("kind").and_then(Value::as_str) == Some("domain-capability")
                        && capability
                            .get("discoverability")
                            .and_then(Value::as_str)
                            == Some("public"))
                        || (capability.get("kind").and_then(Value::as_str) == Some("entrypoint")
                            && capability
                                .get("discoverability")
                                .and_then(Value::as_str)
                                == Some("explicit"))
                })
                .filter_map(|capability| capability.get("id").and_then(Value::as_str))
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    ids.sort();
    let absent = ids
        .iter()
        .filter(|id| !legion_root.join("skills").join(id).join("SKILL.md").is_file())
        .cloned()
        .collect::<Vec<_>>();
    if !absent.is_empty() {
        return Err(HarnessError::internal(format!(
            "host projection declares capabilities with no packaged skill: {}",
            absent.join(", ")
        )));
    }
    Ok(ids)
}
