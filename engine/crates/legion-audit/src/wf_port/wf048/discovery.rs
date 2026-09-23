//! Port of `src/providers/runtime/web/discovery/index.mjs`
//! (`discoverWebSurfaces`) — chunk wf048.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn sha256_id(parts: &[&str]) -> String {
    let joined = parts.join("\u{0}");
    format!("sha256:{}", hex::encode(Sha256::digest(joined.as_bytes())))
}

/// Port of `discoverWebSurfaces({ artifacts, targetId, componentId })`.
pub fn discover_web_surfaces(artifacts: &Value, target_id: Option<&str>, component_id: Option<&str>) -> Value {
    let empty: Vec<Value> = Vec::new();
    let items = artifacts.as_array().unwrap_or(&empty);
    let target_id_str = target_id.unwrap_or_default();

    let surfaces: Vec<Value> = items
        .iter()
        .map(|artifact| {
            let path = artifact.get("path").cloned().unwrap_or(Value::Null);
            let path_str = path.as_str().unwrap_or_default();
            let kind = artifact.get("kind").and_then(Value::as_str).unwrap_or("page").to_string();
            let id = sha256_id(&[target_id_str, path_str, &kind]);
            let component = artifact
                .get("componentId")
                .cloned()
                .filter(|v| !v.is_null())
                .or_else(|| component_id.map(|c| Value::String(c.to_string())))
                .unwrap_or(Value::Null);
            json!({
                "id": id,
                "targetId": target_id,
                "componentId": component,
                "path": path,
                "kind": kind,
                "url": artifact.get("url").cloned().filter(|v| !v.is_null()).unwrap_or(Value::Null),
                "access": artifact.get("access").and_then(Value::as_str).unwrap_or("unknown"),
                "dynamic": artifact.get("dynamic") == Some(&Value::Bool(true)),
                "generated": artifact.get("generated") == Some(&Value::Bool(true)),
            })
        })
        .collect();

    let complete = surfaces.iter().all(|s| !s.get("componentId").map(Value::is_null).unwrap_or(true));
    let coverage_gaps: Vec<Value> = surfaces
        .iter()
        .filter(|s| s.get("componentId").map(Value::is_null).unwrap_or(true))
        .map(|s| Value::String(format!("component-unbound:{}", s.get("id").and_then(Value::as_str).unwrap_or_default())))
        .collect();

    json!({
        "schemaVersion": 1,
        "kind": "legion-web-surface-inventory",
        "targetId": target_id,
        "surfaces": surfaces,
        "complete": complete,
        "coverageGaps": coverage_gaps,
    })
}
