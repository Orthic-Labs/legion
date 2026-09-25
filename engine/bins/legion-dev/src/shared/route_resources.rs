// Port of `src/lib/skills/route-resources.mjs`. Route/adapter-scoped
// resource tables: a bundle's `references/route-resources.json` declares
// resources that bind only inside a named scope.

use crate::checks::read_json;
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;

pub const ROUTE_RESOURCES: &str = "references/route-resources.json";

fn scope_kind(section: &str) -> String {
    match section {
        "adapters" => "adapter".into(),
        "domains" => "domain".into(),
        "methods" => "method".into(),
        "providers" => "provider".into(),
        "workflows" => "workflow".into(),
        other => other.strip_suffix('s').unwrap_or(other).to_string(),
    }
}

/// Load a bundle's route resource table, or `None` when it does not declare
/// one, or the file is not a valid JSON object.
pub fn route_resource_table(skill_root: &Path) -> Option<Value> {
    let path = skill_root.join(ROUTE_RESOURCES);
    if !path.is_file() {
        return None;
    }
    let document = read_json(&path).ok()?;
    if document.is_object() {
        Some(document)
    } else {
        None
    }
}

/// Capability ids a bundle declares only inside named route/adapter scopes.
pub fn scoped_host_capabilities(skill_root: &Path) -> HashSet<String> {
    let mut scoped = HashSet::new();
    let Some(document) = route_resource_table(skill_root) else {
        return scoped;
    };
    let Some(sections) = document.as_object() else {
        return scoped;
    };
    for table in sections.values() {
        let Some(table) = table.as_object() else { continue };
        for entries in table.values() {
            let Some(entries) = entries.as_array() else { continue };
            for entry in entries {
                if entry.get("class").and_then(|v| v.as_str()) == Some("HOST_CAPABILITY") {
                    if let Some(cap) = entry.get("capability").and_then(|v| v.as_str()) {
                        scoped.insert(cap.to_string());
                    }
                }
            }
        }
    }
    scoped
}

/// Scoped host requirements with their registry detail, one row per
/// (scope, capability) pair. `scope` names the binding (`provider:notebooklm`,
/// `adapter:omniroute-codex-worker`); `scopeKind` is the section singular.
///
/// Faithful port of `scopedRequirementDetails(skillRoot, registry, { id })`.
pub fn scoped_requirement_details(skill_root: &Path, registry: &Value, id: &str) -> Result<Vec<Value>, String> {
    let document = match route_resource_table(skill_root) {
        Some(d) => d,
        None => return Ok(vec![]),
    };
    let mut scoped: Vec<Value> = vec![];
    let doc_obj = document.as_object().unwrap();
    for (section, table) in doc_obj {
        let table_obj = match table.as_object() {
            Some(o) => o,
            None => continue,
        };
        let kind = scope_kind(section);
        for (key, entries) in table_obj {
            let entries_arr = match entries.as_array() {
                Some(a) => a,
                None => continue,
            };
            for entry in entries_arr {
                let class = entry.get("class").and_then(Value::as_str);
                let capability_id = entry.get("capability").and_then(Value::as_str);
                if class != Some("HOST_CAPABILITY") || capability_id.is_none() {
                    continue;
                }
                let capability_id = capability_id.unwrap();
                let capability = registry.get("capabilities").and_then(|c| c.get(capability_id));
                let capability = match capability {
                    Some(c) if !c.is_null() => c,
                    _ => {
                        return Err(format!(
                            "skills/{id}/{ROUTE_RESOURCES} declares host capability absent from registry: {capability_id}"
                        ))
                    }
                };
                let mut out = serde_json::Map::new();
                out.insert("scope".into(), Value::from(format!("{kind}:{key}")));
                out.insert("scopeKind".into(), Value::from(kind.clone()));
                out.insert("id".into(), Value::from(capability_id));
                out.insert("kind".into(), capability.get("kind").cloned().unwrap_or(Value::Null));
                out.insert("summary".into(), capability.get("summary").cloned().unwrap_or(Value::Null));
                out.insert("degradation".into(), capability.get("degradation").cloned().unwrap_or(Value::Null));
                out.insert("remedy".into(), capability.get("remedy").cloned().unwrap_or(Value::Null));
                out.insert("probe".into(), capability.get("probe").cloned().unwrap_or(Value::Null));
                scoped.push(Value::Object(out));
            }
        }
    }
    scoped.sort_by(|a, b| {
        let sa = a["scope"].as_str().unwrap_or_default();
        let sb = b["scope"].as_str().unwrap_or_default();
        sa.cmp(sb).then_with(|| a["id"].as_str().unwrap_or_default().cmp(b["id"].as_str().unwrap_or_default()))
    });
    Ok(scoped)
}
