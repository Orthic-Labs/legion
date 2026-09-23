//! Route/adapter-scoped resource tables.
//!
//! Ported from `src/lib/skills/route-resources.mjs`. A bundle's
//! `references/route-resources.json` declares resources that bind only
//! inside a named scope (a provider, adapter, method, domain, or workflow)
//! rather than for every use of the capability. Global requirements stay in
//! `SKILL.md` `hostRequirements`; this table is where an optional adapter or
//! a single research route keeps the host capabilities it alone needs.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

pub const ROUTE_RESOURCES: &str = "references/route-resources.json";

fn scope_kind(section: &str) -> &str {
    match section {
        "adapters" => "adapter",
        "domains" => "domain",
        "methods" => "method",
        "providers" => "provider",
        "workflows" => "workflow",
        other => other.strip_suffix('s').unwrap_or(other),
    }
}

/// Load a bundle's route resource table, or `None` when it does not declare
/// one, or declares one that is not a JSON object. Port of
/// `routeResourceTable`.
pub fn route_resource_table(skill_root: &Path) -> Option<Value> {
    let path = skill_root.join(ROUTE_RESOURCES);
    let text = std::fs::read_to_string(path).ok()?;
    let document: Value = serde_json::from_str(&text).ok()?;
    if document.is_object() {
        Some(document)
    } else {
        None
    }
}

/// Capability ids a bundle declares only inside named route/adapter scopes.
/// Port of `scopedHostCapabilities`.
pub fn scoped_host_capabilities(skill_root: &Path) -> BTreeSet<String> {
    let mut scoped = BTreeSet::new();
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
                if entry.get("class").and_then(Value::as_str) == Some("HOST_CAPABILITY") {
                    if let Some(capability) = entry.get("capability").and_then(Value::as_str) {
                        scoped.insert(capability.to_string());
                    }
                }
            }
        }
    }
    scoped
}

/// One scoped host requirement row, mirroring the JS object shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedRequirementDetail {
    pub scope: String,
    pub scope_kind: String,
    pub id: String,
    pub kind: String,
    pub summary: String,
    pub degradation: String,
    pub remedy: String,
    pub probe: Option<Value>,
}

/// Scoped host requirements with their registry detail, one row per
/// `(scope, capability)` pair, sorted by `(scope, id)`. Port of
/// `scopedRequirementDetails`.
///
/// Returns `Err` (mirroring the JS `throw`) when a declared capability is
/// absent from the registry.
pub fn scoped_requirement_details(
    skill_root: &Path,
    registry: &Value,
    id: &str,
) -> Result<Vec<ScopedRequirementDetail>, String> {
    let Some(document) = route_resource_table(skill_root) else {
        return Ok(Vec::new());
    };
    let Some(sections) = document.as_object() else {
        return Ok(Vec::new());
    };
    let capabilities = registry.get("capabilities").and_then(Value::as_object);
    let mut scoped = Vec::new();
    for (section, table) in sections {
        let Some(table) = table.as_object() else { continue };
        let kind = scope_kind(section);
        for (key, entries) in table {
            let Some(entries) = entries.as_array() else { continue };
            for entry in entries {
                if entry.get("class").and_then(Value::as_str) != Some("HOST_CAPABILITY") {
                    continue;
                }
                let Some(capability_id) = entry.get("capability").and_then(Value::as_str) else {
                    continue;
                };
                let capability = capabilities.and_then(|c| c.get(capability_id)).ok_or_else(|| {
                    format!(
                        "skills/{id}/{ROUTE_RESOURCES} declares host capability absent from registry: {capability_id}"
                    )
                })?;
                scoped.push(ScopedRequirementDetail {
                    scope: format!("{kind}:{key}"),
                    scope_kind: kind.to_string(),
                    id: capability_id.to_string(),
                    kind: capability.get("kind").and_then(Value::as_str).unwrap_or("").to_string(),
                    summary: capability.get("summary").and_then(Value::as_str).unwrap_or("").to_string(),
                    degradation: capability.get("degradation").and_then(Value::as_str).unwrap_or("").to_string(),
                    remedy: capability.get("remedy").and_then(Value::as_str).unwrap_or("").to_string(),
                    probe: capability.get("probe").cloned().filter(|v| !v.is_null()),
                });
            }
        }
    }
    scoped.sort_by(|a, b| a.scope.cmp(&b.scope).then_with(|| a.id.cmp(&b.id)));
    Ok(scoped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn write_table(dir: &Path, value: &Value) {
        fs::create_dir_all(dir.join("references")).unwrap();
        fs::write(dir.join(ROUTE_RESOURCES), serde_json::to_string(value).unwrap()).unwrap();
    }

    #[test]
    fn missing_table_is_none() {
        let dir = tempdir();
        assert!(route_resource_table(dir.path()).is_none());
        assert!(scoped_host_capabilities(dir.path()).is_empty());
    }

    #[test]
    fn invalid_json_is_none() {
        let dir = tempdir();
        fs::create_dir_all(dir.path().join("references")).unwrap();
        fs::write(dir.path().join(ROUTE_RESOURCES), "not json").unwrap();
        assert!(route_resource_table(dir.path()).is_none());
    }

    #[test]
    fn array_document_is_none() {
        let dir = tempdir();
        write_table(dir.path(), &json!([1, 2, 3]));
        assert!(route_resource_table(dir.path()).is_none());
    }

    #[test]
    fn collects_scoped_host_capabilities() {
        let dir = tempdir();
        write_table(
            dir.path(),
            &json!({
                "providers": {
                    "notebooklm": [
                        {"class": "HOST_CAPABILITY", "capability": "browser-automation"}
                    ]
                },
                "adapters": {
                    "omniroute-codex-worker": [
                        {"class": "HOST_CAPABILITY", "capability": "codex-cli"},
                        {"class": "PACKAGE_INTERNAL", "path": "scripts/x.mjs"}
                    ]
                }
            }),
        );
        let scoped = scoped_host_capabilities(dir.path());
        assert_eq!(scoped.len(), 2);
        assert!(scoped.contains("browser-automation"));
        assert!(scoped.contains("codex-cli"));
    }

    fn registry() -> Value {
        json!({
            "capabilities": {
                "browser-automation": {
                    "kind": "tool", "summary": "s", "degradation": "d", "remedy": "r"
                }
            }
        })
    }

    #[test]
    fn scoped_requirement_details_sorted_with_registry_detail() {
        let dir = tempdir();
        write_table(
            dir.path(),
            &json!({
                "providers": {
                    "zeta": [{"class": "HOST_CAPABILITY", "capability": "browser-automation"}],
                    "alpha": [{"class": "HOST_CAPABILITY", "capability": "browser-automation"}]
                }
            }),
        );
        let rows = scoped_requirement_details(dir.path(), &registry(), "my-skill").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].scope, "provider:alpha");
        assert_eq!(rows[1].scope, "provider:zeta");
        assert_eq!(rows[0].kind, "tool");
        assert_eq!(rows[0].summary, "s");
    }

    #[test]
    fn scoped_requirement_details_errors_on_unregistered_capability() {
        let dir = tempdir();
        write_table(
            dir.path(),
            &json!({
                "providers": {
                    "zeta": [{"class": "HOST_CAPABILITY", "capability": "not-registered"}]
                }
            }),
        );
        let err = scoped_requirement_details(dir.path(), &registry(), "my-skill").unwrap_err();
        assert!(err.contains("not-registered"));
        assert!(err.contains("my-skill"));
    }

    fn tempdir() -> crate::wf_port::w2_056::test_support::TempDir {
        crate::wf_port::w2_056::test_support::TempDir::new()
    }
}
