//! Port of `src/lib/inventory/stacks/**`.

use serde_json::{json, Map, Value};
use sha2::Digest;

use super::binding::digest;
use super::error::InventoryError;

type R<T> = Result<T, InventoryError>;

const KNOWN: &[&str] = &[
    "javascript", "typescript", "python", "rust", "go", "java", "kotlin", "swift", "c", "c++",
    "c#", "php", "ruby", "dart", "node", "react", "next", "vue", "svelte", "tauri", "electron",
    "pnpm", "npm", "cargo", "pip", "gradle", "maven", "postgres", "sqlite", "redis", "http",
    "windows", "macos", "linux", "chromium", "ios", "android", "aws", "azure", "gcp",
    "app-store", "play-store", "authenticode", "stripe",
];

/// Port of `stackRecord`.
pub fn stack_record(name: &str, role: &str, evidence_paths: Vec<String>, extra: Map<String, Value>) -> Value {
    let mut sorted = evidence_paths.clone();
    sorted.sort();
    let text = format!("{name}\0{role}\0{}", sorted.join("\0"));
    let hash = sha2::Sha256::digest(text.as_bytes());
    let id = format!("stack:{}", &hex::encode(hash)[..20]);
    let mut record = Map::new();
    record.insert("id".into(), Value::String(id));
    record.insert("name".into(), Value::String(name.into()));
    record.insert("role".into(), Value::String(role.into()));
    record.insert("evidencePaths".into(), Value::Array(evidence_paths.into_iter().map(Value::String).collect()));
    record.insert(
        "tiers".into(),
        json!({
            "inventory": 1, "parser": 0, "native": 0, "cross-file": 0,
            "measured-pack": 0, "runtime": 0, "remediation": 0,
        }),
    );
    for (key, value) in extra {
        record.insert(key, value);
    }
    Value::Object(record)
}

/// Port of `validateStackCatalogue`.
pub fn validate_stack_catalogue(catalogue: &Value) -> R<()> {
    // JS compares `JSON.stringify(catalogue.tiers) !== JSON.stringify(required)`
    // where `required` is the literal array of tier names below.
    let required_names = [
        "inventory", "parser", "native", "cross-file", "measured-pack", "runtime", "remediation",
    ];
    let tiers = catalogue.get("tiers").cloned().unwrap_or(Value::Null);
    let expected = Value::Array(required_names.iter().map(|s| Value::String(s.to_string())).collect());
    if serde_json::to_string(&tiers).unwrap_or_default() != serde_json::to_string(&expected).unwrap_or_default() {
        return Err(InventoryError::new("invalid independent evidence tiers"));
    }
    for item in catalogue
        .get("technologies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let has_id = matches!(item.get("id"), Some(Value::String(_)));
        let has_category = matches!(item.get("category"), Some(Value::String(_)));
        let roles_ok = item
            .get("roles")
            .and_then(Value::as_array)
            .map(|r| !r.is_empty())
            .unwrap_or(false);
        if !has_id || !has_category || !roles_ok {
            return Err(InventoryError::new("invalid technology"));
        }
    }
    Ok(())
}

/// Port of `stackRole`.
pub fn stack_role(record: &Value, role: &str) -> Value {
    let mut map = record.as_object().cloned().unwrap_or_default();
    map.insert("role".into(), Value::String(role.into()));
    Value::Object(map)
}

/// Port of `classifyVersion`.
pub fn classify_version(value: Option<&str>) -> Value {
    match value {
        None => json!({"kind": "unknown", "value": Value::Null}),
        Some(v) => {
            let starts_with_range = v
                .chars()
                .next()
                .map(|c| matches!(c, '~' | '^' | '<' | '>' | '=' | '*'))
                .unwrap_or(false);
            if starts_with_range {
                json!({"kind": "declared-range", "value": v})
            } else {
                json!({"kind": "resolved", "value": v})
            }
        }
    }
}

fn entries(value: &Value, role: &str) -> Vec<(String, Value, String)> {
    match value {
        Value::Array(items) => items
            .iter()
            .map(|item| {
                let name = match item {
                    Value::Object(map) => map
                        .get("name")
                        .or_else(|| map.get("id"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let raw = if item.is_object() { item.clone() } else { json!({"version": Value::Null}) };
                (name, raw, role.to_string())
            })
            .collect(),
        Value::Object(map) => map
            .iter()
            .map(|(name, item)| (name.clone(), item.clone(), role.to_string()))
            .collect(),
        _ => vec![],
    }
}

/// Port of `buildStackGraph`.
pub fn build_stack_graph(portfolio: &Value, components: &Value, projection: &Value, binding: &Value) -> Value {
    let dependencies = projection
        .get("dependencies")
        .or_else(|| projection.get("packages"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    let mut records: Vec<(String, Value, String)> = Vec::new();
    records.extend(entries(&dependencies, "dependency"));
    for (key, role) in [
        ("languages", "language"),
        ("parsers", "parser"),
        ("frameworks", "framework"),
        ("runtimes", "runtime"),
        ("buildSystems", "build"),
        ("deployments", "deployment"),
        ("platforms", "platform"),
    ] {
        if let Some(value) = projection.get(key) {
            records.extend(entries(value, role));
        }
    }

    let target_ids: Vec<Value> = portfolio
        .get("targets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|t| t.get("id").cloned())
        .collect();

    let record_count = records.len();
    let stacks: Vec<Value> = records
        .into_iter()
        .map(|(name, raw, role)| {
            let is_object = raw.is_object();
            let value = if is_object { raw.get("version").cloned().unwrap_or(Value::Null) } else { raw.clone() };
            let resolved = if is_object { raw.get("resolvedVersion").cloned().unwrap_or(Value::Null) } else { Value::Null };
            let evidence: Vec<String> = raw
                .get("evidencePaths")
                .or_else(|| raw.get("evidenceRefs"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            let evidence = if evidence.is_empty() {
                vec![format!("projection:{role}:{name}")]
            } else {
                evidence
            };
            let version_for_classify = resolved
                .as_str()
                .or_else(|| value.as_str())
                .map(str::to_string);
            let mut extra = Map::new();
            extra.insert("category".into(), raw.get("category").cloned().unwrap_or_else(|| Value::String(role.clone())));
            extra.insert("version".into(), classify_version(version_for_classify.as_deref()));
            extra.insert("declaredVersion".into(), if value.is_null() { Value::Null } else { value });
            extra.insert("resolvedVersion".into(), resolved);
            extra.insert("runtimeVersion".into(), raw.get("runtimeVersion").cloned().unwrap_or(Value::Null));
            let known = KNOWN.contains(&name.to_lowercase().as_str());
            extra.insert("known".into(), Value::Bool(known));
            extra.insert(
                "targetIds".into(),
                raw.get("targetIds").cloned().unwrap_or_else(|| Value::Array(target_ids.clone())),
            );
            extra.insert("componentIds".into(), raw.get("componentIds").cloned().unwrap_or_else(|| json!([])));
            extra.insert("knownLimitations".into(), raw.get("knownLimitations").cloned().unwrap_or_else(|| json!([])));
            extra.insert(
                "tiers".into(),
                json!({
                    "inventory": 1,
                    "parser": raw.get("parserTier").cloned().unwrap_or_else(|| Value::Number((if role == "parser" {1} else {0}).into())),
                    "native": raw.get("nativeTier").cloned().unwrap_or_else(|| Value::Number(0.into())),
                    "cross-file": raw.get("crossFileTier").cloned().unwrap_or_else(|| Value::Number(0.into())),
                    "measured-pack": raw.get("measuredPackTier").cloned().unwrap_or_else(|| Value::Number(0.into())),
                    "runtime": raw.get("runtimeTier").cloned().unwrap_or_else(|| Value::Number((if role == "runtime" {1} else {0}).into())),
                    "remediation": raw.get("remediationTier").cloned().unwrap_or_else(|| Value::Number(0.into())),
                }),
            );
            stack_record(&name, &role, evidence, extra)
        })
        .collect();

    let component_ids: Vec<Value> = components
        .get("components")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|c| c.get("id").cloned())
        .collect();

    let known_records = stacks.iter().filter(|s| s.get("known") == Some(&Value::Bool(true))).count();
    let unknown_stacks: Vec<Value> = stacks
        .iter()
        .filter(|s| s.get("known") != Some(&Value::Bool(true)))
        .filter_map(|s| s.get("id").cloned())
        .collect();

    let graph = json!({
        "schemaVersion": 1,
        "kind": "legion-stack-graph",
        "stacks": stacks,
        "targetIds": target_ids,
        "componentIds": component_ids,
        "coverage": {
            "expectedRecords": record_count,
            "knownRecords": known_records,
            "unknownStacks": unknown_stacks,
        },
        "binding": binding,
    });
    let mut map = graph.as_object().cloned().unwrap_or_default();
    map.insert("digest".into(), Value::String(digest(&graph)));
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_version_detects_declared_range() {
        assert_eq!(classify_version(Some("^1.0.0"))["kind"], "declared-range");
        assert_eq!(classify_version(Some("1.0.0"))["kind"], "resolved");
        assert_eq!(classify_version(None)["kind"], "unknown");
    }

    #[test]
    fn build_stack_graph_marks_known_dependency() {
        let portfolio = json!({"targets": [{"id": "target:web"}]});
        let projection = json!({"dependencies": {"rust": "1.0.0"}});
        let graph = build_stack_graph(&portfolio, &json!({"components": []}), &projection, &Value::Null);
        let stacks = graph["stacks"].as_array().unwrap();
        assert_eq!(stacks.len(), 1);
        assert_eq!(stacks[0]["known"], true);
    }
}
