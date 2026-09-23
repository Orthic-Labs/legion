//! Port of `src/lib/inventory/components/**`.

use std::collections::BTreeSet;

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::Digest;

use super::binding::digest;
use super::error::InventoryError;

type R<T> = Result<T, InventoryError>;

const COMPONENT_KINDS: &[&str] = &[
    "ui",
    "domain",
    "api",
    "identity",
    "data",
    "cache-search",
    "queue-job",
    "sync-offline",
    "file-media",
    "integration",
    "notification",
    "commerce",
    "telemetry",
    "admin-support",
    "native-bridge-ipc",
    "helper-sidecar",
    "installer",
    "updater",
    "build-sign-release",
    "infrastructure-dns",
    "privacy",
    "content-community",
    "ai",
    "documentation-legal",
    "unknown-material-component",
];

const RELATION_KINDS: &[&str] = &[
    "authenticates-through",
    "calls",
    "contains",
    "controls",
    "crosses-trust-boundary",
    "depends-on",
    "deploys",
    "emits",
    "installs",
    "invokes",
    "observes",
    "queues",
    "reads",
    "routes-to",
    "runs-on",
    "trusts",
    "updates",
    "writes",
];

fn portable(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    let normalized = normalized.strip_prefix("./").unwrap_or(&normalized);
    let re = Regex::new(r"/{2,}").expect("static regex");
    re.replace_all(normalized, "/").into_owned()
}

/// `item.path ?? item` where `item` may be a string or `{path}` object.
pub fn path_of(item: &Value) -> String {
    match item {
        Value::Object(map) => map
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn str_vec(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Port of `componentId` (sha256 of `[kind, sortedTargetIds, sortedPortableEvidence]`).
pub fn component_id(kind: &str, target_ids: &[String], evidence_paths: &[String]) -> String {
    let mut ids = target_ids.to_vec();
    ids.sort();
    let mut evidence: Vec<String> = evidence_paths.iter().map(|p| portable(p)).collect();
    evidence.sort();
    let identity = json!([kind, ids, evidence]);
    let json_text = serde_json::to_string(&identity).unwrap_or_default();
    let hash = sha2::Sha256::digest(json_text.as_bytes());
    format!("component:{}", &hex::encode(hash)[..20])
}

/// Port of `component(kind, targetIds, evidencePaths, extra)`.
pub fn component(
    kind: &str,
    target_ids: &[String],
    evidence_paths: &[String],
    extra: Map<String, Value>,
) -> Value {
    let mut target_ids_sorted: Vec<String> = target_ids.to_vec();
    target_ids_sorted.sort();
    target_ids_sorted.dedup();
    let mut evidence_sorted: Vec<String> = evidence_paths.to_vec();
    evidence_sorted.sort();
    evidence_sorted.dedup();
    let id = component_id(kind, target_ids, evidence_paths);
    let mut record = Map::new();
    record.insert("id".into(), Value::String(id));
    record.insert("kind".into(), Value::String(kind.to_string()));
    record.insert(
        "targetIds".into(),
        Value::Array(target_ids_sorted.into_iter().map(Value::String).collect()),
    );
    record.insert(
        "rootPaths".into(),
        Value::Array(
            evidence_sorted
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    record.insert(
        "evidencePaths".into(),
        Value::Array(evidence_sorted.into_iter().map(Value::String).collect()),
    );
    record.insert(
        "classificationBasis".into(),
        Value::String("observed".into()),
    );
    record.insert("runtimeBoundary".into(), Value::Null);
    record.insert("privilege".into(), Value::Null);
    record.insert("identity".into(), Value::Null);
    record.insert("dataClassIds".into(), Value::Array(vec![]));
    record.insert("stackIds".into(), Value::Array(vec![]));
    record.insert("external".into(), Value::Bool(false));
    record.insert("trustBoundaries".into(), Value::Array(vec![]));
    for (key, value) in extra {
        record.insert(key, value);
    }
    Value::Object(record)
}

fn component_field<'a>(component: &'a Value, key: &str) -> Option<&'a Value> {
    component.get(key)
}

fn component_str_field(component: &Value, key: &str) -> Option<String> {
    component_field(component, key)
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Port of `validateComponentGraph`.
pub fn validate_component_graph(graph: &Value) -> R<()> {
    let relations = str_vec(graph.get("relations"));
    if !relations.is_empty()
        && relations
            .iter()
            .all(|r| component_str_field(r, "kind").as_deref() == Some("contains"))
    {
        return Err(InventoryError::new(
            "folder containment cannot be only relation evidence",
        ));
    }
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for value in str_vec(graph.get("components")) {
        let id = component_str_field(&value, "id")
            .ok_or_else(|| InventoryError::new("component requires id"))?;
        let kind = component_str_field(&value, "kind").unwrap_or_default();
        if !COMPONENT_KINDS.contains(&kind.as_str()) {
            return Err(InventoryError::new(format!(
                "unknown component kind: {kind}"
            )));
        }
        if ids.contains(&id) {
            return Err(InventoryError::new(format!(
                "duplicate component ID: {id}"
            )));
        }
        ids.insert(id);
    }
    for relation in relations {
        let kind = component_str_field(&relation, "kind").unwrap_or_default();
        if !RELATION_KINDS.contains(&kind.as_str()) {
            return Err(InventoryError::new(format!(
                "unknown relation kind: {kind}"
            )));
        }
        let from = component_str_field(&relation, "from").unwrap_or_default();
        let to = component_str_field(&relation, "to").unwrap_or_default();
        if !ids.contains(&from) || !ids.contains(&to) {
            return Err(InventoryError::new(format!(
                "relation endpoint is unknown: {from}->{to}"
            )));
        }
    }
    Ok(())
}

fn target_ids_of(portfolio: &Value) -> Vec<String> {
    str_vec(portfolio.get("targets"))
        .iter()
        .filter_map(|t| component_str_field(t, "id"))
        .collect()
}

/// Port of `extractBuildComponents`.
pub fn extract_build_components(portfolio: &Value, projection: &Value) -> Vec<Value> {
    let ids = target_ids_of(portfolio);
    str_vec(projection.get("buildOutputs"))
        .iter()
        .map(|output| {
            let path = path_of(output);
            component("build-sign-release", &ids, &[path], Map::new())
        })
        .collect()
}

/// Port of `extractPhysicalComponents`.
pub fn extract_physical_components(portfolio: &Value, projection: &Value) -> Vec<Value> {
    let ids = target_ids_of(portfolio);
    let installer_re = Regex::new(r"(?i)install|setup|\.msi|\.pkg|\.dmg").unwrap();
    let updater_re = Regex::new(r"(?i)updat").unwrap();
    let qualified_re =
        Regex::new(r"(?i)\.(?:exe|app|apk|aab|ipa|wasm|zip|tgz|whl|jar|dll|so)$").unwrap();
    let worker_re = Regex::new(r"(?i)worker|job").unwrap();
    let server_re = Regex::new(r"(?i)server|daemon|sidecar|helper").unwrap();

    let mut outputs: Vec<Value> = str_vec(projection.get("buildOutputs"))
        .iter()
        .map(path_of)
        .map(|path| {
            let kind = if installer_re.is_match(&path) {
                "installer"
            } else if updater_re.is_match(&path) {
                "updater"
            } else if qualified_re.is_match(&path) {
                "build-sign-release"
            } else {
                "unknown-material-component"
            };
            let mut extra = Map::new();
            extra.insert(
                "unknownReason".into(),
                if qualified_re.is_match(&path) {
                    Value::Null
                } else {
                    Value::String("unqualified-build-output".into())
                },
            );
            component(kind, &ids, &[path], extra)
        })
        .collect();

    let runtimes: Vec<Value> = str_vec(projection.get("entrypoints"))
        .iter()
        .map(path_of)
        .map(|path| {
            let kind = if worker_re.is_match(&path) {
                "queue-job"
            } else if server_re.is_match(&path) {
                "helper-sidecar"
            } else {
                "domain"
            };
            component(kind, &ids, &[path], Map::new())
        })
        .collect();

    outputs.extend(runtimes);
    outputs
}

const LOGICAL_RULES: &[(&str, &str)] = &[
    ("identity", r"(?i)auth|oauth|login|session|permission"),
    ("data", r"(?i)db|database|postgres|sqlite|schema|migration"),
    (
        "integration",
        r"(?i)stripe|paypal|sentry|provider|integration|webhook",
    ),
    ("api", r"(?i)route|api|graphql|grpc|controller"),
    ("cache-search", r"(?i)redis|cache|search|index"),
    ("queue-job", r"(?i)queue|job|worker|schedule|cron"),
    ("sync-offline", r"(?i)sync|offline|replicat"),
    ("file-media", r"(?i)upload|media|file|blob|image"),
    ("notification", r"(?i)notification|email|sms|push"),
    ("commerce", r"(?i)payment|billing|checkout|subscription"),
    ("telemetry", r"(?i)analytics|telemetry|metric|trace|crash"),
    ("admin-support", r"(?i)admin|support|moderation"),
    ("native-bridge-ipc", r"(?i)native|bridge|ipc"),
    ("privacy", r"(?i)privacy|consent|retention"),
    ("content-community", r"(?i)content|comment|community|ugc"),
    ("documentation-legal", r"(?i)docs?|legal|license|terms"),
    ("ai", r"(?i)openai|anthropic|model|rag|agent|embedding"),
];

/// Port of `extractLogicalComponents`.
pub fn extract_logical_components(portfolio: &Value, projection: &Value) -> Vec<Value> {
    let paths: Vec<String> = str_vec(projection.get("files")).iter().map(path_of).collect();
    let ids = target_ids_of(portfolio);
    let mut out = Vec::new();
    for (kind, pattern) in LOGICAL_RULES {
        let re = Regex::new(pattern).expect("static regex");
        let evidence: Vec<String> = paths.iter().filter(|p| re.is_match(p)).cloned().collect();
        if !evidence.is_empty() {
            let mut extra = Map::new();
            extra.insert("classificationBasis".into(), Value::String("observed".into()));
            out.push(component(kind, &ids, &evidence, extra));
        }
    }
    out
}

/// Port of `extractDataComponents`.
pub fn extract_data_components(portfolio: &Value, projection: &Value) -> Vec<Value> {
    extract_logical_components(portfolio, projection)
        .into_iter()
        .filter(|c| {
            matches!(
                component_str_field(c, "kind").as_deref(),
                Some("data") | Some("cache-search") | Some("file-media")
            )
        })
        .collect()
}

/// Port of `extractExternalComponents`.
pub fn extract_external_components(portfolio: &Value, projection: &Value) -> Vec<Value> {
    extract_logical_components(portfolio, projection)
        .into_iter()
        .filter(|c| {
            matches!(
                component_str_field(c, "kind").as_deref(),
                Some("integration") | Some("ai")
            )
        })
        .map(|c| {
            let mut map = c.as_object().cloned().unwrap_or_default();
            map.insert("external".into(), Value::Bool(true));
            map.insert("status".into(), Value::String("referenced".into()));
            Value::Object(map)
        })
        .collect()
}

/// Port of `extractDeploymentComponents`.
pub fn extract_deployment_components(portfolio: &Value, projection: &Value) -> Vec<Value> {
    let default_ids = target_ids_of(portfolio);
    str_vec(projection.get("deployments"))
        .iter()
        .map(|item| {
            let path = path_of(item);
            let target_ids: Vec<String> = item
                .get("targetIds")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_else(|| default_ids.clone());
            let mut extra = Map::new();
            extra.insert(
                "runtimeBoundary".into(),
                item.get("runtimeBoundary")
                    .cloned()
                    .unwrap_or_else(|| Value::String("deployment".into())),
            );
            extra.insert("privilege".into(), item.get("privilege").cloned().unwrap_or(Value::Null));
            extra.insert("identity".into(), item.get("identity").cloned().unwrap_or(Value::Null));
            extra.insert(
                "environmentIds".into(),
                item.get("environments").cloned().unwrap_or_else(|| json!([])),
            );
            extra.insert(
                "deploymentKind".into(),
                item.get("kind")
                    .cloned()
                    .unwrap_or_else(|| Value::String("unknown".into())),
            );
            component("infrastructure-dns", &target_ids, &[path], extra)
        })
        .collect()
}

/// Port of `extractRuntimeComponents`.
pub fn extract_runtime_components(portfolio: &Value, projection: &Value) -> Vec<Value> {
    let default_ids = target_ids_of(portfolio);
    let build_outputs: BTreeSet<String> = str_vec(projection.get("buildOutputs"))
        .iter()
        .map(path_of)
        .map(|p| p.replace('\\', "/"))
        .collect();
    let worker_re = Regex::new(r"(?i)worker|job|queue").unwrap();
    let ipc_re = Regex::new(r"(?i)ipc|bridge").unwrap();

    str_vec(projection.get("entrypoints"))
        .iter()
        .filter(|item| {
            item.is_object() || !build_outputs.contains(&path_of(item).replace('\\', "/"))
        })
        .map(|item| {
            let path = path_of(item);
            let kind = if worker_re.is_match(&path) {
                "queue-job"
            } else if ipc_re.is_match(&path) {
                "native-bridge-ipc"
            } else {
                "helper-sidecar"
            };
            let target_ids: Vec<String> = item
                .get("targetIds")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_else(|| default_ids.clone());
            let mut extra = Map::new();
            extra.insert(
                "runtimeBoundary".into(),
                item.get("runtimeBoundary")
                    .cloned()
                    .unwrap_or_else(|| Value::String("process".into())),
            );
            extra.insert("privilege".into(), item.get("privilege").cloned().unwrap_or(Value::Null));
            extra.insert("identity".into(), item.get("identity").cloned().unwrap_or(Value::Null));
            extra.insert(
                "environmentIds".into(),
                item.get("environments").cloned().unwrap_or_else(|| json!([])),
            );
            component(kind, &target_ids, &[path], extra)
        })
        .collect()
}

/// Port of `trustBoundaries`.
pub fn trust_boundaries(components: &[Value], relations: &[Value]) -> Vec<Value> {
    relations
        .iter()
        .filter(|r| r.get("trustBoundary") == Some(&Value::Bool(true)))
        .map(|relation| {
            let mut map = relation.as_object().cloned().unwrap_or_default();
            let from = component_str_field(relation, "from").unwrap_or_default();
            let to = component_str_field(relation, "to").unwrap_or_default();
            let resolved_from = components
                .iter()
                .find(|c| component_str_field(c, "id").as_deref() == Some(from.as_str()))
                .and_then(|c| component_str_field(c, "id"))
                .unwrap_or(from);
            let resolved_to = components
                .iter()
                .find(|c| component_str_field(c, "id").as_deref() == Some(to.as_str()))
                .and_then(|c| component_str_field(c, "id"))
                .unwrap_or(to);
            map.insert("from".into(), Value::String(resolved_from));
            map.insert("to".into(), Value::String(resolved_to));
            Value::Object(map)
        })
        .collect()
}

fn ui_regex() -> Regex {
    Regex::new(r"(?i)next\.config|vite\.config|react|views?|pages?|components?").unwrap()
}

/// Port of `extractComponents` (the composite entry point).
pub fn extract_components(portfolio: &Value, projection: &Value, binding: &Value) -> R<Value> {
    let mut candidates = extract_physical_components(portfolio, projection);
    candidates.extend(extract_logical_components(portfolio, projection));
    candidates.extend(extract_deployment_components(portfolio, projection));
    candidates.extend(extract_runtime_components(portfolio, projection));

    let files: Vec<String> = str_vec(projection.get("files")).iter().map(path_of).collect();
    let ui_re = ui_regex();
    let ui: Vec<String> = files.into_iter().filter(|p| ui_re.is_match(p)).collect();
    if !ui.is_empty() {
        let ids = target_ids_of(portfolio);
        candidates.push(component("ui", &ids, &ui, Map::new()));
    }

    let relations = str_vec(projection.get("componentRelations"));
    let expected_entrypoints = str_vec(projection.get("entrypoints")).len();
    let expected_outputs = str_vec(projection.get("buildOutputs")).len();
    let expected_stores = str_vec(projection.get("dataStores")).len();
    let expected_external_systems = {
        let v = str_vec(projection.get("externalSystems"));
        if !v.is_empty() {
            v.len()
        } else {
            str_vec(projection.get("externalEndpoints")).len()
        }
    };
    let expected_release_mechanisms = str_vec(projection.get("releaseMechanisms")).len();

    build_component_graph(
        portfolio,
        candidates,
        relations,
        binding.clone(),
        expected_entrypoints,
        expected_outputs,
        expected_stores,
        expected_external_systems,
        expected_release_mechanisms,
    )
}

/// Port of `buildComponentGraph`.
#[allow(clippy::too_many_arguments)]
pub fn build_component_graph(
    portfolio: &Value,
    candidates: Vec<Value>,
    relations: Vec<Value>,
    binding: Value,
    expected_entrypoints: usize,
    expected_outputs: usize,
    expected_stores: usize,
    expected_external_systems: usize,
    expected_release_mechanisms: usize,
) -> R<Value> {
    let target_ids: BTreeSet<String> = target_ids_of(portfolio).into_iter().collect();
    let mut by_id: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    for candidate in candidates {
        let candidate_id = component_str_field(&candidate, "id").unwrap_or_default();
        for target_id in str_vec(candidate.get("targetIds"))
            .iter()
            .filter_map(Value::as_str)
        {
            if !target_ids.contains(target_id) {
                return Err(InventoryError::new(format!(
                    "unknown target for component {candidate_id}: {target_id}"
                )));
            }
        }
        if let Some(prior) = by_id.get(&candidate_id) {
            if prior != &candidate {
                return Err(InventoryError::new(format!(
                    "component ID collision: {candidate_id}"
                )));
            }
        }
        by_id.insert(candidate_id, candidate);
    }
    let mut components: Vec<Value> = by_id.into_values().collect();
    components.sort_by(|a, b| {
        component_str_field(a, "id")
            .unwrap_or_default()
            .cmp(&component_str_field(b, "id").unwrap_or_default())
    });

    let mut normalized_relations = relations;
    normalized_relations.sort_by(|a, b| {
        serde_json::to_string(a)
            .unwrap_or_default()
            .cmp(&serde_json::to_string(b).unwrap_or_default())
    });

    let mut covered_targets: BTreeSet<String> = BTreeSet::new();
    for c in &components {
        for id in str_vec(c.get("targetIds")).iter().filter_map(Value::as_str) {
            covered_targets.insert(id.to_string());
        }
    }

    let covered_stores = components
        .iter()
        .filter(|c| {
            matches!(
                component_str_field(c, "kind").as_deref(),
                Some("data") | Some("cache-search") | Some("file-media")
            )
        })
        .count();
    let covered_external_systems = components
        .iter()
        .filter(|c| c.get("external") == Some(&Value::Bool(true)))
        .count();
    let covered_release_mechanisms = components
        .iter()
        .filter(|c| {
            matches!(
                component_str_field(c, "kind").as_deref(),
                Some("installer")
                    | Some("updater")
                    | Some("build-sign-release")
                    | Some("infrastructure-dns")
            )
        })
        .count();
    let unknown_components: Vec<Value> = components
        .iter()
        .filter(|c| component_str_field(c, "kind").as_deref() == Some("unknown-material-component"))
        .filter_map(|c| c.get("id").cloned())
        .collect();
    let relation_confidence: Vec<Value> = normalized_relations
        .iter()
        .map(|r| {
            r.get("confidence")
                .cloned()
                .unwrap_or_else(|| Value::String("unknown".into()))
        })
        .collect();

    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-component-graph",
        "components": components,
        "relations": normalized_relations,
        "binding": binding,
        "coverage": {
            "expectedTargets": str_vec(portfolio.get("targets")).len(),
            "coveredTargets": covered_targets.len(),
            "expectedEntrypoints": expected_entrypoints,
            "expectedOutputs": expected_outputs,
            "expectedStores": expected_stores,
            "expectedExternalSystems": expected_external_systems,
            "expectedReleaseMechanisms": expected_release_mechanisms,
            "coveredStores": covered_stores,
            "coveredExternalSystems": covered_external_systems,
            "coveredReleaseMechanisms": covered_release_mechanisms,
            "unknownComponents": unknown_components,
            "relationConfidence": relation_confidence,
        }
    });
    validate_component_graph(&value)?;
    let mut map = value.as_object().cloned().unwrap_or_default();
    map.insert("digest".into(), Value::String(digest(&value)));
    Ok(Value::Object(map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn portfolio() -> Value {
        json!({"targets": [{"id": "target:web"}]})
    }

    #[test]
    fn component_id_is_stable_for_same_inputs() {
        let a = component_id("api", &["target:web".into()], &["src/routes/x.ts".into()]);
        let b = component_id("api", &["target:web".into()], &["src/routes/x.ts".into()]);
        assert_eq!(a, b);
        assert!(a.starts_with("component:"));
    }

    #[test]
    fn extract_logical_components_matches_known_patterns() {
        let projection = json!({"files": ["src/auth/login.ts", "src/db/schema.sql"]});
        let components = extract_logical_components(&portfolio(), &projection);
        let kinds: BTreeSet<String> = components
            .iter()
            .filter_map(|c| component_str_field(c, "kind"))
            .collect();
        assert!(kinds.contains("identity"));
        assert!(kinds.contains("data"));
    }

    #[test]
    fn build_component_graph_rejects_unknown_target() {
        let bad = component("api", &["target:missing".into()], &["a.ts".into()], Map::new());
        let result = build_component_graph(
            &portfolio(),
            vec![bad],
            vec![],
            Value::Null,
            0,
            0,
            0,
            0,
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn extract_components_end_to_end_produces_digest() {
        let projection = json!({
            "files": ["src/auth/login.ts", "src/components/App.tsx"],
            "entrypoints": [],
            "buildOutputs": [],
        });
        let graph = extract_components(&portfolio(), &projection, &Value::Null).unwrap();
        assert_eq!(graph["kind"], "legion-component-graph");
        assert!(graph["digest"].as_str().unwrap().starts_with("sha256:"));
    }
}
