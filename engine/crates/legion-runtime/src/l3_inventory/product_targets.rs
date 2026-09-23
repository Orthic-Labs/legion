//! Port of `src/lib/inventory/product-targets/**`.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::Digest;

use super::binding::digest;
use super::error::InventoryError;

type R<T> = Result<T, InventoryError>;

pub const KINDS: &[&str] = &[
    "website",
    "web-app",
    "api-service",
    "worker",
    "serverless-function",
    "desktop-app",
    "ios-app",
    "android-app",
    "mobile-extension",
    "cli",
    "library-sdk",
    "browser-extension",
    "editor-extension",
    "plugin-system",
    "data-pipeline",
    "infrastructure",
    "ai-agent-system",
    "embedded-firmware",
    "smart-contract",
    "documentation-product",
    "unknown-deliverable",
];

pub const RELATIONS: &[&str] = &[
    "shares-component",
    "depends-on",
    "client-of",
    "deploys-with",
    "distributed-with",
];

fn portable_path(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    let normalized = normalized.strip_prefix("./").unwrap_or(&normalized);
    Regex::new(r"/{2,}").unwrap().replace_all(normalized, "/").into_owned()
}

fn path_of(item: &Value) -> String {
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

/// Port of `targetId(kind, root, entrypoints)`.
pub fn target_id(kind: &str, root: &str, entrypoints: &[String]) -> String {
    let mut normalized: Vec<String> = entrypoints.iter().map(|e| portable_path(e)).collect();
    normalized.sort();
    let identity = json!([kind, portable_path(root), normalized]);
    let text = serde_json::to_string(&identity).unwrap_or_default();
    let hash = sha2::Sha256::digest(text.as_bytes());
    format!("target:{}", &hex::encode(hash)[..20])
}

/// Port of `validateTarget`.
pub fn validate_target(target: &Value) -> R<()> {
    let kind = target.get("kind").and_then(Value::as_str).unwrap_or_default();
    if !KINDS.contains(&kind) {
        return Err(InventoryError::new(format!("unknown target kind: {kind}")));
    }
    let has_id = matches!(target.get("id"), Some(Value::String(s)) if !s.is_empty());
    let has_root = matches!(target.get("root"), Some(Value::String(s)) if !s.is_empty());
    if !has_id || !has_root {
        return Err(InventoryError::new("target requires id and root"));
    }
    for key in [
        "facets",
        "entrypoints",
        "buildOutputs",
        "distributions",
        "environments",
        "componentIds",
        "stackIds",
        "relations",
        "evidencePaths",
        "conflicts",
    ] {
        if !matches!(target.get(key), Some(Value::Array(_))) {
            return Err(InventoryError::new(format!("target {key} must be an array")));
        }
    }
    let confidence = target.get("confidence").and_then(Value::as_str).unwrap_or_default();
    if !["high", "medium", "low"].contains(&confidence) {
        return Err(InventoryError::new("target confidence is invalid"));
    }
    let basis = target
        .get("classificationBasis")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !["observed", "declared", "inferred", "reviewed"].contains(&basis) {
        return Err(InventoryError::new("target classificationBasis is invalid"));
    }
    if !matches!(target.get("detectorVersion"), Some(Value::String(s)) if !s.is_empty()) {
        return Err(InventoryError::new("target detectorVersion is required"));
    }
    if target.get("binding").is_none() {
        return Err(InventoryError::new("target binding is required"));
    }
    let digest_re = Regex::new(r"^sha256:[a-f0-9]{64}$").unwrap();
    let digest_value = target.get("digest").and_then(Value::as_str).unwrap_or_default();
    if !digest_re.is_match(digest_value) {
        return Err(InventoryError::new("target digest is required"));
    }
    Ok(())
}

/// Port of `validateTargetRegistry`.
pub fn validate_target_registry(registry: &Value) -> R<()> {
    let allowed: BTreeSet<&str> = ["schemaVersion", "additive", "relations", "kinds"].into_iter().collect();
    if let Value::Object(map) = registry {
        for key in map.keys() {
            if !allowed.contains(key.as_str()) {
                return Err(InventoryError::new(format!("unknown target registry field: {key}")));
            }
        }
    }
    let schema_ok = registry.get("schemaVersion") == Some(&json!(1));
    let additive_ok = registry.get("additive") == Some(&Value::Bool(true));
    let kinds = registry.get("kinds").and_then(Value::as_array);
    if !schema_ok || !additive_ok || kinds.is_none() {
        return Err(InventoryError::new("invalid target registry"));
    }
    let kinds = kinds.unwrap();

    let mut aliases: BTreeSet<String> = BTreeSet::new();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    let allowed_kind_keys: BTreeSet<&str> = [
        "id",
        "version",
        "aliases",
        "controlPacks",
        "minimumClaimPolicy",
        "cleanClaim",
    ]
    .into_iter()
    .collect();

    for kind in kinds {
        if let Value::Object(map) = kind {
            for key in map.keys() {
                if !allowed_kind_keys.contains(key.as_str()) {
                    return Err(InventoryError::new(format!("unknown target kind field: {key}")));
                }
            }
        }
        let id = kind.get("id").and_then(Value::as_str).unwrap_or_default();
        if ids.contains(id) {
            return Err(InventoryError::new(format!("duplicate target kind: {id}")));
        }
        ids.insert(id.to_string());
        let version_ok = matches!(kind.get("version"), Some(Value::String(_)));
        let control_packs = kind.get("controlPacks").and_then(Value::as_array);
        let control_packs_ok = control_packs.map(|c| !c.is_empty()).unwrap_or(false);
        let claim_policy_ok = matches!(kind.get("minimumClaimPolicy"), Some(v) if !v.is_null());
        if !KINDS.contains(&id) || !version_ok || !control_packs_ok || !claim_policy_ok {
            return Err(InventoryError::new(format!("invalid target kind: {id}")));
        }
        for alias in kind
            .get("aliases")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            if let Some(alias_str) = alias.as_str() {
                if aliases.contains(alias_str) || KINDS.contains(&alias_str) {
                    return Err(InventoryError::new(format!("duplicate alias: {alias_str}")));
                }
                aliases.insert(alias_str.to_string());
            }
        }
    }
    if ids.len() != KINDS.len() {
        return Err(InventoryError::new("target registry does not cover canonical kinds"));
    }
    let unknown_clean_claim = registry
        .get("kinds")
        .and_then(Value::as_array)
        .and_then(|kinds| kinds.iter().find(|k| k.get("id") == Some(&json!("unknown-deliverable"))))
        .and_then(|k| k.get("cleanClaim"))
        .and_then(Value::as_str);
    if unknown_clean_claim != Some("never") {
        return Err(InventoryError::new("unknown deliverable cannot support clean claim"));
    }
    for relation in registry
        .get("relations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if let Some(r) = relation.as_str() {
            if !RELATIONS.contains(&r) {
                return Err(InventoryError::new(format!("unknown relation: {r}")));
            }
        }
    }
    Ok(())
}

/// Port of `targetRelation`.
pub fn target_relation(kind: &str, from: &str, to: &str, evidence: Vec<Value>) -> R<Value> {
    if !RELATIONS.contains(&kind) {
        return Err(InventoryError::new(format!("unknown target relation: {kind}")));
    }
    Ok(json!({"kind": kind, "from": from, "to": to, "evidence": evidence}))
}

// ---- detectors ----

const DETECTOR_RULES: &[(&str, &str)] = &[
    ("website", r"(?i)(?:^|/)(?:public/)?index\.html$|astro\.config|hugo\.(?:toml|yaml)|_config\.yml"),
    ("web-app", r"(?i)next\.config|vite\.config|react-scripts|svelte\.config|nuxt\.config"),
    ("api-service", r"(?i)fastapi|express|koa|nestjs|openapi\.(?:json|ya?ml)|routes?/"),
    ("worker", r"(?i)worker\.(?:js|ts)|bullmq|celery|cloudflare.*worker|wrangler\.toml"),
    ("serverless-function", r"(?i)serverless\.ya?ml|functions?/[^/]+\.(?:js|ts|py)|lambda"),
    ("desktop-app", r"(?i)tauri\.conf\.json|electron-builder|electron\.js|\.csproj.*winexe"),
    ("ios-app", r"(?i)\.xcodeproj|Info\.plist|Package\.swift"),
    ("android-app", r"(?i)build\.gradle|AndroidManifest\.xml"),
    ("mobile-extension", r"(?i)(?:share|notification|widget).*extension|NSExtension"),
    ("cli", r#"(?i)"bin"\s*:|(?:^|/)bin/[^/]+$|commander|click\.command"#),
    ("library-sdk", r#"(?i)"exports"\s*:|(?:^|/)lib/index\.|pyproject\.toml|Cargo\.toml"#),
    ("browser-extension", r#"(?i)(?:extension|browser-extension)/manifest\.json|browser\.runtime|chrome\.runtime|"manifest_version""#),
    ("editor-extension", r#"(?i)"engines"\s*:\s*\{[^}]*"vscode"|vscode\.commands|extension\.ts"#),
    ("plugin-system", r"(?i)plugins?/|plugin-api|registerPlugin"),
    ("data-pipeline", r"(?i)airflow|dagster|dbt_project|pipelines?/|etl"),
    ("infrastructure", r"(?i)terraform|cloudformation|pulumi|kustomization|helmfile"),
    ("ai-agent-system", r"(?i)agents?/|langchain|autogen|tool_calls?|mcp-server"),
    ("embedded-firmware", r"(?i)platformio\.ini|\.ino$|zephyr|firmware/|stm32"),
    ("smart-contract", r"(?i)\.sol$|hardhat\.config|foundry\.toml|anchor\.toml"),
    ("documentation-product", r"(?i)mkdocs|docusaurus|docs/.*\.md$|vitepress"),
];

fn source_files(projection: &Value) -> Vec<Value> {
    projection
        .get("files")
        .or_else(|| projection.get("filePaths"))
        .or_else(|| projection.get("manifest").and_then(|m| m.get("files")))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Port of `discoverTargets` (synchronous here; the JS `async` was I/O-free).
pub fn discover_targets(projection: &Value, binding: &Value) -> Vec<Value> {
    let files: Vec<String> = source_files(projection)
        .iter()
        .map(|item| match item {
            Value::String(s) => s.clone(),
            Value::Object(map) => map.get("path").and_then(Value::as_str).unwrap_or_default().to_string(),
            _ => String::new(),
        })
        .filter(|p| !p.is_empty())
        .map(|p| p.replace('\\', "/"))
        .collect();

    let structured_evidence = json!({
        "manifests": Value::Null,
        "dependencies": projection.get("dependencies").and_then(Value::as_object).map(|m| m.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
        "packages": projection.get("packages").and_then(Value::as_array).cloned().unwrap_or_default().iter().map(|item| match item {
            Value::String(s) => Value::String(s.clone()),
            other => other.get("name").cloned().unwrap_or(Value::Null),
        }).collect::<Vec<_>>(),
        "scripts": projection.get("scripts").and_then(Value::as_object).map(|m| m.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
        "entrypoints": projection.get("entrypoints").cloned().unwrap_or(Value::Null),
        "buildOutputs": projection.get("buildOutputs").cloned().unwrap_or(Value::Null),
        "deployments": projection.get("deployments").cloned().unwrap_or(Value::Null),
    });
    let text = serde_json::to_string(&structured_evidence).unwrap_or_default();

    let mut results: Vec<Value> = Vec::new();
    for (kind, pattern) in DETECTOR_RULES {
        let re = Regex::new(pattern).expect("static regex");
        let mut evidence: Vec<String> = files.iter().filter(|p| re.is_match(p)).cloned().collect();
        if re.is_match(&text) && !evidence.contains(&"projection".to_string()) {
            evidence.push("projection".to_string());
        }
        // de-dupe preserving first occurrence order (matches JS `indexOf` filter)
        let mut seen = BTreeSet::new();
        evidence.retain(|e| seen.insert(e.clone()));
        if evidence.is_empty() {
            continue;
        }
        let root = if evidence[0] == "projection" {
            ".".to_string()
        } else {
            let parts: Vec<&str> = evidence[0].split('/').collect();
            if parts.len() > 1 {
                parts[..parts.len() - 1].join("/")
            } else {
                ".".to_string()
            }
        };
        let build_outputs: Vec<Value> = projection
            .get("buildOutputs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|item| {
                let path = path_of(item).replace('\\', "/");
                let prefix = if root == "." { "".to_string() } else { root.clone() };
                path.starts_with(&prefix)
            })
            .collect();
        let confidence = if evidence.contains(&"projection".to_string()) && evidence.len() == 1 {
            "medium"
        } else {
            "high"
        };
        let value = json!({
            "id": target_id(kind, &root, &evidence),
            "kind": kind,
            "facets": [],
            "root": root,
            "entrypoints": projection.get("entrypoints").cloned().unwrap_or_else(|| json!([])),
            "buildOutputs": build_outputs,
            "distributions": [],
            "environments": [],
            "componentIds": [],
            "stackIds": [],
            "relations": [],
            "confidence": confidence,
            "classificationBasis": "observed",
            "detectorVersion": "1.0.0",
            "evidencePaths": evidence,
            "conflicts": [],
            "binding": binding,
        });
        let mut map = value.as_object().cloned().unwrap_or_default();
        map.insert("digest".into(), Value::String(digest(&value)));
        results.push(Value::Object(map));
    }

    let outputs = projection
        .get("buildOutputs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for output in outputs {
        let output_path = path_of(&output);
        let already = results.iter().any(|target| {
            target
                .get("evidencePaths")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().any(|e| e.as_str() == Some(output_path.as_str())))
                .unwrap_or(false)
        });
        if already {
            continue;
        }
        let value = json!({
            "id": target_id("unknown-deliverable", &output_path, &[output_path.clone()]),
            "kind": "unknown-deliverable",
            "facets": [],
            "root": output_path,
            "entrypoints": [],
            "buildOutputs": [output_path.clone()],
            "distributions": [],
            "environments": [],
            "componentIds": [],
            "stackIds": [],
            "relations": [],
            "confidence": "medium",
            "classificationBasis": "observed",
            "detectorVersion": "1.0.0",
            "evidencePaths": [output_path],
            "conflicts": [],
            "binding": binding,
        });
        let mut map = value.as_object().cloned().unwrap_or_default();
        map.insert("digest".into(), Value::String(digest(&value)));
        results.push(Value::Object(map));
    }

    results.sort_by(|a, b| {
        a.get("id").and_then(Value::as_str).unwrap_or_default()
            .cmp(b.get("id").and_then(Value::as_str).unwrap_or_default())
    });
    results
}

// ---- build-portfolio ----

fn normalize_target(mut target: Map<String, Value>) -> Value {
    let defaults: [(&str, Value); 12] = [
        ("facets", json!([])),
        ("entrypoints", json!([])),
        ("buildOutputs", json!([])),
        ("distributions", json!([])),
        ("environments", json!([])),
        ("componentIds", json!([])),
        ("stackIds", json!([])),
        ("relations", json!([])),
        ("confidence", json!("medium")),
        ("classificationBasis", json!("observed")),
        ("detectorVersion", json!("1.0.0")),
        ("evidencePaths", json!([])),
    ];
    let mut merged = Map::new();
    for (key, value) in defaults {
        merged.insert(key.to_string(), value);
    }
    merged.insert("conflicts".into(), json!([]));
    merged.insert("binding".into(), Value::Null);
    for (key, value) in target.iter() {
        merged.insert(key.clone(), value.clone());
    }
    merged.remove("digest");
    let value = Value::Object(merged);
    let d = digest(&value);
    let mut out = value.as_object().cloned().unwrap_or_default();
    out.insert("digest".into(), Value::String(d));
    target.clear();
    Value::Object(out)
}

const MERGE_AUTHORITY: &[&str] = &["confidence", "classificationBasis", "detectorVersion", "binding"];

fn confidence_join(left: &str, right: &str) -> &'static str {
    if left == "low" || right == "low" {
        "low"
    } else if left == "medium" || right == "medium" {
        "medium"
    } else {
        "high"
    }
}

fn str_array_union(left: &Value, right: &Value, key: &str) -> Vec<Value> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for v in [left, right] {
        for item in v.get(key).and_then(Value::as_array).cloned().unwrap_or_default() {
            if let Some(s) = item.as_str() {
                set.insert(s.to_string());
            }
        }
    }
    set.into_iter().map(Value::String).collect()
}

fn merge_target(left: &Value, right: &Value) -> R<Value> {
    if left.get("kind") != right.get("kind") || left.get("root") != right.get("root") {
        let id = left.get("id").and_then(Value::as_str).unwrap_or_default();
        return Err(InventoryError::new(format!("target ID collision: {id}")));
    }
    let contradictory: Vec<String> = {
        let mut fields: Vec<String> = MERGE_AUTHORITY
            .iter()
            .filter(|field| {
                serde_json::to_string(left.get(**field).unwrap_or(&Value::Null)).unwrap_or_default()
                    != serde_json::to_string(right.get(**field).unwrap_or(&Value::Null)).unwrap_or_default()
            })
            .map(|s| s.to_string())
            .collect();
        fields.sort();
        fields
    };
    let mut merged_conflicts: Vec<Value> = left
        .get("conflicts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    merged_conflicts.extend(
        right
            .get("conflicts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    );
    if !contradictory.is_empty() {
        merged_conflicts.push(json!({
            "kind": "classification-contradiction",
            "fields": contradictory,
            "leftDigest": left.get("digest").cloned().unwrap_or(Value::Null),
            "rightDigest": right.get("digest").cloned().unwrap_or(Value::Null),
        }));
    }
    // de-dupe conflicts by JSON identity (Map semantics in JS).
    let mut seen = BTreeSet::new();
    let deduped_conflicts: Vec<Value> = merged_conflicts
        .into_iter()
        .filter(|c| seen.insert(serde_json::to_string(c).unwrap_or_default()))
        .collect();

    // relations: de-dupe by JSON identity, last-write-wins like JS `new Map`.
    let mut relation_map: BTreeMap<String, Value> = BTreeMap::new();
    for relation in left
        .get("relations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .chain(right.get("relations").and_then(Value::as_array).cloned().unwrap_or_default())
    {
        relation_map.insert(serde_json::to_string(&relation).unwrap_or_default(), relation);
    }

    let mut value = left.as_object().cloned().unwrap_or_default();
    value.insert(
        "confidence".into(),
        Value::String(
            confidence_join(
                left.get("confidence").and_then(Value::as_str).unwrap_or_default(),
                right.get("confidence").and_then(Value::as_str).unwrap_or_default(),
            )
            .to_string(),
        ),
    );
    value.insert("facets".into(), Value::Array(str_array_union(left, right, "facets")));
    value.insert("entrypoints".into(), Value::Array(str_array_union(left, right, "entrypoints")));
    value.insert("buildOutputs".into(), Value::Array(str_array_union(left, right, "buildOutputs")));
    value.insert("distributions".into(), Value::Array(str_array_union(left, right, "distributions")));
    value.insert("environments".into(), Value::Array(str_array_union(left, right, "environments")));
    value.insert("componentIds".into(), Value::Array(str_array_union(left, right, "componentIds")));
    value.insert("stackIds".into(), Value::Array(str_array_union(left, right, "stackIds")));
    value.insert("relations".into(), Value::Array(relation_map.into_values().collect()));
    value.insert("evidencePaths".into(), Value::Array(str_array_union(left, right, "evidencePaths")));
    value.insert("conflicts".into(), Value::Array(deduped_conflicts));
    value.remove("digest");
    let out_value = Value::Object(value.clone());
    let d = digest(&out_value);
    value.insert("digest".into(), Value::String(d));
    Ok(Value::Object(value))
}

/// Port of `buildPortfolio`.
pub fn build_portfolio(
    candidates: Vec<Value>,
    declarations: Vec<Value>,
    relations: Vec<Value>,
    conflicts: Vec<Value>,
    material_deliverables: Vec<Value>,
    binding: Value,
) -> R<Value> {
    let mut by_id: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    let mut duplicate_candidates = 0u64;
    for raw in candidates.into_iter().chain(declarations) {
        let map = raw.as_object().cloned().unwrap_or_default();
        let target = normalize_target(map);
        validate_target(&target)?;
        let id = target.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
        if let Some(existing) = by_id.get(&id) {
            duplicate_candidates += 1;
            let merged = merge_target(existing, &target)?;
            by_id.insert(id, merged);
        } else {
            by_id.insert(id, target);
        }
    }

    let accounted: BTreeSet<String> = by_id
        .values()
        .flat_map(|target| {
            let mut paths: Vec<String> = target
                .get("evidencePaths")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            paths.extend(
                target
                    .get("buildOutputs")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string),
            );
            paths
        })
        .map(|p| p.replace('\\', "/"))
        .collect();

    for raw in &material_deliverables {
        let path = path_of(raw).replace('\\', "/");
        if accounted.contains(&path) {
            continue;
        }
        let hashed = digest(&Value::String(path.clone()));
        let suffix = &hashed[hashed.len().saturating_sub(20)..];
        let mut map = Map::new();
        map.insert("id".into(), Value::String(format!("target:unknown:{suffix}")));
        map.insert("kind".into(), Value::String("unknown-deliverable".into()));
        map.insert("root".into(), Value::String(path.clone()));
        map.insert("evidencePaths".into(), json!([path.clone()]));
        map.insert("buildOutputs".into(), json!([path.clone()]));
        map.insert("confidence".into(), Value::String("high".into()));
        map.insert("conflicts".into(), json!(["missing-qualified-target-mapping"]));
        let target = normalize_target(map);
        let id = target.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
        by_id.insert(id, target);
    }

    let mut targets: Vec<Value> = by_id.into_values().collect();
    targets.sort_by(|a, b| {
        a.get("id").and_then(Value::as_str).unwrap_or_default()
            .cmp(b.get("id").and_then(Value::as_str).unwrap_or_default())
    });

    let target_ids: BTreeSet<String> = targets
        .iter()
        .filter_map(|t| t.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    for relation in &relations {
        let kind = relation.get("kind").and_then(Value::as_str).unwrap_or_default();
        if !RELATIONS.contains(&kind) {
            return Err(InventoryError::new(format!("unknown target relation: {kind}")));
        }
        let from = relation.get("from").and_then(Value::as_str).unwrap_or_default();
        let to = relation.get("to").and_then(Value::as_str).unwrap_or_default();
        if !target_ids.contains(from) || !target_ids.contains(to) {
            return Err(InventoryError::new(format!(
                "target relation endpoint is unknown: {from}->{to}"
            )));
        }
    }

    let unknown: Vec<&Value> = targets
        .iter()
        .filter(|t| t.get("kind") == Some(&Value::String("unknown-deliverable".into())))
        .collect();
    let expected_deliverables = material_deliverables.len().max(targets.len());

    let mut merged_conflicts = conflicts;
    for target in &targets {
        let id = target.get("id").cloned().unwrap_or(Value::Null);
        for conflict in target.get("conflicts").and_then(Value::as_array).cloned().unwrap_or_default() {
            let mut entry = if let Some(s) = conflict.as_str() {
                let mut m = Map::new();
                m.insert("kind".into(), Value::String(s.to_string()));
                m
            } else {
                conflict.as_object().cloned().unwrap_or_default()
            };
            entry.insert("targetId".into(), id.clone());
            merged_conflicts.push(Value::Object(entry));
        }
    }

    let mut sorted_relations = relations.clone();
    sorted_relations.sort_by(|a, b| {
        serde_json::to_string(a).unwrap_or_default().cmp(&serde_json::to_string(b).unwrap_or_default())
    });

    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-product-portfolio",
        "targets": targets,
        "relations": sorted_relations,
        "conflicts": merged_conflicts,
        "coverage": {
            "expectedDeliverables": expected_deliverables,
            "classifiedTargets": targets.len() - unknown.len(),
            "duplicateCandidates": duplicate_candidates,
            "conflicts": merged_conflicts_len(&merged_conflicts),
            "unknownDeliverables": unknown.iter().filter_map(|t| t.get("id").cloned()).collect::<Vec<_>>(),
        },
        "binding": binding,
    });
    let mut map = value.as_object().cloned().unwrap_or_default();
    map.insert("digest".into(), Value::String(digest(&value)));
    Ok(Value::Object(map))
}

fn merged_conflicts_len(conflicts: &[Value]) -> usize {
    conflicts.len()
}

// ---- review ----

/// Port of `reviewClassification`.
pub fn review_classification(candidates: Vec<Value>, review: Option<Value>) -> R<Value> {
    let Some(review) = review else {
        let status = if candidates
            .iter()
            .any(|c| c.get("kind") == Some(&Value::String("unknown-deliverable".into())))
        {
            "unproven"
        } else {
            "pass"
        };
        return Ok(json!({"status": status, "candidates": candidates, "conflicts": []}));
    };

    let mut by_id: BTreeMap<String, Value> = candidates
        .iter()
        .filter_map(|c| Some((c.get("id")?.as_str()?.to_string(), c.clone())))
        .collect();

    for nomination in review
        .get("nominations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let candidate_id = nomination
            .get("candidateId")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let candidate = by_id
            .get(candidate_id)
            .cloned()
            .ok_or_else(|| InventoryError::new(format!("review nomination references unknown candidate: {candidate_id}")))?;
        if let Some(kind) = nomination.get("kind").and_then(Value::as_str) {
            if !KINDS.contains(&kind) {
                return Err(InventoryError::new(format!("unknown nomination kind: {kind}")));
            }
        }
        if let Some(confidence) = nomination.get("confidence").and_then(Value::as_str) {
            if !["high", "medium", "low"].contains(&confidence) {
                return Err(InventoryError::new(format!("review confidence is invalid: {confidence}")));
            }
        }
        let evidence_refs: Vec<Value> = nomination
            .get("evidenceRefs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let candidate_kind = candidate.get("kind").and_then(Value::as_str).unwrap_or_default();
        let nomination_kind = nomination.get("kind").and_then(Value::as_str);
        if candidate_kind == "unknown-deliverable"
            && nomination_kind.map(|k| k != "unknown-deliverable").unwrap_or(false)
            && evidence_refs.is_empty()
        {
            return Err(InventoryError::new(
                "review evidence is required to classify an unknown deliverable",
            ));
        }
        let allowed_evidence: BTreeSet<String> = candidate
            .get("evidencePaths")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        for evidence_ref in &evidence_refs {
            let s = evidence_ref.as_str().unwrap_or_default();
            if !allowed_evidence.contains(s) {
                return Err(InventoryError::new(format!(
                    "review evidence is not sealed candidate evidence: {s}"
                )));
            }
        }
        let candidate_confidence = candidate.get("confidence").and_then(Value::as_str).unwrap_or_default();
        if candidate_kind != "unknown-deliverable" && candidate_confidence == "high" {
            continue;
        }
        let mut value = candidate.as_object().cloned().unwrap_or_default();
        if let Some(k) = nomination_kind {
            value.insert("kind".into(), Value::String(k.to_string()));
        }
        if let Some(c) = nomination.get("confidence") {
            value.insert("confidence".into(), c.clone());
        }
        value.insert("classificationBasis".into(), Value::String("reviewed".into()));
        value.insert(
            "reviewNomination".into(),
            json!({
                "kind": nomination.get("kind").cloned().unwrap_or(Value::Null),
                "confidence": nomination.get("confidence").cloned().unwrap_or(Value::Null),
                "evidenceRefs": evidence_refs,
            }),
        );
        value.remove("digest");
        let out_value = Value::Object(value.clone());
        let d = digest(&out_value);
        value.insert("digest".into(), Value::String(d));
        by_id.insert(candidate_id.to_string(), Value::Object(value));
    }

    let output: Vec<Value> = by_id.into_values().collect();
    let conflicts = review.get("conflicts").cloned().unwrap_or_else(|| json!([]));
    let has_unknown = output
        .iter()
        .any(|c| c.get("kind") == Some(&Value::String("unknown-deliverable".into())));
    let conflicts_len = conflicts.as_array().map(|a| a.len()).unwrap_or(0);
    let status = if conflicts_len > 0 || has_unknown { "unproven" } else { "pass" };

    Ok(json!({
        "status": status,
        "candidates": output,
        "conflicts": conflicts,
        "review": {
            "nominations": review.get("nominations").cloned().unwrap_or_else(|| json!([])),
            "bounded": true,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_id_is_stable() {
        let a = target_id("cli", "bin", &["bin/x".into()]);
        let b = target_id("cli", "bin", &["bin/x".into()]);
        assert_eq!(a, b);
        assert!(a.starts_with("target:"));
    }

    #[test]
    fn discover_targets_detects_cargo_as_library_sdk() {
        let projection = json!({"files": ["Cargo.toml", "src/lib.rs"]});
        let targets = discover_targets(&projection, &Value::Null);
        assert!(targets.iter().any(|t| t["kind"] == "library-sdk"));
    }

    #[test]
    fn build_portfolio_rejects_unknown_relation_kind() {
        let candidate = json!({
            "id": "target:a", "kind": "cli", "root": "bin",
            "confidence": "high", "classificationBasis": "observed",
            "detectorVersion": "1.0.0", "binding": null,
        });
        let result = build_portfolio(vec![candidate], vec![], vec![json!({"kind": "bogus", "from": "target:a", "to": "target:a"})], vec![], vec![], Value::Null);
        assert!(result.is_err());
    }

    #[test]
    fn review_classification_without_review_flags_unknown_deliverable() {
        let candidates = vec![json!({"id": "target:a", "kind": "unknown-deliverable"})];
        let result = review_classification(candidates, None).unwrap();
        assert_eq!(result["status"], "unproven");
    }
}
