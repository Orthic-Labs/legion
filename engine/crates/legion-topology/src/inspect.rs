use crate::binding::digest;
use crate::projection::build_projection;
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CAPABILITY_IDS: &[&str] = &[
    "repository",
    "build",
    "browser",
    "desktop",
    "vm",
    "simulator-emulator",
    "physical-device",
    "service-deployment",
    "cloud-dns-store-provider",
    "operations",
    "reviewer",
    "human",
    "signing",
    "mutation",
    "external-evidence",
];

pub fn inspect_repository(root: &Path, packs: &[Value]) -> Result<Value, String> {
    let projection = build_projection(root)?;
    let artifact = inspect_product(&projection, packs, None)?;
    Ok(product_topology_stage(artifact))
}

pub fn inspect_targets(root: &Path, packs: &[Value]) -> Result<Value, String> {
    let result = inspect_repository(root, packs)?;
    let artifact = result.get("artifact").cloned().unwrap_or(Value::Null);
    Ok(json!({
        "artifact": artifact.get("portfolio").cloned().unwrap_or(Value::Null),
        "selectionTrace": artifact
            .pointer("/portfolio/coverage")
            .cloned()
            .unwrap_or(Value::Null),
    }))
}

pub fn inspect_components(root: &Path, packs: &[Value]) -> Result<Value, String> {
    let result = inspect_repository(root, packs)?;
    let artifact = result.get("artifact").cloned().unwrap_or(Value::Null);
    Ok(json!({
        "artifact": artifact.get("components").cloned().unwrap_or(Value::Null),
        "selectionTrace": artifact
            .pointer("/components/coverage")
            .cloned()
            .unwrap_or(Value::Null),
    }))
}

pub fn inspect_stacks(root: &Path, packs: &[Value]) -> Result<Value, String> {
    let result = inspect_repository(root, packs)?;
    let artifact = result.get("artifact").cloned().unwrap_or(Value::Null);
    Ok(json!({
        "artifact": artifact.get("stacks").cloned().unwrap_or(Value::Null),
        "selectionTrace": artifact
            .pointer("/stacks/coverage")
            .cloned()
            .unwrap_or(Value::Null),
    }))
}

pub fn inspect_controls(root: &Path, packs: &[Value]) -> Result<Value, String> {
    let result = inspect_repository(root, packs)?;
    let artifact = result.get("artifact").cloned().unwrap_or(Value::Null);
    Ok(json!({
        "artifact": artifact.get("baseline").cloned().unwrap_or(Value::Null),
    }))
}

fn product_topology_stage(artifact: Value) -> Value {
    let portfolio = artifact.get("portfolio").cloned().unwrap_or(Value::Null);
    let components = artifact.get("components").cloned().unwrap_or(Value::Null);
    let stacks = artifact.get("stacks").cloned().unwrap_or(Value::Null);
    let target_count = portfolio
        .get("targets")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    let unknown_targets = portfolio
        .pointer("/coverage/unknownDeliverables")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    let unknown_components = components
        .pointer("/coverage/unknownComponents")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    let expected_targets = components
        .pointer("/coverage/expectedTargets")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let covered_targets = components
        .pointer("/coverage/coveredTargets")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let uncovered_targets = expected_targets.saturating_sub(covered_targets);
    let unknown_stacks = stacks
        .pointer("/coverage/unknownStacks")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    let unknown_external = artifact
        .pointer("/externalSystems/systems")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| item.get("status") == Some(&json!("unknown")))
                .count()
        })
        .unwrap_or(0);
    let journey_gaps = artifact
        .pointer("/journeys/gaps")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    let context_gaps = artifact
        .pointer("/productContext/gaps")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    let capability_gaps = artifact
        .get("claimImpact")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    let scenario_gaps = artifact
        .pointer("/scenarios/omitted")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| item.get("mandatory") == Some(&json!(true)))
                .count()
        })
        .unwrap_or(0);
    let portfolio_conflicts = portfolio
        .get("conflicts")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    let target_conflicts = portfolio
        .get("targets")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| item.get("conflicts").and_then(Value::as_array).map(|c| c.len()).unwrap_or(0))
                .sum::<usize>()
        })
        .unwrap_or(0);
    let conflicts = portfolio_conflicts + target_conflicts;
    let complete = target_count > 0
        && unknown_targets == 0
        && unknown_components == 0
        && uncovered_targets == 0
        && unknown_stacks == 0
        && unknown_external == 0
        && journey_gaps == 0
        && context_gaps == 0
        && capability_gaps == 0
        && scenario_gaps == 0
        && conflicts == 0;
    let detail = if target_count == 0 {
        Some("target-denominator-zero")
    } else if unknown_targets > 0 {
        Some("unaccounted-deliverable")
    } else if unknown_components > 0 {
        Some("unknown-material-component")
    } else if uncovered_targets > 0 {
        Some("target-component-coverage-gap")
    } else if unknown_stacks > 0 {
        Some("unknown-stack")
    } else if unknown_external > 0 {
        Some("external-system-evidence-gap")
    } else if journey_gaps > 0 {
        Some("journey-coverage-gap")
    } else if context_gaps > 0 {
        Some("product-context-gap")
    } else if capability_gaps > 0 {
        Some("capability-evidence-gap")
    } else if scenario_gaps > 0 {
        Some("mandatory-scenario-gap")
    } else if conflicts > 0 {
        Some("target-conflict")
    } else {
        None
    };
    json!({
        "complete": complete,
        "status": if complete { "pass" } else { "unproven" },
        "artifact": artifact,
        "detail": detail,
    })
}

fn inspect_product(projection: &Value, packs: &[Value], binding: Option<&Value>) -> Result<Value, String> {
    let candidates = discover_targets(projection, binding)?;
    let portfolio = build_portfolio(&candidates, &[], &[], &[], &[], binding)?;
    let components = extract_components(&portfolio, projection, binding)?;
    let stacks = build_stack_graph(&portfolio, &components, projection, binding)?;
    let mut targets = Vec::new();
    for target in portfolio
        .get("targets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let target_id = target.get("id").and_then(Value::as_str).unwrap_or_default();
        let component_ids = components
            .get("components")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|component| {
                component
                    .get("targetIds")
                    .and_then(Value::as_array)
                    .is_some_and(|ids| ids.iter().any(|id| id == &json!(target_id)))
            })
            .filter_map(|component| component.get("id").cloned())
            .collect::<Vec<_>>();
        let stack_ids = stacks
            .get("stacks")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|stack| {
                stack
                    .get("targetIds")
                    .and_then(Value::as_array)
                    .is_some_and(|ids| ids.iter().any(|id| id == &json!(target_id)))
            })
            .filter_map(|stack| stack.get("id").cloned())
            .collect::<Vec<_>>();
        let mut object = target.as_object().cloned().unwrap_or_default();
        object.remove("digest");
        object.insert("componentIds".into(), Value::Array(component_ids));
        object.insert("stackIds".into(), Value::Array(stack_ids));
        let value = Value::Object(object);
        let mut with_digest = value.as_object().cloned().unwrap_or_default();
        with_digest.insert("digest".into(), json!(digest(&value)));
        targets.push(Value::Object(with_digest));
    }
    let mut portfolio_object = portfolio.as_object().cloned().unwrap_or_default();
    portfolio_object.remove("digest");
    portfolio_object.insert("targets".into(), Value::Array(targets));
    let portfolio_value = Value::Object(portfolio_object);
    let mut portfolio_with_digest = portfolio_value.as_object().cloned().unwrap_or_default();
    portfolio_with_digest.insert("digest".into(), json!(digest(&portfolio_value)));
    let portfolio = Value::Object(portfolio_with_digest);

    let external_systems = discover_external_systems(projection, &components, binding)?;
    let release_contract = merge_release_contract(json!({}), binding)?;
    let product_context = build_product_context(projection, &release_contract);
    let journeys = build_journeys(&portfolio, &release_contract, projection, binding)?;
    let baseline = compile_baseline(packs, &portfolio, &components, &stacks, &release_contract, binding)?;
    let capabilities = evidence_capabilities(binding);
    let claim_impact = capability_impacts(&baseline, &capabilities);
    let scenarios = compile_scenarios(&baseline, &journeys, &capabilities, binding, &release_contract);
    let gaps = release_contract
        .get("missingDeclarations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|field| json!({ "kind": "release-contract-missing", "field": field }))
        .chain(
            product_context
                .get("gaps")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter(),
        )
        .chain(
            journeys
                .get("gaps")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter(),
        )
        .chain(
            stacks
                .pointer("/coverage/unknownStacks")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|id| json!({ "kind": "unknown-stack", "id": id })),
        )
        .collect::<Vec<_>>();
    let report_skeleton = json!({
        "targetIds": portfolio
            .get("targets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|item| item.get("id").cloned())
            .collect::<Vec<_>>(),
        "componentIds": components
            .get("components")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|item| item.get("id").cloned())
            .collect::<Vec<_>>(),
        "stackIds": stacks
            .get("stacks")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|item| item.get("id").cloned())
            .collect::<Vec<_>>(),
        "externalSystemIds": external_systems
            .get("systems")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|item| item.get("id").cloned())
            .collect::<Vec<_>>(),
        "controlIds": baseline
            .get("controls")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|item| item.get("id").cloned())
            .collect::<Vec<_>>(),
        "scenarioIds": scenarios
            .get("scenarios")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|item| item.get("id").cloned())
            .collect::<Vec<_>>(),
        "gaps": gaps,
    });
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-product-inspection",
        "portfolio": portfolio,
        "components": components,
        "stacks": stacks,
        "externalSystems": external_systems,
        "releaseContract": release_contract,
        "productContext": product_context,
        "journeys": journeys,
        "baseline": baseline,
        "capabilities": capabilities,
        "claimImpact": claim_impact,
        "scenarios": scenarios,
        "reportSkeleton": report_skeleton,
    }))
}

fn discover_targets(projection: &Value, binding: Option<&Value>) -> Result<Vec<Value>, String> {
    let files = projection
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    let manifests = projection
        .get("manifests")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let dependencies = projection
        .get("dependencies")
        .and_then(Value::as_object)
        .map(|map| map.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let structured = json!({
        "manifests": manifests
            .iter()
            .map(|manifest| {
                json!({
                    "name": manifest.get("name"),
                    "bin": manifest.get("bin"),
                    "exports": manifest.get("exports"),
                    "engines": manifest.get("engines"),
                    "manifest_version": manifest.get("manifest_version"),
                    "background": manifest.get("background"),
                    "permissions": manifest.get("permissions"),
                    "type": manifest.get("type"),
                })
            })
            .collect::<Vec<_>>(),
        "dependencies": dependencies,
        "packages": projection
            .get("packages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|item| {
                if let Some(text) = item.as_str() {
                    text.to_owned()
                } else {
                    item.get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                }
            })
            .collect::<Vec<_>>(),
        "scripts": projection
            .get("scripts")
            .and_then(Value::as_object)
            .map(|map| map.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default(),
        "entrypoints": projection.get("entrypoints").cloned().unwrap_or(Value::Null),
        "buildOutputs": projection.get("buildOutputs").cloned().unwrap_or(Value::Null),
        "deployments": projection.get("deployments").cloned().unwrap_or(Value::Null),
    });
    let text = serde_json::to_string(&structured).unwrap_or_default();
    let rules = detector_rules();
    let mut results = Vec::new();
    for (kind, pattern) in rules {
        let mut evidence = files
            .iter()
            .filter(|path| pattern.is_match(path))
            .cloned()
            .collect::<Vec<_>>();
        if pattern.is_match(&text) {
            evidence.push("projection".into());
        }
        evidence.sort();
        evidence.dedup();
        if evidence.is_empty() {
            continue;
        }
        let root = if evidence.first().map(String::as_str) == Some("projection") {
            ".".to_string()
        } else {
            let parts = evidence[0].split('/').collect::<Vec<_>>();
            if parts.len() <= 1 {
                ".".to_string()
            } else {
                parts[..parts.len() - 1].join("/")
            }
        };
        let value = json!({
            "id": target_id(kind, &root, &evidence),
            "kind": kind,
            "facets": [],
            "root": root,
            "entrypoints": projection.get("entrypoints").cloned().unwrap_or(json!([])),
            "buildOutputs": projection.get("buildOutputs").cloned().unwrap_or(json!([])),
            "distributions": [],
            "environments": [],
            "componentIds": [],
            "stackIds": [],
            "relations": [],
            "confidence": if evidence.contains(&"projection".to_string()) && evidence.len() == 1 { "medium" } else { "high" },
            "classificationBasis": "observed",
            "detectorVersion": "1.0.0",
            "evidencePaths": evidence,
            "conflicts": [],
            "binding": binding,
        });
        let mut object = value.as_object().cloned().unwrap_or_default();
        object.insert("digest".into(), json!(digest(&value)));
        results.push(Value::Object(object));
    }
    for output in projection
        .get("buildOutputs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let path = output
            .get("path")
            .and_then(Value::as_str)
            .or_else(|| output.as_str())
            .unwrap_or_default();
        if results
            .iter()
            .any(|target| {
                target
                    .get("evidencePaths")
                    .and_then(Value::as_array)
                    .is_some_and(|paths| paths.iter().any(|item| item == &json!(path)))
            })
        {
            continue;
        }
        let value = json!({
            "id": target_id("unknown-deliverable", path, &[path.to_owned()]),
            "kind": "unknown-deliverable",
            "facets": [],
            "root": path,
            "entrypoints": [],
            "buildOutputs": [path],
            "distributions": [],
            "environments": [],
            "componentIds": [],
            "stackIds": [],
            "relations": [],
            "confidence": "medium",
            "classificationBasis": "observed",
            "detectorVersion": "1.0.0",
            "evidencePaths": [path],
            "conflicts": [],
            "binding": binding,
        });
        let mut object = value.as_object().cloned().unwrap_or_default();
        object.insert("digest".into(), json!(digest(&value)));
        results.push(Value::Object(object));
    }
    results.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(right.get("id").and_then(Value::as_str).unwrap_or_default())
    });
    Ok(results)
}

fn detector_rules() -> Vec<(&'static str, Regex)> {
    vec![
        ("website", Regex::new(r"(?:^|/)(?:public/)?index\.html$|astro\.config|hugo\.(?:toml|yaml)|_config\.yml").unwrap()),
        ("web-app", Regex::new(r"next\.config|vite\.config|react-scripts|svelte\.config|nuxt\.config").unwrap()),
        ("api-service", Regex::new(r"fastapi|express|koa|nestjs|openapi\.(?:json|ya?ml)|routes?/").unwrap()),
        ("worker", Regex::new(r"worker\.(?:js|ts)|bullmq|celery|cloudflare.*worker|wrangler\.toml").unwrap()),
        ("serverless-function", Regex::new(r"serverless\.ya?ml|functions?/[^/]+\.(?:js|ts|py)|lambda").unwrap()),
        ("desktop-app", Regex::new(r"tauri\.conf\.json|electron-builder|electron\.js|\.csproj.*winexe").unwrap()),
        ("ios-app", Regex::new(r"\.xcodeproj|Info\.plist|Package\.swift").unwrap()),
        ("android-app", Regex::new(r"build\.gradle|AndroidManifest\.xml").unwrap()),
        ("mobile-extension", Regex::new(r"(?:share|notification|widget).*extension|NSExtension").unwrap()),
        ("cli", Regex::new(r#""bin"\s*:|(?:^|/)bin/[^/]+$|commander|click\.command"#).unwrap()),
        ("library-sdk", Regex::new(r#""exports"\s*:|(?:^|/)lib/index\.|pyproject\.toml|Cargo\.toml"#).unwrap()),
        ("browser-extension", Regex::new(r#"(?:extension|browser-extension)/manifest\.json|browser\.runtime|chrome\.runtime|"manifest_version""#).unwrap()),
        ("editor-extension", Regex::new(r#""engines"\s*:\s*\{[^}]*"vscode"|vscode\.commands|extension\.ts"#).unwrap()),
        ("plugin-system", Regex::new(r"plugins?/|plugin-api|registerPlugin").unwrap()),
        ("data-pipeline", Regex::new(r"airflow|dagster|dbt_project|pipelines?/|etl").unwrap()),
        ("infrastructure", Regex::new(r"terraform|cloudformation|pulumi|kustomization|helmfile").unwrap()),
        ("ai-agent-system", Regex::new(r"agents?/|langchain|autogen|tool_calls?|mcp-server").unwrap()),
        ("embedded-firmware", Regex::new(r"platformio\.ini|\.ino$|zephyr|firmware/|stm32").unwrap()),
        ("smart-contract", Regex::new(r"\.sol$|hardhat\.config|foundry\.toml|anchor\.toml").unwrap()),
        ("documentation-product", Regex::new(r"mkdocs|docusaurus|docs/.*\.md$|vitepress").unwrap()),
    ]
}

fn portable_path(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim_start_matches("./")
        .replace("//", "/")
}

fn target_id(kind: &str, root: &str, entrypoints: &[String]) -> String {
    let mut normalized = entrypoints
        .iter()
        .map(|path| portable_path(path))
        .collect::<Vec<_>>();
    normalized.sort();
    let payload = json!([kind, portable_path(root), normalized]);
    let bytes = serde_json::to_string(&payload).unwrap_or_default();
    let hex = hex::encode(sha2::Sha256::digest(bytes.as_bytes()));
    format!("target:{}", hex.chars().take(20).collect::<String>())
}

fn normalize_target(target: &Value) -> Value {
    let mut object = target.as_object().cloned().unwrap_or_default();
    for key in [
        "facets",
        "entrypoints",
        "buildOutputs",
        "distributions",
        "environments",
        "componentIds",
        "stackIds",
        "relations",
        "confidence",
        "classificationBasis",
        "detectorVersion",
        "evidencePaths",
        "conflicts",
        "binding",
    ] {
        object.entry(key.to_string()).or_insert(json!([]));
    }
    object
        .entry("confidence".to_string())
        .or_insert(json!("medium"));
    object
        .entry("classificationBasis".to_string())
        .or_insert(json!("observed"));
    object
        .entry("detectorVersion".to_string())
        .or_insert(json!("1.0.0"));
    object.entry("binding".to_string()).or_insert(Value::Null);
    object.remove("digest");
    let value = Value::Object(object);
    let mut with_digest = value.as_object().cloned().unwrap_or_default();
    with_digest.insert("digest".into(), json!(digest(&value)));
    Value::Object(with_digest)
}

fn build_portfolio(
    candidates: &[Value],
    declarations: &[Value],
    relations: &[Value],
    conflicts: &[Value],
    material_deliverables: &[Value],
    binding: Option<&Value>,
) -> Result<Value, String> {
    let mut by_id: BTreeMap<String, Value> = BTreeMap::new();
    let mut duplicate_candidates = 0usize;
    for raw in candidates.iter().chain(declarations.iter()) {
        let target = normalize_target(raw);
        let id = target
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if by_id.contains_key(&id) {
            duplicate_candidates += 1;
        }
        by_id.insert(id, target);
    }
    let mut accounted = BTreeSet::new();
    for target in by_id.values() {
        for path in target
            .get("evidencePaths")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .chain(
                target
                    .get("buildOutputs")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                    .iter(),
            )
        {
            accounted.insert(path.to_string().replace('\\', "/"));
        }
    }
    for raw in material_deliverables {
        let path = raw
            .get("path")
            .and_then(Value::as_str)
            .or_else(|| raw.as_str())
            .unwrap_or_default()
            .replace('\\', "/");
        if accounted.contains(&path) {
            continue;
        }
        let target = normalize_target(&json!({
            "id": format!("target:unknown:{}", digest(&json!(path)).chars().rev().take(20).collect::<String>()),
            "kind": "unknown-deliverable",
            "root": path,
            "evidencePaths": [path],
            "buildOutputs": [path],
            "confidence": "high",
            "conflicts": ["missing-qualified-target-mapping"],
        }));
        by_id.insert(
            target
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            target,
        );
    }
    let targets = by_id.values().cloned().collect::<Vec<_>>();
    let unknown = targets
        .iter()
        .filter(|target| target.get("kind") == Some(&json!("unknown-deliverable")))
        .collect::<Vec<_>>();
    let expected_deliverables = material_deliverables.len().max(targets.len());
    let merged_conflicts = conflicts
        .iter()
        .cloned()
        .chain(
            targets
                .iter()
                .flat_map(|target| {
                    let id = target.get("id").cloned().unwrap_or(Value::Null);
                    target
                        .get("conflicts")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .map(move |conflict| {
                            if let Some(text) = conflict.as_str() {
                                json!({ "targetId": id.clone(), "kind": text })
                            } else {
                                let mut object = conflict.as_object().cloned().unwrap_or_default();
                                object.insert("targetId".into(), id.clone());
                                Value::Object(object)
                            }
                        })
                }),
        )
        .collect::<Vec<_>>();
    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-product-portfolio",
        "targets": targets,
        "relations": relations,
        "conflicts": merged_conflicts,
        "coverage": {
            "expectedDeliverables": expected_deliverables,
            "classifiedTargets": targets.len() - unknown.len(),
            "duplicateCandidates": duplicate_candidates,
            "conflicts": merged_conflicts.len(),
            "unknownDeliverables": unknown.iter().filter_map(|target| target.get("id").cloned()).collect::<Vec<_>>(),
        },
        "binding": binding,
    });
    let mut object = value.as_object().cloned().unwrap_or_default();
    object.insert("digest".into(), json!(digest(&value)));
    Ok(Value::Object(object))
}

fn component(kind: &str, target_ids: &[String], evidence_paths: &[String], extra: Map<String, Value>) -> Value {
    let mut sorted_targets = target_ids.to_vec();
    sorted_targets.sort();
    let mut sorted_paths = evidence_paths
        .iter()
        .map(|path| portable_path(path))
        .collect::<Vec<_>>();
    sorted_paths.sort();
    let identity = json!([kind, sorted_targets, sorted_paths]);
    let hex = hex::encode(
        sha2::Sha256::digest(serde_json::to_string(&identity).unwrap_or_default().as_bytes()),
    );
    let id = format!("component:{}", hex.chars().take(20).collect::<String>());
    let mut object = Map::new();
    object.insert("id".into(), json!(id));
    object.insert("kind".into(), json!(kind));
    object.insert("targetIds".into(), json!(sorted_targets));
    object.insert("rootPaths".into(), json!(sorted_paths.clone()));
    object.insert("evidencePaths".into(), json!(sorted_paths));
    object.insert("classificationBasis".into(), json!("observed"));
    object.insert("runtimeBoundary".into(), Value::Null);
    object.insert("privilege".into(), Value::Null);
    object.insert("identity".into(), Value::Null);
    object.insert("dataClassIds".into(), json!([]));
    object.insert("stackIds".into(), json!([]));
    object.insert("external".into(), json!(false));
    object.insert("trustBoundaries".into(), json!([]));
    for (key, value) in extra {
        object.insert(key, value);
    }
    Value::Object(object)
}

fn extract_components(
    portfolio: &Value,
    projection: &Value,
    binding: Option<&Value>,
) -> Result<Value, String> {
    let target_ids = portfolio
        .get("targets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|target| target.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();
    let files = projection
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for output in projection
        .get("buildOutputs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let path = output
            .get("path")
            .and_then(Value::as_str)
            .or_else(|| output.as_str())
            .unwrap_or_default();
        candidates.push(component("build-sign-release", &target_ids, &[path.to_owned()], Map::new()));
    }
    for path in files.iter().filter(|path| {
        Regex::new(r"next\.config|vite\.config|react|views?|pages?|components?")
            .unwrap()
            .is_match(path)
    }) {
        candidates.push(component("ui", &target_ids, &[path.clone()], Map::new()));
    }
    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-component-graph",
        "components": candidates,
        "relations": [],
        "binding": binding,
        "coverage": {
            "expectedTargets": target_ids.len(),
            "coveredTargets": if candidates.is_empty() { 0 } else { target_ids.len() },
            "expectedEntrypoints": projection.get("entrypoints").and_then(Value::as_array).map(|items| items.len()).unwrap_or(0),
            "expectedOutputs": projection.get("buildOutputs").and_then(Value::as_array).map(|items| items.len()).unwrap_or(0),
            "expectedStores": projection.get("dataStores").and_then(Value::as_array).map(|items| items.len()).unwrap_or(0),
            "expectedExternalSystems": projection.get("externalSystems").and_then(Value::as_array).map(|items| items.len()).unwrap_or(0),
            "expectedReleaseMechanisms": projection.get("releaseMechanisms").and_then(Value::as_array).map(|items| items.len()).unwrap_or(0),
            "coveredStores": 0,
            "coveredExternalSystems": 0,
            "coveredReleaseMechanisms": 0,
            "unknownComponents": [],
            "relationConfidence": [],
        },
    });
    let mut object = value.as_object().cloned().unwrap_or_default();
    object.insert("digest".into(), json!(digest(&value)));
    Ok(Value::Object(object))
}

fn build_stack_graph(
    portfolio: &Value,
    components: &Value,
    projection: &Value,
    binding: Option<&Value>,
) -> Result<Value, String> {
    let records = projection
        .get("dependencies")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(name, version)| (name.clone(), version.clone(), "dependency"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let target_ids = portfolio
        .get("targets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|target| target.get("id").cloned())
        .collect::<Vec<_>>();
    let stacks = records
        .iter()
        .map(|(name, version, role)| {
            json!({
                "id": format!("stack:{}", hex::encode(sha2::Sha256::digest(format!("{name}\0{role}\0").as_bytes())).chars().take(20).collect::<String>()),
                "name": name,
                "role": role,
                "evidencePaths": [format!("projection:{role}:{name}")],
                "category": role,
                "version": { "kind": "resolved", "value": version },
                "declaredVersion": version,
                "resolvedVersion": Value::Null,
                "runtimeVersion": Value::Null,
                "known": false,
                "targetIds": target_ids,
                "componentIds": [],
                "knownLimitations": [],
                "tiers": {
                    "inventory": 1,
                    "parser": 0,
                    "native": 0,
                    "cross-file": 0,
                    "measured-pack": 0,
                    "runtime": 0,
                    "remediation": 0,
                },
            })
        })
        .collect::<Vec<_>>();
    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-stack-graph",
        "stacks": stacks,
        "targetIds": target_ids,
        "componentIds": components
            .get("components")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|item| item.get("id").cloned())
            .collect::<Vec<_>>(),
        "coverage": {
            "expectedRecords": records.len(),
            "knownRecords": 0,
            "unknownStacks": stacks.iter().filter_map(|stack| stack.get("id").cloned()).collect::<Vec<_>>(),
        },
        "binding": binding,
    });
    let mut object = value.as_object().cloned().unwrap_or_default();
    object.insert("digest".into(), json!(digest(&value)));
    Ok(Value::Object(object))
}

fn discover_external_systems(
    projection: &Value,
    components: &Value,
    binding: Option<&Value>,
) -> Result<Value, String> {
    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-external-system-inventory",
        "systems": [],
        "componentIds": components
            .get("components")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|item| item.get("id").cloned())
            .collect::<Vec<_>>(),
        "binding": binding,
    });
    let mut object = value.as_object().cloned().unwrap_or_default();
    object.insert("digest".into(), json!(digest(&value)));
    Ok(Value::Object(object))
}

fn merge_release_contract(_input: Value, binding: Option<&Value>) -> Result<Value, String> {
    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-release-contract",
        "observed": {},
        "declared": {},
        "policy": {},
        "externalEvidence": {},
        "conflicts": [],
        "missing": [],
        "claimLevel": "source",
        "requestedClaimLevel": "source",
        "targetIds": [],
        "supportedPlatforms": [],
        "supportedVersions": [],
        "architectures": [],
        "browsers": [],
        "devices": [],
        "installationModes": [],
        "environments": [],
        "roles": [],
        "tenants": [],
        "plansAndEntitlements": [],
        "criticalJourneyIds": [],
        "dataClasses": [],
        "crownJewelAssets": [],
        "budgets": {},
        "unsupportedScenarios": [],
        "acceptedRiskAuthority": Value::Null,
        "releaseCandidates": [],
        "observedDeclaredConflicts": [],
        "missingDeclarations": [],
        "binding": binding,
    });
    let mut object = value.as_object().cloned().unwrap_or_default();
    object.insert("digest".into(), json!(digest(&value)));
    Ok(Value::Object(object))
}

fn build_product_context(projection: &Value, contract: &Value) -> Value {
    json!({
        "roles": [],
        "tenants": [],
        "actors": [],
        "accounts": [],
        "permissions": [],
        "bindings": projection.get("actorBindings").cloned().unwrap_or(json!([])),
        "gaps": [],
        "plans": [],
        "entitlements": [],
        "dataClasses": [],
        "assets": projection.get("assets").cloned().unwrap_or(json!([])),
        "riskCandidates": projection.get("riskCandidates").cloned().unwrap_or(json!([])),
        "riskAuthority": contract.pointer("/declared/riskAuthority").cloned().unwrap_or(Value::Null),
    })
}

fn build_journeys(
    portfolio: &Value,
    _contract: &Value,
    _projection: &Value,
    binding: Option<&Value>,
) -> Result<Value, String> {
    let target_ids = portfolio
        .get("targets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|target| target.get("id").cloned())
        .collect::<Vec<_>>();
    let gaps = vec![json!({ "kind": "journey-denominator-missing", "targetIds": target_ids })];
    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-journey-inventory",
        "journeys": [],
        "gaps": gaps,
        "complete": false,
        "binding": binding,
    });
    let mut object = value.as_object().cloned().unwrap_or_default();
    object.insert("digest".into(), json!(digest(&value)));
    Ok(Value::Object(object))
}

fn compile_baseline(
    _packs: &[Value],
    portfolio: &Value,
    _components: &Value,
    _stacks: &Value,
    _contract: &Value,
    binding: Option<&Value>,
) -> Result<Value, String> {
    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-control-baseline",
        "controls": [],
        "traces": [],
        "binding": binding,
        "denominator": [],
        "unimplemented": [],
    });
    let mut object = value.as_object().cloned().unwrap_or_default();
    object.insert("digest".into(), json!(digest(&value)));
    Ok(Value::Object(object))
}

fn evidence_capabilities(_binding: Option<&Value>) -> Vec<Value> {
    CAPABILITY_IDS
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "available": false,
                "owner": "host",
                "receipt": Value::Null,
                "reason": "host-capability-unavailable",
            })
        })
        .collect()
}

fn capability_impacts(_baseline: &Value, _capabilities: &[Value]) -> Vec<Value> {
    Vec::new()
}

fn compile_scenarios(
    _baseline: &Value,
    _journeys: &Value,
    _capabilities: &[Value],
    binding: Option<&Value>,
    _contract: &Value,
) -> Value {
    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-scenario-matrix",
        "axes": {},
        "scenarios": [],
        "omitted": [{
            "id": "scenario-matrix:dimensions",
            "mandatory": true,
            "reason": "scenario-dimensions-missing",
            "coverageEffect": "unproven",
        }],
        "binding": binding,
        "complete": false,
    });
    let mut object = value.as_object().cloned().unwrap_or_default();
    object.insert("digest".into(), json!(digest(&value)));
    Value::Object(object)
}
