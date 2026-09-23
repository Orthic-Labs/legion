//! Integration tests porting the JS test coverage for
//! `src/providers/security/model-extractors/common.mjs`,
//! `src/providers/security/model-extractors/cloud.mjs`,
//! `src/providers/security/model-extractors/data.mjs`,
//! `src/providers/security/model-extractors/developer-machine.mjs`, and
//! `src/providers/security/model-extractors/http.mjs` (chunk wf054).
//!
//! Cloud and developer-machine assertions are ported from
//! `../../../../tests/security-l4/b7-007-specialist-extractors.test.mjs`; the shared
//! entity/relation/fact constructor determinism assertion is ported from
//! `../../../../tests/security-model.test.mjs`. `http.mjs` and `data.mjs` have no
//! dedicated JS test file in the tree at the time of this port (confirmed by search); their
//! cases below are derived directly from each file's own extraction logic.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod wf054;` inside it)
//! into `legion_audit`'s crate root.

use std::collections::{HashMap, HashSet};

use legion_audit::wf_port::wf054::{
    cloud, data, developer_machine, entity, extract_common, fact, http, relation, EntityOptions,
    FactFields, PackageManifest, ENTITY_KINDS, FACT_KINDS, RELATION_KINDS,
};

fn source_text(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn files_of(pairs: &[(&str, &str)]) -> Vec<String> {
    pairs.iter().map(|(k, _)| k.to_string()).collect()
}

// =================================================================================================
// common.mjs — constructors (ported from security-model.test.mjs)
// =================================================================================================

#[test]
fn model_entity_relation_fact_constructors_produce_deterministic_ids() {
    let e1 = entity(
        "entrypoint",
        "GET /x",
        serde_json::json!({ "method": "GET" }),
        &["ev1".to_string()],
        EntityOptions::default(),
    );
    let e2 = entity(
        "entrypoint",
        "GET /x",
        serde_json::json!({ "method": "GET" }),
        &["ev1".to_string()],
        EntityOptions::default(),
    );
    assert_eq!(e1["id"], e2["id"]);

    let e1_id = e1["id"].as_str().unwrap().to_string();
    let r1 = relation(
        "invokes",
        &e1_id,
        &e1_id,
        &["ev1".to_string()],
        serde_json::json!({}),
        EntityOptions::default(),
    );
    let f1 = fact(
        "network-reachability",
        FactFields { subject: Some("actor:external"), object: Some(&e1_id), ..FactFields::default() },
        &[],
    );
    assert!(r1["id"].as_str().unwrap().starts_with("sha256:"));
    assert!(f1["id"].as_str().unwrap().starts_with("sha256:"));
}

#[test]
fn common_extractor_models_repository_artifacts_and_manifests() {
    let files = vec!["app.py".to_string(), "src/lib.py".to_string()];
    let manifests = vec![serde_json::json!("package.json"), serde_json::json!("pyproject.toml")];
    let out = extract_common(&files, &manifests);

    assert_eq!(out.entities.len(), 4);
    for e in &out.entities {
        assert_eq!(e["kind"], "repository-artifact");
        assert!(e["id"].as_str().unwrap().starts_with("sha256:"));
    }
    assert!(out.entities.iter().any(|e| e["name"] == "app.py" && e["attributes"]["path"] == "app.py"));
    assert!(out.entities.iter().any(|e| e["name"] == "manifest package.json" && e["attributes"]["manifest"] == true));
    assert_eq!(out.evidence.len(), 4);
    assert!(out.relations.is_empty());
    assert!(out.initial_facts.is_empty());
    assert!(out.coverage_gaps.is_empty());

    // Deterministic: rerunning yields identical output.
    let again = extract_common(&files, &manifests);
    assert_eq!(out, again);
}

#[test]
fn common_extractor_coerces_object_manifests_like_js_string_of_object() {
    // extractCommon never destructures `.path` — a manifest that is a JS object (rather
    // than a bare string) is stringified via `${manifest}` / `String(manifest)`, which JS
    // coerces to the literal "[object Object]". Ported faithfully (see mod.rs header note).
    let manifests = vec![serde_json::json!({ "path": "package.json", "dependencies": [] })];
    let out = extract_common(&[], &manifests);
    assert_eq!(out.entities.len(), 1);
    assert_eq!(out.entities[0]["name"], "manifest [object Object]");
    assert_eq!(out.evidence[0]["file"], "[object Object]");
}

// =================================================================================================
// cloud.mjs (ported from b7-007-specialist-extractors.test.mjs)
// =================================================================================================

const CLOUD_TF: &str = r#"
      resource "aws_iam_role" "app" {
        assume_role_policy = jsonencode({ Effect = "Allow" })
      }
      resource "aws_security_group_rule" "ingress" {
        type        = "ingress"
        cidr_blocks = ["0.0.0.0/0"]
      }
      resource "aws_s3_bucket" "data" {}
      resource "aws_secretsmanager_secret" "db" {
        kms_key_id = "alias/app"
      }
      resource "aws_iam_role_policy" "app" {
        policy = jsonencode({ Action = ["s3:GetObject"], Resource = ["*"] })
      }
      # workload_identity federated_identity oidc_provider
    "#;
const CLOUD_DOCKERFILE: &str = "FROM node:20\nCMD [\"node\", \"server.js\"]";

fn cloud_fixture() -> (Vec<String>, HashMap<String, String>, Vec<PackageManifest>, HashSet<String>) {
    let files = vec!["infra/main.tf".to_string(), "infra/Dockerfile".to_string()];
    let text = source_text(&[("infra/main.tf", CLOUD_TF), ("infra/Dockerfile", CLOUD_DOCKERFILE)]);
    let manifests = vec![PackageManifest {
        path: "package.json".to_string(),
        dependencies: vec!["@aws-sdk/client-s3".to_string()],
        scripts: vec![],
    }];
    let release_files: HashSet<String> = ["infra/Dockerfile".to_string()].into_iter().collect();
    (files, text, manifests, release_files)
}

#[test]
fn cloud_extractor_shares_the_common_contract_shape() {
    let (files, text, manifests, release_files) = cloud_fixture();
    let result = cloud::extract(&files, &text, &manifests, &release_files);

    for e in &result.entities {
        assert!(e["id"].as_str().unwrap().starts_with("sha256:"), "entity id is a stableId");
        let kind = e["kind"].as_str().unwrap();
        assert!(ENTITY_KINDS.contains(&kind), "entity kind {kind} is registered");
    }
    let entity_ids: HashSet<&str> = result.entities.iter().map(|e| e["id"].as_str().unwrap()).collect();
    for r in &result.relations {
        assert!(r["id"].as_str().unwrap().starts_with("sha256:"), "relation id is a stableId");
        let kind = r["kind"].as_str().unwrap();
        assert!(RELATION_KINDS.contains(&kind), "relation kind {kind} is registered");
        assert!(entity_ids.contains(r["from"].as_str().unwrap()), "relation.from references a produced entity");
        assert!(entity_ids.contains(r["to"].as_str().unwrap()), "relation.to references a produced entity");
    }
    for f in &result.initial_facts {
        assert!(f["id"].as_str().unwrap().starts_with("sha256:"), "fact id is a stableId");
        let kind = f["kind"].as_str().unwrap();
        assert!(FACT_KINDS.contains(&kind), "fact kind {kind} is registered");
    }
}

#[test]
fn cloud_extractor_models_iam_public_exposure_workload_identity_storage_secrets_deployment() {
    let (files, text, manifests, release_files) = cloud_fixture();
    let result = cloud::extract(&files, &text, &manifests, &release_files);

    assert!(result.entities.iter().any(|e| e["kind"] == "identity" && e["attributes"]["environment"] == "cloud"), "IAM role identity");
    assert!(
        result.entities.iter().any(|e| e["kind"] == "entrypoint" && e["attributes"]["entrypointType"] == "network-ingress"),
        "public entrypoint"
    );
    assert!(result.entities.iter().any(|e| e["kind"] == "asset" && e["attributes"]["assetKind"] == "storage"), "storage asset");
    assert!(result.entities.iter().any(|e| e["kind"] == "asset" && e["attributes"]["assetKind"] == "secret"), "secret asset");
    assert!(result.entities.iter().any(|e| e["kind"] == "deployment-context"), "deployment context");
    assert!(result.entities.iter().any(|e| e["attributes"]["workloadIdentity"] == true), "workload identity");
    assert!(result.initial_facts.iter().any(|f| f["kind"] == "network-reachability"), "public exposure fact");
    assert!(result.coverage_gaps.is_empty(), "no coverage gap when cloud signal present");
}

#[test]
fn cloud_extractor_models_cloud_sdk_dependency_as_a_service_entity() {
    let (files, text, manifests, release_files) = cloud_fixture();
    let result = cloud::extract(&files, &text, &manifests, &release_files);
    assert!(result.entities.iter().any(|e| e["kind"] == "service" && e["attributes"]["dependency"] == "@aws-sdk/client-s3"));
}

#[test]
fn cloud_extractor_missing_rendered_configuration_yields_typed_coverage_gap() {
    let files = vec!["infra/main.tf".to_string()];
    let text: HashMap<String, String> = HashMap::new();
    let result = cloud::extract(&files, &text, &[], &HashSet::new());
    assert!(result.coverage_gaps.iter().any(|g| g["kind"] == "missing-rendered-configuration" && g["domain"] == "cloud"));
}

#[test]
fn cloud_extractor_absent_signal_yields_context_not_detected_gap() {
    let result = cloud::extract(&[], &HashMap::new(), &[], &HashSet::new());
    assert!(result.coverage_gaps.iter().any(|g| g["kind"] == "cloud-context-not-detected"));
}

#[test]
fn cloud_extractor_is_deterministic() {
    let (files, text, manifests, release_files) = cloud_fixture();
    let first = cloud::extract(&files, &text, &manifests, &release_files);
    let second = cloud::extract(&files, &text, &manifests, &release_files);
    assert_eq!(first, second);
}

// =================================================================================================
// developer-machine.mjs (ported from b7-007-specialist-extractors.test.mjs)
// =================================================================================================

fn dev_machine_fixture() -> (Vec<String>, HashMap<String, String>, Vec<PackageManifest>) {
    let pairs = [
        (
            ".claude/settings.json",
            r#"{ "hooks": { "PreToolUse": [{ "command": "exec('ls')" }] }, "permissions": "fetch(url); readFile(x);" }"#,
        ),
        (".mcp.json", r#"{ "servers": {} }"#),
    ];
    let files = files_of(&pairs);
    let text = source_text(&pairs);
    let manifests = vec![PackageManifest {
        path: "package.json".to_string(),
        dependencies: vec![],
        scripts: vec!["build".to_string(), "postinstall".to_string(), "preinstall".to_string()],
    }];
    (files, text, manifests)
}

#[test]
fn developer_machine_extractor_shares_the_common_contract_shape() {
    let (files, text, manifests) = dev_machine_fixture();
    let result = developer_machine::extract(&files, &text, &manifests);

    for e in &result.entities {
        assert!(e["id"].as_str().unwrap().starts_with("sha256:"));
        let kind = e["kind"].as_str().unwrap();
        assert!(ENTITY_KINDS.contains(&kind), "entity kind {kind} is registered");
    }
    let entity_ids: HashSet<&str> = result.entities.iter().map(|e| e["id"].as_str().unwrap()).collect();
    for r in &result.relations {
        let kind = r["kind"].as_str().unwrap();
        assert!(RELATION_KINDS.contains(&kind), "relation kind {kind} is registered");
        assert!(entity_ids.contains(r["from"].as_str().unwrap()));
        assert!(entity_ids.contains(r["to"].as_str().unwrap()));
    }
    for f in &result.initial_facts {
        let kind = f["kind"].as_str().unwrap();
        assert!(FACT_KINDS.contains(&kind), "fact kind {kind} is registered");
    }
}

#[test]
fn developer_machine_extractor_models_hooks_config_grants_and_bypass() {
    let (files, text, manifests) = dev_machine_fixture();
    let result = developer_machine::extract(&files, &text, &manifests);

    assert!(result
        .entities
        .iter()
        .any(|e| e["attributes"]["processKind"] == "package-lifecycle-hook" && e["attributes"]["script"] == "postinstall"));
    assert!(result
        .entities
        .iter()
        .any(|e| e["attributes"]["processKind"] == "package-lifecycle-hook" && e["attributes"]["script"] == "preinstall"));
    assert!(result.entities.iter().any(|e| e["attributes"]["configKind"] == "editor-agent-config"));
    assert!(result.entities.iter().any(|e| e["kind"] == "permission-scope" && e["attributes"]["grantKind"] == "process"));
    assert!(result.entities.iter().any(|e| e["kind"] == "permission-scope" && e["attributes"]["grantKind"] == "network"));
    assert!(result.entities.iter().any(|e| e["kind"] == "permission-scope" && e["attributes"]["grantKind"] == "filesystem"));
    assert!(result.initial_facts.iter().any(|f| f["kind"] == "code-execution"));
    assert!(result.coverage_gaps.is_empty(), "no coverage gap when dev-machine signal present");
}

#[test]
fn developer_machine_extractor_missing_rendered_configuration_yields_typed_coverage_gap() {
    let files = vec![".claude/settings.json".to_string()];
    let manifests = vec![];
    let result = developer_machine::extract(&files, &HashMap::new(), &manifests);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|g| g["kind"] == "missing-rendered-configuration" && g["domain"] == "developer-machine"));
}

#[test]
fn developer_machine_extractor_absent_signal_yields_context_not_detected_gap() {
    let result = developer_machine::extract(&[], &HashMap::new(), &[]);
    assert!(result.coverage_gaps.iter().any(|g| g["kind"] == "developer-machine-context-not-detected"));
}

#[test]
fn developer_machine_extractor_is_deterministic() {
    let (files, text, manifests) = dev_machine_fixture();
    let first = developer_machine::extract(&files, &text, &manifests);
    let second = developer_machine::extract(&files, &text, &manifests);
    assert_eq!(first, second);
}

// =================================================================================================
// http.mjs — no dedicated JS test in the tree; cases derived from source logic
// =================================================================================================

#[test]
fn http_extractor_models_express_route_with_source_and_process_and_auth_relation() {
    let pairs = [("src/routes.js", "app.post('/api/items', requireAuth, handler)")];
    let files = files_of(&pairs);
    let text = source_text(&pairs);
    let result = http::extract(&files, &text);

    assert_eq!(result.entities.len(), 3);
    let entrypoint = result.entities.iter().find(|e| e["kind"] == "entrypoint").unwrap();
    assert_eq!(entrypoint["name"], "POST /api/items");
    assert_eq!(entrypoint["attributes"]["method"], "POST");
    assert_eq!(entrypoint["attributes"]["path"], "/api/items");
    assert_eq!(entrypoint["attributes"]["framework"], "express");
    assert!(result.entities.iter().any(|e| e["kind"] == "source" && e["name"] == "POST /api/items input"));
    assert!(result.entities.iter().any(|e| e["kind"] == "process" && e["name"] == "POST /api/items handler"));

    assert_eq!(result.relations.len(), 3, "accepts-input-from + invokes + protected-by");
    assert!(result.relations.iter().any(|r| r["kind"] == "accepts-input-from"));
    assert!(result.relations.iter().any(|r| r["kind"] == "invokes"));
    // Ported unchecked from JS: `protected-by` is not a member of RELATION_KINDS (see
    // mod.rs header note) but the extractor emits it anyway.
    assert!(result.relations.iter().any(|r| r["kind"] == "protected-by"));
    assert!(!RELATION_KINDS.contains(&"protected-by"));
    assert!(result.initial_facts.is_empty(), "auth present means no network-reachability fact");
}

#[test]
fn http_extractor_models_unauthenticated_route_as_a_network_reachability_fact() {
    let pairs = [("src/routes.js", "router.get('/public/ping', handler)")];
    let files = files_of(&pairs);
    let text = source_text(&pairs);
    let result = http::extract(&files, &text);

    assert!(result.relations.iter().all(|r| r["kind"] != "protected-by"));
    assert_eq!(result.initial_facts.len(), 1);
    let f = &result.initial_facts[0];
    assert_eq!(f["kind"], "network-reachability");
    assert_eq!(f["subject"], "actor:external");
    assert_eq!(f["action"], "connect");
}

#[test]
fn http_extractor_matches_fastapi_flask_and_go_web_frameworks() {
    let pairs = [
        ("api.py", "@app.get('/items')\ndef list_items(): pass"),
        ("app.py", "@app.route('/health')\ndef health(): pass"),
        ("main.go", "router.GET(\"/status\", statusHandler)"),
    ];
    let files = files_of(&pairs);
    let text = source_text(&pairs);
    let result = http::extract(&files, &text);

    assert!(result.entities.iter().any(|e| e["attributes"]["framework"] == "fastapi" && e["attributes"]["method"] == "GET"));
    assert!(result.entities.iter().any(|e| e["attributes"]["framework"] == "go-web" && e["attributes"]["method"] == "GET"));
    // Flask's JS regex has one capture group (the path); the loop body still reads
    // match[1] as method and match[2] as path, so `method` becomes the upper-cased path
    // text and `path` is JS `undefined` (dropped from attributes, rendered as the literal
    // text "undefined" in names). Ported faithfully (see mod.rs http module doc).
    let flask_entry = result.entities.iter().find(|e| e["attributes"]["framework"] == "flask").unwrap();
    assert_eq!(flask_entry["attributes"]["method"], "/HEALTH");
    assert!(flask_entry["attributes"].get("path").is_none(), "path key dropped like JS undefined");
    assert_eq!(flask_entry["name"], "/HEALTH undefined");
}

#[test]
fn http_extractor_skips_files_with_no_projected_source_text() {
    let files = vec!["src/routes.js".to_string()];
    let result = http::extract(&files, &HashMap::new());
    assert!(result.entities.is_empty());
    assert!(result.evidence.is_empty());
}

#[test]
fn http_extractor_is_deterministic() {
    let pairs = [("src/routes.js", "app.post('/api/items', requireAuth, handler)\nrouter.get('/x', h)")];
    let files = files_of(&pairs);
    let text = source_text(&pairs);
    let first = http::extract(&files, &text);
    let second = http::extract(&files, &text);
    assert_eq!(first, second);
}

// =================================================================================================
// data.mjs — no dedicated JS test in the tree; cases derived from source logic
// =================================================================================================

#[test]
fn data_extractor_models_database_cache_and_vector_store_clients() {
    let pairs = [(
        "src/store.js",
        "const rows = await db.query('select 1');\nconst hit = await redis.get('k');\nconst emb = await vector.search(x);",
    )];
    let files = files_of(&pairs);
    let text = source_text(&pairs);
    let result = data::extract(&files, &text);

    assert!(result.entities.iter().any(|e| e["kind"] == "data-store" && e["name"] == "database client src/store.js"));
    assert!(result.entities.iter().any(|e| e["kind"] == "data-store" && e["name"] == "cache client src/store.js"));
    assert!(result.entities.iter().any(|e| e["kind"] == "data-store" && e["name"] == "vector store client src/store.js"));
    assert_eq!(result.entities.len(), 3);
    assert!(result.relations.is_empty());
    assert!(result.initial_facts.is_empty());
    assert!(result.coverage_gaps.is_empty(), "extractData never emits coverage gaps");
}

#[test]
fn data_extractor_flags_sensitive_field_names_as_an_unregistered_data_class_kind() {
    let pairs = [("src/user.js", "const password = req.body.password;")];
    let files = files_of(&pairs);
    let text = source_text(&pairs);
    let result = data::extract(&files, &text);

    let data_class = result.entities.iter().find(|e| e["kind"] == "data-class").unwrap();
    assert_eq!(data_class["name"], "sensitive data src/user.js");
    assert_eq!(data_class["attributes"]["sensitive"], true);
    // Ported unchecked from JS: `data-class` is not a member of ENTITY_KINDS (see mod.rs
    // header note) but the extractor emits it anyway.
    assert!(!ENTITY_KINDS.contains(&"data-class"));
}

#[test]
fn data_extractor_sensitive_pattern_is_word_bounded_and_case_insensitive() {
    let matching = [("a.js", "const ApiKey = 'x';")];
    let non_matching = [("b.js", "const passwordless = true;")];
    let m = data::extract(&files_of(&matching), &source_text(&matching));
    let n = data::extract(&files_of(&non_matching), &source_text(&non_matching));
    assert!(m.entities.iter().any(|e| e["kind"] == "data-class"), "apiKey matches \\b(?:...|apiKey|...)\\b case-insensitively");
    assert!(!n.entities.iter().any(|e| e["kind"] == "data-class"), "passwordless does not match the word-bounded pattern");
}

#[test]
fn data_extractor_skips_files_with_no_projected_source_text() {
    let files = vec!["src/store.js".to_string()];
    let result = data::extract(&files, &HashMap::new());
    assert!(result.entities.is_empty());
}

#[test]
fn data_extractor_is_deterministic() {
    let pairs = [("src/store.js", "db.query(x); redis.get(y); const password = z;")];
    let files = files_of(&pairs);
    let text = source_text(&pairs);
    let first = data::extract(&files, &text);
    let second = data::extract(&files, &text);
    assert_eq!(first, second);
}
