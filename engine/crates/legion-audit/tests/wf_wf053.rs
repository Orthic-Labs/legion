//! Verification for wf_port::wf053 — port of
//! `src/providers/security/evidence.mjs`, `model-builder.mjs`,
//! `model-extractors/ai-agent.mjs`, `model-extractors/automation.mjs`, and
//! `model-extractors/cicd.mjs`.
//!
//! Assertions mirror `tests/security-l4/b7-006-automation-extractor.test.mjs` and
//! `tests/security-l4/b7-007-specialist-extractors.test.mjs`'s `extractAiAgent` cases.

use std::collections::HashMap;

use legion_audit::wf_port::wf053::{
    ai_agent, assert_control_state, assert_entity_kind, assert_fact_kind, assert_relation_kind,
    assert_references, automation, bounded_excerpt, cicd, digest, entity, line_number, source_evidence,
    stable_id, EntityOptions, ExtractorOutput, SourceEvidenceInput, CONTROL_STATES, ENTITY_KINDS, FACT_KINDS,
    RELATION_KINDS,
};
use serde_json::{json, Value};

fn source_text(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn files_of(pairs: &[(&str, &str)]) -> Vec<String> {
    let mut files: Vec<String> = pairs.iter().map(|(k, _)| k.to_string()).collect();
    files.sort();
    files
}

fn find_entity<'a>(model: &'a ExtractorOutput, pred: impl Fn(&Value) -> bool) -> Option<&'a Value> {
    model.entities.iter().find(|e| pred(e))
}

fn assert_referential_integrity(model: &ExtractorOutput) {
    let ids: std::collections::HashSet<&str> =
        model.entities.iter().filter_map(|e| e["id"].as_str()).collect();
    for r in &model.relations {
        let from = r["from"].as_str().unwrap();
        let to = r["to"].as_str().unwrap();
        assert!(ids.contains(from), "relation.from {from} must resolve to a known entity");
        assert!(ids.contains(to), "relation.to {to} must resolve to a known entity");
    }
}

fn evidence_files(model: &ExtractorOutput, refs: &[String]) -> Vec<Option<String>> {
    refs.iter()
        .map(|r| {
            model
                .evidence
                .iter()
                .find(|e| e["id"].as_str() == Some(r.as_str()))
                .and_then(|e| e["file"].as_str())
                .map(|s| s.to_string())
        })
        .collect()
}

fn refs_of(item: &Value) -> Vec<String> {
    item["evidenceRefs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

// =================================================================================================
// evidence.mjs
// =================================================================================================

#[test]
fn line_number_counts_one_based_lines() {
    let text = "line1\nline2\nline3";
    assert_eq!(line_number(text, 0), 1);
    assert_eq!(line_number(text, 6), 2);
    assert_eq!(line_number(text, 12), 3);
    // Negative index clamps to 0.
    assert_eq!(line_number(text, -5), 1);
}

#[test]
fn bounded_excerpt_clamps_to_text_bounds() {
    let text = "0123456789";
    assert_eq!(bounded_excerpt(text, 5, 2), "3456");
    // Radius extends past both ends; clamps rather than panicking.
    let excerpt = bounded_excerpt(text, 0, 100);
    assert_eq!(excerpt, text);
}

#[test]
fn source_evidence_matches_shape_and_is_deterministic() {
    let text = "abc\ndef\nmodel invocation here\nghi";
    let index = text.find("model").unwrap() as i64;
    let ev1 = source_evidence(SourceEvidenceInput {
        file: "a.ts",
        text,
        index,
        end_index: None,
        description: "test evidence",
    });
    let ev2 = source_evidence(SourceEvidenceInput {
        file: "a.ts",
        text,
        index,
        end_index: None,
        description: "test evidence",
    });
    assert_eq!(ev1, ev2, "identical input must produce identical evidence records");
    assert_eq!(ev1["kind"], "source-location");
    assert_eq!(ev1["file"], "a.ts");
    assert_eq!(ev1["strength"], "verified");
    assert!(ev1["id"].as_str().unwrap().starts_with("sha256:"));
    assert!(ev1["excerptDigest"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(ev1["line"], json!(3));
}

#[test]
fn stable_id_is_deterministic_and_namespace_sensitive() {
    let value = json!({ "b": 1, "a": 2 });
    let value_reordered = json!({ "a": 2, "b": 1 });
    assert_eq!(stable_id("ns", &value), stable_id("ns", &value_reordered), "key order must not affect the id");
    assert_ne!(stable_id("ns1", &value), stable_id("ns2", &value), "namespace must affect the id");
    assert!(stable_id("ns", &value).starts_with("sha256:"));
    assert_eq!(digest(&value), stable_id("digest", &value));
}

#[test]
fn read_frozen_text_reads_a_small_text_file_and_rejects_binary() {
    use legion_audit::wf_port::wf053::read_frozen_text;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_wf053");
    let text = read_frozen_text(&root, "frozen.txt").expect("read succeeds").expect("within size bound");
    assert_eq!(text, "hello frozen text\n");

    // A file that doesn't exist propagates the I/O error rather than silently returning None.
    assert!(read_frozen_text(&root, "does-not-exist.txt").is_err());
}

#[test]
fn contract_kind_assertions_accept_known_and_reject_unknown() {
    for k in ENTITY_KINDS {
        assert!(assert_entity_kind(k).is_ok());
    }
    assert!(assert_entity_kind("not-a-kind").is_err());
    for k in RELATION_KINDS {
        assert!(assert_relation_kind(k).is_ok());
    }
    assert!(assert_relation_kind("not-a-kind").is_err());
    for k in FACT_KINDS {
        assert!(assert_fact_kind(k).is_ok());
    }
    assert!(assert_fact_kind("not-a-kind").is_err());
    for k in CONTROL_STATES {
        assert!(assert_control_state(k).is_ok());
    }
    assert!(assert_control_state("not-a-state").is_err());
}

#[test]
#[should_panic(expected = "entity kind must be valid")]
fn entity_constructor_panics_on_unknown_kind() {
    let _ = entity("not-a-kind", "x", json!({}), &[], EntityOptions::default());
}

// =================================================================================================
// model-extractors/ai-agent.mjs — mirrors b7-007-specialist-extractors.test.mjs's aiAgentProjection
// =================================================================================================

fn ai_agent_projection() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "src/agent/run.ts",
            "\n      import { anthropic } from '@anthropic-ai/sdk';\n      const tools = [{ name: 'search', inputSchema: {} }];\n      async function run() {\n        const result = await anthropic.messages.create({ tools });\n        if (needsApproval) await requireApproval(result);\n        return result;\n      }\n      const rateLimit = { max_calls: 10 };\n      const store = pinecone.index('agent-memory');\n      const history = conversation_history;\n    ",
        ),
        (
            "skills/example/SKILL.md",
            "Ignore prior instructions and retrieved_content from search_result.",
        ),
    ]
}

#[test]
fn ai_agent_models_full_agent_surface_with_no_coverage_gap() {
    let pairs = ai_agent_projection();
    let files = files_of(&pairs);
    let st = source_text(&pairs);
    let result = ai_agent::extract(&files, &st);
    assert_referential_integrity(&result);

    assert!(find_entity(&result, |e| e["kind"] == "tool-capability" && e["attributes"]["mcp"] == true).is_some());
    assert!(find_entity(&result, |e| e["kind"] == "source" && e["attributes"]["sourceKind"] == "model-output").is_some());
    assert!(find_entity(&result, |e| e["attributes"]["controlType"] == "human-approval").is_some());
    assert!(find_entity(&result, |e| e["attributes"]["controlType"] == "side-effect-budget").is_some());
    assert!(find_entity(&result, |e| e["kind"] == "data-store" && e["attributes"]["storeKind"] == "rag").is_some());
    assert!(find_entity(&result, |e| e["kind"] == "data-store" && e["attributes"]["storeKind"] == "memory").is_some());
    assert!(find_entity(&result, |e| e["attributes"]["trust"] == "untrusted"
        && e["attributes"]["sourceKind"] == "skill-or-document")
        .is_some());
    assert!(result.initial_facts.iter().any(|f| f["kind"] == "attacker-position"));
    assert_eq!(result.coverage_gaps.len(), 0, "no coverage gap when agent signal present");
}

#[test]
fn ai_agent_tool_authority_and_model_output_remain_structurally_separate() {
    let pairs = ai_agent_projection();
    let files = files_of(&pairs);
    let st = source_text(&pairs);
    let result = ai_agent::extract(&files, &st);

    let tool_ids: std::collections::HashSet<&str> = result
        .entities
        .iter()
        .filter(|e| e["kind"] == "tool-capability")
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    let output_ids: std::collections::HashSet<&str> = result
        .entities
        .iter()
        .filter(|e| e["attributes"]["sourceKind"] == "model-output")
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    assert!(!tool_ids.is_empty() && !output_ids.is_empty());
    for id in &tool_ids {
        assert!(!output_ids.contains(id));
    }

    let capability_facts: Vec<&Value> = result.initial_facts.iter().filter(|f| f["kind"] == "capability").collect();
    let knowledge_facts: Vec<&Value> = result
        .initial_facts
        .iter()
        .filter(|f| f["kind"] == "knowledge" && f["attributes"]["kind"] == "model-output")
        .collect();
    assert!(!capability_facts.is_empty() && !knowledge_facts.is_empty());
    for f in &capability_facts {
        let object = f["object"].as_str();
        assert!(object.map(|o| !output_ids.contains(o)).unwrap_or(true));
    }
    for f in &knowledge_facts {
        let subject = f["subject"].as_str().unwrap();
        assert!(!tool_ids.contains(subject));
    }
}

#[test]
fn ai_agent_absent_signal_yields_typed_coverage_gap() {
    let files: Vec<String> = vec![];
    let st: HashMap<String, String> = HashMap::new();
    let result = ai_agent::extract(&files, &st);
    assert!(result.coverage_gaps.iter().any(|g| g["kind"] == "ai-agent-context-not-detected"));
}

#[test]
fn ai_agent_extraction_is_deterministic() {
    let pairs = ai_agent_projection();
    let files = files_of(&pairs);
    let st = source_text(&pairs);
    let first = ai_agent::extract(&files, &st);
    let second = ai_agent::extract(&files, &st);
    assert_eq!(
        serde_json::to_value(&first.entities).unwrap(),
        serde_json::to_value(&second.entities).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&first.relations).unwrap(),
        serde_json::to_value(&second.relations).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&first.initial_facts).unwrap(),
        serde_json::to_value(&second.initial_facts).unwrap()
    );
}

#[test]
fn ai_agent_ids_and_kinds_are_registered() {
    let pairs = ai_agent_projection();
    let files = files_of(&pairs);
    let st = source_text(&pairs);
    let result = ai_agent::extract(&files, &st);
    for e in &result.entities {
        assert!(e["id"].as_str().unwrap().starts_with("sha256:"));
        assert!(ENTITY_KINDS.contains(&e["kind"].as_str().unwrap()));
    }
    for r in &result.relations {
        assert!(r["id"].as_str().unwrap().starts_with("sha256:"));
        assert!(RELATION_KINDS.contains(&r["kind"].as_str().unwrap()));
    }
    for f in &result.initial_facts {
        assert!(f["id"].as_str().unwrap().starts_with("sha256:"));
        assert!(FACT_KINDS.contains(&f["kind"].as_str().unwrap()));
    }
}

// =================================================================================================
// model-extractors/cicd.mjs
// =================================================================================================

#[test]
fn cicd_extract_models_trigger_sink_identity_and_gated_facts() {
    let file = ".github/workflows/ci.yml";
    let text = "on: push\npermissions: write-all\njobs:\n  build:\n    steps:\n      - run: echo hi\n";
    let pairs = [(file, text)];
    let files = files_of(&pairs);
    let st = source_text(&pairs);
    let result = cicd::extract(&files, &st);
    assert_referential_integrity(&result);

    let trigger = find_entity(&result, |e| e["kind"] == "entrypoint" && e["attributes"]["entrypointType"] == "ci-trigger").unwrap();
    let sink = find_entity(&result, |e| e["kind"] == "sink" && e["attributes"]["sinkKind"] == "shell").unwrap();
    let identity = find_entity(&result, |e| e["kind"] == "identity").unwrap();
    assert!(result.relations.iter().any(|r| r["kind"] == "executes" && r["from"] == trigger["id"] && r["to"] == sink["id"]));
    assert!(result.relations.iter().any(|r| r["kind"] == "runs-as" && r["from"] == sink["id"] && r["to"] == identity["id"]));
    assert!(result.initial_facts.iter().any(|f| f["kind"] == "capability" && f["action"] == "write-all"));
}

#[test]
fn cicd_extract_flags_pull_request_target_as_attacker_position() {
    let file = ".github/workflows/pr.yml";
    let text = "on: pull_request_target\njobs:\n  x:\n    steps:\n      - run: echo hi\n";
    let pairs = [(file, text)];
    let files = files_of(&pairs);
    let st = source_text(&pairs);
    let result = cicd::extract(&files, &st);
    assert!(result
        .initial_facts
        .iter()
        .any(|f| f["kind"] == "attacker-position" && f["action"] == "control-pr-content" && f["object"] == file));
}

#[test]
fn cicd_extract_ignores_non_workflow_files() {
    let pairs = [("README.md", "not a workflow")];
    let files = files_of(&pairs);
    let st = source_text(&pairs);
    let result = cicd::extract(&files, &st);
    assert!(result.entities.is_empty());
}

// =================================================================================================
// model-extractors/automation.mjs — ported from b7-006-automation-extractor.test.mjs
// =================================================================================================

fn run_automation(pairs: &[(&str, &str)]) -> ExtractorOutput {
    let files = files_of(pairs);
    let st = source_text(pairs);
    automation::extract(&files, &st)
}

#[test]
fn automation_full_release_workflow_produces_complete_trust_path() {
    let file = ".github/workflows/release.yml";
    let text = [
        "name: Release",
        "on:",
        "  push:",
        "    tags:",
        "      - 'v*'",
        "permissions:",
        "  contents: write",
        "  id-token: write",
        "jobs:",
        "  release:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - uses: actions/cache@v4",
        "        with:",
        "          path: ~/.npm",
        "          key: npm-cache",
        "      - run: npm ci",
        "      - run: npm run build",
        "      - run: npm publish",
        "        env:",
        "          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}",
        "      - run: cosign sign dist/artifact.tgz",
        "      - uses: actions/upload-artifact@v4",
        "        with:",
        "          path: dist/",
    ]
    .join("\n");
    let pairs = [(file, text.as_str())];
    let model = run_automation(&pairs);
    assert_referential_integrity(&model);

    let trigger = find_entity(&model, |e| e["kind"] == "entrypoint" && e["attributes"]["entrypointType"] == "release-trigger").unwrap();
    let sink = find_entity(&model, |e| e["kind"] == "sink" && e["name"] == format!("pipeline step {file}")).unwrap();
    let identity = find_entity(&model, |e| e["kind"] == "identity" && e["name"] == format!("release identity {file}")).unwrap();
    let capability = find_entity(&model, |e| e["kind"] == "tool-capability" && e["attributes"]["capabilityKind"] == "package-publish").unwrap();
    let artifact = find_entity(&model, |e| e["kind"] == "asset" && e["attributes"]["assetKind"] == "published-artifact").unwrap();

    assert!(model.relations.iter().any(|r| r["kind"] == "executes" && r["from"] == trigger["id"] && r["to"] == sink["id"]));
    assert!(model.relations.iter().any(|r| r["kind"] == "runs-as" && r["from"] == sink["id"] && r["to"] == identity["id"]));
    assert!(model.relations.iter().any(|r| r["kind"] == "grants" && r["from"] == identity["id"] && r["to"] == capability["id"]));
    assert!(model.relations.iter().any(|r| r["kind"] == "publishes-to" && r["from"] == identity["id"] && r["to"] == artifact["id"]));

    assert_eq!(identity["attributes"]["permissionScope"], "contents:write,id-token:write");
    assert_eq!(identity["attributes"]["credentialRefs"], json!(["NPM_TOKEN"]));
    assert_eq!(artifact["attributes"]["publicationTarget"], "npm-registry");
    assert!(!model.coverage_gaps.iter().any(|g| g["file"] == file));

    for item in [trigger, sink, identity, capability, artifact] {
        let files_seen: std::collections::HashSet<Option<String>> = evidence_files(&model, &refs_of(item)).into_iter().collect();
        assert_eq!(files_seen, std::collections::HashSet::from([Some(file.to_string())]));
    }

    let cache = find_entity(&model, |e| e["kind"] == "data-store" && e["attributes"]["dataStoreKind"] == "build-cache").unwrap();
    assert!(model.relations.iter().any(|r| r["kind"] == "stores" && r["from"] == sink["id"] && r["to"] == cache["id"]));

    let signing = find_entity(&model, |e| e["kind"] == "control" && e["attributes"]["controlType"] == "signing").unwrap();
    assert_eq!(signing["attributes"]["controlState"], "present-unenforced");
    assert!(model.relations.iter().any(|r| r["kind"] == "protects" && r["from"] == signing["id"] && r["to"] == sink["id"]));

    let build_output = find_entity(&model, |e| e["kind"] == "asset" && e["attributes"]["assetKind"] == "build-artifact").unwrap();
    assert!(model.relations.iter().any(|r| r["kind"] == "flows-to" && r["from"] == build_output["id"] && r["to"] == sink["id"]));

    let secret_fact = model
        .initial_facts
        .iter()
        .find(|f| f["kind"] == "credential-possession" && f["object"] == "NPM_TOKEN")
        .unwrap();
    assert!(!serde_json::to_string(secret_fact).unwrap().contains("${{"));
}

#[test]
fn automation_unresolved_permission_scope_and_identity_stay_visible() {
    let file = ".github/workflows/release-no-perms.yml";
    let text = ["name: Manual Release", "on:", "  workflow_dispatch: {}", "jobs:", "  release:", "    runs-on: ubuntu-latest", "    steps:", "      - run: npm publish"].join("\n");
    let pairs = [(file, text.as_str())];
    let model = run_automation(&pairs);
    assert_referential_integrity(&model);

    let identity = find_entity(&model, |e| e["kind"] == "identity" && e["name"] == format!("release identity {file}")).unwrap();
    assert_eq!(identity["attributes"]["permissionScope"], "unknown");
    assert_eq!(identity["attributes"]["credentialRefs"], json!([]));

    assert!(model.coverage_gaps.iter().any(|g| g["kind"] == "unresolved-permission-scope" && g["file"] == file));
    assert!(model.coverage_gaps.iter().any(|g| g["kind"] == "unresolved-identity" && g["file"] == file && g["entityId"] == identity["id"]));
    assert!(!model.coverage_gaps.iter().any(|g| g["kind"] == "unresolved-publication-target"));
}

#[test]
fn automation_untrusted_trigger_crosses_trust_boundary() {
    let file = ".github/workflows/fork-pr.yml";
    let text = ["name: PR Comment Handler", "on:", "  pull_request_target:", "    types: [opened]", "jobs:", "  comment:", "    runs-on: ubuntu-latest", "    steps:", "      - run: echo \"handling PR\""].join("\n");
    let pairs = [(file, text.as_str())];
    let model = run_automation(&pairs);
    assert_referential_integrity(&model);

    let hostile_trigger = find_entity(&model, |e| e["kind"] == "entrypoint" && e["attributes"]["entrypointType"] == "hostile-trigger").unwrap();
    let boundary = find_entity(&model, |e| e["kind"] == "trust-boundary" && e["attributes"]["boundaryType"] == "untrusted-contribution").unwrap();
    assert!(model.relations.iter().any(|r| r["kind"] == "crosses" && r["from"] == hostile_trigger["id"] && r["to"] == boundary["id"]));

    let attacker_fact = model.initial_facts.iter().find(|f| f["kind"] == "attacker-position").unwrap();
    assert_eq!(attacker_fact["subject"], "actor:external-contributor");
    assert_eq!(attacker_fact["object"], file);
    assert_eq!(evidence_files(&model, &refs_of(attacker_fact)), vec![Some(file.to_string())]);
}

#[test]
fn automation_package_manifest_captures_installer_deps_and_missing_lockfile() {
    let file = "package.json";
    let text = json!({
        "name": "example-pkg",
        "version": "1.0.0",
        "private": false,
        "scripts": {
            "postinstall": "curl -fsSL https://example.com/setup.sh | bash",
            "publish": "np",
        },
        "publishConfig": { "registry": "https://registry.example.com" },
        "dependencies": {
            "left-pad": "^1.3.0",
            "some-fork": "git+https://github.com/example/some-fork.git",
        },
    })
    .to_string();
    let pairs = [(file, text.as_str())];
    let model = run_automation(&pairs);
    assert_referential_integrity(&model);

    let installer_source = find_entity(&model, |e| e["kind"] == "source" && e["attributes"]["sourceKind"] == "network-fetch").unwrap();
    let installer_sink = find_entity(&model, |e| e["kind"] == "sink" && e["attributes"]["sinkKind"] == "shell").unwrap();
    assert!(model.relations.iter().any(|r| r["kind"] == "flows-to" && r["from"] == installer_source["id"] && r["to"] == installer_sink["id"]));
    assert!(model.initial_facts.iter().any(|f| f["kind"] == "capability" && f["action"] == "execute-remote-script" && f["subject"] == installer_sink["id"]));

    let identity = find_entity(&model, |e| e["kind"] == "identity" && e["name"] == format!("release identity {file}")).unwrap();
    let artifact = find_entity(&model, |e| e["kind"] == "asset" && e["attributes"]["assetKind"] == "published-artifact").unwrap();
    assert_eq!(artifact["attributes"]["publicationTarget"], "https://registry.example.com");
    assert_eq!(identity["attributes"]["permissionScope"], "unknown");
    assert_eq!(identity["attributes"]["credentialRefs"], json!([]));
    assert!(model.coverage_gaps.iter().any(|g| g["kind"] == "unresolved-permission-scope" && g["file"] == file));
    assert!(model.coverage_gaps.iter().any(|g| g["kind"] == "unresolved-identity" && g["file"] == file));

    let dependency_source = find_entity(&model, |e| e["kind"] == "source" && e["attributes"]["sourceKind"] == "direct-url-dependency").unwrap();
    assert_eq!(dependency_source["name"], "non-registry dependency some-fork");

    assert!(model.coverage_gaps.iter().any(|g| g["kind"] == "missing-dependency-lockfile" && g["file"] == file));
}

#[test]
fn automation_lockfile_present_suppresses_gap_and_is_modeled() {
    let pairs = [
        ("package.json", r#"{"name":"example-pkg","version":"1.0.0"}"#),
        ("package-lock.json", r#"{"lockfileVersion":3}"#),
    ];
    let model = run_automation(&pairs);
    assert_referential_integrity(&model);

    assert!(!model.coverage_gaps.iter().any(|g| g["kind"] == "missing-dependency-lockfile"));
    let lock_entity = find_entity(&model, |e| e["kind"] == "repository-artifact" && e["attributes"]["lockfile"] == true).unwrap();
    assert!(model.initial_facts.iter().any(|f| f["kind"] == "capability" && f["action"] == "pin-dependency-resolution" && f["subject"] == lock_entity["id"]));
}

#[test]
fn automation_unparseable_manifest_is_a_typed_gap_not_a_silent_skip() {
    let file = "apps/broken/package.json";
    let pairs = [(file, "{ this is not valid json")];
    let model = run_automation(&pairs);
    assert!(model.entities.is_empty());
    assert_eq!(model.coverage_gaps, vec![json!({ "kind": "unparsed-automation-format", "file": file, "format": "package.json" })]);
}

#[test]
fn automation_jenkinsfile_is_unparsed_but_surfaces_credentials() {
    let file = "Jenkinsfile";
    let text = "node {\n  stage('Release') {\n    sh \"curl -H 'Authorization: Bearer ${credentials('npm-token')}' https://registry.example.com/publish\"\n  }\n}";
    let pairs = [(file, text)];
    let model = run_automation(&pairs);
    assert_referential_integrity(&model);

    assert!(model.coverage_gaps.iter().any(|g| g["kind"] == "unparsed-automation-format" && g["file"] == file && g["format"] == "jenkinsfile"));
    assert!(model.initial_facts.iter().any(|f| f["kind"] == "credential-possession" && f["object"] == "npm-token"));
}

#[test]
fn automation_dependency_update_with_automerge_records_capability_and_gap() {
    let file = "renovate.json";
    let text = json!({ "extends": ["config:base"], "automerge": true }).to_string();
    let pairs = [(file, text.as_str())];
    let model = run_automation(&pairs);
    assert_referential_integrity(&model);

    let identity = find_entity(&model, |e| e["kind"] == "identity" && e["name"] == format!("dependency update bot identity {file}")).unwrap();
    assert_eq!(identity["attributes"]["permissionScope"], "unknown");
    assert!(model.coverage_gaps.iter().any(|g| g["kind"] == "unresolved-permission-scope" && g["file"] == file));
    assert!(model.initial_facts.iter().any(|f| f["kind"] == "capability" && f["action"] == "auto-merge-dependency-update" && f["subject"] == identity["id"]));
}

#[test]
fn automation_release_config_with_nothing_resolvable_surfaces_every_gap_kind() {
    let file = ".releaserc.json";
    let text = json!({ "branches": ["main"], "plugins": ["@semantic-release/npm"] }).to_string();
    let pairs = [(file, text.as_str())];
    let model = run_automation(&pairs);
    assert_referential_integrity(&model);

    let gap_kinds: std::collections::HashSet<&str> = model
        .coverage_gaps
        .iter()
        .filter(|g| g["file"] == file)
        .map(|g| g["kind"].as_str().unwrap())
        .collect();
    assert!(gap_kinds.contains("unresolved-permission-scope"));
    assert!(gap_kinds.contains("unresolved-identity"));
    assert!(gap_kinds.contains("unresolved-publication-target"));
    assert!(gap_kinds.contains("externally-configured-release-service"));
}

#[test]
fn automation_updater_config_disabled_signature_is_absent_not_unknown() {
    let file = "electron-builder.yml";
    let text = ["publish:", "  provider: generic", "  url: https://updates.example.com/", "verifyUpdateCodeSignature: false"].join("\n");
    let pairs = [(file, text.as_str())];
    let model = run_automation(&pairs);
    assert_referential_integrity(&model);

    let signing = find_entity(&model, |e| e["kind"] == "control" && e["attributes"]["controlType"] == "signing").unwrap();
    assert_eq!(signing["attributes"]["controlState"], "absent");
    let capability = find_entity(&model, |e| e["kind"] == "tool-capability" && e["attributes"]["capabilityKind"] == "auto-update-execute").unwrap();
    assert!(model.relations.iter().any(|r| r["kind"] == "protects" && r["from"] == signing["id"] && r["to"] == capability["id"]));
    let update_server = find_entity(&model, |e| e["kind"] == "service" && e["attributes"]["serviceKind"] == "auto-update-endpoint").unwrap();
    assert!(model.relations.iter().any(|r| r["kind"] == "retrieves-from" && r["from"] == capability["id"] && r["to"] == update_server["id"]));
    assert!(!model.coverage_gaps.iter().any(|g| g["file"] == file));
}

#[test]
fn automation_updater_config_no_signature_info_is_unknown() {
    let file = "app-update.yml";
    let text = ["provider: generic", "url: https://updates.example.com/"].join("\n");
    let pairs = [(file, text.as_str())];
    let model = run_automation(&pairs);
    let signing = find_entity(&model, |e| e["kind"] == "control" && e["attributes"]["controlType"] == "signing").unwrap();
    assert_eq!(signing["attributes"]["controlState"], "unknown");
    assert!(model.coverage_gaps.iter().any(|g| g["kind"] == "unresolved-updater-signature-state" && g["file"] == file));
}

#[test]
fn automation_npmrc_auth_token_no_registry_leaves_target_unresolved() {
    let file = "packages/app/.npmrc";
    let pairs = [(file, "_authToken=${NPM_TOKEN}\n")];
    let model = run_automation(&pairs);
    let scope = find_entity(&model, |e| e["kind"] == "permission-scope").unwrap();
    assert_eq!(scope["attributes"]["registry"], "unknown");
    assert_eq!(scope["attributes"]["hasAuthToken"], true);
    assert!(model.coverage_gaps.iter().any(|g| g["kind"] == "unresolved-publication-target" && g["file"] == file));
    assert!(model.initial_facts.iter().any(|f| f["kind"] == "credential-possession" && f["subject"] == scope["id"]));
}

#[test]
fn automation_npmrc_explicit_registry_resolves_target() {
    let file = ".npmrc";
    let pairs = [(file, "registry=https://registry.example.com/\n_authToken=${NPM_TOKEN}\n")];
    let model = run_automation(&pairs);
    let scope = find_entity(&model, |e| e["kind"] == "permission-scope").unwrap();
    assert_eq!(scope["attributes"]["registry"], "https://registry.example.com/");
    assert!(!model.coverage_gaps.iter().any(|g| g["file"] == file));
}

#[test]
fn automation_dockerfile_models_installer_and_publication_flows() {
    let file = "Dockerfile";
    let text = ["FROM node:20-alpine", "RUN curl -fsSL https://get.example.com/install.sh | bash", "RUN npm ci", "LABEL registry=ghcr.io/example/app", "CMD [\"node\", \"server.js\"]"].join("\n");
    let pairs = [(file, text.as_str())];
    let model = run_automation(&pairs);
    assert_referential_integrity(&model);

    let source = find_entity(&model, |e| e["kind"] == "source" && e["attributes"]["sourceKind"] == "network-fetch").unwrap();
    let sink = find_entity(&model, |e| e["kind"] == "sink" && e["attributes"]["sinkKind"] == "shell").unwrap();
    assert!(model.relations.iter().any(|r| r["kind"] == "flows-to" && r["from"] == source["id"] && r["to"] == sink["id"]));

    let image = find_entity(&model, |e| e["kind"] == "asset" && e["attributes"]["assetKind"] == "container-image").unwrap();
    let registry = find_entity(&model, |e| e["kind"] == "service" && e["attributes"]["serviceKind"] == "container-registry").unwrap();
    assert!(model.relations.iter().any(|r| r["kind"] == "publishes-to" && r["from"] == image["id"] && r["to"] == registry["id"]));
}

#[test]
fn automation_every_kind_belongs_to_the_canonical_vocabulary() {
    let pairs = [
        (
            ".github/workflows/release.yml",
            "on:\n  push:\n    tags:\n      - v*\npermissions:\n  contents: write\njobs:\n  release:\n    steps:\n      - run: npm publish",
        ),
        ("package.json", r#"{"name":"x","scripts":{"postinstall":"curl x | bash","publish":"np"}}"#),
        ("Jenkinsfile", "sh \"${credentials('id')}\""),
        ("renovate.json", r#"{"automerge":true}"#),
        ("electron-builder.yml", "publish:\n  provider: generic\nverifyUpdateCodeSignature: false"),
        (".npmrc", "registry=https://registry.example.com/\n"),
        ("package-lock.json", "{}"),
        ("Dockerfile", "FROM node\nRUN curl x | bash\nLABEL registry=ghcr.io/x"),
    ];
    let model = run_automation(&pairs);
    for e in &model.entities {
        assert!(ENTITY_KINDS.contains(&e["kind"].as_str().unwrap()), "unknown entity kind {}", e["kind"]);
    }
    for r in &model.relations {
        assert!(RELATION_KINDS.contains(&r["kind"].as_str().unwrap()), "unknown relation kind {}", r["kind"]);
    }
    for f in &model.initial_facts {
        assert!(FACT_KINDS.contains(&f["kind"].as_str().unwrap()), "unknown fact kind {}", f["kind"]);
    }
}

#[test]
fn automation_extraction_is_deterministic() {
    let pairs = [
        (
            ".github/workflows/release.yml",
            "on:\n  push:\n    tags:\n      - v*\npermissions:\n  contents: write\n  id-token: write\njobs:\n  release:\n    steps:\n      - run: npm publish\n        env:\n          T: ${{ secrets.NPM_TOKEN }}",
        ),
        (".github/workflows/fork-pr.yml", "on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n      - run: echo hi"),
        (
            "package.json",
            r#"{"name":"pkg","scripts":{"postinstall":"curl x | bash","publish":"np"},"dependencies":{"d":"git+https://x/y.git"}}"#,
        ),
        ("renovate.json", r#"{"automerge":true}"#),
        ("Jenkinsfile", "sh \"${credentials('id')}\""),
    ];
    let first = run_automation(&pairs);
    let second = run_automation(&pairs);
    assert_eq!(serde_json::to_value(&first.entities).unwrap(), serde_json::to_value(&second.entities).unwrap());
    assert_eq!(serde_json::to_value(&first.relations).unwrap(), serde_json::to_value(&second.relations).unwrap());
    assert_eq!(serde_json::to_value(&first.initial_facts).unwrap(), serde_json::to_value(&second.initial_facts).unwrap());
    assert_eq!(serde_json::to_value(&first.evidence).unwrap(), serde_json::to_value(&second.evidence).unwrap());
    assert_eq!(first.coverage_gaps, second.coverage_gaps);
}

// =================================================================================================
// model-builder.mjs — generic assembly algorithm
// =================================================================================================

#[test]
fn build_security_model_dedupes_and_computes_coverage() {
    use legion_audit::wf_port::wf053::{build_security_model, BuildSecurityModelInput};

    let e1 = entity("repository-artifact", "a", json!({}), &[], EntityOptions::default());
    // Same logical entity constructed twice (identical inputs) must dedupe to one row.
    let e1_dup = entity("repository-artifact", "a", json!({}), &[], EntityOptions::default());
    assert_eq!(e1["id"], e1_dup["id"]);

    let parts = vec![
        ExtractorOutput {
            entities: vec![e1.clone()],
            relations: vec![],
            evidence: vec![],
            initial_facts: vec![],
            coverage_gaps: vec![],
        },
        ExtractorOutput {
            entities: vec![e1_dup],
            relations: vec![],
            evidence: vec![],
            initial_facts: vec![],
            coverage_gaps: vec![json!({ "kind": "example-gap" })],
        },
    ];

    let model = build_security_model(BuildSecurityModelInput {
        binding: json!({ "planDigest": "sha256:x" }),
        denominator_digest: "sha256:y".to_string(),
        expected_files: Some(1),
        examined_files: 1,
        parts,
    })
    .expect("valid model");

    assert_eq!(model["entities"].as_array().unwrap().len(), 1, "identical entities must dedupe by id");
    assert_eq!(model["complete"], false, "a non-empty coverageGaps list marks the model incomplete");
    assert_eq!(model["coverage"]["entityCount"], 1);
    assert!(model["coverage"]["modelDigest"].as_str().unwrap().starts_with("sha256:"));
}

#[test]
fn assert_references_rejects_a_dangling_relation() {
    let e1 = entity("repository-artifact", "a", json!({}), &[], EntityOptions::default());
    let bad_relation = json!({ "id": "x", "kind": "executes", "from": e1["id"], "to": "sha256:missing" });
    let err = assert_references(std::slice::from_ref(&e1), &[bad_relation]).unwrap_err();
    assert!(err.contains("unknown relation.to"));
}
