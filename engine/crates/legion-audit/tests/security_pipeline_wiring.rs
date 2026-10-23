//! End-to-end wiring of the attack-path providers: fixture repo -> surface
//! model -> typed candidates -> synthesis hypothesis -> chain adjudication.
//! Missing or unbound inputs must surface as explicit gaps, and chain
//! adjudication without independent verdicts must stay unproven.
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_audit::{
    native_providers::security::pipeline, topological_with_artifacts, AuditProvider,
    InventoryEntry, InventoryEnvelope, NativeProviderRegistry, ProviderExecutor, ProviderKind,
};
use legion_contracts::{ProviderResult, ProviderSpec, ProviderStatus};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

const MODEL: &str = "security.surface-model";
const SYNTHESIS: &str = "security.attack-path-synthesis";
const CHAIN: &str = "security.chain-adjudication";

fn spec(id: &str) -> ProviderSpec {
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    ))
    .unwrap();
    let registry: Value = serde_json::from_str(&raw).unwrap();
    let item = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == id)
        .unwrap_or_else(|| panic!("{id} is not registered"));
    serde_json::from_value(item.clone()).unwrap()
}

fn provider(id: &str) -> AuditProvider {
    provider_from(&spec(id))
}

fn provider_from(spec: &ProviderSpec) -> AuditProvider {
    AuditProvider {
        id: spec.id.to_string(),
        version: spec.provider_version.clone(),
        role: spec.role.clone(),
        phase: spec.phase.clone(),
        lens_ids: spec.lens_ids.clone(),
        dependencies: spec.depends_on.iter().map(ToString::to_string).collect(),
        kind: ProviderKind::RustAlgorithm,
        configuration: BTreeMap::from([(String::from("selector"), spec.selector.clone())]),
        bounds: BTreeMap::new(),
        clean_claim: spec.clean_claim.clone(),
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: spec.selectable,
    }
}

const SERVER_JS: &str = "const express = require('express');\nconst app = express();\napp.get('/export', (req, res) => res.send('ok'));\n";
const ENV_FILE: &str = "API_KEY=placeholder\n";

fn fixture() -> (PathBuf, InventoryEnvelope) {
    fixture_with(&[
        ("src/server.js", SERVER_JS, true),
        (".env", ENV_FILE, false),
    ])
}

fn fixture_with(files: &[(&str, &str, bool)]) -> (PathBuf, InventoryEnvelope) {
    let root = std::env::temp_dir().join(format!(
        "legion-security-pipeline-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    let mut entries = Vec::new();
    for (path, body, source_file) in files.iter().copied() {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, body).unwrap();
        entries.push(InventoryEntry {
            path: path.into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file,
            digest: Some(format!("sha256:{}", hex::encode(Sha256::digest(body)))),
        });
    }
    let inventory = InventoryEnvelope::new("pipeline-fixture", "rev-1", entries).unwrap();
    (root, inventory)
}

/// Typed candidate v2 pair: an entrypoint-sourced credential read that a
/// crown-jewel principal use consumes through the registered bridge.
fn candidates() -> Value {
    json!({
        "candidates": [
            {
                "id": "cand-1",
                "ruleId": "fixture.credential-read",
                "sources": ["src/server.js"],
                "chainRoles": ["starter"],
                "preconditions": [{"kind": "attacker-position", "action": "reach-entrypoint"}],
                "effects": ["data-access:read:credential-material"],
            },
            {
                "id": "cand-2",
                "ruleId": "fixture.credential-use",
                "assets": [".env"],
                "chainRoles": ["privilege-escalation"],
                "preconditions": ["credential-possession:possess"],
                "effects": [{"kind": "principal-access", "action": "authenticate", "scope": "control-plane"}],
            }
        ]
    })
}

fn registry_with(root: &PathBuf, artifacts: &[(&str, Value)]) -> NativeProviderRegistry {
    let mut registry = NativeProviderRegistry::new(root);
    for (key, value) in artifacts {
        registry
            .security
            .artifacts
            .insert((*key).to_string(), value.clone());
    }
    registry
}

fn gap_codes(doc: &Value) -> Vec<String> {
    doc["coverageGaps"]
        .as_array()
        .map(|gaps| {
            gaps.iter()
                .filter_map(|g| g["code"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn run(
    registry: &NativeProviderRegistry,
    id: &str,
    inventory: &InventoryEnvelope,
) -> ProviderResult {
    registry
        .execute(&provider(id), inventory)
        .unwrap_or_else(|error| panic!("{id}: {error}"))
}

#[test]
fn registered_providers_form_an_acceptable_dag() {
    let ids = [MODEL, SYNTHESIS, CHAIN];
    let specs: Vec<ProviderSpec> = ids.iter().map(|id| spec(id)).collect();
    for spec in &specs {
        assert_eq!(spec.benchmark["status"], "unproven");
        assert_eq!(spec.clean_claim, "evidence-only");
        assert_eq!(spec.runner["kind"], "runtime-script");
        assert_eq!(spec.reasoning["producerSeparation"], true);
        assert_eq!(spec.reasoning["freshContext"], true);
    }
    // The security family compiles to an acyclic artifact DAG in which the
    // pipeline runs surface-model -> synthesis -> chain adjudication.
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    ))
    .unwrap();
    let registry: Value = serde_json::from_str(&raw).unwrap();
    let providers: Vec<AuditProvider> = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["family"] == "security")
        .map(|item| {
            let spec: ProviderSpec = serde_json::from_value(item.clone()).unwrap();
            let mut audit = provider_from(&spec);
            audit
                .configuration
                .insert("consumes".into(), json!(spec.consumes));
            audit
                .configuration
                .insert("produces".into(), json!(spec.produces));
            audit
        })
        .collect();
    let order = topological_with_artifacts(&providers).expect("artifact DAG accepts the pipeline");
    let position = |id: &str| order.iter().position(|p| p == id).unwrap();
    assert!(position(MODEL) < position(SYNTHESIS));
    assert!(position(SYNTHESIS) < position(CHAIN));
    assert!(position("security.opengrep") < position(SYNTHESIS));
}

#[test]
fn fixture_repo_flows_model_to_candidates_to_hypothesis() {
    let (root, inventory) = fixture();
    let registry = registry_with(&root, &[("security-candidates", candidates())]);

    let model_result = run(&registry, MODEL, &inventory);
    assert!(model_result.applicable);
    let model = &model_result.details["security-model"];
    assert_eq!(model["kind"], "legion-security-model");
    let kinds: Vec<&str> = model["entities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entity| entity["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"entrypoint"), "{kinds:?}");
    assert!(kinds.contains(&"crown-jewel"), "{kinds:?}");

    let result = run(&registry, SYNTHESIS, &inventory);
    let doc = &result.details["attackPaths"];
    let hypotheses = doc["hypotheses"].as_array().unwrap();
    assert_eq!(hypotheses.len(), 1, "{doc:#}");
    let h = &hypotheses[0];
    assert_eq!(h["status"], "hypothesis");
    assert_eq!(h["memberCandidateIds"], json!(["cand-1", "cand-2"]));
    assert_eq!(h["start"]["entrypoint"], "src/server.js");
    assert_eq!(h["joins"].as_array().unwrap().len(), 1);
    assert_eq!(h["provider"], SYNTHESIS);
    assert_eq!(h["binding"]["digest"], json!(inventory.digest));
    assert!(h["synthesisContextId"]
        .as_str()
        .unwrap()
        .starts_with("ctx:"));
    assert_eq!(doc["authority"]["establishesPaths"], false);
    assert!(result.findings.is_empty());
    assert!(!doc.to_string().contains("\"PROVEN\""));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_model_is_an_unproven_gap_not_zero_paths() {
    let (root, inventory) = fixture();
    // No root: the model cannot be derived and none was injected.
    let result = pipeline::execute(
        None,
        &BTreeMap::from([("security-candidates".to_string(), candidates())]),
        &provider(SYNTHESIS),
        &inventory,
    )
    .unwrap();
    let doc = &result.details["attackPaths"];
    assert_eq!(doc["coverage"], "UNPROVEN");
    assert!(gap_codes(doc).contains(&"security-model-missing".to_string()));
    assert!(doc["hypotheses"].as_array().unwrap().is_empty());
    assert!(!result.complete);
    assert_ne!(result.status, ProviderStatus::Complete);
    assert_eq!(result.coverage.as_ref().unwrap().examined, 0);

    // An injected model bound to another revision is discarded, not trusted.
    let registry = registry_with(
        &root,
        &[
            ("security-candidates", candidates()),
            (
                "security-model",
                json!({
                    "kind": "legion-security-model",
                    "binding": {"repositoryRevision": "other", "inventoryDigest": "sha256:0"},
                    "entities": [], "relations": [], "evidence": [], "gaps": [],
                    "coverage": {"complete": true}
                }),
            ),
        ],
    );
    let result = registry.execute(&provider(SYNTHESIS), &inventory).unwrap();
    let doc = &result.details["attackPaths"];
    assert!(gap_codes(doc).contains(&"security-model-binding-mismatch".to_string()));
    assert!(!result.complete);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn untyped_detector_candidates_never_read_as_no_paths() {
    let (root, inventory) = fixture();
    // Pack-derived candidates carry no typed effects: nothing can compose.
    let registry = registry_with(&root, &[]);
    let result = run(&registry, SYNTHESIS, &inventory);
    let doc = &result.details["attackPaths"];
    assert!(doc["hypotheses"].as_array().unwrap().is_empty());
    assert!(
        !gap_codes(doc).is_empty(),
        "absence of hypotheses must be explained by a gap: {doc:#}"
    );
    assert!(!result.complete);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn chain_adjudication_without_verdicts_is_unproven() {
    let (root, inventory) = fixture();
    let registry = registry_with(&root, &[("security-candidates", candidates())]);
    let result = run(&registry, CHAIN, &inventory);
    let doc = &result.details["chainVerdicts"];
    assert_eq!(doc["status"], "UNPROVEN");
    assert_eq!(doc["authority"]["selfAdjudicates"], false);
    assert_eq!(doc["hypothesisCount"], 1);
    assert!(doc["verdicts"].as_array().unwrap().is_empty());
    assert_eq!(doc["pending"].as_array().unwrap().len(), 1);
    assert_eq!(doc["claims"]["chainsProven"], 0);
    assert!(gap_codes(doc).contains(&"chain-adjudication-pending".to_string()));
    assert!(!result.complete);
    assert_eq!(result.status, ProviderStatus::Partial);
    assert!(result.findings.is_empty());
    assert!(!doc.to_string().contains("\"PROVEN\""));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn self_adjudication_by_the_synthesizer_is_refused() {
    let (root, inventory) = fixture();
    let plain = registry_with(&root, &[("security-candidates", candidates())]);
    let synthesis = run(&plain, SYNTHESIS, &inventory);
    let h = synthesis.details["attackPaths"]["hypotheses"][0].clone();
    let path_id = h["id"].as_str().unwrap().to_owned();
    let context = h["synthesisContextId"].as_str().unwrap().to_owned();

    let registry = registry_with(
        &root,
        &[
            ("security-candidates", candidates()),
            (
                CHAIN,
                json!({
                    "adjudicator": {"provider": SYNTHESIS, "contextId": context},
                    "memberVerdicts": [],
                    "assessments": [{
                        "pathId": path_id,
                        "contextId": context,
                        "verdict": "PROVEN",
                        "rationale": "self-asserted",
                        "devilsAdvocate": "none",
                    }],
                }),
            ),
        ],
    );
    let result = run(&registry, CHAIN, &inventory);
    let doc = &result.details["chainVerdicts"];
    assert_eq!(doc["status"], "UNPROVEN");
    assert_eq!(doc["claims"]["chainsProven"], 0);
    let verdicts = doc["verdicts"].as_array().unwrap();
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0]["verdict"], "UNPROVEN");
    assert!(!result.complete);
    fs::remove_dir_all(root).unwrap();
}

const TRIAGE_WORKFLOW: &str = "name: triage
on: issues
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: |
            Triage this issue: ${{ github.event.issue.body }}
      - run: |
          bash -c \"${{ steps.claude.outputs.response }}\"
";

#[test]
fn real_pack_output_composes_into_a_hypothesis() {
    let (root, inventory) = fixture_with(&[
        (".github/workflows/triage.yml", TRIAGE_WORKFLOW, true),
        ("src/server.js", SERVER_JS, true),
    ]);
    // No injected candidates: the shipped heuristic packs are the generators.
    let registry = registry_with(&root, &[]);
    let result = run(&registry, SYNTHESIS, &inventory);
    let doc = &result.details["attackPaths"];
    let codes = gap_codes(doc);
    assert!(
        !codes.contains(&"no-starter-candidates".to_string()),
        "{doc:#}"
    );
    assert!(
        !codes.contains(&"no-composable-candidates".to_string()),
        "{doc:#}"
    );
    assert_ne!(doc["coverage"], "UNPROVEN", "{doc:#}");
    let hypotheses = doc["hypotheses"].as_array().unwrap();
    assert!(!hypotheses.is_empty(), "{doc:#}");
    for h in hypotheses {
        assert_eq!(h["status"], "hypothesis");
        assert_eq!(h["adjudicationState"], "PROPOSED");
    }
    // Untrusted issue text -> model influence -> agent-run execution.
    let has_chain = hypotheses.iter().any(|h| {
        h["edges"].as_array().is_some_and(|edges| {
            edges
                .iter()
                .any(|e| e["effect"] == "control-bypass:influence-model")
        })
    });
    assert!(has_chain, "{doc:#}");
    assert_eq!(doc["authority"]["establishesPaths"], false);
    assert_eq!(doc["claims"]["pathsProven"], 0);
    assert!(result.findings.is_empty());
    assert!(!doc.to_string().contains("\"PROVEN\""));
    // Still never complete or adjudicated by the deterministic pass.
    let chain = run(&registry, CHAIN, &inventory);
    assert_eq!(chain.details["chainVerdicts"]["status"], "UNPROVEN");
    assert_eq!(chain.details["chainVerdicts"]["claims"]["chainsProven"], 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn clean_repo_reports_no_composable_candidates_as_unproven() {
    let (root, inventory) = fixture();
    let registry = registry_with(&root, &[]);
    let result = run(&registry, SYNTHESIS, &inventory);
    let doc = &result.details["attackPaths"];
    assert_eq!(doc["coverage"], "UNPROVEN");
    let codes = gap_codes(doc);
    assert!(
        codes.contains(&"no-composable-candidates".to_string()),
        "{codes:?}"
    );
    assert!(doc["hypotheses"].as_array().unwrap().is_empty());
    assert!(!result.complete);
    assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn untyped_candidates_report_no_composable_candidates_not_no_starters() {
    let (root, inventory) = fixture();
    let registry = registry_with(
        &root,
        &[(
            "security-candidates",
            json!([{"id": "u-1", "ruleId": "fixture.untyped", "sources": ["src/server.js"], "effects": []}]),
        )],
    );
    let result = run(&registry, SYNTHESIS, &inventory);
    let doc = &result.details["attackPaths"];
    assert_eq!(doc["coverage"], "UNPROVEN");
    let codes = gap_codes(doc);
    assert!(
        codes.contains(&"no-composable-candidates".to_string()),
        "{codes:?}"
    );
    assert!(
        !codes.contains(&"no-starter-candidates".to_string()),
        "{codes:?}"
    );
    fs::remove_dir_all(root).unwrap();
}
