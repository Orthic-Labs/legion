//! G5 production wiring: helpers that used to have only test callers now feed
//! provider results and packets, and absence is an explicit gap. Authored by
//! the G5 worker; the lead compiles and runs.
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use legion_audit::{
    domain_contract::{self, DomainContractSet},
    native_providers::{
        reasoning::pattern_cards::bind_domain_contract_set,
        security::{dependency_osv, pipeline, SecurityProviderExecutor},
    },
    profiles::AuditProfile,
    runtime_obligations::RuntimeDeclarations,
    AuditProvider, InventoryEntry, InventoryEnvelope, ProviderExecution, ProviderKind,
};
use legion_contracts::{ProviderId, ProviderResult, ProviderStatus};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temp_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "legion-production-wiring-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn entry(path: &str, body: &str, source_file: bool) -> InventoryEntry {
    InventoryEntry {
        path: path.into(),
        symbols: Vec::new(),
        dependencies: Vec::new(),
        package_scripts: Vec::new(),
        source_file,
        digest: Some(format!("sha256:{}", hex::encode(Sha256::digest(body)))),
    }
}

fn materialize(files: &[(&str, &str, bool)]) -> (PathBuf, InventoryEnvelope) {
    let root = temp_root();
    let mut entries = Vec::new();
    for (path, body, source_file) in files {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(&full, body).unwrap();
        entries.push(entry(path, body, *source_file));
    }
    let inventory = InventoryEnvelope::new("wiring", "rev-1", entries).unwrap();
    (root, inventory)
}

// ----------------------------------------------------------- dependency inventory

#[test]
fn dependency_inventory_reaches_provider_analysis_with_unsupported_formats_as_gaps() {
    let cargo_lock = "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    let (root, inventory) = materialize(&[
        ("Cargo.lock", cargo_lock, false),
        ("uv.lock", "version = 1\n", false),
    ]);
    let artifact = dependency_osv::frozen_inventory_artifact(&root, &inventory, None);
    assert!(artifact["inventory"]["sourceDigest"].is_string());
    let analysis = dependency_osv::analyze(&json!({
        "projection": {"files": [{"path": "Cargo.lock"}, {"path": "uv.lock"}]},
        "artifacts": {dependency_osv::INVENTORY_ARTIFACT: artifact},
        "plan": {"binding": {}},
    }));
    let summary = &analysis["dependencyInventory"];
    assert_eq!(summary["state"], "present");
    assert_eq!(summary["claims"]["advisoryCurrent"], false);
    assert!(summary["graphDigest"].is_string());
    let kinds: Vec<&Value> = analysis["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["kind"] == "dependency-lock-unsupported")
        .collect();
    assert_eq!(kinds.len(), 1, "{analysis:#}");
    assert_eq!(kinds[0]["path"], "uv.lock");
    assert_eq!(analysis["complete"], false);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tampered_lock_bytes_are_a_digest_gap_not_silently_parsed() {
    let (root, inventory) = materialize(&[("Cargo.lock", "version = 3\n", false)]);
    fs::write(root.join("Cargo.lock"), "version = 3\n# drift\n").unwrap();
    let artifact = dependency_osv::frozen_inventory_artifact(&root, &inventory, None);
    let analysis = dependency_osv::analyze(&json!({
        "projection": {"files": [{"path": "Cargo.lock"}]},
        "artifacts": {dependency_osv::INVENTORY_ARTIFACT: artifact},
        "plan": {"binding": {}},
    }));
    assert!(analysis["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["kind"] == "dependency-lock-digest-mismatch"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn absent_inventory_is_recorded_not_invented() {
    let analysis = dependency_osv::analyze(&json!({
        "projection": {"files": []}, "artifacts": {}, "plan": {"binding": {}},
    }));
    assert_eq!(analysis["dependencyInventory"]["state"], "absent");
    assert_eq!(
        analysis["dependencyInventory"]["claims"]["advisoryCurrent"],
        false
    );
}

// ----------------------------------------------------------- domain contracts

fn bind(inventory: &InventoryEnvelope, root: &PathBuf) -> Value {
    let required = domain_contract::contracts_required(inventory);
    let inputs = domain_contract::contract_inputs_from_inventory(inventory, |path| {
        fs::read(root.join(path)).ok()
    });
    let set = (!inputs.is_empty() || required).then(|| {
        DomainContractSet::build(
            &inputs,
            &[domain_contract::inventory_snapshot(inventory)],
            required,
        )
    });
    let mut plan = json!({"lens": "correctness"});
    bind_domain_contract_set(&mut plan, set.as_ref());
    plan["domainContract"].clone()
}

#[test]
fn no_contract_files_bind_as_explicit_absent() {
    let (root, inventory) = materialize(&[("src/a.rs", "fn a() {}\n", true)]);
    assert_eq!(bind(&inventory, &root)["status"], "absent");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn required_but_missing_contracts_are_a_gap_never_clean() {
    let (root, inventory) =
        materialize(&[(".legion/domain-contracts/REQUIRED", "required\n", false)]);
    let bound = bind(&inventory, &root);
    assert_eq!(bound["status"], "gap", "{bound:#}");
    assert_eq!(bound["required"], true);
    assert_eq!(bound["executionAuthority"], false);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn declared_contract_that_cannot_be_read_is_a_digest_gap() {
    let (root, inventory) = materialize(&[(
        ".legion/domain-contracts/orders.json",
        "{\"schemaVersion\":1,\"terms\":[],\"mappings\":[]}",
        false,
    )]);
    fs::remove_file(root.join(".legion/domain-contracts/orders.json")).unwrap();
    let bound = bind(&inventory, &root);
    assert_eq!(bound["status"], "gap", "{bound:#}");
    assert!(bound["gaps"].to_string().contains("digest-mismatch"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn present_contract_file_binds_with_a_digest() {
    let (root, inventory) = materialize(&[(
        ".legion/domain-contracts/orders.json",
        "{\"schemaVersion\":1,\"terms\":[],\"mappings\":[]}",
        false,
    )]);
    let bound = bind(&inventory, &root);
    assert_eq!(bound["status"], "bound", "{bound:#}");
    assert!(bound["domainContractDigest"].is_string());
    fs::remove_dir_all(root).unwrap();
}

// ----------------------------------------------------------- runtime obligations

fn declarations(files: &[(&str, &str)]) -> RuntimeDeclarations {
    let (root, inventory) = materialize(
        &files
            .iter()
            .map(|(p, b)| (*p, *b, false))
            .collect::<Vec<_>>(),
    );
    let out =
        RuntimeDeclarations::from_inventory(&inventory, |path| fs::read(root.join(path)).ok());
    fs::remove_dir_all(root).unwrap();
    out
}

#[test]
fn undeclared_journeys_and_rust_matrix_are_explicit_per_stack_gaps() {
    let decl = declarations(&[
        (
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[features]\nfast = []\n",
        ),
        ("db/migrations/001.sql", "create table t(id int);\n"),
    ]);
    let gaps = decl.gaps();
    assert!(
        gaps.iter()
            .any(|g| g.starts_with("runtime-journey-gap:postgres:")),
        "{gaps:?}"
    );
    assert!(gaps.contains(&"runtime-rust-target-matrix-undeclared:rust-core".to_owned()));
    let postgres = decl.gaps_for_stack(legion_audit::runtime_obligations::Stack::Postgres);
    assert!(!postgres.is_empty());
    assert!(postgres.iter().all(|g| !g.starts_with("runtime-rust-")));
    let report = decl.provider_report();
    assert_eq!(report["claims"]["journeysDischarged"], false);
    let candidates = decl
        .obligation_candidates(&[AuditProfile::Repository])
        .unwrap();
    assert!(candidates
        .iter()
        .any(|c| c.concern.contains(":gap:postgres:")));
    assert!(candidates
        .iter()
        .any(|c| c.concern == "rust-target-matrix:undeclared"));
}

#[test]
fn malformed_journey_declaration_is_a_gap_not_absence() {
    let decl = declarations(&[(".legion/journeys.json", "{not json")]);
    assert!(decl.journeys_declared);
    assert!(decl.journeys.is_empty());
    assert!(decl
        .gaps()
        .iter()
        .any(|g| g.starts_with("runtime-declaration-problem:journey-declaration-unparsed")));
}

#[test]
fn declared_journey_is_unmet_until_evidence_is_imported() {
    let journeys = json!({"schemaVersion": 1, "journeys": [{
        "id": "checkout-dup", "stack": "node-commerce", "category": "checkout",
        "axis": "functional", "title": "checkout", "steps": ["open", "pay"],
        "producer": {"kind": "gap", "reason": "no-owner-yet"},
    }]})
    .to_string();
    let decl = declarations(&[(".legion/journeys.json", journeys.as_str())]);
    assert_eq!(decl.journeys.len(), 1);
    assert!(decl
        .gaps()
        .contains(&"runtime-journey-evidence-not-imported:node-commerce:checkout-dup".to_owned()));
}

// ----------------------------------------------------------- security pipeline

const MODEL: &str = "security.surface-model";
const SYNTHESIS: &str = "security.attack-path-synthesis";
const CHAIN: &str = "security.chain-adjudication";
const SERVER_JS: &str = "const express = require('express');\nconst app = express();\napp.get('/export', (req, res) => res.send('ok'));\n";

fn spec_provider(id: &str) -> AuditProvider {
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
        .unwrap();
    let spec: legion_contracts::ProviderSpec = serde_json::from_value(item.clone()).unwrap();
    AuditProvider {
        id: spec.id.to_string(),
        version: spec.provider_version.clone(),
        role: spec.role.clone(),
        phase: spec.phase.clone(),
        lens_ids: spec.lens_ids.clone(),
        dependencies: Vec::new(),
        kind: ProviderKind::RustAlgorithm,
        configuration: BTreeMap::from([("selector".to_owned(), spec.selector.clone())]),
        bounds: BTreeMap::new(),
        clean_claim: spec.clean_claim.clone(),
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: spec.selectable,
    }
}

fn scanner_result(candidates: Value) -> ProviderExecution {
    ProviderExecution {
        provider: "security.opengrep".into(),
        skipped: false,
        result: ProviderResult {
            schema_version: 1,
            provider: ProviderId::new("security.opengrep").unwrap(),
            applicable: true,
            required: false,
            status: ProviderStatus::Complete,
            complete: true,
            coverage: None,
            findings: Vec::new(),
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details: BTreeMap::from([("candidates".to_owned(), candidates)]),
        },
    }
}

fn scanner_candidates() -> Value {
    json!([
        {
            "id": "scan-1", "ruleId": "scanner.credential-read",
            "file": "src/server.js", "line": 1,
            "sources": ["src/server.js"], "chainRoles": ["starter"],
            "preconditions": [{"kind": "attacker-position", "action": "reach-entrypoint"}],
            "effects": ["data-access:read:credential-material"],
        },
        {
            "id": "scan-2", "ruleId": "scanner.credential-use",
            "file": "src/server.js", "line": 2,
            "assets": [".env"], "chainRoles": ["privilege-escalation"],
            "preconditions": ["credential-possession:possess"],
            "effects": [{"kind": "principal-access", "action": "authenticate", "scope": "control-plane"}],
        },
        {"ruleId": "scanner.hardcoded-api-key", "file": "src/server.js", "line": 3},
    ])
}

fn pipeline_fixture() -> (PathBuf, InventoryEnvelope) {
    materialize(&[
        ("src/server.js", SERVER_JS, true),
        (".env", "API_KEY=placeholder\n", false),
    ])
}

#[test]
fn synthesis_consumes_scanner_candidates_from_prior_results() {
    let (root, inventory) = pipeline_fixture();
    let prior = vec![scanner_result(scanner_candidates())];
    let result = pipeline::execute_with_prior(
        Some(&root),
        &BTreeMap::new(),
        &prior,
        &spec_provider(SYNTHESIS),
        &inventory,
    )
    .unwrap();
    let doc = &result.details["attackPaths"];
    assert_eq!(doc["candidateSources"]["security.opengrep"], 3, "{doc:#}");
    let hypotheses = doc["hypotheses"].as_array().unwrap();
    assert!(
        hypotheses
            .iter()
            .any(|h| h["memberCandidateIds"] == json!(["scan-1", "scan-2"])),
        "{doc:#}"
    );
    // A scanner record with no id still joined, with a derived id and a
    // derived credential effect marked as such.
    assert_eq!(doc["inputs"]["candidateCount"].as_u64().unwrap() >= 3, true);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn hypotheses_are_unadjudicated_candidates_and_never_findings() {
    let (root, inventory) = pipeline_fixture();
    let prior = vec![scanner_result(scanner_candidates())];
    let result = pipeline::execute_with_prior(
        Some(&root),
        &BTreeMap::new(),
        &prior,
        &spec_provider(SYNTHESIS),
        &inventory,
    )
    .unwrap();
    assert!(result.findings.is_empty());
    let candidates = result.details["candidates"].as_array().expect("candidates");
    assert!(!candidates.is_empty());
    for candidate in candidates {
        assert_eq!(candidate["kind"], "attack-path-hypothesis");
        assert_eq!(candidate["verdict"], "UNADJUDICATED");
        assert_eq!(candidate["evidenceStrength"], "possible");
        assert!(candidate["locations"]
            .as_array()
            .is_some_and(|l| !l.is_empty()));
    }
    assert!(!result.details["attackPaths"]
        .to_string()
        .contains("\"PROVEN\""));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn incomplete_scanner_source_keeps_synthesis_non_exhaustive() {
    let (root, inventory) = pipeline_fixture();
    let mut scanner = scanner_result(scanner_candidates());
    scanner.result.complete = false;
    scanner.result.status = ProviderStatus::Partial;
    let result = pipeline::execute_with_prior(
        Some(&root),
        &BTreeMap::new(),
        &[scanner],
        &spec_provider(SYNTHESIS),
        &inventory,
    )
    .unwrap();
    assert!(!result.complete);
    assert!(result.details["attackPaths"]["coverageGaps"]
        .to_string()
        .contains("candidate-source-incomplete"));
    fs::remove_dir_all(root).unwrap();
}

fn synthesis_and_chain() -> (PathBuf, ProviderResult, ProviderResult) {
    let (root, inventory) = pipeline_fixture();
    let synthesis = pipeline::execute_with_prior(
        Some(&root),
        &BTreeMap::new(),
        &[scanner_result(scanner_candidates())],
        &spec_provider(SYNTHESIS),
        &inventory,
    )
    .unwrap();
    let prior = vec![ProviderExecution {
        provider: SYNTHESIS.into(),
        skipped: false,
        result: synthesis.clone(),
    }];
    let chain = pipeline::execute_with_prior(
        Some(&root),
        &BTreeMap::new(),
        &prior,
        &spec_provider(CHAIN),
        &inventory,
    )
    .unwrap();
    (root, synthesis, chain)
}

#[test]
fn chain_adjudication_reuses_synthesis_hypotheses_and_emits_review_requests() {
    let (root, synthesis, chain) = synthesis_and_chain();
    let hypotheses = synthesis.details["attackPaths"]["hypotheses"]
        .as_array()
        .unwrap();
    let verdicts = &chain.details["chainVerdicts"];
    assert_eq!(
        verdicts["hypothesisCount"].as_u64().unwrap() as usize,
        hypotheses.len()
    );
    let requests = chain.details["chainReviewRequests"].as_array().unwrap();
    assert_eq!(requests.len(), hypotheses.len());
    for request in requests {
        assert_eq!(request["kind"], pipeline::CHAIN_REQUEST_KIND);
        assert_eq!(request["requires"]["freshContext"], true);
        assert_eq!(request["requires"]["producerSeparation"], true);
    }
    // Without returned verdicts everything stays pending and unproven.
    assert_eq!(verdicts["status"], "UNPROVEN");
    assert_eq!(verdicts["claims"]["chainsProven"], 0);
    assert!(!chain.complete);
    assert!(chain.findings.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn returned_verdicts_must_be_separate_requested_and_unique() {
    let (root, _synthesis, chain) = synthesis_and_chain();
    let requests: Vec<Value> = chain.details["chainReviewRequests"]
        .as_array()
        .unwrap()
        .clone();
    let path_id = requests[0]["pathId"].clone();
    let request_id = requests[0]["requestId"].clone();
    let synthesizer = requests[0]["synthesizer"].clone();

    // Adjudicator sharing the synthesizer's context is not independent.
    let same_context = json!({
        "adjudicator": {"provider": "reasoning.security", "contextId": synthesizer["contextId"]},
        "assessments": [],
    });
    assert!(pipeline::ingest_chain_verdicts(&requests, &same_context).is_err());

    // Missing adjudicator identity.
    assert!(pipeline::ingest_chain_verdicts(&requests, &json!({"assessments": []})).is_err());

    // Unrequested assessment.
    let unrequested = json!({
        "adjudicator": {"provider": "reasoning.security", "contextId": "ctx:fresh-1"},
        "assessments": [{"requestId": "chainreq:forged", "pathId": path_id}],
    });
    assert!(pipeline::ingest_chain_verdicts(&requests, &unrequested).is_err());

    // Duplicate assessment.
    let duplicate = json!({
        "adjudicator": {"provider": "reasoning.security", "contextId": "ctx:fresh-1"},
        "assessments": [
            {"requestId": request_id, "pathId": path_id},
            {"requestId": request_id, "pathId": path_id},
        ],
    });
    assert!(pipeline::ingest_chain_verdicts(&requests, &duplicate).is_err());

    // A separate, requested, unique return is accepted as input only; the
    // executor still gates it through adjudicate_chain.
    let good = json!({
        "adjudicator": {"provider": "reasoning.security", "contextId": "ctx:fresh-1"},
        "assessments": [{"requestId": request_id, "pathId": path_id}],
    });
    let artifact = pipeline::ingest_chain_verdicts(&requests, &good).unwrap();
    assert_eq!(artifact["assessments"].as_array().unwrap().len(), 1);
    let executor = SecurityProviderExecutor::default()
        .with_chain_verdicts(&requests, &good)
        .unwrap();
    assert!(executor.artifacts.contains_key(CHAIN));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_deterministic_pass_never_proves_a_chain_from_an_empty_assessment() {
    let (root, inventory) = pipeline_fixture();
    let (_, synthesis, chain) = synthesis_and_chain();
    let requests = chain.details["chainReviewRequests"]
        .as_array()
        .unwrap()
        .clone();
    let returned = json!({
        "adjudicator": {"provider": "reasoning.security", "contextId": "ctx:fresh-1"},
        "assessments": [{"requestId": requests[0]["requestId"], "pathId": requests[0]["pathId"]}],
    });
    let artifact = pipeline::ingest_chain_verdicts(&requests, &returned).unwrap();
    let injected = BTreeMap::from([(CHAIN.to_owned(), artifact)]);
    let prior = vec![ProviderExecution {
        provider: SYNTHESIS.into(),
        skipped: false,
        result: synthesis,
    }];
    let result = pipeline::execute_with_prior(
        Some(&root),
        &injected,
        &prior,
        &spec_provider(CHAIN),
        &inventory,
    )
    .unwrap();
    assert_eq!(result.details["chainVerdicts"]["claims"]["chainsProven"], 0);
    assert!(!result.complete);
    let _ = MODEL;
    fs::remove_dir_all(root).unwrap();
}
