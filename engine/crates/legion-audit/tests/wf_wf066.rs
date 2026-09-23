//! Port of test assertions for chunk wf066 (`tools/audit/{render-report.mjs,
//! security-chain-pipeline.mjs, security-pipeline.mjs}`), driving the Rust
//! ports in `legion_audit::wf_port::wf066`.
//!
//! `tests/security-pipeline.test.mjs` and `tests/security-chain-pipeline.test.mjs`
//! assertions are ported below for the bundle-level behavior this chunk owns
//! (`prepareAdjudicationBundle`/`finalizeAdjudicationBundle`,
//! `prepareChainAdjudicationBundle`/`finalizeChainAdjudicationBundle`).
//! `security-chain-pipeline.test.mjs` drives its fixtures through
//! `reconcileAttackPaths` (`src/providers/security/attack-path-reconcile.mjs`),
//! which this chunk does not own; the port below builds an equivalent
//! already-reconciled-and-eligible path directly instead of re-deriving one
//! through that adapter, and covers the same two chain-pipeline-owned
//! assertions the JS suite makes at the bundle level ("each path gets a
//! unique context", "duplicate path verdicts are invalid", "all valid
//! verdicts make the bundle complete"). `render-report.mjs`'s own JS suite
//! (`tests/decomposition-report.test.mjs`) exercises the CLI end to end
//! (`--facts`/`--report`/`--agent` file I/O); the assertions on this port's
//! owned pure logic (quality gate, coverage gate, decomposition-assessment
//! evidence bar, dedupe, health score) are ported as unit tests inside
//! `render_report.rs` itself, per this chunk's `tests/fixtures/wf_wf066/`
//! note below.

use serde_json::json;

use legion_audit::wf_port::wf066::render_report::{clean_path, coverage_gate, quality_gate, render_report, RenderOptions};
use legion_audit::wf_port::wf066::security_chain_pipeline::{
    finalize_chain_adjudication_bundle, prepare_chain_adjudication_bundle,
};
use legion_audit::wf_port::wf066::security_pipeline::{
    finalize_adjudication_bundle, prepare_adjudication_bundle, PrepareAdjudicationOptions,
};

// =================================================================================================
// security-pipeline.test.mjs
// =================================================================================================

fn candidate_report() -> serde_json::Value {
    json!({
        "provider": "security.internal-suite",
        "candidates": [{
            "id": "candidate-1",
            "provider": "security.internal-suite",
            "ruleId": "security.command-injection",
            "claim": "Input reaches command execution.",
            "evidence": [{ "file": "src/run.ts", "line": 4 }],
        }],
    })
}

#[test]
fn adjudication_bundle_uses_separate_providers_and_contexts() {
    let options = PrepareAdjudicationOptions {
        generator_context_id: Some("generator".into()),
        adjudicator_context_id: Some("adjudicator".into()),
        ..Default::default()
    };
    let bundle = prepare_adjudication_bundle(&candidate_report(), &options).unwrap();
    assert_eq!(bundle.packets[0].candidate.context_id, "generator");
    assert_eq!(bundle.packets[0].adjudicator.context_id, "adjudicator");
    assert_ne!(bundle.packets[0].candidate.provider, bundle.packets[0].adjudicator.provider);
}

#[test]
fn each_candidate_gets_its_own_fresh_adjudication_context() {
    let mut report = candidate_report();
    report["candidates"].as_array_mut().unwrap().push(json!({
        "id": "candidate-2",
        "provider": "security.internal-suite",
        "ruleId": "security.path-traversal",
        "claim": "Input reaches a filesystem path.",
        "evidence": [{ "file": "src/files.ts", "line": 9 }],
    }));
    let options = PrepareAdjudicationOptions { generator_context_id: Some("generator".into()), ..Default::default() };
    let bundle = prepare_adjudication_bundle(&report, &options).unwrap();
    let contexts: std::collections::HashSet<&str> = bundle.packets.iter().map(|p| p.adjudicator.context_id.as_str()).collect();
    assert_eq!(contexts.len(), 2);
    assert!(contexts.iter().all(|c| *c != "generator"));

    let reused_options = PrepareAdjudicationOptions {
        generator_context_id: Some("generator".into()),
        adjudicator_context_id: Some("reused".into()),
        ..Default::default()
    };
    let error = prepare_adjudication_bundle(&report, &reused_options).unwrap_err();
    assert!(matches!(
        error,
        legion_audit::wf_port::wf066::security_pipeline::SecurityPipelineError::SingleContextForMultipleCandidates
    ));
}

#[test]
fn all_candidates_require_verdicts() {
    let options = PrepareAdjudicationOptions {
        generator_context_id: Some("generator".into()),
        adjudicator_context_id: Some("adjudicator".into()),
        ..Default::default()
    };
    let bundle = prepare_adjudication_bundle(&candidate_report(), &options).unwrap();
    let result = finalize_adjudication_bundle(&bundle, &json!({ "verdicts": [] }), &[]);
    assert_eq!(result["complete"], json!(false));
    assert_eq!(result["missingVerdicts"], json!(["candidate-1"]));
}

#[test]
fn false_positive_verdict_closes_without_severity_or_variants() {
    let options = PrepareAdjudicationOptions {
        generator_context_id: Some("generator".into()),
        adjudicator_context_id: Some("adjudicator".into()),
        ..Default::default()
    };
    let bundle = prepare_adjudication_bundle(&candidate_report(), &options).unwrap();
    let base_verdict = json!({
        "candidateId": "candidate-1",
        "verdict": "FALSE_POSITIVE",
        "threatModel": "remote unauthenticated",
        "reachability": "blocked",
        "impact": "none because input is fixed before the sink",
        "rationale": "The command argument is selected from a closed enum.",
    });
    let result = finalize_adjudication_bundle(&bundle, &json!({ "verdicts": [base_verdict] }), &[]);
    assert_eq!(result["complete"], json!(true));
    assert_eq!(result["status"], json!("pass"));
    assert_eq!(result["verdicts"][0]["severity"], serde_json::Value::Null);
}

#[test]
fn true_positive_requires_severity_and_completed_matching_variant_receipt() {
    let options = PrepareAdjudicationOptions {
        generator_context_id: Some("generator".into()),
        adjudicator_context_id: Some("adjudicator".into()),
        ..Default::default()
    };
    let bundle = prepare_adjudication_bundle(&candidate_report(), &options).unwrap();
    let verdict = json!({
        "candidateId": "candidate-1", "verdict": "TRUE_POSITIVE", "severity": "critical",
        "evidenceStrength": "verified",
        "threatModel": "remote unauthenticated", "attackerControl": "proven", "reachability": "proven",
        "impact": "arbitrary command execution", "proof": { "kind": "repro", "artifact": "tests/repro.ts" },
        "devilsAdvocate": "false positive excluded: attacker controls input and sink is reachable",
    });
    let missing = finalize_adjudication_bundle(&bundle, &json!({ "verdicts": [verdict.clone()] }), &[]);
    assert_eq!(missing["complete"], json!(false));
    assert_eq!(missing["missingVariantAnalysis"].as_array().unwrap().len(), 1);

    let receipts = vec![json!({ "findingId": "candidate-1", "ruleId": "security.command-injection", "complete": true, "matchesExamined": 4 })];
    let complete = finalize_adjudication_bundle(&bundle, &json!({ "verdicts": [verdict] }), &receipts);
    assert_eq!(complete["complete"], json!(true));
    assert_eq!(complete["status"], json!("findings"));
}

// =================================================================================================
// security-chain-pipeline.test.mjs (bundle-level assertions only — see module doc comment)
// =================================================================================================

fn chain_binding() -> serde_json::Value {
    json!({
        "planDigest": "sha256:plan", "repositoryRevision": "rev1", "dirtyPatchDigest": serde_json::Value::Null,
        "blueprintGenerationId": "gen1", "blueprintManifestDigest": "sha256:manifest", "registryDigest": "sha256:registry",
    })
}

fn chain_plan() -> serde_json::Value {
    json!({
        "seal": { "digest": "sha256:plan" },
        "binding": { "repositoryRevision": "rev1", "dirtyPatchDigest": serde_json::Value::Null, "blueprint": { "generationId": "gen1", "manifestDigest": "sha256:manifest" }, "registryDigest": "sha256:registry" },
    })
}

fn chain_candidates() -> serde_json::Value {
    json!({
        "binding": chain_binding(),
        "candidates": [{ "id": "c1", "sources": [], "sinks": [], "assets": [], "requiredControls": [], "observedControls": [] }],
    })
}

fn chain_candidate_adjudication() -> serde_json::Value {
    json!({ "binding": chain_binding(), "verdicts": [{ "candidateId": "c1", "verdict": "TRUE_POSITIVE" }] })
}

fn chain_model() -> serde_json::Value {
    json!({ "binding": chain_binding(), "entities": [], "relations": [], "evidence": [] })
}

fn eligible_reconciled_paths(ids: &[&str]) -> serde_json::Value {
    let hypotheses: Vec<serde_json::Value> = ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "provider": "security.attack-path-synthesis",
                "reconciliation": { "eligibleForChainAdjudication": true },
                "steps": [{ "candidateId": "c1" }],
                "joins": [],
            })
        })
        .collect();
    json!({ "binding": chain_binding(), "hypotheses": hypotheses })
}

#[test]
fn each_path_gets_a_unique_context() {
    let bundle = prepare_chain_adjudication_bundle(
        &chain_plan(),
        &eligible_reconciled_paths(&["path-1", "path-2"]),
        &chain_candidates(),
        &chain_candidate_adjudication(),
        &chain_model(),
        None,
    )
    .unwrap();
    let contexts: std::collections::HashSet<&str> = bundle.packets.iter().map(|(_, p)| p.0["adjudicator"]["contextId"].as_str().unwrap()).collect();
    assert_eq!(contexts.len(), 2);
}

fn unproven_raw_for(packet_path_id: &str, context_id: &str) -> serde_json::Value {
    json!({
        "pathId": packet_path_id, "contextId": context_id, "verdict": "UNPROVEN", "evidenceStrength": "possible",
        "stepAssessments": [{ "candidateId": "c1", "usableInChain": false }],
        "joinAssessments": [], "terminalImpact": serde_json::Value::Null, "proof": serde_json::Value::Null, "negativeControl": serde_json::Value::Null,
        "devilsAdvocate": "x", "rationale": "x", "severity": serde_json::Value::Null,
    })
}

#[test]
fn duplicate_path_verdicts_are_invalid() {
    let bundle = prepare_chain_adjudication_bundle(
        &chain_plan(),
        &eligible_reconciled_paths(&["path-1"]),
        &chain_candidates(),
        &chain_candidate_adjudication(),
        &chain_model(),
        None,
    )
    .unwrap();
    let (path_id, packet) = &bundle.packets[0];
    let context_id = packet.0["adjudicator"]["contextId"].as_str().unwrap();
    let raw = unproven_raw_for(path_id, context_id);
    let result = finalize_chain_adjudication_bundle(&bundle, &json!({ "verdicts": [raw.clone(), raw] }));
    assert_eq!(result["complete"], json!(false));
    assert!(result["invalidVerdicts"].as_array().unwrap().iter().any(|item| item["error"].as_str().unwrap().contains("duplicate")));
}

#[test]
fn all_valid_verdicts_make_the_bundle_complete() {
    let bundle = prepare_chain_adjudication_bundle(
        &chain_plan(),
        &eligible_reconciled_paths(&["path-1"]),
        &chain_candidates(),
        &chain_candidate_adjudication(),
        &chain_model(),
        None,
    )
    .unwrap();
    let (path_id, packet) = &bundle.packets[0];
    let context_id = packet.0["adjudicator"]["contextId"].as_str().unwrap();
    let raw = unproven_raw_for(path_id, context_id);
    let result = finalize_chain_adjudication_bundle(&bundle, &json!({ "verdicts": [raw] }));
    assert_eq!(result["complete"], json!(true));
    assert_eq!(result["verdicts"].as_array().unwrap().len(), 1);
}

// =================================================================================================
// render-report.mjs — decomposition-report.test.mjs-adjacent assertions
// (the bulk of that suite's assertions are ported as unit tests inside
// render_report.rs itself; these cover the end-to-end render() entry point).
// =================================================================================================

#[test]
fn clean_path_strips_backslashes_leading_dot_run_and_trailing_slash() {
    assert_eq!(clean_path(Some("a\\b\\c/")), Some("a/b/c".to_string()));
    assert_eq!(clean_path(Some("./foo/bar")), Some("foo/bar".to_string()));
    assert_eq!(clean_path(Some("")), None);
}

#[test]
fn quality_gate_not_clean_when_a_gate_check_has_findings() {
    let facts = json!({ "checks": [{ "check": "lint", "status": "ran", "findings_count": 2, "exit_code": 0 }] });
    assert_eq!(quality_gate(&facts)["state"], json!("NOT CLEAN"));
}

#[test]
fn coverage_gate_unproven_without_ratio() {
    let coverage = json!({ "perFile": [{ "file": "a.rs", "touched": [], "covered": [], "uncovered": [], "tests": [] }] });
    let gate = coverage_gate(Some(&coverage)).unwrap();
    assert_eq!(gate["state"], json!("UNPROVEN"));
}

#[test]
fn render_report_includes_not_scanned_banner_for_missing_security_check() {
    let facts = json!({
        "workspace": ".",
        "generated_at": "2026-01-01T00:00:00Z",
        "checks": [{ "check": "secrets", "status": "skipped", "skip_reason": "gitleaks not installed" }],
    });
    let options = RenderOptions {
        trajectory_history: Some(std::env::temp_dir().join("wf066-render-report-not-scanned.json")),
        ..Default::default()
    };
    let rendered = render_report(&facts, None, &options).unwrap();
    assert!(rendered.markdown.contains("NOT SCANNED: secrets"));
    let _ = std::fs::remove_file(options.trajectory_history.unwrap());
}
