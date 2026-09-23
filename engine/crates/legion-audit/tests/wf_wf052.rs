//! Integration tests porting the JS test coverage for
//! `src/providers/security/{contracts,candidate-engine,attack-path-synthesis,attack-path-reconcile,evidence-synthesis}.mjs`
//! (see `../../../../tests/security-attack-path-synthesis.test.mjs` and
//! `../../../../tests/security-evidence-synthesis.test.mjs` in the JS tree;
//! `attack-path-reconcile.mjs` and `candidate-engine.mjs` have no dedicated
//! JS test file — their scenarios below are ported from
//! `attack-path-reconcile.mjs`'s and `candidate-engine.mjs`'s own doc
//! comments and behaviour, cross-checked against the module unit tests).
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod wf052;`
//! inside it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf052::attack_path_reconcile::reconcile_attack_paths;
use legion_audit::wf_port::wf052::attack_path_synthesis::{synthesize_attack_paths, Limits};
use legion_audit::wf_port::wf052::candidate_engine::create_security_candidate_v2;
use legion_audit::wf_port::wf052::contracts::binding_from_plan;
use legion_audit::wf_port::wf052::evidence_synthesis::synthesize_security_evidence;
use serde_json::{json, Value};

fn plan_with() -> Value {
    json!({
        "seal": {"digest": "sha256:plan"},
        "binding": {
            "repositoryRevision": "rev1",
            "dirtyPatchDigest": null,
            "blueprint": {"generationId": "gen1", "manifestDigest": "sha256:manifest"},
            "registryDigest": "sha256:registry",
        },
        "providers": [],
    })
}

fn binding() -> Value {
    binding_from_plan(&plan_with()).unwrap()
}

fn model_with(entities: Value, initial_facts: Value) -> Value {
    json!({
        "schemaVersion": 1, "kind": "security-surface-model", "binding": binding(),
        "denominatorDigest": "sha256:denom", "complete": true,
        "entities": entities, "relations": [], "initialFacts": initial_facts, "evidence": [],
        "coverage": {}, "coverageGaps": [],
    })
}

fn candidates_artifact(list: Value) -> Value {
    json!({
        "schemaVersion": 1, "kind": "security-candidates", "binding": binding(),
        "denominatorDigest": "sha256:denom", "complete": true, "candidates": list,
    })
}

fn adjudication_artifact(verdicts: Value, complete: bool) -> Value {
    json!({
        "schemaVersion": 1, "kind": "security-adjudication-result", "binding": binding(),
        "complete": complete, "verdicts": verdicts,
    })
}

fn variants_artifact(receipts: Value, complete: bool) -> Value {
    json!({
        "schemaVersion": 2, "kind": "security-variant-results", "binding": binding(),
        "complete": complete, "receipts": receipts,
    })
}

fn candidate_json() -> Value {
    json!({
        "id": "c1", "provider": "security.credentials", "ruleId": "credentials.format",
        "sources": [], "sinks": [], "assets": [], "requiredControls": [], "observedControls": [],
        "evidenceRefs": ["ev1"], "binding": binding(),
    })
}

fn verdict_json() -> Value {
    json!({
        "candidateId": "c1", "candidateProvider": "security.credentials", "verdict": "TRUE_POSITIVE",
        "evidenceStrength": "verified", "severity": "high", "threatModel": "x", "attackerControl": "y",
        "reachability": "z", "impact": "w", "rationale": "r", "proof": {"digest": "sha256:p"},
        "rootCauseSignature": {"class": "credential-in-repository"},
    })
}

fn complete_receipt() -> Value {
    json!({
        "schemaVersion": 2, "kind": "security-variant-receipt", "findingId": "c1", "ruleId": "credentials.format",
        "rootCauseSignature": {"class": "credential-in-repository"}, "provider": "security.variant-analysis",
        "providerVersion": "2", "binding": binding(),
        "denominator": {"kind": "source-files", "digest": "sha256:d", "expected": 1, "examined": 1, "unexamined": []},
        "strategies": [], "matches": [{"id": "m1", "file": "a.ts", "line": 3, "semanticFingerprint": "sha256:f", "disposition": "CONFIRMED"}],
        "summary": {"enumerated": 1, "examined": 1, "confirmed": 1, "rejected": 0, "duplicates": 0, "outOfScope": 0, "unresolved": 0},
        "complete": true, "coverageGaps": [], "receiptDigest": "sha256:receipt",
    })
}

// ---- evidence-synthesis.mjs ----

#[test]
fn surviving_finding_without_complete_receipt_makes_synthesis_incomplete() {
    let plan = plan_with();
    let model = model_with(json!([{"id": "ctrl1", "kind": "control", "evidenceRefs": []}]), json!([]));
    let result = synthesize_security_evidence(
        &plan,
        &model,
        &candidates_artifact(json!([candidate_json()])),
        &adjudication_artifact(json!([verdict_json()]), true),
        &adjudication_artifact(json!([]), true),
        &variants_artifact(json!([]), true),
    )
    .unwrap();
    assert_eq!(result["complete"], false);
    assert!(result["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["kind"] == "finding-missing-candidate-or-variant-receipt"));
}

#[test]
fn false_positive_candidate_never_becomes_a_finding() {
    let plan = plan_with();
    let model = model_with(json!([{"id": "ctrl1", "kind": "control", "evidenceRefs": []}]), json!([]));
    let mut verdict = verdict_json();
    verdict["verdict"] = json!("FALSE_POSITIVE");
    let result = synthesize_security_evidence(
        &plan,
        &model,
        &candidates_artifact(json!([candidate_json()])),
        &adjudication_artifact(json!([verdict]), true),
        &adjudication_artifact(json!([]), true),
        &variants_artifact(json!([complete_receipt()]), true),
    )
    .unwrap();
    assert_eq!(result["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn complete_inputs_produce_findings_and_synthesis_is_complete() {
    let plan = plan_with();
    let model = model_with(json!([{"id": "ctrl1", "kind": "control", "evidenceRefs": []}]), json!([]));
    let result = synthesize_security_evidence(
        &plan,
        &model,
        &candidates_artifact(json!([candidate_json()])),
        &adjudication_artifact(json!([verdict_json()]), true),
        &adjudication_artifact(json!([]), true),
        &variants_artifact(json!([complete_receipt()]), true),
    )
    .unwrap();
    assert_eq!(result["complete"], true);
    assert_eq!(result["findings"].as_array().unwrap().len(), 1);
    assert_eq!(result["findings"][0]["severity"], "high");
    assert_eq!(result["findings"][0]["variantReceiptId"], "sha256:receipt");
}

#[test]
fn proven_path_references_constituent_findings_and_is_not_double_counted() {
    let plan = plan_with();
    let model = model_with(json!([{"id": "ctrl1", "kind": "control", "evidenceRefs": []}]), json!([]));
    let proven = json!({
        "pathId": "path-1", "verdict": "PROVEN", "severity": "critical", "priority": "PRIVILEGE_ESCALATION",
        "start": {"factIds": ["f1"]}, "objective": {"id": "objective.privilege-escalation"},
        "steps": [{"candidateId": "c1"}], "controls": [], "terminalImpact": {"kind": "x"}, "proof": {"digest": "sha256:p"},
        "stepAssessments": [], "joinAssessments": [],
    });
    let result = synthesize_security_evidence(
        &plan,
        &model,
        &candidates_artifact(json!([candidate_json()])),
        &adjudication_artifact(json!([verdict_json()]), true),
        &adjudication_artifact(json!([proven]), true),
        &variants_artifact(json!([complete_receipt()]), true),
    )
    .unwrap();
    assert_eq!(result["attackPaths"].as_array().unwrap().len(), 1);
    assert_eq!(result["attackPaths"][0]["constituentFindingIds"].as_array().unwrap().len(), 1);
    assert_eq!(result["coverage"]["survivingCandidateVerdicts"], 1);
    assert_eq!(result["coverage"]["provenPaths"], 1);
}

#[test]
fn partial_and_blocked_paths_carry_no_severity_and_are_classified_separately() {
    let plan = plan_with();
    let model = model_with(json!([{"id": "ctrl1", "kind": "control", "evidenceRefs": []}]), json!([]));
    let partial = json!({
        "pathId": "p2", "verdict": "PARTIALLY_SUPPORTED", "evidenceStrength": "strong-inference", "severity": null,
        "stepAssessments": [], "joinAssessments": [], "controls": [], "controlAssessments": [],
        "terminalImpact": null, "proof": null,
    });
    let mut blocked = partial.clone();
    blocked["pathId"] = json!("p3");
    blocked["verdict"] = json!("BLOCKED");
    blocked["controlAssessments"] = json!([{"controlId": "ctrl1", "status": "EFFECTIVE"}]);

    let result = synthesize_security_evidence(
        &plan,
        &model,
        &candidates_artifact(json!([candidate_json()])),
        &adjudication_artifact(json!([verdict_json()]), true),
        &adjudication_artifact(json!([partial, blocked]), true),
        &variants_artifact(json!([complete_receipt()]), true),
    )
    .unwrap();
    assert_eq!(result["hypotheses"]["partiallySupported"].as_array().unwrap().len(), 1);
    assert_eq!(result["hypotheses"]["blocked"].as_array().unwrap().len(), 1);
    assert_eq!(result["attackPaths"].as_array().unwrap().len(), 0);
    assert_eq!(result["findings"][0]["severity"], "high");
}

#[test]
fn binding_mismatch_fails_synthesis() {
    let plan = plan_with();
    let model = model_with(json!([]), json!([]));
    let mut stale = candidates_artifact(json!([candidate_json()]));
    stale["binding"]["repositoryRevision"] = json!("other");
    let err = synthesize_security_evidence(
        &plan,
        &model,
        &stale,
        &adjudication_artifact(json!([verdict_json()]), true),
        &adjudication_artifact(json!([]), true),
        &variants_artifact(json!([complete_receipt()]), true),
    )
    .unwrap_err();
    assert!(err.0.contains("does not match"));
}

#[test]
fn same_root_cause_groups_variants_without_destructive_dedup() {
    let plan = plan_with();
    let model = model_with(json!([{"id": "ctrl1", "kind": "control", "evidenceRefs": []}]), json!([]));
    let mut candidate_b = candidate_json();
    candidate_b["id"] = json!("c2");
    let mut verdict_b = verdict_json();
    verdict_b["candidateId"] = json!("c2");
    let mut receipt_b = complete_receipt();
    receipt_b["findingId"] = json!("c2");

    let result = synthesize_security_evidence(
        &plan,
        &model,
        &candidates_artifact(json!([candidate_json(), candidate_b])),
        &adjudication_artifact(json!([verdict_json(), verdict_b]), true),
        &adjudication_artifact(json!([]), true),
        &variants_artifact(json!([complete_receipt(), receipt_b]), true),
    )
    .unwrap();
    assert_eq!(result["findings"].as_array().unwrap().len(), 2, "two findings kept");
    assert_eq!(result["systemicRootCauses"].as_array().unwrap().len(), 1, "grouped by root cause");
    assert_eq!(result["systemicRootCauses"][0]["findingIds"].as_array().unwrap().len(), 2);
}

// ---- attack-path-synthesis.mjs (selected cross-module scenarios; the full
// suite lives as unit tests inside attack_path_synthesis.rs itself) ----

#[test]
fn synthesis_output_feeds_reconciliation_end_to_end() {
    let plan = plan_with();
    let start = json!({
        "kind": "object-access", "subject": "actor:external", "action": "read",
        "object": "jewel-id", "scope": "cross-tenant", "id": "fact:1", "evidenceRefs": ["ev1"],
    });
    let model = model_with(json!([{"id": "jewel-id", "kind": "crown-jewel"}]), json!([start]));
    let attack = json!({
        "schemaVersion": 2, "kind": "security-candidate", "id": "c1",
        "provider": "security.test", "providerVersion": "1", "ruleId": "r", "candidateClass": "test",
        "claim": "test", "severityHint": "high", "sources": [], "sinks": [], "assets": [],
        "trustBoundaryCrossings": [],
        "preconditions": [{"kind": "object-access", "subject": "actor:external", "action": "read", "object": "jewel-id"}],
        "effects": [{"kind": "data-access", "subject": "actor:external", "action": "read", "object": "jewel-id"}],
        "chainRoles": [], "requiredControls": [], "observedControls": [], "evidenceRefs": ["ev1"],
        "binding": binding(), "denominatorDigest": "sha256:denom",
        "verdict": "UNADJUDICATED", "adjudicationRequired": true,
    });
    let objectives = vec![json!({
        "id": "objective.crown-jewel-access", "priority": "DIRECT_CROWN_JEWEL", "description": "crown jewel",
        "matches": {"assetKinds": ["crown-jewel"], "factKinds": ["data-access", "object-access", "code-execution", "principal-access"]},
    })];

    let hypotheses = synthesize_attack_paths(
        &plan,
        &model,
        &candidates_artifact(json!([attack])),
        &[],
        &objectives,
        Limits::default(),
    )
    .unwrap();
    assert!(!hypotheses["hypotheses"].as_array().unwrap().is_empty());

    // Every primitive step survives adjudication: reconciliation must mark
    // the path PARTIALLY_SUPPORTED (eligible for chain adjudication) and
    // never PROVEN.
    let adjudication = adjudication_artifact(json!([{"candidateId": "c1", "verdict": "TRUE_POSITIVE"}]), true);
    let reconciled = reconcile_attack_paths(&plan, &hypotheses, &adjudication).unwrap();
    let reconciled_hyps = reconciled["hypotheses"].as_array().unwrap();
    assert_eq!(reconciled_hyps.len(), hypotheses["hypotheses"].as_array().unwrap().len());
    for hyp in reconciled_hyps {
        assert_eq!(hyp["status"], "PARTIALLY_SUPPORTED");
        assert_ne!(hyp["status"], "PROVEN");
    }
}

// ---- candidate-engine.mjs: created candidates flow straight into
// synthesis's candidatesArtifact shape. ----

#[test]
fn created_candidate_is_usable_directly_as_synthesis_input() {
    let plan = plan_with();
    let model = model_with(json!([{"id": "asset-1", "kind": "asset"}]), json!([]));
    let observation = json!({
        "ruleId": "r1", "candidateClass": "test", "claim": "a claim", "severityHint": "high",
        "sources": ["asset-1"],
        "preconditions": [{"kind": "capability", "subject": "actor:x"}],
        "effects": [{"kind": "capability", "subject": "actor:x", "action": "b"}],
        "evidenceRefs": ["ev1"],
    });
    let candidate = create_security_candidate_v2(&plan, &model, "security.test", "1", "sha256:denom", &observation).unwrap();
    assert_eq!(candidate["schemaVersion"], 2);
    assert_eq!(candidate["verdict"], "UNADJUDICATED");

    // No objective matches this candidate's effects, so synthesis with it
    // completes cleanly with zero hypotheses (no crash on a real
    // candidate-engine-produced record).
    let result = synthesize_attack_paths(
        &plan,
        &model,
        &candidates_artifact(json!([candidate])),
        &[],
        &[],
        Limits::default(),
    )
    .unwrap();
    assert_eq!(result["hypotheses"].as_array().unwrap().len(), 0);
    assert_eq!(result["complete"], true);
}
