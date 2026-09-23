//! Integration test for packet Q4's port of
//! `src/lib/verification/arcane/completion-evidence.mjs`
//! (`loadCompletionEvidence`), against the production entry point
//! `legion_policy::wf_port::q_q4::completion_evidence::load_completion_evidence`.
//!
//! NOTE: this file depends on `wf_port::q_q4` being declared in
//! `engine/crates/legion-policy/src/wf_port/mod.rs` (the integrator wires
//! this automatically per the packet's parent instructions). Until then,
//! `cargo test` for this file will fail to resolve the module path — that
//! is expected and not a defect in this port.

use legion_policy::wf_port::q_q4::completion_evidence::{
    load_completion_evidence, AcceptanceCriterion, AuthorityProofIssuer, AuthorityVerifyResult,
    Execution, ReceiptStore, RecordVerifier, RecordVerifyResult,
};
use serde_json::{json, Value};

struct FakeStore(Vec<Value>);
impl ReceiptStore for FakeStore {
    fn list(&self, _run_id: &Value) -> Vec<Value> {
        self.0.clone()
    }
}

struct FakeIssuer;
impl AuthorityProofIssuer for FakeIssuer {
    fn find_by_digest(&self, digest: &Value) -> Option<Value> {
        if digest == &json!("digest-1") {
            Some(json!({"id": "authority-1"}))
        } else {
            None
        }
    }
    fn verify(&self, _authority: &Value, _expected: &Value) -> AuthorityVerifyResult {
        AuthorityVerifyResult { allowed: true }
    }
}

struct FakeVerifier;
impl RecordVerifier for FakeVerifier {
    fn verify_record(&self, _record: &Value, _expected_binding: &Value) -> RecordVerifyResult {
        RecordVerifyResult { allowed: true }
    }
}

fn matching_receipt() -> Value {
    json!({
        "kind": "legion-evidence-capability-receipt",
        "producerAuthority": "oracle",
        "observedAt": "2026-01-01T00:00:00Z",
        "observation": {
            "acceptanceId": "crit-1",
            "requirementId": "req-1",
            "productionSymbol": "sym",
            "liveConsumer": "consumer",
            "acceptanceSurface": "surface",
            "integratedState": {"git": "abc"},
            "latestMaterialChange": "2026-01-01",
            "contractVersion": 1,
            "contractDigest": "digest-c",
            "sourceRevision": "rev-1",
            "authorityProofDigest": "digest-1",
            "validUntil": "2026-02-01",
        }
    })
}

#[test]
fn matching_authenticated_receipt_registers_and_proves() {
    let execution = Execution {
        run_id: json!("run-1"),
        task_id: json!("task-1"),
        contract_id: json!("contract-1"),
        contract_version: json!(1),
        contract_digest: json!("digest-c"),
        source_revision: json!("rev-1"),
        acceptance_criteria: vec![AcceptanceCriterion { id: json!("crit-1") }],
    };
    let result = load_completion_evidence(
        &FakeStore(vec![matching_receipt()]),
        true,
        Some(&FakeIssuer),
        &FakeVerifier,
        &execution,
        &json!({"git": "abc"}),
        &json!("2026-01-01"),
    );
    assert_eq!(result.evidence_registry.len(), 1);
    assert_eq!(result.acceptance_proofs.len(), 1);
    assert_eq!(result.acceptance_proofs[0].acceptance_id, json!("crit-1"));
}

#[test]
fn no_criteria_is_empty() {
    let execution = Execution {
        run_id: json!("run-1"),
        task_id: json!("task-1"),
        contract_id: json!("contract-1"),
        contract_version: json!(1),
        contract_digest: json!("digest-c"),
        source_revision: json!("rev-1"),
        acceptance_criteria: vec![],
    };
    let result = load_completion_evidence(
        &FakeStore(vec![]),
        true,
        Some(&FakeIssuer),
        &FakeVerifier,
        &execution,
        &json!({}),
        &json!(null),
    );
    assert!(result.acceptance_proofs.is_empty());
}
