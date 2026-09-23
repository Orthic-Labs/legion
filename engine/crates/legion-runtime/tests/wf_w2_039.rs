//! Integration tests for ported chunk w2_039 (`src/lib/core/{binding,
//! adjudicate-run,execute-plan}.mjs` — see
//! `legion_runtime::wf_port::w2_039` doc comment for full disposition of
//! all five files in the chunk).
//!
//! NOTE: this test file assumes the integrator has wired
//! `pub mod wf_port;` (already present in `lib.rs`) and
//! `pub mod w2_039;` inside `src/wf_port/mod.rs` — see the w2_039 report for
//! the exact one-line patch. Until that lands this file will not compile.

use legion_runtime::wf_port::w2_039::binding::{
    assert_artifact_binding, canonicalize, digest, same_binding, BoundArtifact,
};
use legion_runtime::wf_port::w2_039::judgment::{
    adjudicate_subjects_without_reviewer, validate_judgment_receipt, JudgmentReceipt, Subject,
};
use legion_runtime::wf_port::w2_039::run_ledger::{Reservation, RunLedger, RunLimits};
use serde_json::json;

// ---- binding.mjs -----------------------------------------------------

#[test]
fn binding_digest_is_order_and_slash_insensitive() {
    let left = json!({"root": "C:\\repo\\pkg", "rev": "abc123"});
    let right = json!({"rev": "abc123", "root": "C:/repo/pkg"});
    assert!(same_binding(Some(&left), Some(&right)));
    assert_eq!(digest(&left), digest(&right));
}

#[test]
fn binding_canonicalize_is_idempotent() {
    let value = json!({"b": [3, {"y": 1, "x": 2}], "a": "p\\q"});
    let once = canonicalize(&value);
    let twice = canonicalize(&once);
    assert_eq!(once, twice);
}

#[derive(Debug)]
struct Plan {
    binding: Option<serde_json::Value>,
}
impl BoundArtifact for Plan {
    fn binding(&self) -> Option<&serde_json::Value> {
        self.binding.as_ref()
    }
}

#[test]
fn binding_assert_artifact_binding_guards_execution_receipts() {
    let sealed_binding = json!({"rev": "abc"});
    let matching = Plan {
        binding: Some(json!({"rev": "abc"})),
    };
    assert!(assert_artifact_binding(Some(&matching), Some(&sealed_binding), "execution-receipt").is_ok());

    let drifted = Plan {
        binding: Some(json!({"rev": "xyz"})),
    };
    let err = assert_artifact_binding(Some(&drifted), Some(&sealed_binding), "execution-receipt")
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "execution-receipt binding does not match sealed plan"
    );
}

// ---- execute-plan.mjs: RunLedger --------------------------------------

#[test]
fn run_ledger_allows_reservations_within_limits() {
    let mut ledger = RunLedger::new(RunLimits {
        max_steps: 5.0,
        max_calls: 5.0,
        max_spend_micros: 1_000.0,
        ..RunLimits::default()
    });
    for _ in 0..5 {
        ledger
            .reserve(Reservation {
                steps: 1.0,
                calls: 1.0,
                spend_micros: 100.0,
            })
            .expect("within limits");
    }
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.steps, 5.0);
    assert_eq!(snapshot.calls, 5.0);
    assert_eq!(snapshot.spend_micros, 500.0);
    assert!(snapshot.terminal.is_none());
}

#[test]
fn run_ledger_stops_the_run_on_the_sixth_step() {
    let mut ledger = RunLedger::new(RunLimits {
        max_steps: 5.0,
        ..RunLimits::default()
    });
    for _ in 0..5 {
        ledger.reserve(Reservation { steps: 1.0, ..Default::default() }).unwrap();
    }
    let err = ledger
        .reserve(Reservation { steps: 1.0, ..Default::default() })
        .expect_err("6th step exceeds max_steps=5");
    assert_eq!(err.code, "LEGION_RUN_BUDGET");
    assert_eq!(err.reason.as_str(), "step-limit");
    // Failed reservation must not have been committed.
    assert_eq!(ledger.snapshot().steps, 5.0);
    assert!(ledger.snapshot().terminal.is_some());
}

// ---- adjudicate-run.mjs -------------------------------------------------

#[test]
fn adjudicate_subjects_disabled_mode_end_to_end() {
    let subjects = vec![
        Subject {
            id: json!("run-1"),
            evidence: vec![json!("artifacts/plan.json")],
        },
        Subject {
            id: json!("run-2"),
            evidence: vec![],
        },
    ];
    let binding = json!({"rev": "abc"});
    let result = adjudicate_subjects_without_reviewer(
        &subjects,
        "disabled",
        Some(&binding),
        Some("audit"),
        false,
    )
    .unwrap();

    assert!(result.complete);
    assert_eq!(result.receipts.len(), 2);
    assert_eq!(result.receipts[0].context_id, "audit-0");
    assert_eq!(result.receipts[1].context_id, "audit-1");
    for receipt in &result.receipts {
        assert_eq!(receipt.status, "skipped");
        assert!(!receipt.complete);
        validate_judgment_receipt(receipt, Some(&binding))
            .expect("skipped receipts must still satisfy the schema invariants");
    }
}

#[test]
fn adjudicate_subjects_required_mode_without_reviewer_blocks_completion() {
    let subjects = vec![Subject {
        id: json!("run-1"),
        evidence: vec![],
    }];
    let result =
        adjudicate_subjects_without_reviewer(&subjects, "required", None, None, false).unwrap();
    assert!(!result.complete);
    assert_eq!(result.receipts[0].status, "unproven");
}

#[test]
fn validate_judgment_receipt_round_trips_through_json() {
    let receipt = JudgmentReceipt {
        schema_version: 1,
        kind: "legion-judgment-receipt".to_string(),
        subject_id: json!("run-1"),
        status: "confirmed".to_string(),
        complete: true,
        binding: Some(json!({"rev": "abc"})),
        context_id: "audit-0".to_string(),
        reviewer: Some(json!("reviewer-a")),
        verdict: Some(json!("confirmed")),
        evidence_refs: vec![json!("artifacts/plan.json")],
        gaps: vec![],
    };
    let expected_binding = json!({"rev": "abc"});
    assert!(validate_judgment_receipt(&receipt, Some(&expected_binding)).is_ok());

    let value = receipt.to_json();
    assert_eq!(value["schemaVersion"], json!(1));
    assert_eq!(value["kind"], json!("legion-judgment-receipt"));
    assert_eq!(value["verdict"], json!("confirmed"));
}
