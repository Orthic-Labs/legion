//! Integration tests for ported chunk w2_040 (`src/lib/core/
//! {execution-receipt,kernel-binding}.mjs` — see
//! `legion_runtime::wf_port::w2_040` doc comment for full disposition of
//! all five files in the chunk, including the two left NOT-STARTED /
//! PORTED-PARTIAL and why).
//!
//! NOTE: this test file assumes the integrator has wired `pub mod wf_port;`
//! (already present in `lib.rs`) and `pub mod w2_040;` inside
//! `src/wf_port/mod.rs` — see the w2_040 report for the exact one-line
//! patch. Until that lands this file will not compile.

use std::collections::BTreeMap;

use legion_runtime::wf_port::w2_040::execution_receipt::{
    blocked, execution_receipt, BlockedSpec, ExecutionReceiptInput, SPAWN_STATUS,
};
use legion_runtime::wf_port::w2_040::kernel_binding::{KernelBinding, KernelPrimitives, ARCANE_NAMESPACE};
use serde_json::json;

// ---- execution-receipt.mjs --------------------------------------------

#[test]
fn spawn_status_is_the_full_closed_set() {
    assert_eq!(SPAWN_STATUS.len(), 11);
    assert!(SPAWN_STATUS.contains(&"completed"));
    assert!(SPAWN_STATUS.contains(&"blocked"));
}

#[test]
fn execution_receipt_requires_provider_and_known_spawn_status() {
    assert!(execution_receipt(ExecutionReceiptInput {
        provider: String::new(),
        spawn_status: "completed".to_string(),
        ..Default::default()
    })
    .is_err());

    assert!(execution_receipt(ExecutionReceiptInput {
        provider: "codex".to_string(),
        spawn_status: "bogus".to_string(),
        ..Default::default()
    })
    .is_err());
}

#[test]
fn execution_receipt_defaults_match_js_shape() {
    let receipt = execution_receipt(ExecutionReceiptInput {
        provider: "claude-code".to_string(),
        spawn_status: "completed".to_string(),
        started_at: Some(2_000),
        completed_at: Some(2_120),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(receipt["schemaVersion"], 1);
    assert_eq!(receipt["kind"], "legion-execution-result");
    assert_eq!(receipt["durationMs"], 120);
    assert_eq!(receipt["stdoutArtifact"]["path"], "raw/claude-code.stdout");
    assert_eq!(receipt["stderrArtifact"]["path"], "raw/claude-code.stderr");
    assert_eq!(receipt["tool"]["status"], "not-applicable");
    assert_eq!(receipt["providerResult"]["provider"], "claude-code");
}

#[test]
fn blocked_produces_a_blocked_receipt_with_coverage_gap() {
    let spec = BlockedSpec {
        provider: Some("gemini".to_string()),
        executable: Some("/usr/bin/gemini".to_string()),
        ..Default::default()
    };
    let receipt = blocked(Some(&spec), "sandbox denied");
    assert_eq!(receipt["spawnStatus"], "blocked");
    assert_eq!(receipt["provider"], "gemini");
    assert_eq!(receipt["command"]["executable"], "/usr/bin/gemini");
    assert_eq!(
        receipt["providerResult"]["coverageGaps"],
        json!([{"kind": "execution-blocked", "reason": "sandbox denied"}])
    );
}

// ---- kernel-binding.mjs ------------------------------------------------

#[test]
fn arcane_namespace_matches_js_constant() {
    assert_eq!(ARCANE_NAMESPACE, "arcane");
}

#[test]
fn unbound_kernel_fails_closed_on_every_canonical_write() {
    let binding = KernelBinding::new();
    let record: BTreeMap<String, String> = BTreeMap::new();

    assert!(!binding.kernel_bound());
    let status = binding.kernel_status();
    assert!(!status.bound);
    assert!(!status.identity);
    assert!(!status.events);
    assert!(!status.objects);

    let err = binding.append_event(ARCANE_NAMESPACE, &record).unwrap_err();
    assert_eq!(err.code, "ARC_KERNEL_PRIMITIVE_UNAVAILABLE");
    assert!(err.fail_closed);

    let err = binding.read_object(ARCANE_NAMESPACE, "run_x").unwrap_err();
    assert_eq!(err.code, "ARC_KERNEL_PRIMITIVE_UNAVAILABLE");

    let err = binding.put_object(ARCANE_NAMESPACE, "run_x", &record).unwrap_err();
    assert_eq!(err.code, "ARC_KERNEL_PRIMITIVE_UNAVAILABLE");
}

#[test]
fn unbound_kernel_mints_provisional_ids_of_correct_grammar() {
    let binding = KernelBinding::new();
    let minted = binding.mint_id("request").unwrap();
    assert!(minted.provisional);
    assert!(minted.id.starts_with("req_"));
    assert_eq!(minted.id.len(), "req_".len() + 26);

    let err = binding.mint_id("no-such-family").unwrap_err();
    assert_eq!(err.code, "ARC_ID_INVALID");
}

struct RecordingKernel;

impl KernelPrimitives for RecordingKernel {
    fn mint_id(&self, family: &str) -> Option<String> {
        Some(format!("bound-{family}"))
    }
    fn has_mint_id(&self) -> bool {
        true
    }
}

#[test]
fn binding_a_partial_kernel_reports_only_the_bound_primitives() {
    let binding = KernelBinding::new();
    binding.bind_kernel(Box::new(RecordingKernel));
    assert!(binding.kernel_bound());

    let status = binding.kernel_status();
    assert!(status.bound);
    assert!(status.identity);
    // RecordingKernel implements only mint_id; events/objects stay unbound
    // and must still fail closed even though the binding as a whole is
    // "bound" — this is the exact honesty guarantee kernel-binding.mjs's
    // per-primitive `Boolean(bound?.foo)` status reporting exists for.
    assert!(!status.events);
    assert!(!status.objects);

    let minted = binding.mint_id("claim").unwrap();
    assert_eq!(minted.id, "bound-claim");
    assert!(!minted.provisional);

    let record: BTreeMap<String, String> = BTreeMap::new();
    let err = binding.append_event(ARCANE_NAMESPACE, &record).unwrap_err();
    assert_eq!(err.code, "ARC_KERNEL_PRIMITIVE_UNAVAILABLE");

    binding.unbind_kernel();
    assert!(!binding.kernel_bound());
}
