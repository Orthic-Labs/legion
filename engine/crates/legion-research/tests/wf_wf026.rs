//! Integration-level parity test for wf026 (research-core budget metering
//! and patch-stage scripts: `meter.py`, `patch_guard.py`, `patcher.py`),
//! exercised against the crate's public API rather than the in-module unit
//! tests under `src/wf_port/wf026/*.rs`.
//!
//! NOTE: this file depends on `pub mod wf_port;` and, inside it,
//! `pub mod wf026;` landing in `src/lib.rs` / `src/wf_port/mod.rs` — files
//! this packet does not own. The exact patch is in the packet report.
//! Until the integrator applies it, this file will not compile.

use std::fs;
use std::path::PathBuf;

use legion_research::wf_port::wf026::patch_guard;
use legion_research::wf_port::wf026::patcher;
use legion_research::wf_port::wf026::{meter, patcher::DEFAULT_MAX_HUNKS, patcher::DEFAULT_MAX_HUNK_BYTES};
use serde_json::json;
use sha2::{Digest, Sha256};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_wf026")
}

/// Copies the fixture run directory into a scratch temp dir so tests never
/// mutate the checked-in fixture.
fn scratch_run_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "legion-wf026-integration-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::copy(
        fixtures_dir().join("run_ok/manifest.json"),
        dir.join("manifest.json"),
    )
    .unwrap();
    dir
}

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "legion-wf026-integration-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn meter_consume_matches_meter_py_external_request_success() {
    let run_dir = scratch_run_dir("meter-external-ok");
    let result = meter::consume(&run_dir, "external_request", 1, None).unwrap();
    assert_eq!(result["ok"], json!(true));
    assert_eq!(result["usage"]["external_requests"], json!(1));
    assert_eq!(result["budget"]["external_requests"], json!(12));
}

#[test]
fn meter_consume_matches_meter_py_worker_lifecycle() {
    let run_dir = scratch_run_dir("meter-worker-lifecycle");
    let start = meter::consume(&run_dir, "worker", 1, Some("start")).unwrap();
    assert_eq!(start["ok"], json!(true));
    assert_eq!(start["usage"]["workers_active"], json!(1));
    assert_eq!(start["usage"]["workers_started"], json!(1));

    let finish = meter::consume(&run_dir, "worker", 1, Some("finish")).unwrap();
    assert_eq!(finish["ok"], json!(true));
    assert_eq!(finish["usage"]["workers_active"], json!(0));
    // workers_started is never decremented by a finish event.
    assert_eq!(finish["usage"]["workers_started"], json!(1));
}

#[test]
fn meter_consume_refuses_over_budget_worker_start() {
    let run_dir = scratch_run_dir("meter-worker-over-budget");
    // budget.workers is 1 in the fixture; two starts must refuse the second.
    let first = meter::consume(&run_dir, "worker", 1, Some("start")).unwrap();
    assert_eq!(first["ok"], json!(true));

    let second = meter::consume(&run_dir, "worker", 1, Some("start")).unwrap();
    assert_eq!(second["ok"], json!(false));
    assert_eq!(
        second["reason"],
        json!("research budget exceeded: workers_active 2 > 1")
    );
}

/// End-to-end: `patch_guard::issue_receipt` on the fixture draft, then
/// `patcher::apply_patch` a diff against it, gated by a receipt that
/// (faithfully, matching the Python originals — see the module docs on
/// this mismatch) `validate_correction_receipt` rejects because of the
/// `issued_by` inconsistency between the two Python scripts.
#[test]
fn patch_guard_receipt_is_rejected_by_patcher_validation_same_as_python() {
    let dir = scratch_dir("patch-guard-mismatch");
    let draft = fixtures_dir().join("draft.md");
    let receipt = patch_guard::issue_receipt(&draft, "run-fixture-ok", Some(&dir.join("key"))).unwrap();

    let draft_bytes = fs::read(&draft).unwrap();
    let (ok, reason) =
        patcher::validate_correction_receipt(&receipt, Some(&draft_bytes), Some(&dir.join("key")));
    assert!(!ok);
    assert_eq!(reason, "receipt must be an authenticated rhook patch receipt v2");
}

/// Applying a correction diff directly (bypassing the receipt mismatch
/// above) still matches `patcher.apply_patch`'s hunk relocation and output.
#[test]
fn patcher_apply_patch_matches_apply_patch_py_on_fixture_draft() {
    let draft = fixtures_dir().join("draft.md");
    let source = fs::read_to_string(&draft).unwrap();
    let diff = "--- a\n+++ b\n@@ -1,3 +1,3 @@\n line1\n-line2\n+LINE2 corrected\n line3\n";

    let result = patcher::apply_patch(&source, diff, DEFAULT_MAX_HUNKS, DEFAULT_MAX_HUNK_BYTES);
    assert!(result.ok, "reason: {:?}", result.reason);
    assert_eq!(result.applied, 1);
    assert_eq!(result.output.unwrap(), "line1\nLINE2 corrected\nline3\n");
}

/// A receipt built with `issued_by: "rhook.research-patch-guard"` (the
/// value `patcher.validate_correction_receipt` actually requires, matching
/// `test_research_stopping.py`-style hand-built fixtures elsewhere in this
/// packet's test suite) validates and gates a successful patch apply.
#[test]
fn valid_rhook_receipt_gates_a_successful_patch_apply() {
    let dir = scratch_dir("patch-guard-valid");
    let draft = fixtures_dir().join("draft.md");
    let draft_bytes = fs::read(&draft).unwrap();
    let source = String::from_utf8(draft_bytes.clone()).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&draft_bytes);
    let draft_sha256 = hex::encode(hasher.finalize());

    let key_path = dir.join("key");
    let mut receipt = json!({
        "receipt_version": 2,
        "issued_by": "rhook.research-patch-guard",
        "issued_at": "2026-01-01T00:00:00Z",
        "run_id": "run-fixture-ok",
        "stage": "patch",
        "allowed_tools": ["Read", "Edit"],
        "sourced_draft_sha256": draft_sha256,
        "max_hunks": 8,
        "max_hunk_bytes": 4096,
    });
    let key = patch_guard::load_or_create_key(Some(&key_path)).unwrap();
    receipt["signature"] = json!(patch_guard::sign(&receipt, &key));

    let (ok, reason) = patcher::validate_correction_receipt(&receipt, Some(&draft_bytes), Some(&key_path));
    assert!(ok, "reason: {reason}");

    let diff = "--- a\n+++ b\n@@ -1,3 +1,3 @@\n line1\n-line2\n+LINE2\n line3\n";
    let result = patcher::apply_patch(
        &source,
        diff,
        receipt["max_hunks"].as_u64().unwrap() as u32,
        receipt["max_hunk_bytes"].as_u64().unwrap() as u32,
    );
    assert!(result.ok, "reason: {:?}", result.reason);
    assert_eq!(result.output.unwrap(), "line1\nLINE2\nline3\n");
}
