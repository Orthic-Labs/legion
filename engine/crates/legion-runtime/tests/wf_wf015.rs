//! Tests ported from `tests/remediation/apply.test.mjs` and
//! `tests/remediation/worktree.test.mjs` for wf015
//! (`src/lib/remediation/{agent-patch,apply,checkpoint,cleanup,code-proposal}.mjs`).
//!
//! This test file depends on `legion_runtime::wf_port::wf015`, which is not
//! yet wired into `legion-runtime`'s public module tree (the integrator adds
//! `pub mod wf_port;` in `src/lib.rs` and `pub mod wf015;` in
//! `src/wf_port/mod.rs` per the wf015 chunk assignment). Until that wiring
//! lands, this file will not compile as part of the crate's test target.

use std::future::Future;
use std::pin::Pin;

use legion_runtime::wf_port::wf015::{
    agent_patch_packet, agent_patch_proposal, apply_receipt, checkpoint_digest, cleanup_receipt,
    code_proposal, create_checkpoint, require_apply_capability, restore_plan, rollback_receipt,
    tree_fingerprint, HostCapabilities, PatchInfo, ProcessOutcome, ProcessRunner,
};
use serde_json::json;

// ---------------------------------------------------------------------------
// apply.test.mjs
// ---------------------------------------------------------------------------

#[test]
fn apply_requires_explicit_host_mutation_capability() {
    // JS: assert.throws(() => requireApplyCapability({ capabilities: { mutation: false } }), /mutation capability/);
    let err = require_apply_capability(&HostCapabilities { mutation: false }).unwrap_err();
    assert!(err.to_string().contains("mutation capability"));

    // JS: assert.doesNotThrow(() => requireApplyCapability({ capabilities: { mutation: true } }));
    assert!(require_apply_capability(&HostCapabilities { mutation: true }).is_ok());
}

#[test]
fn apply_verifies_the_target_tree_fingerprint_before_apply() {
    let before = tree_fingerprint(&["a.ts".to_string()]);
    let after = tree_fingerprint(&["a.ts".to_string(), "b.ts".to_string()]);
    assert_ne!(before, after);

    let receipt = apply_receipt("p1", "sha256:p", "/w", &before, &after, true);
    assert!(receipt.applied);
    assert!(!receipt.rolled_back);
}

#[test]
fn rollback_restores_the_pre_apply_fingerprint() {
    let before = tree_fingerprint(&["a.ts".to_string()]);
    let after = tree_fingerprint(&["a.ts".to_string(), "b.ts".to_string()]);
    let apply = apply_receipt("p1", "sha256:p", "/w", &before, &after, true);
    let rollback = rollback_receipt(Some(&apply), "sha256:rev", &before, "/w");
    assert!(rollback.restored);
}

#[test]
fn rollback_with_no_prior_apply_never_reports_restored() {
    // Extends the ported case: JS `rollbackReceipt({ apply: undefined, ... })`
    // reads `apply?.beforeFingerprint` as `undefined`, so
    // `restoredFingerprint === apply?.beforeFingerprint` is always `false`.
    let rollback = rollback_receipt(None, "sha256:rev", "sha256:anything", "/w");
    assert!(!rollback.restored);
    assert!(rollback.apply_digest.is_none());
}

// ---------------------------------------------------------------------------
// worktree.test.mjs (checkpoint/cleanup portion only — this chunk does not
// own worktree.mjs or provenance/passport.mjs)
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_digest_is_deterministic_and_restore_plan_is_a_reverse() {
    let checkpoint = create_checkpoint(
        "/w",
        "abc",
        &["a.ts".to_string(), "b.ts".to_string()],
    );
    let again = create_checkpoint(
        "/w",
        "abc",
        &["b.ts".to_string(), "a.ts".to_string()],
    );
    assert_eq!(checkpoint.digest, again.digest);

    let restore = restore_plan(&checkpoint);
    assert_eq!(restore.kind, "legion-checkpoint-restore");
    assert_eq!(restore.steps.len(), 2);
    assert!(restore.recovery_command.contains("git -C /w checkout"));
}

#[test]
fn checkpoint_digest_helper_matches_create_checkpoint() {
    let checkpoint = create_checkpoint("/w", "abc", &["a.ts".to_string()]);
    let body = json!({
        "schemaVersion": 1,
        "kind": "legion-remediation-checkpoint",
        "worktreePath": "/w",
        "baseCommit": "abc",
        "files": ["a.ts"],
        "createdAt": null,
    });
    assert_eq!(checkpoint.digest, checkpoint_digest(&body));
}

#[test]
fn cleanup_receipt_keeps_exact_recovery_commands_on_failure() {
    let receipt = cleanup_receipt(
        "/w",
        false,
        Some("in-use".to_string()),
        Some(vec![
            "git".to_string(),
            "worktree".to_string(),
            "remove".to_string(),
            "--force".to_string(),
            "/w".to_string(),
        ]),
        None,
    );
    assert!(!receipt.removed);
    assert!(receipt.recovery_command.is_some());
    assert_eq!(receipt.error.as_deref(), Some("in-use"));
}

#[test]
fn cleanup_receipt_on_success_clears_error_and_residuals() {
    let receipt = cleanup_receipt("/w", true, None, None, None);
    assert!(receipt.removed);
    assert!(receipt.error.is_none());
    assert!(receipt.residual_paths.is_empty());
    assert!(receipt.recovery_command.is_none());
}

// ---------------------------------------------------------------------------
// restore_checkpoint / cleanup_sandbox async paths (no direct JS test exists
// for these beyond the sync helpers above; covered here against the
// `ProcessRunner` contract itself).
// ---------------------------------------------------------------------------

struct FakeRunner {
    fail: bool,
}

impl ProcessRunner for FakeRunner {
    fn run<'a>(
        &'a self,
        _executable: &'a str,
        _args: &'a [String],
        _cwd: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = ProcessOutcome> + Send + 'a>> {
        Box::pin(async move {
            if self.fail {
                ProcessOutcome {
                    exit_code: 1,
                    stderr: Some("boom".to_string()),
                }
            } else {
                ProcessOutcome {
                    exit_code: 0,
                    stderr: None,
                }
            }
        })
    }
}

#[tokio::test]
async fn restore_checkpoint_reports_failure_with_recovery_command() {
    use legion_runtime::wf_port::wf015::restore_checkpoint;

    let checkpoint = create_checkpoint("/w", "abc", &["a.ts".to_string()]);
    let runner = FakeRunner { fail: true };
    let receipt = restore_checkpoint(&checkpoint, &runner).await;
    assert!(!receipt.restored);
    assert_eq!(receipt.error.as_deref(), Some("boom"));
    assert!(receipt.recovery_command.contains("git -C /w checkout"));
}

#[tokio::test]
async fn restore_checkpoint_with_no_files_is_a_no_op_success() {
    use legion_runtime::wf_port::wf015::restore_checkpoint;

    let checkpoint = create_checkpoint("/w", "abc", &[]);
    let runner = FakeRunner { fail: true };
    let receipt = restore_checkpoint(&checkpoint, &runner).await;
    assert!(receipt.restored);
    assert!(receipt.files.is_empty());
}

#[tokio::test]
async fn cleanup_sandbox_reports_failure_with_residual_paths() {
    use legion_runtime::wf_port::wf015::{cleanup_sandbox, Sandbox};

    let sandbox = Sandbox {
        sandbox_path: Some("/w".to_string()),
        cleanup_command: None,
        cleanup_cwd: None,
        created_paths: vec!["/w/extra".to_string()],
    };
    let runner = FakeRunner { fail: true };
    let receipt = cleanup_sandbox(&sandbox, &runner).await;
    assert!(!receipt.removed);
    assert_eq!(receipt.error.as_deref(), Some("boom"));
    assert_eq!(
        receipt.recovery_command,
        Some(vec![
            "git".to_string(),
            "worktree".to_string(),
            "remove".to_string(),
            "--force".to_string(),
            "/w".to_string(),
        ])
    );
    assert!(receipt.residual_paths.contains(&"/w".to_string()));
    assert!(receipt.residual_paths.contains(&"/w/extra".to_string()));
}

// ---------------------------------------------------------------------------
// agent-patch.mjs / code-proposal.mjs — no dedicated JS test file exists for
// these two modules; shape-level assertions cover the fields the module doc
// comment says are load-bearing (bounded packet, producer-not-verifier tier).
// ---------------------------------------------------------------------------

#[test]
fn agent_patch_packet_is_bounded_and_sorts_scope() {
    let packet = agent_patch_packet(
        "f1",
        Some("sha256:root"),
        "/worktree",
        &["b".to_string(), "a".to_string()],
        None,
    );
    assert_eq!(packet["kind"], "legion-agent-patch-packet");
    assert_eq!(packet["bounded"], true);
    assert_eq!(packet["maxBatches"], 4);
    assert_eq!(packet["scope"], json!(["a", "b"]));
    assert_eq!(
        packet["verification"],
        "performed by neutral verification after the packet returns"
    );
}

#[test]
fn agent_patch_proposal_is_tiered_agent_guided() {
    let proposal = agent_patch_proposal(
        "f1",
        None,
        Some("packet-1"),
        Some("model-x"),
        &PatchInfo {
            path: "patches/agent.patch".to_string(),
            digest: Some("sha256:patch".to_string()),
        },
        &[],
        &[],
        &[],
    );
    assert_eq!(proposal["tier"], "AGENT_GUIDED");
    assert_eq!(proposal["findingId"], "f1");
    assert_eq!(proposal["producer"]["kind"], "agent-guided");
    assert_eq!(proposal["producer"]["packetId"], "packet-1");
    assert!(proposal["id"].as_str().unwrap().starts_with("sha256:"));
}

#[test]
fn code_proposal_pulls_patch_from_changes_and_sets_validation_plan() {
    let packet = json!({ "packetId": "packet-1" });
    let changes = vec![
        json!({ "kind": "text" }),
        json!({ "kind": "source-patch", "patch": { "path": "a.patch", "digest": "sha256:x" } }),
    ];
    let binding = json!({ "runId": "run-1" });
    let proposal = code_proposal(&packet, &changes, &binding);
    assert_eq!(proposal["owner"], "code");
    assert_eq!(proposal["packetId"], "packet-1");
    assert_eq!(proposal["patch"]["path"], "a.patch");
    assert_eq!(
        proposal["validationPlan"],
        json!(["parse-check", "affected-provider-rerun", "baseline-gate-recheck"])
    );
    assert_eq!(proposal["affectedFamilies"], json!(["security", "code"]));
}

#[test]
fn code_proposal_with_no_patch_in_changes_is_null() {
    let packet = json!({ "packetId": "packet-1" });
    let changes = vec![json!({ "kind": "text" })];
    let binding = json!({});
    let proposal = code_proposal(&packet, &changes, &binding);
    assert!(proposal["patch"].is_null());
}
