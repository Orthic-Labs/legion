//! Integration tests for chunk w2_047
//! (`src/lib/host/arcane/{hook-adapter-core,host-event-ledger,host-event,
//! host-runtime-output,legacy-bridge}.mjs`).
//!
//! NOTE: as of this chunk, `wf_port/mod.rs` does not yet declare `pub mod
//! w2_047;` (the integrator wires that, per the chunk assignment). This file
//! compiles once that wiring lands.

use legion_runtime::wf_port::w2_047::host_event::{classify_observation, normalize_host_event};
use legion_runtime::wf_port::w2_047::hook_adapter_pure::{
    classify_vcs_push, command_of, is_destructive_command, vcs_rewrite_approval_key,
};
use legion_runtime::wf_port::w2_047::host_runtime_output::{
    render_host_runtime_output, serialize_host_runtime_output, DecisionEnvelope,
};
use legion_runtime::wf_port::w2_047::observation_outbox::ObservationOutbox;
use serde_json::{json, Value as Json};

fn deny_envelope() -> DecisionEnvelope {
    DecisionEnvelope {
        code: Some("ARC_EFFECT_CLASS_UNAUTHORIZED".to_string()),
        public_reason: "ARC_EFFECT_CLASS_UNAUTHORIZED: Effect class is not authorized.".to_string(),
        enforcement_health: "strong".to_string(),
        retry_signature: Json::Null,
        termination: Json::Null,
        certification: Json::Null,
        missing_classes: Json::Null,
        responsible_producer: Json::Null,
        remediation_routes: Json::Null,
        missing_evidence: Json::Null,
    }
}

/// End-to-end: a hook payload carrying a destructive `rm -rf` command is
/// refused before it would ever reach `normalize_host_event`/ingestion — the
/// exact ordering `handleHookEvent` uses (destructive check first).
#[test]
fn destructive_command_pipeline_shape() {
    let hook_payload = json!({
        "eventType": "PreToolUse",
        "tool_input": {"command": "rm -rf /important"},
        "workspace": "/repo",
    });
    let command = command_of(&hook_payload);
    assert!(is_destructive_command(command));

    // The host event itself still normalizes fine (a caller may want to log
    // it even though the effect is refused).
    let raw = json!({"eventType": "PreToolUse", "workspace": "/repo"});
    let event = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "2026-01-01T00:00:00Z".to_string()).unwrap();
    assert_eq!(event["eventType"], "pre-effect");

    let output = render_host_runtime_output("PreToolUse", false, false, deny_envelope).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    let serialized = serialize_host_runtime_output(Some(&output));
    assert!(serialized.ends_with('\n'));
}

/// A non-destructive `git push --force origin main` is classified as a
/// target-bound rewrite and escalated (asked, not flatly denied) when no
/// approval store consumed a matching key — mirroring
/// `handleHookEvent`'s VCS-rewrite branch shape.
#[test]
fn vcs_force_push_escalates_with_target_bound_key() {
    let hook_payload = json!({"tool_input": {"command": "git push --force origin main"}});
    let command = command_of(&hook_payload);
    assert!(!is_destructive_command(command));

    let push = classify_vcs_push(command).unwrap();
    assert!(push.rewrite);
    let key = vcs_rewrite_approval_key(Some("session-1"), Some(&push));
    assert_eq!(key.as_deref(), Some("session-1|VCS_PUSH|origin/main"));

    // No approval consumed -> escalate: true, so the render is 'ask', not 'deny'.
    let output = render_host_runtime_output("PreToolUse", false, true, deny_envelope).unwrap();
    assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "ask");
}

/// A successful `FILE_WRITE` observation normalizes and classifies as a
/// mutation, end to end from raw hook JSON.
#[test]
fn file_write_observation_classifies_as_mutation() {
    let raw = json!({
        "eventType": "PostToolUse",
        "workspace": "/repo",
        "effect": {"effectClass": "FILE_WRITE", "target": "/repo/a.txt", "operation": "write"},
        "result": {"outcome": "success", "exitCode": 0, "terminal": true, "observedDigest": null},
    });
    let event = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "x".to_string()).unwrap();
    assert_eq!(event["eventType"], "post-effect");
    assert_eq!(classify_observation(&event, None), "mutation-observation");
}

/// A failed effect is classified `failure` even when its effect class would
/// otherwise be a mutation — the ordering `classifyObservation` enforces.
#[test]
fn failed_effect_is_failure_not_mutation() {
    let raw = json!({
        "eventType": "PostToolUse",
        "workspace": "/repo",
        "effect": {"effectClass": "FILE_WRITE", "target": "/repo/a.txt", "operation": "write"},
        "result": {"outcome": "failure", "exitCode": 1, "terminal": true, "observedDigest": null},
    });
    let event = normalize_host_event(&raw, None, || "hev_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(), || "x".to_string()).unwrap();
    assert_eq!(classify_observation(&event, None), "failure");
}

/// Observation outbox: enqueue -> next_batch -> acknowledge round trip using
/// a real temp directory, mirroring the JS `ObservationOutbox` durability
/// contract (delivered entries leave `pending`).
#[test]
fn observation_outbox_round_trip() {
    let dir = std::env::temp_dir().join(format!("wf_w2_047_it_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let outbox = ObservationOutbox::new(&dir).unwrap();

    let (event_id, dup) = outbox.enqueue(json!({"runId": "r1", "usage": {"calls": 1}}), Some("ev-1".to_string())).unwrap();
    assert!(!dup);
    let batch = outbox.next_batch(10, usize::MAX).unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].event_id, event_id);

    let delivered = outbox.acknowledge(&[event_id], Some(json!({"ok": true}))).unwrap();
    assert_eq!(delivered, 1);
    let (pending, delivered_count, dead) = outbox.inspect().unwrap();
    assert_eq!((pending, delivered_count, dead), (0, 1, 0));

    let _ = std::fs::remove_dir_all(&dir);
}
