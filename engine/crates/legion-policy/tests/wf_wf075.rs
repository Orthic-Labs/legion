//! Integration tests for wf075: faithful Rust ports of
//! `src/lib/verification/arcane/s11-bindings/m7-production.mjs`,
//! `src/lib/verification/arcane/scoped-acceptance.mjs`, and
//! `src/lib/verification/arcane/seal-reachability.mjs`.
//!
//! Unit tests for each behavior already live alongside the ported code
//! under `src/wf_port/wf075/*.rs`; this file exercises the same three
//! modules from the crate's public surface, as an integration owner would
//! once `wf_port`/`wf075` (and wf070, which `m7_production` depends on) are
//! wired into `legion-policy`'s `src/lib.rs` — see this packet's report.

use legion_policy::wf_port::wf070::canon::CanonVal;
use legion_policy::wf_port::wf075::{m7_production, scoped_acceptance, seal_reachability};

#[test]
fn m7_binding_ids_lists_all_three_bindings_sorted() {
    assert_eq!(
        m7_production::m7_binding_ids(),
        vec!["AE-CONVERGENCE-006", "AE-STATE-TRANSITIONS-REPLAY-002", "AE-TRAJECTORY-RESUME-002"]
    );
}

#[test]
fn m7_full_replay_binding_reconstructs_identical_state() {
    let obs = m7_production::execute_m7_binding("AE-STATE-TRANSITIONS-REPLAY-002").expect("known binding");
    assert_eq!(obs.producer, "ArchitectureEventStore.accept/replay");
    assert_eq!(obs.value.get("acceptedFingerprint"), obs.value.get("replayFingerprint"));
    assert_eq!(obs.value.get("eventCount"), Some(&CanonVal::Int(6)));
}

#[test]
fn m7_revision_tripwire_binding_rejects_fourth_revision() {
    let obs = m7_production::execute_m7_binding("AE-CONVERGENCE-006").expect("known binding");
    assert_eq!(obs.value.get("fourthRejected"), Some(&CanonVal::Bool(true)));
    assert_eq!(obs.value.get("revisions"), Some(&CanonVal::Int(3)));
}

#[test]
fn m7_epoch_mismatch_binding_denies_resume() {
    let obs = m7_production::execute_m7_binding("AE-TRAJECTORY-RESUME-002").expect("known binding");
    assert_eq!(obs.value.get("valid"), Some(&CanonVal::Bool(false)));
    assert_eq!(obs.value.get("resume_authorized"), Some(&CanonVal::Bool(false)));
}

#[test]
fn m7_unknown_binding_id_returns_none() {
    assert!(m7_production::execute_m7_binding("NOT-A-BINDING").is_none());
}

fn item(id: &str) -> CanonVal {
    CanonVal::obj().set("id", CanonVal::Str(id.to_string()))
}

fn stage(id: &str, deps: &[&str], items: &[&str]) -> CanonVal {
    CanonVal::obj()
        .set("stage_id", CanonVal::Str(id.to_string()))
        .set("owner", CanonVal::Str("owner-a".to_string()))
        .set("dependencies", CanonVal::Arr(deps.iter().map(|d| CanonVal::Str(d.to_string())).collect()))
        .set("required_items", CanonVal::Arr(items.iter().map(|i| item(i)).collect()))
}

fn schedule(version: i64) -> CanonVal {
    CanonVal::obj().set("schedule_version", CanonVal::Int(version)).set("waves", CanonVal::Arr(vec![]))
}

#[test]
fn scoped_acceptance_fingerprint_requires_item_id() {
    let bad = CanonVal::obj();
    assert!(scoped_acceptance::fingerprint_acceptance_item(&bad).is_err());
}

#[test]
fn scoped_acceptance_diff_marks_dependents_invalidated() {
    let prev_stages = vec![stage("s1", &[], &["i1"]), stage("s2", &["s1"], &["i2"])];
    let next_stages = vec![stage("s1", &[], &["i1-v2"]), stage("s2", &["s1"], &["i2"])];
    let sched = schedule(1);
    let previous = scoped_acceptance::ScopedAcceptanceSpec { stages: &prev_stages, schedule: &sched };
    let next = scoped_acceptance::ScopedAcceptanceSpec { stages: &next_stages, schedule: &sched };
    let diff = scoped_acceptance::diff_scoped_acceptance(&previous, &next).expect("valid stages");
    assert!(diff.acceptance_changed);
    assert_eq!(diff.directly_changed_stage_ids, vec!["s1".to_string()]);
    assert_eq!(diff.invalidated_stage_ids, vec!["s1".to_string(), "s2".to_string()]);
    assert!(diff.preserved_stage_ids.is_empty());
}

#[test]
fn scoped_acceptance_diff_no_change_preserves_all_stages() {
    let stages = vec![stage("s1", &[], &["i1"]), stage("s2", &["s1"], &["i2"])];
    let sched = schedule(1);
    let spec = scoped_acceptance::ScopedAcceptanceSpec { stages: &stages, schedule: &sched };
    let diff = scoped_acceptance::diff_scoped_acceptance(&spec, &spec).expect("valid stages");
    assert!(!diff.acceptance_changed);
    assert!(!diff.schedule_changed);
    assert_eq!(diff.preserved_stage_ids, vec!["s1".to_string(), "s2".to_string()]);
}

fn sound_requirement(id: &str) -> seal_reachability::SealRequirement {
    seal_reachability::SealRequirement {
        id: Some(id.to_string()),
        producer: Some("producer-a".to_string()),
        durable_store: true,
        authenticated_persistence: true,
        verifier: Some("verifier-b".to_string()),
        completion_consumer: Some("consumer-c".to_string()),
        close_path: true,
        ..Default::default()
    }
}

#[test]
fn seal_reachability_sound_seal_with_recovery_path_is_allowed() {
    let req = sound_requirement("r1");
    let path = seal_reachability::RecoveryPath { requirement_id: "r1".to_string(), authenticated: true, close_path: true };
    let decision = seal_reachability::compile_seal_reachability(&[req], &[], &[path]);
    assert!(decision.allowed);
    assert_eq!(decision.code, None);
}

#[test]
fn seal_reachability_missing_lifecycle_step_is_denied() {
    let mut req = sound_requirement("r1");
    req.close_path = false;
    let decision = seal_reachability::compile_seal_reachability(&[req], &[], &[]);
    assert!(!decision.allowed);
    assert_eq!(decision.code, Some("ARC_UNSOUND_SEAL"));
}

#[test]
fn seal_reachability_self_attested_producer_equals_verifier_is_denied() {
    let mut req = sound_requirement("r1");
    req.verifier = req.producer.clone();
    let path = seal_reachability::RecoveryPath { requirement_id: "r1".to_string(), authenticated: true, close_path: true };
    let decision = seal_reachability::compile_seal_reachability(&[req], &[], &[path]);
    assert!(!decision.allowed);
}

#[test]
fn seal_reachability_external_provider_capability_gates_soundness() {
    let mut req = sound_requirement("r1");
    req.external_provider = Some("prov-x".to_string());
    let path = seal_reachability::RecoveryPath { requirement_id: "r1".to_string(), authenticated: true, close_path: true };

    let unreachable = seal_reachability::compile_seal_reachability(&[req.clone()], &[], &[path.clone()]);
    assert!(!unreachable.allowed);

    let cap = seal_reachability::ProviderCapability {
        provider_id: Some("prov-x".to_string()),
        machine_readable: true,
        gateable: true,
        downloadable: true,
        trusted_retrieval: true,
        trajectory_bindable: true,
        sensitivity: Some("normal".to_string()),
        retention: Some("30d".to_string()),
        deletion_owner: Some("host".to_string()),
    };
    let reachable = seal_reachability::compile_seal_reachability(&[req], &[cap], &[path]);
    assert!(reachable.allowed);
}
