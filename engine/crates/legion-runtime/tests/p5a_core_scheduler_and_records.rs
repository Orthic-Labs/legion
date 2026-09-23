//! Packet P5a-core integration tests: exercise the p5_core public API
//! surface for the src/lib/core scheduler and small record ports
//! (scheduler.mjs, completeness.mjs, judgment-packets.mjs,
//! reviewer-policy.mjs, claim-levels.mjs, run-layout.mjs,
//! plan-stages/registry.mjs) from outside the crate, the way a caller
//! would use them.

use legion_runtime::p5_core::{
    achieved_claim_level, build_judgment_packet, reconcile_claim, required_stages_for, run_layout,
    reviewer_policy, schedule_providers, JudgmentPacketInput, ScheduleMode, ScheduleOptions,
    SchedulerProvider, CLAIM_LEVELS, PLANNING_STAGE_IDS,
};
use serde_json::Value;
use std::collections::BTreeMap;

#[test]
fn schedule_providers_serial_mode_runs_one_at_a_time() {
    let providers = vec![SchedulerProvider::new("a"), SchedulerProvider::new("b")];
    let opts = ScheduleOptions {
        mode: ScheduleMode::Serial,
        concurrency: 4,
        resources: None,
    };
    let result = schedule_providers(&providers, &opts).unwrap();
    assert_eq!(result.waves.len(), 2);
    assert_eq!(result.waves[0].len(), 1);
    assert_eq!(result.waves[1].len(), 1);
}

#[test]
fn claim_levels_constant_matches_expected_order() {
    assert_eq!(
        CLAIM_LEVELS,
        ["inventory", "source", "runtime", "product", "release"]
    );
}

#[test]
fn planning_stage_ids_has_twelve_fixed_stages() {
    assert_eq!(PLANNING_STAGE_IDS.len(), 12);
    assert_eq!(PLANNING_STAGE_IDS[0], "repository-binding");
    assert_eq!(PLANNING_STAGE_IDS[11], "plan-sealing");
}

#[test]
fn required_stages_source_level_excludes_runtime_only_stages() {
    let stages = required_stages_for("source");
    assert!(stages.contains(&"control-baseline"));
    assert!(!stages.contains(&"provider-dag"));
}

#[test]
fn run_layout_root_and_directory_count_roundtrip() {
    let layout = run_layout("/tmp/run");
    assert_eq!(layout.root, "/tmp/run");
    assert!(layout.directories.contains(&"reports".to_string()));
}

#[test]
fn reconcile_claim_end_to_end() {
    let result = reconcile_claim(
        &["evidence-a".to_string(), "evidence-b".to_string()],
        &["evidence-a".to_string()],
    );
    assert!(!result.complete);
    assert_eq!(result.gaps, vec!["evidence-b".to_string()]);
}

#[test]
fn build_judgment_packet_end_to_end() {
    let packet = build_judgment_packet(JudgmentPacketInput {
        subject: Value::String("subject-1".into()),
        evidence: vec![Value::String("e1".into())],
        omitted: vec![],
        reviewer_role: "senior".into(),
        budget: serde_json::json!({"maxTokens": 100}),
        lens: None,
    });
    assert_eq!(packet["reviewerRole"], "senior");
    assert_eq!(packet["evidence"], serde_json::json!(["e1"]));
}

#[test]
fn reviewer_policy_end_to_end_fresh_context() {
    let policy = reviewer_policy("producer-1", "reviewer-1", "ctx-99", &[]).unwrap();
    assert_eq!(policy.producer, "producer-1");
    assert_eq!(policy.reviewer, "reviewer-1");
    assert!(policy.fresh);
}

#[test]
fn achieved_claim_level_end_to_end() {
    let mut decisions = BTreeMap::new();
    decisions.insert("inventory".to_string(), "pass".to_string());
    assert_eq!(achieved_claim_level(&decisions), Some("inventory"));
}
