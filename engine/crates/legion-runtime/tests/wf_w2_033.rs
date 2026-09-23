//! Chunk w2_033 integration smoke tests exercising the `wf_port::w2_033` module's public
//! entry points end to end, per the "assert on the production entry point" rule.

use legion_runtime::wf_port::w2_033::rank_tracker::{compare, normalize, NormalizeDefaults};
use legion_runtime::wf_port::w2_033::search_ops::{
    brief, deploy, outcome, start, verify, Deployment, Evaluation, Intervention, Outcome,
    SearchOpsState, SCHEMA_VERSION,
};
use legion_runtime::wf_port::w2_033::seo_closure::{headings, validate_phases, PhaseRange};
use legion_runtime::wf_port::w2_033::seo_project::{cache_key, env_state, preflight, PlannedCall};
use serde_json::json;
use std::collections::BTreeSet;

#[test]
fn rank_tracker_normalize_and_compare_round_trip() {
    let defaults = NormalizeDefaults {
        market: Some("US".into()),
        language: Some("en".into()),
        device: None,
        provider: Some("provider-x".into()),
        collected_at: Some("2026-01-01T00:00:00Z".into()),
    };
    let prev = vec![normalize(
        &json!({"keyword": "widgets", "position": 8, "observed_url": "https://ex.com/a"}),
        &defaults,
        "now",
    )
    .unwrap()];
    let curr = vec![normalize(
        &json!({"keyword": "widgets", "position": 2, "observed_url": "https://ex.com/b",
                 "intended_page": "https://ex.com/a"}),
        &defaults,
        "now",
    )
    .unwrap()];
    let result = compare(&prev, &curr);
    assert_eq!(result.status, "ok");
    assert_eq!(result.ownership_changes, 1);
    assert_eq!(result.intended_page_mismatches, 1);
}

#[test]
fn search_ops_full_lifecycle_via_public_entry_points() {
    let mut state = SearchOpsState {
        schema_version: SCHEMA_VERSION,
        ..Default::default()
    };
    let intervention = Intervention {
        id: "iv-1".into(),
        target: "https://example.com/landing".into(),
        hypothesis: "adding FAQ schema increases CTR".into(),
        proposed_action: "add FAQPage schema".into(),
        primary_metric: "ctr".into(),
        evaluation: Evaluation {
            earliest_date: "2026-03-01".into(),
            maturity_condition: None,
        },
        ..Default::default()
    };
    start(&mut state, intervention).unwrap();

    deploy(
        &mut state,
        "iv-1",
        Deployment {
            recorded_at: "t1".into(),
            identity: "operator".into(),
            authorized_capability: "cms.publish".into(),
            idempotency_key: "idem-1".into(),
            effect_receipt: "receipt-1".into(),
            evidence: Some("deploy-log.json".into()),
            rollback: "revert commit abc".into(),
            verified: None,
        },
    )
    .unwrap();

    verify(&mut state, "iv-1", "pass", "verify-evidence.json".into(), "t2".into()).unwrap();
    assert_eq!(state.interventions[0].status, "verified");

    outcome(
        &mut state,
        "iv-1",
        Outcome {
            recorded_at: "t3".into(),
            verdict: "improved".into(),
            metrics: json!({"ctr_delta": 0.02}),
            evidence: Some("outcome-evidence.json".into()),
            confounders: vec![],
            causal_strength: "observational".into(),
        },
    )
    .unwrap();
    assert_eq!(state.interventions[0].status, "outcome_recorded");

    // No runs recorded yet.
    assert!(brief(&state).is_none());
}

#[test]
fn seo_closure_headings_and_phase_validation() {
    let md = "## Bot Policy\n\n## Crawl Efficiency\n";
    let hs = headings(md);
    assert!(hs.contains("bot-policy"));
    assert!(hs.contains("crawl-efficiency"));

    let phases = vec![PhaseRange {
        id: 1,
        source_lines: Some((74, 80)),
        has_owners: true,
    }];
    let statuses: BTreeSet<String> = ["pass", "partial", "fail", "na", "not_testable"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let gates: BTreeSet<String> = BTreeSet::new();
    let errors = validate_phases(&phases, &statuses, &gates, &gates, 80);
    // Only 1 phase supplied instead of 30, so the id-range check fires; no other error.
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("must be exactly 1..30"));
}

#[test]
fn seo_project_cache_key_and_preflight_and_env_state() {
    let key = cache_key("google_api", "serp", "example.com", "US", "en", "desktop", "daily");
    assert_eq!(key.len(), 64);

    let calls = vec![PlannedCall {
        provider: "dataforseo".into(),
        capability: "serp".into(),
        count: 50,
        estimated_unit_cost_usd: 0.02,
        cache_hits: 10,
    }];
    let result = preflight(&calls, Some(10.0));
    assert_eq!(result.status, "ok");
    assert_eq!(result.estimated_paid_cost_usd, 0.8);

    assert_eq!(env_state(&[Some("x")]), "present");
    assert_eq!(env_state(&[None]), "absent");
}
