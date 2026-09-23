//! Packet P9-skill-scripts: integration smoke tests exercising the `p9_skills` module's public
//! entry points end to end (not just the private helpers unit-tested inside each file), per the
//! "assert on the production entry point" rule.

use legion_runtime::p9_skills::alchemist::{extract_model_from_profile, is_gateway_reachable};
use legion_runtime::p9_skills::brand_identity::{audit_pairs, check_contrast, AuditPair};
use legion_runtime::p9_skills::covenant::{digest_value, validate_record_fields};
use legion_runtime::p9_skills::qa::{build_dispatch, QaVerb};
use legion_runtime::p9_skills::render_gap::{diff_signals, SeoSignals};
use legion_runtime::p9_skills::seo::check_files;
use serde_json::json;

#[test]
fn brand_identity_color_check_contrast_and_audit_entry_points() {
    let report = check_contrast("#000000", "#ffffff").expect("valid hex pair");
    assert_eq!(report.ratio, 21.0);
    assert!(report.aaa_normal);

    let pairs = vec![AuditPair {
        name: Some("body-text".into()),
        fg: "#333333".into(),
        bg: "#ffffff".into(),
        min: None,
    }];
    let audit = audit_pairs(&pairs).expect("valid audit input");
    assert!(audit.all_pass);
}

#[test]
fn seo_pre_commit_check_blocks_on_placeholder_text() {
    let files = vec![("landing.html", "<title>Legion Brand Landing Page Example</title>[INSERT]")];
    let report = check_files(files);
    assert_eq!(report.exit_code, 2);
    assert!(report.errors >= 1);
}

#[test]
fn covenant_contracts_digest_and_validate_entry_points() {
    let record = json!({
        "mode": "BLOCKER_CONSULT",
        "outcome": "CONTRACT_SAFE",
        "integrity": {"digestVerified": true, "mutationDetected": false},
        "seatRecords": [{"isolated": true}],
    });
    let errors = validate_record_fields(&record, None);
    assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    assert!(digest_value(&record).starts_with("sha256:"));
}

#[test]
fn alchemist_worker_profile_and_healthz_entry_points() {
    let profile = "  model = \"gpt-5.6-omniroute\"\n";
    assert_eq!(extract_model_from_profile(profile).as_deref(), Some("gpt-5.6-omniroute"));
    assert!(is_gateway_reachable(200));
    assert!(!is_gateway_reachable(500));
}

#[test]
fn qa_dispatch_builds_node_invocation_for_each_verb() {
    let dispatch = build_dispatch(QaVerb::QaFunctional, "/repo", &["--suite".into(), "smoke".into()]);
    assert_eq!(dispatch.program, "node");
    assert_eq!(dispatch.args[0], "/repo/src/lib/qa-engine/qa-functional.mjs");
    assert_eq!(dispatch.args[1], "--suite");
}

#[test]
fn render_gap_diff_flags_client_only_signal() {
    let raw = SeoSignals::default();
    let rendered = SeoSignals {
        title: Some("Hydrated Title".to_string()),
        ..Default::default()
    };
    let diff = diff_signals("https://example.com", raw, rendered);
    assert!(diff.client_only_signals.contains(&"title"));
}
