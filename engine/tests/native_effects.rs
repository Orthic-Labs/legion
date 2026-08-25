//! LEG-I01 effect-boundary, receipt, and process-cleanup acceptance corpus.

use legion_effects::{ExternalToolRequest, Sensitivity, ToolOrigin};
use serde_json::Value;
use std::collections::BTreeMap;

fn fixtures() -> Value {
    serde_json::from_str(include_str!(
        "../../migration/native-rust/fixtures/effect-cases.v1.json"
    ))
    .expect("LEG-001 effect fixtures remain valid JSON")
}

#[test]
fn effect_fixtures_are_classification_only_and_non_mutating() {
    let fixture = fixtures();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        assert_eq!(case["simulation"]["realEffects"], 0);
        assert_eq!(case["simulation"]["productionMutation"], false);
        assert_eq!(case["simulation"]["duplicateRealEffects"], false);
    }
}

#[test]
fn external_request_rejects_shell_and_runtime_reentry() {
    let mut request = ExternalToolRequest {
        request_id: "effect-fixture".into(),
        provider_id: "fixture-provider".into(),
        plan_id: "fixture-plan".into(),
        policy_id: "fixture-policy".into(),
        executable: "python3".into(),
        cwd: "/tmp".into(),
        origin: ToolOrigin::LegionOwned,
        shell: true,
        ..Default::default()
    };
    assert!(request.validate().is_err());
    request.shell = false;
    assert!(request.validate().is_err());
}

#[test]
fn redaction_preserves_argv_shape_without_secret_values() {
    let mut request = ExternalToolRequest {
        request_id: "redaction-fixture".into(),
        provider_id: "fixture-provider".into(),
        plan_id: "fixture-plan".into(),
        policy_id: "fixture-policy".into(),
        executable: "/usr/bin/tool".into(),
        cwd: "/tmp".into(),
        args: vec!["--token".into(), "secret-value".into()],
        sensitive_argument_indexes: [1].into_iter().collect(),
        environment: BTreeMap::from([(String::from("TOKEN"), String::from("secret-value"))]),
        sensitive_environment_names: [String::from("TOKEN")].into_iter().collect(),
        environment_allowlist: [String::from("TOKEN")].into_iter().collect(),
        ..Default::default()
    };
    request.shell = false;
    let redacted = request.redacted();
    assert_eq!(redacted.args.len(), request.args.len());
    assert!(!redacted.args.iter().any(|value| value == "secret-value"));
    assert!(redacted.redacted_argument_indexes.contains(&1));
    assert!(redacted.redacted_environment_names.contains("TOKEN"));
    let _ = Sensitivity::Restricted;
}
