//! Integration coverage for the P5b-controls-config packet's production
//! entry points: control/pack validation, source ingest, and config
//! merge/validate. Mirrors the intent of the JS suites under
//! tests/controls/** and tests/config/** at the level this port reaches
//! (see the packet report for exact per-file status).

use legion_runtime::p5_core::config_core::{
    merge_config, validate_config, CONFIG_SCHEMA_VERSION,
};
use legion_runtime::p5_core::controls_contracts::{control_digest, validate_pack};
use legion_runtime::p5_core::controls_sources::{ingest_source, IngestItem, IngestSource};
use legion_runtime::p5_core::controls_support::Value;

fn sample_control() -> Value {
    Value::object([
        ("id", Value::str("ctl.sample")),
        ("version", Value::Number(1.0)),
        ("selector", Value::object([("op", Value::str("always"))])),
        ("denominator", Value::str("d")),
        ("evidence", Value::array([Value::str("repository")])),
        ("families", Value::array([Value::str("f1")])),
        ("lenses", Value::array([Value::str("l1")])),
        ("providers", Value::array([])),
        ("rules", Value::array([Value::str("r1")])),
        ("scenarios", Value::array([Value::str("s1")])),
        ("decisionMode", Value::str("deterministic")),
        ("missingEvidenceEffect", Value::str("unproven")),
        ("claimLevels", Value::array([Value::str("inventory")])),
        ("remediationOwner", Value::str("code")),
        ("sourceConcepts", Value::array([Value::str("sc1")])),
        ("stopShip", Value::Bool(false)),
        ("benchmark", Value::object([("status", Value::str("unproven"))])),
        (
            "provenance",
            Value::object([("source", Value::str("src")), ("lineage", Value::array([]))]),
        ),
    ])
}

#[test]
fn a_valid_pack_of_one_control_validates_and_digests() {
    let pack = Value::object([
        ("id", Value::str("pack.sample")),
        ("version", Value::Number(1.0)),
        ("class", Value::str("universal")),
        ("dependencies", Value::array([])),
        (
            "source",
            Value::object([("kind", Value::str("internal")), ("rights", Value::str("cleared"))]),
        ),
        ("qualification", Value::str("unproven")),
        ("controls", Value::array([sample_control()])),
    ]);

    assert!(validate_pack(&pack).is_ok());
    let d = control_digest(&sample_control()).unwrap();
    assert!(d.starts_with("sha256:"));
}

#[test]
fn ingest_source_then_config_merge_round_trip() {
    let source = IngestSource {
        digest: format!("sha256:{}", "b".repeat(64)),
        rights_status: "cleared".into(),
    };
    let item = IngestItem {
        disposition: "mapped".into(),
        rights_status: None,
        control_ids: vec!["ctl.sample".into()],
        derived_content: false,
    };
    let (_out_source, items) = ingest_source(&source, &[item]).unwrap();
    assert_eq!(items.len(), 1);
    assert!(items[0].id.ends_with(":1"));

    let defaults = Value::object([("schemaVersion", Value::Number(CONFIG_SCHEMA_VERSION as f64))]);
    let cli = Value::object([("profile", Value::str("full"))]);
    let merged = merge_config(&defaults, None, None, Some(&cli)).unwrap();
    validate_config(&merged, "config").unwrap();
    if let Value::Object(map) = &merged {
        assert_eq!(map.get("profile"), Some(&Value::str("full")));
    } else {
        panic!("expected merged config to be an object");
    }
}
