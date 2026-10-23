//! Packet P5c integration smoke tests.
//!
//! Requires the `pub mod p5_core;` lib.rs patch in the packet report to be
//! applied (shared file — not edited directly by this packet). Exercises
//! each ported module's production entry point end to end, not just the
//! unit-level helper it happens to call.

use serde_json::json;

use legion_runtime::p5_core::{
    bound_packet_evidence, escape_for_reasoning, read_ecosystem_manifests,
    untrusted_evidence_envelope, validate_lenses, verification_digest, verification_receipt,
    EvidenceInput, LensRecord,
};

#[test]
fn ecosystem_manifests_reads_from_a_real_temp_directory() {
    let dir = std::env::temp_dir().join(format!("legion-p5c-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies": {"left-pad": "^1.0.0"}}"#,
    )
    .unwrap();
    let manifests = read_ecosystem_manifests(&dir, &["package.json".to_string()]);
    assert_eq!(manifests.len(), 1);
    assert_eq!(manifests[0].dependencies, vec!["left-pad"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn untrusted_evidence_round_trips_through_bound_packet_evidence() {
    let envelope = untrusted_evidence_envelope(EvidenceInput {
        file: "src/x.rs",
        line: Some(3),
        end_line: Some(3),
        text: "eval(process.env.SECRET)",
    });
    assert_eq!(escape_for_reasoning("a\u{0000}b"), "a\\u0000b");
    let bound = bound_packet_evidence(vec![envelope], 1024);
    assert_eq!(bound.included.len(), 1);
    assert!(!bound.packet_coverage_gap);
}

#[test]
fn verification_receipt_and_digest_agree_on_semantic_equality() {
    let prior = json!({"generatedAt": "t1", "data": {"a": 1, "b": 2}});
    let current = json!({"generatedAt": "t2", "data": {"b": 2, "a": 1}});
    let receipt = verification_receipt(prior, current).unwrap();
    assert!(receipt.valid);

    let facts_a = json!({"commit": "abc", "checks": []});
    let facts_b = json!({"checks": [], "commit": "abc"});
    assert_eq!(
        verification_digest(&facts_a).unwrap(),
        verification_digest(&facts_b).unwrap()
    );
}

#[test]
fn validate_lenses_rejects_a_record_missing_a_required_field() {
    let mut fields = std::collections::BTreeMap::new();
    for key in [
        "family",
        "denominatorKind",
        "evidence",
        "cleanClaim",
        "decisionMode",
        "reasoning",
    ] {
        fields.insert(key.to_string(), json!("x"));
    }
    // "benchmark" intentionally omitted.
    let record = LensRecord {
        id: "lens-1".to_string(),
        dependencies: vec![],
        fields,
    };
    assert!(validate_lenses(&[record]).is_err());
}
