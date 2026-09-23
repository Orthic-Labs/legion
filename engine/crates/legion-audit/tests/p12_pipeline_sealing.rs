//! Packet P12-audit-lib: production-entry-point tests for the ported
//! plan-sealing and finding-id-derivation logic in
//! `legion_audit::p12_pipeline`.
//!
//! NOTE: this test binary is not yet wired into `Cargo.toml` (that file is
//! owned by a concurrent packet). Until a `[[test]]` entry for
//! `p12_pipeline_sealing` is added (see the packet report for the exact
//! patch), `cargo test -p legion-audit` will not pick this file up on its
//! own the way it picks up `tests/p12_*.rs` implicitly — Cargo only infers
//! `[[test]]` targets automatically when no explicit `[[test]]` entries
//! exist for the crate; this crate already declares several, which turns
//! off that inference for the whole `tests/` directory.

use legion_audit::p12_pipeline::{
    assert_supported_schema_version, derive_finding_id, locus_content_hash, seal_plan,
    verify_plan_seal, verify_plan_signature, FindingLocus, SchemaLabel,
};
use serde_json::json;

#[test]
fn seal_plan_production_round_trip_unsigned() {
    let plan = json!({"revision": "deadbeef", "providers": [{"id": "p1"}]});
    let sealed = seal_plan(&plan, None);
    assert!(verify_plan_seal(&sealed));
    assert!(!verify_plan_signature(&sealed, None));
}

#[test]
fn seal_plan_production_round_trip_signed() {
    let plan = json!({"revision": "deadbeef", "providers": [{"id": "p1"}]});
    let sealed = seal_plan(&plan, Some("p12-test-key"));
    assert!(verify_plan_seal(&sealed));
    assert!(verify_plan_signature(&sealed, Some("p12-test-key")));
    assert!(!verify_plan_signature(&sealed, Some("not-the-key")));
}

#[test]
fn schema_version_gate_refuses_newer_than_supported() {
    assert!(assert_supported_schema_version(1, SchemaLabel::ProviderResult).is_ok());
    assert!(assert_supported_schema_version(2, SchemaLabel::SecurityVerdict).is_err());
}

#[test]
fn finding_id_derivation_is_deterministic_across_calls() {
    let locus = FindingLocus {
        path: "engine/crates/legion-audit/src/p12_pipeline/mod.rs".into(),
        start_line: 42,
        end_line: 50,
    };
    let a = derive_finding_id("legion", "no-unwrap-in-lib", Some(&locus)).unwrap();
    let b = derive_finding_id("legion", "no-unwrap-in-lib", Some(&locus)).unwrap();
    assert_eq!(a, b);
    assert!(a.starts_with("audit:rule:"));
    assert_eq!(
        locus_content_hash(&locus.path, locus.start_line, locus.end_line).len(),
        "sha256:".len() + 64
    );
}
