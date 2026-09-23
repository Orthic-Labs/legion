//! Tests for the Rust port of the JS `external-evidence` / `external/*` runtime providers
//! (see `src/native_providers/p10_runtime/external.rs`). The module is included directly by
//! path rather than through the crate's public tree, since wiring it into
//! `native_providers/mod.rs` / `p10_runtime/mod.rs` is owned by another packet.

#[path = "../src/native_providers/p10_runtime/external.rs"]
mod external;

use serde_json::json;

#[test]
fn import_external_evidence_empty_is_unproven_with_denominator_gap() {
    let out = external::import_external_evidence(&json!({}));
    assert_eq!(out["status"], "unproven");
    let gaps = out["coverageGaps"].as_array().unwrap();
    assert!(gaps.iter().any(|g| g == "external-evidence-denominator-empty"));
    assert!(out["validations"].as_array().unwrap().is_empty());
}

#[test]
fn import_external_evidence_incomplete_item_never_fabricates_a_pass() {
    let out = external::import_external_evidence(&json!({
        "evidence": [{"producer": "acme"}],
        "expected": {},
    }));
    assert_eq!(out["status"], "unproven");
    let validations = out["validations"].as_array().unwrap();
    assert_eq!(validations.len(), 1);
    assert_eq!(validations[0]["validation"]["status"], "unproven");
}

#[test]
fn validate_external_evidence_never_passes_without_real_signature_verification() {
    // Even a "complete looking" envelope must never validate: this crate cannot verify Ed25519
    // signatures today (no PEM-capable crypto crate in engine/Cargo.lock), so verification
    // fails closed rather than fabricating a pass. See external.rs module docs, divergence 1.
    let evidence = json!({
        "producer": "acme", "scope": "third-party", "targetId": "t1", "environment": "sandbox",
        "artifactDigest": "sha256:aa", "controlId": "email", "binding": {"targetId": "t1"},
        "issuedAt": "2026-01-01T00:00:00Z", "checkedAt": "2026-01-01T00:00:00Z",
        "expiresAt": "2026-01-02T00:00:00Z", "signedContent": "{}", "signature": "AAAA",
    });
    // `trustedProducers` must name this evidence's producer so the JS-ported
    // `else if (trusted) { ... }` branch in validate.mjs:26 is the one taken;
    // an untrusted producer takes the `producer-untrusted` branch instead and
    // never reaches signature verification at all.
    let out = external::validate_external_evidence(
        &evidence,
        &json!({
            "now": "2026-01-01T00:00:00Z",
            "maxAgeMs": 60000,
            "trustedProducers": [{"id": "acme"}],
        }),
    );
    assert_eq!(out["status"], "unproven");
    assert!(out["payload"].is_null());
    assert!(out["gaps"].as_array().unwrap().iter().any(|g| g == "signature-invalid"));
}

#[test]
fn verify_third_party_evidence_sets_provider_and_family_on_empty_input() {
    let out = external::verify_third_party_evidence(&json!({}));
    assert_eq!(out["provider"], "runtime.external.third-party");
    assert_eq!(out["family"], "third-party");
    assert_eq!(out["networkAttempted"], false);
    assert_eq!(out["kind"], "legion-external-third-party-evidence");
    // Conditional-provider fallback with no applicability source or exercises is always unproven.
    assert_eq!(out["status"], "unproven");
}

#[test]
fn verify_analytics_evidence_family_and_provider_set() {
    let out = external::verify_analytics_evidence(&json!({}));
    assert_eq!(out["provider"], "runtime.external.analytics");
    assert_eq!(out["family"], "analytics");
}

#[test]
fn verify_commerce_evidence_family_and_provider_set() {
    let out = external::verify_commerce_evidence(&json!({}));
    assert_eq!(out["provider"], "runtime.external.commerce");
    assert_eq!(out["family"], "commerce");
}

#[test]
fn verify_email_evidence_family_and_provider_set() {
    let out = external::verify_email_evidence(&json!({}));
    assert_eq!(out["provider"], "runtime.external.email");
    assert_eq!(out["family"], "email");
}

#[test]
fn verify_backup_evidence_empty_exercises_report_full_denominator() {
    let out = external::verify_backup_evidence(&json!({}));
    assert_eq!(out["provider"], "runtime.external.backup");
    assert_eq!(out["family"], "backup");
    assert_eq!(out["claimLevel"], "external");
    assert_eq!(out["suppliedOnly"], true);
    assert_eq!(out["denominator"]["total"], 19);
    let gaps = out["coverageGaps"].as_array().unwrap();
    assert!(gaps.iter().any(|g| g == "operations-denominator-empty"));
}

#[test]
fn verify_incident_evidence_family_and_claim_level() {
    let out = external::verify_incident_evidence(&json!({}));
    assert_eq!(out["provider"], "runtime.external.incidents");
    assert_eq!(out["family"], "incidents");
    assert_eq!(out["claimLevel"], "external");
}

#[test]
fn verify_cloud_evidence_missing_trusted_producers_key_defaults_to_empty_not_invalid() {
    // Omitting `trustedProducers` defaults to an empty (valid) list, matching the JS default
    // parameter `trustedProducers = []`; it must not itself be flagged as a malformed collection.
    let out = external::verify_cloud_evidence(&json!({"binding": {}}));
    assert_eq!(out["provider"], "runtime.external.cloud");
    assert_eq!(out["family"], "cloud");
    let gaps = out["coverageGaps"].as_array().unwrap();
    assert!(!gaps.iter().any(|g| g == "trusted-producers-invalid"));
    assert_eq!(out["status"], "unproven");
}

#[test]
fn verify_dns_evidence_family_and_provider_set() {
    let out = external::verify_dns_evidence(&json!({}));
    assert_eq!(out["provider"], "runtime.external.dns");
    assert_eq!(out["family"], "dns");
}

#[test]
fn digest_is_present_and_stable_for_identical_input() {
    let a = external::import_external_evidence(&json!({}));
    let b = external::import_external_evidence(&json!({}));
    assert_eq!(a["digest"], b["digest"]);
    assert!(a["digest"].as_str().unwrap().starts_with("sha256:"));
}
