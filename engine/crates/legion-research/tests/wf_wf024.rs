//! Integration-level parity test for wf024 (research-core assurance
//! scripts: `domain_verify.py`, `draft_integrity.py`, `effect_audit.py`),
//! exercised against the crate's public API rather than the in-module unit
//! tests under `src/wf_port/wf024/*.rs`.
//!
//! NOTE: this file depends on `pub mod wf_port;` and, inside it,
//! `pub mod wf024;` landing in `src/lib.rs` / `src/wf_port/mod.rs` — files
//! this packet does not own. The exact patch is in the packet report.
//! Until the integrator applies it, this file will not compile.

use std::fs;
use std::path::PathBuf;

use legion_research::wf_port::wf024::{domain_verify, draft_integrity, effect_audit};
use serde_json::{json, Value};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_wf024")
}

fn load(name: &str) -> Value {
    let text = fs::read_to_string(fixtures_dir().join(name)).expect("fixture must be readable");
    serde_json::from_str(&text).expect("fixture must be valid JSON")
}

#[test]
fn domain_verify_medical_route_fixture_passes() {
    let route = load("medical_route.json");
    let evidence: Vec<Value> = load("medical_evidence.json")
        .as_array()
        .expect("array")
        .clone();
    let claims: Vec<Value> = load("medical_claims.json").as_array().expect("array").clone();

    let result = domain_verify::verify(&route, &evidence, &claims);
    assert_eq!(result["ok"], json!(true), "result: {result}");
}

#[test]
fn domain_verify_legal_route_fixture_fails_missing_authority() {
    let route = load("legal_route.json");
    let evidence: Vec<Value> = load("legal_evidence.json").as_array().expect("array").clone();
    let claims: Vec<Value> = load("legal_claims.json").as_array().expect("array").clone();

    let result = domain_verify::verify(&route, &evidence, &claims);
    assert_eq!(result["ok"], json!(false), "result: {result}");
}

#[test]
fn draft_integrity_matches_sourced_draft_hash() {
    let dir = fixtures_dir().join("draft_ok");
    let manifest = load("draft_ok/manifest.json");
    let result = draft_integrity::check(&dir, &manifest);
    assert_eq!(result["ok"], json!(true), "result: {result}");
    assert_eq!(result["authority"], json!("sourced-draft"));
}

#[test]
fn draft_integrity_detects_tampered_draft() {
    let dir = fixtures_dir().join("draft_tampered");
    let manifest = load("draft_tampered/manifest.json");
    let result = draft_integrity::check(&dir, &manifest);
    assert_eq!(result["ok"], json!(false), "result: {result}");
    assert_eq!(
        result["reason"],
        json!("draft hash differs from the last authorized draft artifact")
    );
}

#[test]
fn effect_audit_reconciles_fixture_events() {
    let manifest = load("effect_audit_manifest.json");
    let events_path = fixtures_dir().join("effect_audit_events.jsonl");
    let events = effect_audit::read_events(&events_path).expect("events must parse");
    let result = effect_audit::audit(&manifest, &events);
    assert_eq!(result["ok"], json!(true), "result: {result}");
}

#[test]
fn effect_audit_flags_over_budget_fixture() {
    let manifest = load("effect_audit_over_budget_manifest.json");
    let events_path = fixtures_dir().join("effect_audit_events.jsonl");
    let events = effect_audit::read_events(&events_path).expect("events must parse");
    let result = effect_audit::audit(&manifest, &events);
    assert_eq!(result["ok"], json!(false), "result: {result}");
    assert_eq!(result["over_budget"]["external_requests"], json!(true));
}
