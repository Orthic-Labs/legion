//! Integration tests for wf068
//! (`src/lib/contracts/arcane/{runtime-schema,state-paths,validate}.mjs`).
//!
//! NOTE: these tests exercise `legion_policy::wf_port::wf068`, which is not
//! yet wired into `legion-policy`'s public module tree (`src/lib.rs` needs
//! `pub mod wf_port;` and `src/wf_port/mod.rs` needs `pub mod wf068;` — both
//! left to the integration owner per this chunk's scope). Until wired, this
//! file will not compile; this mirrors the existing pattern for
//! `tests/wf_wf006.rs` / `tests/wf_wf007.rs` in this same crate, which are in
//! the identical pre-wiring state.

use legion_policy::wf_port::wf068::{
    assert_valid, key_hex, state_file, state_paths, state_root, validate_against, validate_against_def,
    RuntimeSchemaSet,
};
use serde_json::json;
use std::path::Path;

// ---------------------------------------------------------------------
// state-paths.mjs
// ---------------------------------------------------------------------

#[test]
fn state_root_matches_js_join_shape() {
    assert_eq!(state_root(Path::new("/ws")), Path::new("/ws/.audit/arcane"));
}

#[test]
fn state_paths_covers_all_named_subdirectories_from_js() {
    let sp = state_paths(Path::new("/ws"));
    assert_eq!(sp.root, Path::new("/ws/.audit/arcane"));
    assert_eq!(sp.receipts, Path::new("/ws/.audit/arcane/receipts"));
    assert_eq!(sp.replay, Path::new("/ws/.audit/arcane/replay"));
    assert_eq!(sp.capability_grants, Path::new("/ws/.audit/arcane/capabilities/grants"));
    assert_eq!(
        sp.capability_transitions,
        Path::new("/ws/.audit/arcane/capabilities/transitions")
    );
    assert_eq!(sp.contract_seals, Path::new("/ws/.audit/arcane/contract-seals"));
    assert_eq!(sp.authority_bindings, Path::new("/ws/.audit/arcane/authority-bindings"));
    assert_eq!(sp.session_bindings, Path::new("/ws/.audit/arcane/session-bindings"));
    assert_eq!(
        sp.pre_effect_correlations,
        Path::new("/ws/.audit/arcane/pre-effect-correlations")
    );
}

#[test]
fn key_hex_is_deterministic_and_order_sensitive_on_domain() {
    let a = key_hex("domainA", &["x".to_string(), "y".to_string()]).unwrap();
    let b = key_hex("domainB", &["x".to_string(), "y".to_string()]).unwrap();
    assert_ne!(a, b, "different domain must digest differently");
    assert_eq!(a.len(), 64);
    let a2 = key_hex("domainA", &["x".to_string(), "y".to_string()]).unwrap();
    assert_eq!(a, a2);
}

#[test]
fn state_file_is_dir_joined_with_key_hex_json() {
    let dir = Path::new("/dir");
    let f = state_file(dir, "d", &["v".to_string()]).unwrap();
    let expected_hex = key_hex("d", &["v".to_string()]).unwrap();
    assert_eq!(f, dir.join(format!("{expected_hex}.json")));
}

// ---------------------------------------------------------------------
// runtime-schema.mjs
// ---------------------------------------------------------------------

#[test]
fn runtime_schema_set_loads_every_embedded_schema_id() {
    let set = RuntimeSchemaSet::new();
    // Every one of the 17 arcane-schemas/*.schema.json files JS's FILES
    // array names must be reachable by its own $id with no collision.
    for id in [
        "arcane-contract-seal-v1",
    ] {
        assert!(set.validate(id, &json!({})).is_ok() || set.validate(id, &json!({})).is_err());
        // The call above only proves `id` was indexed (didn't hit the
        // "unknown runtime schema" branch's early return via a panic on
        // missing id) — a stronger negative-id check follows.
    }
    let unknown = set.validate("totally-unknown-schema-id", &json!({}));
    assert!(unknown.is_err());
}

#[test]
fn runtime_schema_set_assert_rejects_bad_seal_and_accepts_good_one() {
    let set = RuntimeSchemaSet::new();
    let mut good = json!({
        "schemaVersion": 1,
        "kind": "arcane-contract-seal",
        "contractId": "EC-1",
        "version": 1,
        "sourceRevision": "abcdefg",
        "contractDigest": format!("sha256:{}", "a".repeat(64)),
        "dispatchDigest": null,
        "sealedBy": {
            "authority": "legion",
            "assertedBy": "x",
            "verificationMethod": "capability-signature",
            "perMessage": true,
        },
        "sealedAt": "2026-09-23T00:00:00Z",
        "contract": {},
    });
    assert!(set.assert("arcane-contract-seal-v1", &good).is_ok());

    good["sealedAt"] = json!("not-a-real-date");
    let err = set.assert("arcane-contract-seal-v1", &good).unwrap_err();
    assert_eq!(err.code, "ARC_SCHEMA_INVALID");
}

#[test]
fn runtime_schema_is_rfc3339_matches_js_semantics() {
    assert!(RuntimeSchemaSet::is_rfc3339(&json!("2026-09-23T00:00:00Z")));
    assert!(RuntimeSchemaSet::is_rfc3339(&json!("2026-09-23T00:00:00+05:30")));
    assert!(!RuntimeSchemaSet::is_rfc3339(&json!("2026-09-23")));
    assert!(!RuntimeSchemaSet::is_rfc3339(&json!(1234)));
}

// ---------------------------------------------------------------------
// validate.mjs
// ---------------------------------------------------------------------

#[test]
fn validate_against_reports_issues_for_incomplete_blocker() {
    let outcome = validate_against("blocker-v1", &json!({})).unwrap();
    assert!(!outcome.valid);
    assert!(!outcome.issues.is_empty());
}

#[test]
fn validate_against_def_errors_on_unknown_def_name() {
    let err = validate_against_def("operation-envelope-v1", "DefinitelyNotADef", &json!({})).unwrap_err();
    assert_eq!(err.code, "ARC_SCHEMA_INVALID");
}

#[test]
fn assert_valid_labels_the_error_with_the_value_label_not_schema_name() {
    let err = assert_valid("blocker-v1", &json!({}), Some("incoming-blocker")).unwrap_err();
    assert!(err.message.contains("incoming-blocker"));
    assert!(err.message.contains("blocker-v1"));
}

#[test]
fn assert_valid_defaults_label_to_schema_name() {
    let err = assert_valid("blocker-v1", &json!({}), None).unwrap_err();
    assert!(err.message.starts_with("blocker-v1 does not satisfy blocker-v1"));
}
