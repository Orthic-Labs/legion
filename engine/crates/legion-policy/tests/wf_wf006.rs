//! Integration tests for wf006's ported modules
//! (`legion_policy::wf_port::wf006::*`).
//!
//! NOTE for the integration owner: this file will not compile until
//! `pub mod wf_port;` is added to `engine/crates/legion-policy/src/lib.rs`
//! and `pub mod wf006;` to `engine/crates/legion-policy/src/wf_port/mod.rs`
//! (see the wf006 report). Until then, the equivalent coverage lives as
//! `#[cfg(test)]` unit tests inside each `wf_port::wf006::*` submodule.

use legion_policy::wf_port::wf006::canonical::{canonical_json, digest_value, Json};
use legion_policy::wf_port::wf006::capability_store::{CapabilityInput, CapabilityStore, CheckCtx};
use legion_policy::wf_port::wf006::errors::ArcCode;
use legion_policy::wf_port::wf006::preeffect_correlation::PreEffectCorrelationStore;
use legion_policy::wf_port::wf006::preeffect_gate::{is_mutating, path_matches, workspace_relative};
use legion_policy::wf_port::wf006::receipt_auth::{
    sign_record, verify_record, PresentedAuth, StaticKeyRing, VerifyOpts,
};
use legion_policy::wf_port::wf006::receipt_store::ReceiptStore;
use std::collections::BTreeMap;
use std::fs;

#[test]
fn capability_lifecycle_issue_check_consume_revoke() {
    let mut store = CapabilityStore::new_in_memory();
    let mut input = CapabilityInput { capability_id: "cap-e2e".into(), ..Default::default() };
    input.max_uses = Some(1);
    let id = store.issue(input).unwrap();

    assert!(store.check(&id, &CheckCtx::default()).allowed);
    store.consume(&id, &CheckCtx::default()).unwrap();
    let exhausted = store.check(&id, &CheckCtx::default());
    assert_eq!(exhausted.code, Some(ArcCode::ArcCapabilityExhausted));

    let mut input2 = CapabilityInput { capability_id: "cap-e2e-2".into(), ..Default::default() };
    input2.max_uses = Some(5);
    let id2 = store.issue(input2).unwrap();
    store.revoke(&id2, "operator abort").unwrap();
    assert_eq!(store.check(&id2, &CheckCtx::default()).code, Some(ArcCode::ArcCapabilityRevoked));
}

#[test]
fn receipt_auth_end_to_end_sign_verify_deny_paths() {
    let ring = StaticKeyRing::new().with_key("k1", b"top-secret-key", false);
    let record = Json::Obj(vec![
        ("runId".into(), Json::str("run-7")),
        ("taskId".into(), Json::str("task-7")),
    ]);
    let bound = &["runId", "taskId"];
    let signed = sign_record(&record, &ring, "k1", bound, None).unwrap();

    let ok_auth = PresentedAuth::Signed {
        alg: &signed.alg,
        key_id: &signed.key_id,
        mac: &signed.mac,
        mac_domain: None,
        bound_fields_digest: Some(&signed.bound_fields_digest),
    };
    let opts = VerifyOpts { bound_fields: bound, expected_binding: BTreeMap::new(), force_mac_domain: None };
    assert!(verify_record(&record, ok_auth, &ring, &opts).unwrap().allowed);

    // Wrong key entirely -> unavailable, fail-closed error not a denial.
    let err = sign_record(&record, &ring, "no-such-key", bound, None).unwrap_err();
    assert_eq!(err.code, ArcCode::ArcAuthKeyUnavailable);
    assert!(err.fail_closed());
}

#[test]
fn receipt_store_chain_survives_quarantine_and_stays_partially_verifiable() {
    let root = std::env::temp_dir().join(format!("wf006-it-receipts-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let mut store = ReceiptStore::new(root.clone()).unwrap();
    store.append(Json::Obj(vec![("receiptId".into(), Json::str("a")), ("runId".into(), Json::str("r1"))])).unwrap();
    store.append(Json::Obj(vec![("receiptId".into(), Json::str("b")), ("runId".into(), Json::str("r1"))])).unwrap();
    store.append(Json::Obj(vec![("receiptId".into(), Json::str("c")), ("runId".into(), Json::str("r1"))])).unwrap();

    assert!(store.verify_chain().ok);
    store.quarantine(2, "digest mismatch observed").unwrap();
    assert!(store.get("b").is_none());
    assert!(store.get("a").is_some());
    assert!(store.get("c").is_some());
    assert!(store.verify_chain().ok, "chain stays verifiable across a tombstone boundary");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn preeffect_correlation_reserve_finalize_get_round_trip() {
    let root = std::env::temp_dir().join(format!("wf006-it-correlation-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let store = PreEffectCorrelationStore::new(root.clone());
    let (request_id, created) = store.reserve("tool-use-e2e").unwrap();
    assert!(created);
    let record = store.finalize("tool-use-e2e", &request_id, "cap-e2e", "requested", "authorized").unwrap();
    assert_eq!(record.capability_id, "cap-e2e");
    let got = store.get_finalized("tool-use-e2e").unwrap();
    assert_eq!(got, record);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn preeffect_gate_utilities_glob_and_workspace_relative() {
    assert!(is_mutating("FILE_WRITE"));
    assert!(!is_mutating("FILE_READ"));
    assert!(path_matches("engine/crates/**/*.rs", "engine/crates/legion-policy/src/lib.rs"));
    assert_eq!(
        workspace_relative("/Repo/engine/crates/legion-policy/src/lib.rs", Some("/repo")),
        "engine/crates/legion-policy/src/lib.rs"
    );
}

#[test]
fn canonical_digest_value_is_stable_across_key_order() {
    let a = Json::Obj(vec![("b".into(), Json::I64(1)), ("a".into(), Json::I64(2))]);
    let b = Json::Obj(vec![("a".into(), Json::I64(2)), ("b".into(), Json::I64(1))]);
    assert_eq!(digest_value(&a).unwrap(), digest_value(&b).unwrap());
    assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
}
