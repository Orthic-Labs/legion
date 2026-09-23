//! Integration tests for wf067's ported modules
//! (`legion_policy::wf_port::wf067::*`).
//!
//! NOTE for the integration owner: this file will not compile until
//! `pub mod wf_port;` is added to `engine/crates/legion-policy/src/lib.rs`
//! (if not already present from another wf packet) and `pub mod wf067;` to
//! `engine/crates/legion-policy/src/wf_port/mod.rs` (see the wf067 report).
//! Until then, the equivalent coverage lives as `#[cfg(test)]` unit tests
//! inside each `wf_port::wf067::*` submodule.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use legion_policy::wf_port::wf067::authority::{
    payload_claims_authority, require_authority, AssertForTurnInput, AuthorityLedger, RequireAuthorityOpts,
};
use legion_policy::wf_port::wf067::binding_store::{AuthorityBindingStore, ObserveInput};
use legion_policy::wf_port::wf067::canonical::{canonical_json, digest_value, is_digest, Json};
use legion_policy::wf_port::wf067::errors::ArcCode;
use legion_policy::wf_port::wf067::ids::{assert_id, is_id, mint_id, Family};
use legion_policy::wf_port::wf067::invocation_proof::{
    AuthorityInvocationProofIssuer, BindingKey, IssueOutcome, KeyRing, LedgerStore, StaticKeyRing,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root(label: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("wf067-it-{label}-{}-{n}", std::process::id()))
}

// ---------------------------------------------------------------------
// canonical.mjs
// ---------------------------------------------------------------------

#[test]
fn canonical_digest_is_stable_across_key_order() {
    let a = Json::Obj(vec![("b".into(), Json::I64(1)), ("a".into(), Json::I64(2))]);
    let b = Json::Obj(vec![("a".into(), Json::I64(2)), ("b".into(), Json::I64(1))]);
    assert_eq!(digest_value(&a).unwrap(), digest_value(&b).unwrap());
    assert!(is_digest(&digest_value(&a).unwrap()));
}

#[test]
fn canonical_json_rejects_non_finite_numbers() {
    assert!(canonical_json(&Json::F64(f64::NAN)).is_err());
}

// ---------------------------------------------------------------------
// ids.mjs
// ---------------------------------------------------------------------

#[test]
fn ids_mint_and_validate_round_trip_per_family() {
    let id = mint_id(Family::Artifact, 1_700_000_000_000).unwrap();
    assert!(id.starts_with("art_"));
    assert!(is_id(Family::Artifact, &id));
    assert!(assert_id(Family::Artifact, &id, None).is_ok());
    assert!(assert_id(Family::Run, &id, None).is_err());
}

#[test]
fn ids_sequence_families_validate_grammar_without_minting() {
    assert!(is_id(Family::ExecutionTask, "T-3.1"));
    assert!(!is_id(Family::ExecutionTask, "T-3."));
    let err = assert_id(Family::ExecutionContract, "not-ec", None).unwrap_err();
    assert_eq!(err.code, ArcCode::ArcIdInvalid);
}

// ---------------------------------------------------------------------
// authority.mjs
// ---------------------------------------------------------------------

#[test]
fn authority_ledger_end_to_end_gate() {
    let mut ledger = AuthorityLedger::new(|| 42);
    ledger
        .assert_for_turn(AssertForTurnInput {
            turn_id: "t1",
            authority: "oracle",
            asserted_by: "host:agent",
            verification_method: "capability-signature",
            per_message: true,
            source: "host",
        })
        .unwrap();

    let allowed = require_authority(&ledger, "t1", &["oracle"], RequireAuthorityOpts::default());
    assert!(allowed.allowed);

    let denied = require_authority(&ledger, "t1", &["alchemist"], RequireAuthorityOpts::default());
    assert_eq!(denied.code, Some(ArcCode::ArcAuthorityNotAsserted));
}

#[test]
fn authority_model_source_and_payload_claims_are_refused() {
    let mut ledger = AuthorityLedger::new(|| 0);
    let err = ledger
        .assert_for_turn(AssertForTurnInput {
            turn_id: "t1",
            authority: "oracle",
            asserted_by: "model",
            verification_method: "capability-signature",
            per_message: true,
            source: "model",
        })
        .unwrap_err();
    assert_eq!(err.code, ArcCode::ArcAuthorityModelClaimed);
    assert!(payload_claims_authority(&["authority"]));
}

// ---------------------------------------------------------------------
// authority-binding-store.mjs
// ---------------------------------------------------------------------

#[test]
fn binding_store_observe_get_find_latest_rollback_lifecycle() {
    let store = AuthorityBindingStore::new(temp_root("binding"), || "2026-01-01T00:00:00.000Z".to_string());

    let observed = store
        .observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "alchemist", event_id: "e1", session_root: false })
        .unwrap();
    assert!(observed.bound && observed.created);

    let fetched = store.get("claude-code", "s1", Some("a1")).unwrap().unwrap();
    assert_eq!(fetched.authority, "alchemist");

    let found = store.find_latest("claude-code", "s1", Some("alchemist")).unwrap().unwrap();
    assert_eq!(found.observed_event_id, "e1");

    assert!(store.rollback("claude-code", "s1", Some("a1"), Some(&fetched)).unwrap());
    assert!(store.get("claude-code", "s1", Some("a1")).unwrap().is_none());
}

#[test]
fn binding_store_assert_for_turn_produces_matching_ledger_assertion() {
    let store = AuthorityBindingStore::new(temp_root("binding-assert"), || "2026-01-01T00:00:00.000Z".to_string());
    store
        .observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "oracle", event_id: "e1", session_root: false })
        .unwrap();

    let mut ledger = AuthorityLedger::new(|| 0);
    let assertion = store.assert_for_turn("claude-code", "s1", Some("a1"), "turn-1", &mut ledger, Some("k1"), None, None).unwrap();
    assert_eq!(assertion.authority, "oracle");

    let gate = require_authority(&ledger, "turn-1", &["oracle"], RequireAuthorityOpts::default());
    assert!(gate.allowed, "{gate:?}");
}

// ---------------------------------------------------------------------
// authority-invocation-proof.mjs
// ---------------------------------------------------------------------

struct FixedLedgerStore {
    records: Vec<Json>,
}
impl LedgerStore for FixedLedgerStore {
    fn verify_ok(&self) -> bool {
        true
    }
    fn records(&self) -> Vec<Json> {
        self.records.clone()
    }
}

fn sample_ledger() -> Json {
    Json::Obj(vec![
        ("schemaVersion".into(), Json::I64(1)),
        ("kind".into(), Json::str("arcane-host-event-ledger-record")),
        ("eventId".into(), Json::str("ev1")),
        ("eventSequence".into(), Json::I64(1)),
        ("previousDigest".into(), Json::Null),
        ("turnCorrelationDigest".into(), Json::str("td1")),
        ("stopOrdinal".into(), Json::Null),
        ("adapter".into(), Json::str("claude-code")),
        ("eventType".into(), Json::str("Stop")),
        ("sessionId".into(), Json::str("s1")),
        ("runId".into(), Json::str("run-1")),
        ("taskId".into(), Json::str("task-1")),
        ("contractId".into(), Json::str("EC-1")),
        ("contractVersion".into(), Json::I64(1)),
        ("contractDigest".into(), Json::str("sha256:abc")),
        ("sourceRevision".into(), Json::str("rev1")),
        ("observedAuthority".into(), Json::str("oracle")),
        ("payloadDigest".into(), Json::str("sha256:def")),
        ("observedAt".into(), Json::str("2026-01-01T00:00:00.000Z")),
        ("authentication".into(), Json::Obj(vec![("keyId".into(), Json::str("root")), ("mac".into(), Json::str("x"))])),
    ])
}

#[test]
fn invocation_proof_issue_verify_consume_end_to_end() {
    let mut keyring = StaticKeyRing::new().with_key("root", b"root-secret");
    let ledger = sample_ledger();
    let ledger_store = FixedLedgerStore { records: vec![ledger.clone()] };
    let binding = BindingKey { run_id: "run-1", task_id: "task-1", contract_id: "EC-1", contract_version: "1", contract_digest: "sha256:abc" };
    let mut issuer =
        AuthorityInvocationProofIssuer::new(temp_root("proof"), &mut keyring, "root", &ledger_store, || "2026-01-01T00:00:00.000Z".to_string());

    let IssueOutcome::Issued(proof) = issuer.issue(&ledger, &binding, "completion-claim", "oracle").unwrap();
    let verified = issuer.verify(Some(&proof), &BTreeMap::new());
    assert!(verified.allowed, "{verified:?}");
    let consumed = issuer.consume(&proof, Some("sha256:artifact")).unwrap();
    assert!(consumed.allowed, "{consumed:?}");
}

#[test]
fn invocation_proof_rejects_role_not_authorized_for_purpose() {
    let mut keyring = StaticKeyRing::new().with_key("root", b"root-secret");
    let ledger = sample_ledger();
    let ledger_store = FixedLedgerStore { records: vec![ledger.clone()] };
    let binding = BindingKey { run_id: "run-1", task_id: "task-1", contract_id: "EC-1", contract_version: "1", contract_digest: "sha256:abc" };
    let mut issuer =
        AuthorityInvocationProofIssuer::new(temp_root("proof-reject"), &mut keyring, "root", &ledger_store, || "2026-01-01T00:00:00.000Z".to_string());
    let err = issuer.issue(&ledger, &binding, "budget-amendment", "oracle").unwrap_err();
    assert_eq!(err.code, ArcCode::ArcAuthForged);
}
