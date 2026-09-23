//! Integration tests for wf007's ported modules
//! (`legion_policy::wf_port::wf007::*`).
//!
//! NOTE for the integration owner: this file will not compile until
//! `pub mod wf_port;` is added to `engine/crates/legion-policy/src/lib.rs`
//! (if not already, from a prior chunk's integration) and `pub mod wf007;`
//! to `engine/crates/legion-policy/src/wf_port/mod.rs` (see the wf007
//! report). Until then, the equivalent coverage lives as `#[cfg(test)]`
//! unit tests inside each `wf_port::wf007::*` submodule.

use legion_policy::wf_port::wf007::canon::{constant_time_equal, digest, digest_value_domain, hmac_sha256_hex};
use legion_policy::wf_port::wf007::policy::{
    fail_closed_engine, ClaimContext, ClaimLevel, EffectRule, LockedDomainEntry, PolicyBundle, PolicyEngine,
};
use legion_policy::wf_port::wf007::provision_keys::{provision_keys, ProvisionOptions};
use legion_policy::wf_port::wf007::replay::{ReplayCheck, ReplayGuard, ReplayGuardOptions, ReplayScope};
use legion_policy::wf_port::wf007::user_approval::{ExpectedBinding, KeyLookup, UserApprovalAuthority};
use legion_policy::wf_port::wf007::user_intent::{classify_latest_user_intent, latest_external_user_turn, Intent};

use std::collections::BTreeMap;

const T0: &str = "2026-01-01T00:00:00.000Z";
const T0_MS: i64 = 1_767_225_600_000;

// --- replay.mjs -------------------------------------------------------

#[test]
fn replay_guard_end_to_end_scope_nonce_sequence_and_freshness() {
    let mut guard = ReplayGuard::new(ReplayGuardOptions::default());
    let scope = ReplayScope {
        issuer_id: Some("iss-1".into()),
        session_id: Some("sess-1".into()),
        run_id: Some("run-1".into()),
        workspace_id: Some("ws-1".into()),
    };

    let first = guard.check(ReplayCheck { scope: &scope, nonce: "n1", sequence: 1, timestamp: T0 }, T0_MS);
    assert!(first.allowed);

    let replayed = guard.check(ReplayCheck { scope: &scope, nonce: "n1", sequence: 2, timestamp: T0 }, T0_MS);
    assert!(!replayed.allowed);
    assert_eq!(replayed.code.as_str(), "ARC_REPLAY_NONCE_SEEN");

    let regressed = guard.check(ReplayCheck { scope: &scope, nonce: "n2", sequence: 1, timestamp: T0 }, T0_MS);
    assert_eq!(regressed.code.as_str(), "ARC_REPLAY_SEQUENCE_REGRESSION");

    let stale = guard.check(ReplayCheck { scope: &scope, nonce: "n3", sequence: 2, timestamp: T0 }, T0_MS + 1_000_000);
    assert_eq!(stale.code.as_str(), "ARC_REPLAY_STALE");
}

// --- policy.mjs ---------------------------------------------------------

fn sample_bundle() -> PolicyBundle {
    PolicyBundle {
        policy_id: "arcane-policy-v1".into(),
        version: 1,
        digest: "sha256:aaaa".into(),
        effect_rules: vec![
            EffectRule { effect_class: "FILE_WRITE".into(), rule: "allow".into(), approval_required: false, trust_minimum: "capability-signature".into(), required_enforcement: "strong".into() },
            EffectRule { effect_class: "FILE_DELETE".into(), rule: "allow".into(), approval_required: true, trust_minimum: "capability-signature".into(), required_enforcement: "strong".into() },
            EffectRule { effect_class: "VCS_PUSH".into(), rule: "deny".into(), approval_required: false, trust_minimum: "capability-signature".into(), required_enforcement: "strong".into() },
        ],
        waiver_authority: vec!["operator".into()],
        claim_levels: BTreeMap::from([(
            "L1".to_string(),
            ClaimLevel {
                allow_stale_evidence: false,
                required_evidence_classes: vec!["test-run".into()],
                required_enforcement: "observed".into(),
                required_fields: vec!["sha".into()],
            },
        )]),
        locked_domains: vec![LockedDomainEntry { pattern: "docs/*".into(), claim_level: "L1".into(), note: None }],
        ..Default::default()
    }
}

#[test]
fn policy_engine_effect_decision_and_claim_prerequisites_end_to_end() {
    let engine = PolicyEngine::new(sample_bundle());

    assert!(engine.effect_decision("FILE_WRITE", None).allowed);
    assert!(!engine.effect_decision("VCS_PUSH", None).allowed);
    assert_eq!(engine.effect_decision("FILE_DELETE", None).code, Some("ARC_APPROVAL_REQUIRED"));
    assert!(engine.effect_decision("FILE_DELETE", Some("sha256:xyz")).allowed);
    assert_eq!(engine.effect_decision("UNKNOWN_CLASS", None).code, Some("ARC_EFFECT_CLASS_UNAUTHORIZED"));

    let ctx = ClaimContext { evidence_classes: &["test-run"], enforcement_health: "observed", fields: &["sha"], ..Default::default() };
    assert!(engine.evaluate_claim_prerequisites("L1", &ctx).allowed);

    let matches = engine.locked_domains_for(&["docs/readme.md", "src/lib.rs"]);
    assert_eq!(matches.len(), 1);
}

#[test]
fn fail_closed_policy_engine_denies_by_name_not_by_bucket() {
    let engine = fail_closed_engine("no bundle available");
    let d = engine.effect_decision("FILE_WRITE");
    assert!(!d.allowed);
    assert_eq!(d.code, Some("ARC_POLICY_UNAVAILABLE"));
    assert_eq!(engine.degradation(), "fail-closed");
}

// --- keys.mjs / user-approval.mjs ---------------------------------------

struct TestKeyRing {
    keys: BTreeMap<String, Vec<u8>>,
    active: Option<String>,
}
impl KeyLookup for TestKeyRing {
    fn get(&self, key_id: &str) -> Result<Vec<u8>, ()> {
        self.keys.get(key_id).cloned().ok_or(())
    }
    fn active_key_id(&self) -> Option<String> {
        self.active.clone()
    }
}

#[test]
fn user_approval_authority_derives_and_consumes_a_transcript_bound_approval() {
    let mut keys = BTreeMap::new();
    keys.insert("k1".to_string(), vec![9u8; 32]);
    let ring = TestKeyRing { keys, active: Some("k1".to_string()) };
    let authority = UserApprovalAuthority::new(Some(ring), vec!["FILE_DELETE".to_string()]);

    let transcript = r#"{"type":"user","message":{"content":[{"type":"text","text":"please delete the stale branch"}]}}"#;
    let expected = ExpectedBinding {
        transcript_text: Some(transcript),
        session_id: "sess-e2e",
        run_id: "run-e2e",
        task_id: "task-e2e",
        contract_id: "contract-e2e",
        contract_version: 1,
        contract_digest: "sha256:bbbb",
        effect_class: "FILE_DELETE",
        target: "/tmp/branch",
    };

    let record = authority.derive_record(&expected, T0_MS).expect("transcript admits EXECUTE intent");
    let grant = authority.consume(Some(&record), &expected, T0_MS).expect("approval consumed");
    assert!(!grant.approval_digest.is_empty());

    // Second consume of the same record is a replay.
    let denial = authority.consume(Some(&record), &expected, T0_MS).unwrap_err();
    assert_eq!(denial.code, "ARC_REPLAY_NONCE_SEEN");
}

#[test]
fn classify_latest_user_intent_recognizes_execute_and_revoke() {
    let execute = r#"{"type":"user","message":{"content":[{"type":"text","text":"please implement the fix"}]}}"#;
    assert_eq!(classify_latest_user_intent(execute).intent, Intent::Execute);

    let revoke = r#"{"type":"user","message":{"content":[{"type":"text","text":"stop, make no changes"}]}}"#;
    assert_eq!(classify_latest_user_intent(revoke).intent, Intent::Revoke);

    assert_eq!(latest_external_user_turn(execute).as_deref(), Some("please implement the fix"));
}

// --- provision-keys.mjs ---------------------------------------------------

#[test]
fn provision_keys_is_idempotent_and_rotate_adds_a_new_active_key() {
    let dir = std::env::temp_dir().join(format!("legion-wf007-it-{}", T0_MS));
    let opts = ProvisionOptions { dir: dir.clone(), rotate: false };
    let first = provision_keys(&opts).expect("first provision succeeds");
    assert!(first.created);

    let second = provision_keys(&opts).expect("second provision is idempotent");
    assert!(!second.created);
    assert_eq!(first.key_id, second.key_id);

    let rotate_opts = ProvisionOptions { dir: dir.clone(), rotate: true };
    let rotated = provision_keys(&rotate_opts).expect("rotate provisions a new key");
    assert!(rotated.created);
    assert_ne!(rotated.key_id, first.key_id);

    let _ = std::fs::remove_dir_all(&dir);
}

// --- canon primitives (shared building block for replay + user-approval) --

#[test]
fn canon_primitives_match_known_vectors() {
    assert_eq!(digest(""), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert!(constant_time_equal(b"same", b"same"));
    assert!(!constant_time_equal(b"same", b"diff"));
    let mac = hmac_sha256_hex(&[0x0bu8; 20], b"Hi There");
    assert_eq!(mac, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    let d = digest_value_domain("dom", &[Some("a"), None]);
    assert_eq!(d, digest(r#"{"domain":"dom","values":["a",null]}"#));
}
