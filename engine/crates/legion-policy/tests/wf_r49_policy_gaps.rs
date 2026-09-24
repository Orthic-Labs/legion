//! Packet r49 — closes the wf007 PORTED-PARTIAL gap on
//! `src/lib/guard/compat/policy/policy.mjs`: schema validation of a raw
//! bundle, disk loading (`loadPolicy`), and the two source-text conformance
//! audits (`policyDuplicationAudit`, `capabilityIssuanceAudit`).
//!
//! No network access, no browser launch, no subprocess: all three surfaces
//! are plain local filesystem reads over caller-supplied paths, exactly
//! like the JS originals, so no fake/trait indirection is needed here.
//! Temp files use the process id plus a process-wide atomic counter in
//! their names to stay unique under parallel test execution.

use legion_policy::wf_port::wf007::policy::{
    capability_issuance_audit, digest_value_json, load_policy, policy_duplication_audit,
    validate_policy_bundle,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("legion-r49-{}-{}-{}", std::process::id(), n, name))
}

fn write_temp(name: &str, contents: &str) -> PathBuf {
    let path = temp_path(name);
    std::fs::write(&path, contents).expect("write temp fixture");
    path
}

fn fixture_bundle_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_wf008/arcane-policy-v1.json")
}

#[test]
fn load_policy_reads_and_validates_the_real_fixture_bundle() {
    let loaded = load_policy(&fixture_bundle_path()).expect("shipped fixture bundle must load");
    assert_eq!(loaded.policy_id, "POL-1");
    assert_eq!(loaded.version, 1);
    assert!(loaded.digest.starts_with("sha256:"));
    assert_eq!(loaded.digest.len(), "sha256:".len() + 64);

    // Digest is over the canonical form: re-digesting the same parsed value
    // must reproduce it, and re-parsing+redigesting the file must be stable.
    assert_eq!(digest_value_json(&loaded.bundle), loaded.digest);
    let loaded_again = load_policy(&fixture_bundle_path()).expect("second load");
    assert_eq!(loaded_again.digest, loaded.digest);
}

#[test]
fn validate_policy_bundle_accepts_the_real_fixture() {
    let raw = std::fs::read_to_string(fixture_bundle_path()).unwrap();
    let bundle: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let (valid, issues) = validate_policy_bundle(&bundle);
    assert!(valid, "fixture bundle should validate cleanly, issues: {issues:?}");
}

#[test]
fn load_policy_fails_closed_on_missing_file() {
    let missing = temp_path("does-not-exist.json");
    let err = load_policy(&missing).expect_err("missing file must fail closed");
    assert_eq!(err.code, "ARC_POLICY_UNAVAILABLE");
}

#[test]
fn load_policy_fails_closed_on_malformed_json() {
    let path = write_temp("malformed.json", "{ not json");
    let err = load_policy(&path).expect_err("malformed JSON must fail closed");
    assert_eq!(err.code, "ARC_POLICY_MALFORMED");
}

#[test]
fn load_policy_fails_closed_on_unknown_field() {
    // additionalProperties:false at the schema root: an unrecognised field
    // must fail validation rather than being silently ignored.
    let raw = std::fs::read_to_string(fixture_bundle_path()).unwrap();
    let mut bundle: serde_json::Value = serde_json::from_str(&raw).unwrap();
    bundle
        .as_object_mut()
        .unwrap()
        .insert("notAKnownField".to_string(), serde_json::json!(true));
    let path = write_temp("unknown-field.json", &serde_json::to_string(&bundle).unwrap());
    let err = load_policy(&path).expect_err("unknown field must fail closed");
    assert_eq!(err.code, "ARC_POLICY_MALFORMED");
    assert!(!err.issues.is_empty());
}

#[test]
fn policy_duplication_audit_flags_a_minted_allow_decision() {
    let clean = write_temp("clean-adapter.mjs", "export function check(x) { return gateDecision(x); }\n");
    let dirty = write_temp(
        "dirty-adapter.mjs",
        "export function check(x) { return { allowed: true, code: null }; }\n",
    );
    let result = policy_duplication_audit(&[clean.as_path(), dirty.as_path()]);
    assert_eq!(result.scanned.len(), 2);
    assert_eq!(result.violations.len(), 1);
    assert_eq!(result.violations[0].file, dirty.display().to_string());
    assert!(result.violations[0].why.contains("mints an allow decision"));
}

#[test]
fn policy_duplication_audit_flags_direct_rule_table_reads_and_rank_redeclaration() {
    let a = write_temp("reads-effect-rules.mjs", "const rule = bundle.effectRules.find(r => r.effectClass === x);\n");
    let b = write_temp("redeclares-rank.mjs", "const ENFORCEMENT_RANK = { unsupported: 0 };\n");
    let result = policy_duplication_audit(&[a.as_path(), b.as_path()]);
    assert_eq!(result.violations.len(), 2);
}

#[test]
fn capability_issuance_audit_allows_the_two_trusted_modules() {
    let gate = write_temp("preeffect-gate.mjs", "export function authorize(x) { return store.issue(x); }\n");
    let receipts = write_temp("receipt-store.mjs", "export function record(x) { return ledger.issue(x); }\n");
    let result = capability_issuance_audit(&[gate.as_path(), receipts.as_path()]);
    assert!(result.violations.is_empty());
}

#[test]
fn capability_issuance_audit_flags_an_unrelated_module_minting_a_capability() {
    let rogue = write_temp("rogue-adapter.mjs", "export function sneak(x) { return capabilityStore.issue(x); }\n");
    let result = capability_issuance_audit(&[rogue.as_path()]);
    assert_eq!(result.violations.len(), 1);
    assert!(result.violations[0].why.contains("mints a capability outside"));
}

#[test]
fn capability_issuance_audit_exempts_a_const_bound_authority_invocation_proof_issuer() {
    let src = "const proofIssuer = new AuthorityInvocationProofIssuer(key);\n\
               export function prove(x) { return proofIssuer.issue(x); }\n";
    let path = write_temp("proof-issuer-user.mjs", src);
    let result = capability_issuance_audit(&[path.as_path()]);
    assert!(result.violations.is_empty(), "exempted receiver must not be flagged: {:?}", result.violations);
}

#[test]
fn capability_issuance_audit_does_not_exempt_a_different_receiver_on_the_same_file() {
    let src = "const proofIssuer = new AuthorityInvocationProofIssuer(key);\n\
               export function sneak(x) { return otherStore.issue(x); }\n";
    let path = write_temp("mixed-receivers.mjs", src);
    let result = capability_issuance_audit(&[path.as_path()]);
    assert_eq!(result.violations.len(), 1);
}
