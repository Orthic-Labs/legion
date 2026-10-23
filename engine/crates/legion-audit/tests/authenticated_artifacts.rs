//! A03 authenticated-import tests (authored by the A03 worker; root executes).
//! Fixtures live under tests/fixtures/authenticated-artifacts/.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use legion_audit::artifact_evidence::{
    authenticate_sarif, load_trust_enrollment, redact_export, verify_artifact_evidence,
    ArtifactEvidenceEnvelope, ExecutionMode, ExpectedEvidence, ProvenanceVerifier, ReplayPolicy,
    TrustEnrollment, UnconfiguredVerifier, VerifiedIssuer,
};
use legion_audit::evidence_issuers::{
    evidence_attestation_message, key_id_for, HostEvidenceVerifier, TRUST_ROOT_ID,
};
use legion_audit::native_providers::security::imported_sarif::{ingest_sarif, SarifAuthentication};
use serde_json::{json, Value};

const NOW: &str = "2026-10-23T10:00:00Z";

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/authenticated-artifacts")
}

fn read_json(relative: &str) -> Value {
    let bytes = fs::read(fixture_root().join(relative)).expect("fixture readable");
    serde_json::from_slice(&bytes).expect("fixture JSON")
}

fn envelope(relative: &str) -> ArtifactEvidenceEnvelope {
    ArtifactEvidenceEnvelope::from_value(&read_json(relative)).expect("fixture envelope")
}

fn attestation() -> Vec<u8> {
    fs::read(fixture_root().join("node-ci/attestation.json")).expect("attestation fixture")
}

fn trust() -> TrustEnrollment {
    serde_json::from_value(read_json("trust-enrollment.json")).expect("trust fixture")
}

/// Test-only stand-in for the root-supplied host/CI verifier. Production
/// code ships `UnconfiguredVerifier`; nothing in src/ authenticates fixturally.
struct FixtureVerifier;

impl ProvenanceVerifier for FixtureVerifier {
    fn verifier_id(&self) -> &str {
        "fixture-ci-verifier"
    }
    fn verify(
        &self,
        envelope: &ArtifactEvidenceEnvelope,
        claims_digest: &str,
        attestation: &[u8],
    ) -> Result<VerifiedIssuer, String> {
        if attestation != self::attestation().as_slice() {
            return Err("fixture attestation mismatch".into());
        }
        Ok(VerifiedIssuer {
            issuer_id: envelope.issuer.issuer_id.clone(),
            key_id: envelope.issuer.key_id.clone(),
            claims_digest: claims_digest.to_string(),
        })
    }
}

fn expected_for(envelope: &ArtifactEvidenceEnvelope) -> ExpectedEvidence {
    ExpectedEvidence {
        kind: envelope.kind,
        repositories: envelope.subject.repositories.clone(),
        target: envelope.subject.target.clone(),
        variant: envelope.subject.variant.clone(),
        toolchain: envelope.subject.toolchain.clone(),
        config_digest: envelope.subject.config_digest.clone(),
        test_selection_digest: envelope.subject.test_selection_digest.clone(),
        dependency_graph_digest: envelope.subject.dependency_graph_digest.clone(),
        workload_digest: envelope.subject.workload_digest.clone(),
        command: envelope.subject.command.clone(),
        required_scope: envelope.scope.examined.clone(),
        required_artifacts: envelope.artifacts.clone(),
        replay_policy: ReplayPolicy::Deny,
        upstream_runtime: envelope.upstream_runtime.clone(),
    }
}

fn raw_for(envelope: &ArtifactEvidenceEnvelope) -> BTreeMap<String, Vec<u8>> {
    envelope
        .artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.path.clone(),
                fs::read(fixture_root().join(&artifact.path)).expect("raw artifact fixture"),
            )
        })
        .collect()
}

#[test]
fn valid_node_ci_evidence_imports_authenticated_without_launching_node() {
    let envelope = envelope("node-ci/envelope.json");
    let verdict = verify_artifact_evidence(
        &envelope,
        &raw_for(&envelope),
        &attestation(),
        &expected_for(&envelope),
        &trust(),
        &FixtureVerifier,
        NOW,
    );
    assert!(verdict.reasons.is_empty(), "{:?}", verdict.reasons);
    assert!(verdict.authenticated && verdict.satisfies_obligation);
    let record = verdict.record.expect("record");
    assert_eq!(record.upstream_runtime.as_deref(), Some("node-20"));
    assert!(record.newly_executed);
    assert_eq!(record.repositories.len(), 2);
    assert_eq!(
        record.artifact_digest,
        "sha256:4474131c7336675e8477094c9dafbd71275968387c50c06704c72ab6ac38d57d"
    );
}

#[test]
fn valid_xcode_build_receipt_uses_same_boundary() {
    let envelope = envelope("xcode/envelope.json");
    let verdict = verify_artifact_evidence(
        &envelope,
        &raw_for(&envelope),
        &attestation(),
        &expected_for(&envelope),
        &trust(),
        &FixtureVerifier,
        NOW,
    );
    assert!(verdict.satisfies_obligation, "{:?}", verdict.reasons);
    assert_eq!(
        verdict.record.expect("record").upstream_runtime.as_deref(),
        Some("xcode-16")
    );
}

#[test]
fn unconfigured_verifier_never_authenticates() {
    let envelope = envelope("node-ci/envelope.json");
    let verdict = verify_artifact_evidence(
        &envelope,
        &raw_for(&envelope),
        &attestation(),
        &expected_for(&envelope),
        &trust(),
        &UnconfiguredVerifier,
        NOW,
    );
    assert!(!verdict.authenticated && !verdict.satisfies_obligation);
    assert!(verdict.record.is_none());
    assert!(verdict
        .reasons
        .iter()
        .any(|reason| reason.contains("provenance-verifier-unconfigured")));
}

#[test]
fn untrusted_issuer_and_artifact_substitution_are_forgery_class() {
    let mut forged = envelope("node-ci/envelope.json");
    forged.issuer.issuer_id = "attacker.invalid".into();
    let verdict = verify_artifact_evidence(
        &forged,
        &raw_for(&forged),
        &attestation(),
        &expected_for(&envelope("node-ci/envelope.json")),
        &trust(),
        &FixtureVerifier,
        NOW,
    );
    assert!(!verdict.authenticated);
    assert!(verdict.reasons.iter().any(|r| r == "untrusted-issuer"));

    let envelope = envelope("node-ci/envelope.json");
    let mut raw = raw_for(&envelope);
    raw.insert(
        "node-ci/test-results.json".into(),
        b"{\"suites\":3,\"passed\":0,\"failed\":42}".to_vec(),
    );
    let verdict = verify_artifact_evidence(
        &envelope,
        &raw,
        &attestation(),
        &expected_for(&envelope),
        &trust(),
        &FixtureVerifier,
        NOW,
    );
    assert!(!verdict.authenticated);
    assert!(verdict.reasons.iter().any(|r| r == "artifact-substitution"));
}

#[test]
fn wrong_branch_target_toolchain_and_stale_evidence_cannot_satisfy() {
    let envelope = envelope("node-ci/envelope.json");
    let mut expected = expected_for(&envelope);
    expected.repositories[0].branch = Some("develop".into());
    expected.target = "web-staging".into();
    expected.toolchain = "node-18.0.0/pnpm-8".into();
    let verdict = verify_artifact_evidence(
        &envelope,
        &raw_for(&envelope),
        &attestation(),
        &expected,
        &trust(),
        &FixtureVerifier,
        NOW,
    );
    assert!(!verdict.satisfies_obligation);
    for code in [
        "repository-branch-mismatch",
        "target-mismatch",
        "toolchain-mismatch",
    ] {
        assert!(verdict.reasons.iter().any(|r| r == code), "missing {code}");
    }

    let stale = verify_artifact_evidence(
        &envelope,
        &raw_for(&envelope),
        &attestation(),
        &expected_for(&envelope),
        &trust(),
        &FixtureVerifier,
        "2026-10-25T10:00:00Z",
    );
    assert!(stale.authenticated && !stale.satisfies_obligation);
    assert!(stale.reasons.iter().any(|r| r == "evidence-stale"));
}

#[test]
fn incomplete_scope_and_missing_sibling_repo_cannot_certify() {
    let mut partial = envelope("node-ci/envelope.json");
    partial
        .scope
        .examined
        .retain(|item| item != "journey:checkout");
    partial.scope.missing.push("journey:checkout".into());
    let verdict = verify_artifact_evidence(
        &partial,
        &raw_for(&partial),
        &attestation(),
        &expected_for(&envelope("node-ci/envelope.json")),
        &trust(),
        &FixtureVerifier,
        NOW,
    );
    assert!(!verdict.satisfies_obligation);
    assert!(verdict
        .reasons
        .iter()
        .any(|r| r == "examined-scope-incomplete"));
    assert!(verdict
        .reasons
        .iter()
        .any(|r| r == "missing-scope-declared"));

    let mut single_repo = envelope("node-ci/envelope.json");
    single_repo
        .subject
        .repositories
        .retain(|repo| repo.repository_id == "web");
    let verdict = verify_artifact_evidence(
        &single_repo,
        &raw_for(&single_repo),
        &attestation(),
        &expected_for(&envelope("node-ci/envelope.json")),
        &trust(),
        &FixtureVerifier,
        NOW,
    );
    assert!(!verdict.authenticated);
    assert!(verdict
        .reasons
        .iter()
        .any(|r| r == "repository-set-mismatch"));
}

#[test]
fn replay_is_never_relabelled_as_newly_executed() {
    let mut replayed = envelope("node-ci/envelope.json");
    replayed.execution_mode = ExecutionMode::Replayed;
    replayed.replay_of = Some("node-ci-test-2026-10-22-001".into());

    let denied = verify_artifact_evidence(
        &replayed,
        &raw_for(&replayed),
        &attestation(),
        &expected_for(&replayed),
        &trust(),
        &FixtureVerifier,
        NOW,
    );
    assert!(!denied.satisfies_obligation);
    assert!(denied.reasons.iter().any(|r| r == "replay-not-permitted"));

    let mut expected = expected_for(&replayed);
    expected.replay_policy = ReplayPolicy::AllowIdenticalImmutable;
    let allowed = verify_artifact_evidence(
        &replayed,
        &raw_for(&replayed),
        &attestation(),
        &expected,
        &trust(),
        &FixtureVerifier,
        NOW,
    );
    assert!(allowed.satisfies_obligation, "{:?}", allowed.reasons);
    let record = allowed.record.expect("record");
    assert!(!record.newly_executed);
    assert_eq!(
        record.replay_of.as_deref(),
        Some("node-ci-test-2026-10-22-001")
    );
}

#[test]
fn trust_enrollment_inside_scanned_root_or_with_secret_is_rejected() {
    let root = fixture_root();
    let path = root.join("trust-enrollment.json");
    assert!(load_trust_enrollment(&path, &[root.as_path()]).is_err());
    let secret_path = root.join("trust-enrollment-with-secret.json");
    let relative = Path::new("trust-enrollment.json");
    assert!(load_trust_enrollment(relative, &[]).is_err());
    assert!(load_trust_enrollment(&secret_path, &[]).is_err());
    // The same well-formed file loads when no forbidden root contains it
    // (root passes the real scanned/scratch roots in production).
    let loaded = load_trust_enrollment(&path, &[]).expect("well-formed enrollment");
    assert_eq!(loaded.issuers.len(), 1);
}

#[test]
fn local_sarif_stays_candidate_until_envelope_covers_its_bytes() {
    let raw = fs::read(fixture_root().join("node-ci/results.sarif")).expect("sarif fixture");
    let digest = "sha256:c2e2f8bc6a6112c4da98f18023ef9f8ea4307d1e7e35e42180487d4a06b5cb18";
    let binding = json!({"revision": "r1", "root": "/repo"});
    let tool = json!({"name": "fixture-tool", "version": "1.0.0"});
    let sarif = ingest_sarif(None, Some(&raw), &binding, Some(digest), &tool).expect("ingest");
    assert!(matches!(
        sarif.authentication,
        SarifAuthentication::SelfAttestedCandidate
    ));
    assert!(!sarif.has_execution_provenance() && !sarif.satisfies_obligation());

    let mut covering = envelope("node-ci/envelope.json");
    covering.artifacts = vec![legion_audit::artifact_evidence::ArtifactBinding {
        path: "node-ci/results.sarif".into(),
        digest: digest.into(),
        bytes: raw.len() as u64,
        role: "sarif".into(),
    }];
    let verdict = verify_artifact_evidence(
        &covering,
        &raw_for(&covering),
        &attestation(),
        &expected_for(&covering),
        &trust(),
        &FixtureVerifier,
        NOW,
    );
    assert!(verdict.satisfies_obligation, "{:?}", verdict.reasons);
    let upgraded = authenticate_sarif(sarif, &verdict);
    assert!(upgraded.has_execution_provenance() && upgraded.satisfies_obligation());
}

#[test]
fn exported_projection_redacts_secret_spellings_but_keeps_digest() {
    let exported = redact_export(&json!({
        "clientSecretValue": "do-not-export",
        "evidenceId": "node-ci-test-2026-10-23-001"
    }));
    assert_eq!(exported["clientSecretValue"]["redacted"], json!(true));
    assert!(exported["clientSecretValue"]["digest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:")));
    assert!(!exported.to_string().contains("do-not-export"));
    assert_eq!(exported["evidenceId"], json!("node-ci-test-2026-10-23-001"));
}

// ---- Host-enrolled Ed25519 issuer verification ----

const SEED: [u8; 32] = [7u8; 32];

fn issuers_json(public_hex: &str, repos: &[&str], workflow: &str, subject: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schemaVersion": 1,
        "issuers": [{
            "issuerId": "ci.example.invalid",
            "publicKey": public_hex,
            "allowedRepositories": repos,
            "allowedWorkflows": [workflow],
            "allowedSubjects": [subject],
        }]
    }))
    .unwrap()
}

fn signed_envelope(seed: [u8; 32]) -> (ArtifactEvidenceEnvelope, Vec<u8>, String) {
    use ed25519_dalek::{Signer, SigningKey};
    let enrolled = SigningKey::from_bytes(&SEED).verifying_key();
    let mut value = read_json("node-ci/envelope.json");
    value["issuer"]["trustRootId"] = json!(TRUST_ROOT_ID);
    value["issuer"]["keyId"] = json!(key_id_for(&hex::encode(enrolled.to_bytes())).unwrap());
    let mut envelope = ArtifactEvidenceEnvelope::from_value(&value).unwrap();
    let claims = envelope.canonical_claims_digest().unwrap();
    let signing = SigningKey::from_bytes(&seed);
    let signature = hex::encode(
        signing
            .sign(&evidence_attestation_message(&claims))
            .to_bytes(),
    );
    let digest = {
        use sha2::{Digest, Sha256};
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(signature.as_bytes()))
        )
    };
    envelope.issuer.attestation_digest = digest;
    (envelope, signature.into_bytes(), claims)
}

fn host_verifier(
    repos: &[&str],
    workflow: &str,
    subject: &str,
) -> (HostEvidenceVerifier, TrustEnrollment) {
    let public = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&SEED)
            .verifying_key()
            .to_bytes(),
    );
    HostEvidenceVerifier::from_bytes(&issuers_json(&public, repos, workflow, subject)).unwrap()
}

fn run(
    envelope: &ArtifactEvidenceEnvelope,
    attestation: &[u8],
    verifier: &HostEvidenceVerifier,
    trust: &TrustEnrollment,
    now: &str,
    expected: &ExpectedEvidence,
) -> legion_audit::artifact_evidence::ImportVerdict {
    verify_artifact_evidence(
        envelope,
        &raw_for(envelope),
        attestation,
        expected,
        trust,
        verifier,
        now,
    )
}

fn allowed(envelope: &ArtifactEvidenceEnvelope) -> (HostEvidenceVerifier, TrustEnrollment) {
    host_verifier(
        &["web", "api"],
        &envelope.subject.command.adapter_id,
        &envelope.subject.target,
    )
}

#[test]
fn enrolled_signed_envelope_satisfies_matching_obligation() {
    let (envelope, attestation, _) = signed_envelope(SEED);
    let (verifier, trust) = allowed(&envelope);
    let verdict = run(
        &envelope,
        &attestation,
        &verifier,
        &trust,
        NOW,
        &expected_for(&envelope),
    );
    assert!(verdict.reasons.is_empty(), "{:?}", verdict.reasons);
    assert!(verdict.authenticated && verdict.satisfies_obligation);
}

fn reasons_of(verdict: &legion_audit::artifact_evidence::ImportVerdict) -> String {
    verdict.reasons.join(",")
}

#[test]
fn wrong_signing_key_is_unmet_with_named_reason() {
    let (envelope, attestation, _) = signed_envelope([9u8; 32]);
    let (verifier, trust) = allowed(&envelope);
    let verdict = run(
        &envelope,
        &attestation,
        &verifier,
        &trust,
        NOW,
        &expected_for(&envelope),
    );
    assert!(!verdict.satisfies_obligation && !verdict.authenticated);
    assert!(
        reasons_of(&verdict).contains("signature-invalid"),
        "{:?}",
        verdict.reasons
    );
}

#[test]
fn unenrolled_issuer_is_unmet() {
    let (mut envelope, attestation, _) = signed_envelope(SEED);
    envelope.issuer.issuer_id = "rogue.example.invalid".into();
    let (verifier, trust) = allowed(&envelope);
    let verdict = run(
        &envelope,
        &attestation,
        &verifier,
        &trust,
        NOW,
        &expected_for(&envelope),
    );
    assert!(!verdict.satisfies_obligation);
    assert!(
        reasons_of(&verdict).contains("untrusted-issuer"),
        "{:?}",
        verdict.reasons
    );
}

#[test]
fn repository_supplied_enrollment_is_refused() {
    let dir = std::env::temp_dir().join(format!("legion-issuers-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit-evidence-issuers.json");
    let public = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&SEED)
            .verifying_key()
            .to_bytes(),
    );
    fs::write(&path, issuers_json(&public, &["web"], "w", "t")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let canonical = fs::canonicalize(&path).unwrap();
    // The audited root contains the enrollment file: refused, never loaded.
    let refused = HostEvidenceVerifier::load(&canonical, &[fs::canonicalize(&dir).unwrap()]);
    assert!(refused.is_err(), "repo-supplied enrollment must be refused");
    // Loose permissions are refused too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let other = std::env::temp_dir().join("legion-issuers-elsewhere-root");
        fs::create_dir_all(&other).unwrap();
        let loose = HostEvidenceVerifier::load(&canonical, &[fs::canonicalize(&other).unwrap()]);
        assert!(loose.is_err());
    }
    // Absent file: unchanged (None).
    assert!(HostEvidenceVerifier::load(&dir.join("absent.json"), &[])
        .unwrap()
        .is_none());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn wrong_subject_and_disallowed_scope_are_unmet() {
    let (envelope, attestation, _) = signed_envelope(SEED);
    // Expectation names a different target.
    let (verifier, trust) = allowed(&envelope);
    let mut wrong = expected_for(&envelope);
    wrong.target = "other-target".into();
    let verdict = run(&envelope, &attestation, &verifier, &trust, NOW, &wrong);
    assert!(reasons_of(&verdict).contains("target-mismatch"));
    assert!(!verdict.satisfies_obligation);
    // Issuer not allowed for the claimed repository set.
    let (verifier, trust) = host_verifier(
        &["web"],
        &envelope.subject.command.adapter_id,
        &envelope.subject.target,
    );
    let verdict = run(
        &envelope,
        &attestation,
        &verifier,
        &trust,
        NOW,
        &expected_for(&envelope),
    );
    assert!(reasons_of(&verdict).contains("repository-not-allowed-for-issuer"));
    assert!(!verdict.satisfies_obligation);
}

#[test]
fn stale_evidence_is_unmet() {
    let (envelope, attestation, _) = signed_envelope(SEED);
    let (verifier, trust) = allowed(&envelope);
    let verdict = run(
        &envelope,
        &attestation,
        &verifier,
        &trust,
        "2099-01-01T00:00:00Z",
        &expected_for(&envelope),
    );
    assert!(!verdict.satisfies_obligation);
    assert!(
        reasons_of(&verdict).contains("evidence-stale"),
        "{:?}",
        verdict.reasons
    );
}

#[test]
fn replayed_envelope_in_the_same_run_is_unmet() {
    let (envelope, attestation, _) = signed_envelope(SEED);
    let (verifier, trust) = allowed(&envelope);
    let expected = expected_for(&envelope);
    assert!(run(&envelope, &attestation, &verifier, &trust, NOW, &expected).satisfies_obligation);
    let second = run(&envelope, &attestation, &verifier, &trust, NOW, &expected);
    assert!(!second.satisfies_obligation);
    assert!(
        reasons_of(&second).contains("replayed-evidence"),
        "{:?}",
        second.reasons
    );
}
