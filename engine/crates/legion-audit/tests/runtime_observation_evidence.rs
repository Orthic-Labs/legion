//! Issue #63: signed backend-auth-probe and compatibility-run observations
//! verified through the host-enrolled Ed25519 issuers before they satisfy
//! exactly the plan-named probes. Deterministic: in-test keys, no network.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use legion_audit::artifact_evidence::{
    verify_runtime_observation, ArtifactBinding, ArtifactEvidenceEnvelope, CommandBinding,
    CompatibilityRun, ExpectedEvidence, ExpectedObservation, ImportKind, ObservationKind,
    ObservationLedger, ObservationVerdict, ProbeOutcome, ProbeResult, ReplayPolicy,
    RepositoryBinding, RuntimeObservationPayload, TrustEnrollment, OBSERVATION_ARTIFACT_ROLE,
    OBSERVATION_SCHEMA_VERSION,
};
use legion_audit::evidence_issuers::{
    evidence_attestation_message, key_id_for, HostEvidenceVerifier, TRUST_ROOT_ID,
};
use legion_audit::native_providers::architecture::{compatibility, framework, producer, Analysis};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SEED: [u8; 32] = [7u8; 32];
const FORGER_SEED: [u8; 32] = [9u8; 32];
const NOW: &str = "2026-10-30T12:00:00Z";
const ISSUED: &str = "2026-10-30T11:55:00Z";
const FRESH_UNTIL: &str = "2026-10-30T13:00:00Z";
const TARGET: &str = "svc-api";
const ISSUER: &str = "rightkit.example.invalid";

fn digest(text: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes())))
}

fn public_hex(seed: [u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

fn enrolled() -> (HostEvidenceVerifier, TrustEnrollment) {
    let issuers = serde_json::to_vec(&json!({
        "schemaVersion": 1,
        "issuers": [{
            "issuerId": ISSUER,
            "publicKey": public_hex(SEED),
            "allowedRepositories": ["web"],
            "allowedWorkflows": ["probe-runner"],
            "allowedSubjects": [TARGET],
        }]
    }))
    .unwrap();
    HostEvidenceVerifier::from_bytes(&issuers).unwrap()
}

/// Everything a case may vary; defaults describe one genuine observation.
#[derive(Clone)]
struct Case {
    kind: ObservationKind,
    signer: [u8; 32],
    issuer_id: String,
    evidence_id: String,
    observation_id: String,
    sequence: u64,
    envelope_target: String,
    deployed_digest: String,
    probes: Vec<(&'static str, ProbeOutcome)>,
    claimed_scope: Option<Vec<&'static str>>,
}

impl Case {
    fn new(kind: ObservationKind) -> Self {
        Self {
            kind,
            signer: SEED,
            issuer_id: ISSUER.into(),
            evidence_id: "ev-1".into(),
            observation_id: "obs-1".into(),
            sequence: 1,
            envelope_target: TARGET.into(),
            deployed_digest: digest("deployed-build-1"),
            probes: vec![
                ("auth.rejects-anonymous", ProbeOutcome::Passed),
                ("auth.rejects-expired-token", ProbeOutcome::Passed),
            ],
            claimed_scope: None,
        }
    }
}

fn compat_run() -> CompatibilityRun {
    CompatibilityRun {
        producer_version: "2.1.0".into(),
        consumer_version: "2.0.3".into(),
        platform: "linux-x64".into(),
        contract: "orders-v2".into(),
    }
}

fn required_probes() -> Vec<String> {
    vec![
        "auth.rejects-anonymous".into(),
        "auth.rejects-expired-token".into(),
    ]
}

fn repositories() -> Vec<RepositoryBinding> {
    vec![RepositoryBinding {
        repository_id: "web".into(),
        revision: "abc123".into(),
        branch: None,
        snapshot_digest: digest("snapshot"),
    }]
}

fn command() -> CommandBinding {
    CommandBinding {
        adapter_id: "probe-runner".into(),
        command_digest: digest("probe-command"),
        executable_digest: None,
    }
}

fn expected_for(kind: ObservationKind) -> ExpectedObservation {
    let probes = required_probes();
    ExpectedObservation {
        evidence: ExpectedEvidence {
            kind: ImportKind::Runtime,
            repositories: repositories(),
            target: TARGET.into(),
            variant: None,
            toolchain: "rightkit-probe-1".into(),
            config_digest: digest("config-1"),
            test_selection_digest: None,
            dependency_graph_digest: digest("deps"),
            workload_digest: None,
            command: command(),
            required_scope: probes.clone(),
            required_artifacts: Vec::new(),
            replay_policy: ReplayPolicy::Deny,
            upstream_runtime: None,
        },
        kind,
        deployed_artifact_digest: digest("deployed-build-1"),
        environment: "staging".into(),
        required_probes: probes,
        max_age_seconds: 900,
        compatibility: (kind == ObservationKind::CompatibilityRun).then(compat_run),
    }
}

struct Built {
    envelope: ArtifactEvidenceEnvelope,
    raw: BTreeMap<String, Vec<u8>>,
    attestation: Vec<u8>,
}

fn build(case: &Case) -> Built {
    let payload = RuntimeObservationPayload {
        schema_version: OBSERVATION_SCHEMA_VERSION,
        observation_kind: case.kind,
        observation_id: case.observation_id.clone(),
        sequence: case.sequence,
        deployed_artifact_digest: case.deployed_digest.clone(),
        configuration_digest: digest("config-1"),
        environment: "staging".into(),
        probes: case
            .probes
            .iter()
            .map(|(id, outcome)| ProbeResult {
                probe_id: (*id).into(),
                outcome: *outcome,
            })
            .collect(),
        compatibility: (case.kind == ObservationKind::CompatibilityRun).then(compat_run),
        issued_at: ISSUED.into(),
        max_age_seconds: 600,
    };
    let bytes = serde_json::to_vec(&payload).unwrap();
    let artifact = ArtifactBinding {
        path: "observation.json".into(),
        digest: format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        bytes: bytes.len() as u64,
        role: OBSERVATION_ARTIFACT_ROLE.into(),
    };
    let scope: Vec<&str> = case
        .claimed_scope
        .clone()
        .unwrap_or_else(|| case.probes.iter().map(|(id, _)| *id).collect());
    let key_id = key_id_for(&public_hex(SEED)).unwrap();
    let value = json!({
        "schemaVersion": 1,
        "evidenceId": case.evidence_id,
        "kind": "runtime",
        "executionMode": "executed",
        "issuer": {
            "issuerId": case.issuer_id,
            "trustRootId": TRUST_ROOT_ID,
            "keyId": key_id,
            "attestationFormat": "host-ci-provenance",
            "attestationDigest": digest("placeholder"),
        },
        "subject": {
            "repositories": repositories(),
            "target": case.envelope_target,
            "toolchain": "rightkit-probe-1",
            "configDigest": digest("config-1"),
            "dependencyGraphDigest": digest("deps"),
            "command": command(),
        },
        "artifacts": [artifact],
        "outcome": "passed",
        "scope": {"examined": scope, "missing": []},
        "issuedAt": ISSUED,
        "freshUntil": FRESH_UNTIL,
    });
    let mut envelope = ArtifactEvidenceEnvelope::from_value(&value).unwrap();
    let claims = envelope.canonical_claims_digest().unwrap();
    let signature = hex::encode(
        SigningKey::from_bytes(&case.signer)
            .sign(&evidence_attestation_message(&claims))
            .to_bytes(),
    );
    envelope.issuer.attestation_digest = digest(&signature);
    Built {
        envelope,
        raw: BTreeMap::from([("observation.json".to_string(), bytes)]),
        attestation: signature.into_bytes(),
    }
}

fn run(
    case: &Case,
    verifier: &HostEvidenceVerifier,
    trust: &TrustEnrollment,
    ledger: &ObservationLedger,
    now: &str,
) -> ObservationVerdict {
    let built = build(case);
    verify_runtime_observation(
        &built.envelope,
        &built.raw,
        &built.attestation,
        &expected_for(case.kind),
        trust,
        verifier,
        ledger,
        now,
    )
}

fn run_fresh(case: &Case) -> ObservationVerdict {
    let (verifier, trust) = enrolled();
    run(case, &verifier, &trust, &ObservationLedger::new(), NOW)
}

fn has(verdict: &ObservationVerdict, needle: &str) -> bool {
    verdict.reasons.iter().any(|reason| reason.contains(needle))
}

fn compat_default() -> Analysis {
    compatibility::analyze(&json!({})).unwrap()
}

fn backend_default() -> Analysis {
    framework::analyze_backend(&json!({})).unwrap()
}

fn gaps(analysis: &Analysis) -> Vec<String> {
    analysis
        .coverage_gaps
        .iter()
        .filter_map(|gap| gap.get("kind").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

#[test]
fn genuine_backend_auth_observation_satisfies_exactly_the_named_probes() {
    let verdict = run_fresh(&Case::new(ObservationKind::BackendAuthProbe));
    assert!(verdict.satisfies_obligation(), "{:?}", verdict.reasons);
    let observation = verdict.observation().unwrap();
    assert_eq!(observation.satisfied_probes(), required_probes().as_slice());
    assert_eq!(observation.target(), TARGET);
    assert_eq!(
        observation.deployed_artifact_digest(),
        digest("deployed-build-1")
    );

    let mut analysis = backend_default();
    producer::apply_observations("framework.backend", &mut analysis, &[verdict]);
    let output = analysis.output();
    assert_eq!(
        output["authProbeObservations"][0]["satisfiedProbes"],
        json!(required_probes())
    );
    assert_eq!(
        output["authProbeObservations"][0]["generalCorrectnessClaim"],
        json!(false)
    );
    // Never general authentication correctness.
    assert_eq!(output["certificationClaim"], json!(false));
    assert_eq!(analysis.status, "unproven");
    assert!(!analysis.complete);
}

#[test]
fn genuine_compatibility_observation_satisfies_named_probes_only() {
    let verdict = run_fresh(&Case::new(ObservationKind::CompatibilityRun));
    assert!(verdict.satisfies_obligation(), "{:?}", verdict.reasons);
    let mut analysis = compat_default();
    assert!(gaps(&analysis).contains(&"compatibility-denominator-unavailable".to_string()));
    producer::apply_observations("compatibility.core", &mut analysis, &[verdict]);
    assert_eq!(analysis.status, "pass");
    assert!(analysis.complete);
    assert!(
        analysis.coverage_gaps.is_empty(),
        "{:?}",
        analysis.coverage_gaps
    );
    assert_eq!(analysis.denominator["expected"], json!(2));
    assert_eq!(analysis.denominator["examined"], json!(2));
    let output = analysis.output();
    assert_eq!(output["certificationClaim"], json!(false));
    assert_eq!(
        output["runtimeObservationScope"],
        json!("named-probes-only")
    );
}

#[test]
fn default_path_is_unchanged_without_observations() {
    let mut compat = compat_default();
    let before = compat.clone();
    producer::apply_observations("compatibility.core", &mut compat, &[]);
    assert_eq!(compat, before);
    let mut backend = backend_default();
    let before = backend.clone();
    producer::apply_observations("framework.backend", &mut backend, &[]);
    assert_eq!(backend, before);
}

#[test]
fn forged_signature_is_rejected_and_stays_unknown_with_named_gap() {
    let mut case = Case::new(ObservationKind::CompatibilityRun);
    case.signer = FORGER_SEED;
    let verdict = run_fresh(&case);
    assert!(!verdict.satisfies_obligation());
    assert!(has(&verdict, "signature-invalid"), "{:?}", verdict.reasons);
    let mut analysis = compat_default();
    producer::apply_observations("compatibility.core", &mut analysis, &[verdict]);
    assert_eq!(analysis.status, "unproven");
    assert!(gaps(&analysis)
        .iter()
        .any(|gap| gap.starts_with("runtime-observation-rejected:compatibility-run:")));
    assert!(gaps(&analysis).contains(&"compatibility-denominator-unavailable".to_string()));
}

#[test]
fn unenrolled_issuer_is_rejected() {
    let mut case = Case::new(ObservationKind::BackendAuthProbe);
    case.issuer_id = "rogue.example.invalid".into();
    let verdict = run_fresh(&case);
    assert!(!verdict.satisfies_obligation());
    assert!(has(&verdict, "untrusted-issuer"), "{:?}", verdict.reasons);
}

#[test]
fn stale_observation_is_rejected_even_inside_the_envelope_window() {
    // Envelope freshUntil is 13:00; the payload's own 10-minute age is spent.
    let (verifier, trust) = enrolled();
    let verdict = run(
        &Case::new(ObservationKind::BackendAuthProbe),
        &verifier,
        &trust,
        &ObservationLedger::new(),
        "2026-10-30T12:30:00Z",
    );
    assert!(!verdict.satisfies_obligation());
    assert!(has(&verdict, "observation-stale"), "{:?}", verdict.reasons);
    // Past the envelope window too.
    let (verifier, trust) = enrolled();
    let verdict = run(
        &Case::new(ObservationKind::BackendAuthProbe),
        &verifier,
        &trust,
        &ObservationLedger::new(),
        "2026-10-30T14:00:00Z",
    );
    assert!(has(&verdict, "evidence-stale"), "{:?}", verdict.reasons);
}

#[test]
fn wrong_target_digest_or_subject_is_rejected() {
    let mut case = Case::new(ObservationKind::BackendAuthProbe);
    case.deployed_digest = digest("some-other-build");
    let verdict = run_fresh(&case);
    assert!(!verdict.satisfies_obligation());
    assert!(
        has(&verdict, "deployed-artifact-digest-mismatch"),
        "{:?}",
        verdict.reasons
    );

    let mut case = Case::new(ObservationKind::BackendAuthProbe);
    case.envelope_target = "svc-billing".into();
    let verdict = run_fresh(&case);
    assert!(!verdict.satisfies_obligation());
    assert!(has(&verdict, "target-mismatch"), "{:?}", verdict.reasons);
}

#[test]
fn replayed_observation_is_rejected_by_evidence_set_and_ledger() {
    let (verifier, trust) = enrolled();
    let ledger = ObservationLedger::new();
    let case = Case::new(ObservationKind::BackendAuthProbe);
    assert!(run(&case, &verifier, &trust, &ledger, NOW).satisfies_obligation());
    // Same envelope again: the verifier's evidence replay set rejects it.
    let again = run(&case, &verifier, &trust, &ledger, NOW);
    assert!(!again.satisfies_obligation());
    assert!(has(&again, "replayed-evidence"), "{:?}", again.reasons);
    // Freshly signed envelope reusing the observation nonce: ledger rejects.
    let mut reuse = case.clone();
    reuse.evidence_id = "ev-2".into();
    reuse.sequence = 2;
    let verdict = run(&reuse, &verifier, &trust, &ledger, NOW);
    assert!(
        has(&verdict, "observation-replayed"),
        "{:?}",
        verdict.reasons
    );
    // New nonce but non-monotonic sequence: rejected.
    let mut old = case.clone();
    old.evidence_id = "ev-3".into();
    old.observation_id = "obs-3".into();
    old.sequence = 1;
    let verdict = run(&old, &verifier, &trust, &ledger, NOW);
    assert!(
        has(&verdict, "observation-sequence-not-monotonic"),
        "{:?}",
        verdict.reasons
    );
    // A genuinely newer one is still accepted.
    let mut next = case.clone();
    next.evidence_id = "ev-4".into();
    next.observation_id = "obs-4".into();
    next.sequence = 2;
    assert!(run(&next, &verifier, &trust, &ledger, NOW).satisfies_obligation());
}

#[test]
fn partial_scope_never_satisfies_unclaimed_probes() {
    // Payload covers fewer probes than the plan names.
    let mut case = Case::new(ObservationKind::BackendAuthProbe);
    case.probes = vec![("auth.rejects-anonymous", ProbeOutcome::Passed)];
    let verdict = run_fresh(&case);
    assert!(!verdict.satisfies_obligation());
    assert!(
        has(&verdict, "probe-coverage-partial"),
        "{:?}",
        verdict.reasons
    );
    let mut analysis = backend_default();
    producer::apply_observations("framework.backend", &mut analysis, &[verdict]);
    assert!(gaps(&analysis)
        .iter()
        .any(|gap| gap.starts_with("runtime-observation-rejected:backend-auth-probe:")));
    assert_eq!(analysis.status, "unproven");
    assert!(analysis.output()["authProbeObservations"]
        .as_array()
        .unwrap()
        .is_empty());

    // Signed scope claims more probes than the payload carries.
    let mut over = Case::new(ObservationKind::BackendAuthProbe);
    over.probes = vec![("auth.rejects-anonymous", ProbeOutcome::Passed)];
    over.claimed_scope = Some(vec!["auth.rejects-anonymous", "auth.rejects-expired-token"]);
    let verdict = run_fresh(&over);
    assert!(
        has(&verdict, "envelope-scope-differs-from-payload-probes"),
        "{:?}",
        verdict.reasons
    );
}

#[test]
fn failed_probe_is_a_finding_not_a_satisfaction() {
    let mut case = Case::new(ObservationKind::CompatibilityRun);
    case.probes[1].1 = ProbeOutcome::Failed;
    let verdict = run_fresh(&case);
    assert!(verdict.satisfies_obligation(), "{:?}", verdict.reasons);
    let observation = verdict.observation().unwrap();
    assert_eq!(observation.satisfied_probes(), ["auth.rejects-anonymous"]);
    assert_eq!(observation.failed_probes(), ["auth.rejects-expired-token"]);
    let mut analysis = compat_default();
    producer::apply_observations("compatibility.core", &mut analysis, &[verdict]);
    assert_eq!(analysis.status, "unproven");
    assert!(!analysis.complete);
    assert_eq!(analysis.findings.len(), 1);
    assert_eq!(
        analysis.findings[0]["id"],
        json!("compatibility-probe-failed:auth.rejects-expired-token")
    );
}
