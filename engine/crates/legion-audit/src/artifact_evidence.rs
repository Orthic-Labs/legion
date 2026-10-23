//! Authenticated imports of upstream build, test, runtime & artifact evidence (A03).
//!
//! This module is the only boundary that may mark imported evidence
//! `authenticated`. It launches no process: upstream Node/Xcode/Gradle CI may
//! have produced the evidence, but Audit only verifies an immutable envelope
//! against exact frozen-plan expectations plus an externally enrolled trust
//! root. Cryptographic provenance checking is delegated to a root-supplied
//! [`ProvenanceVerifier`] (pinned RustRight client for broker evidence, host/CI
//! adapter for CI provenance); no signature scheme is implemented or faked
//! here, and an unconfigured verifier never authenticates anything.
//!
//! Timestamps use strict `YYYY-MM-DDTHH:MM:SSZ` UTC form and compare
//! lexicographically, matching the A02 assurance convention. All digests are
//! `sha256:` + 64 lowercase hex characters.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::AuditError;
use crate::native_providers::legacy_checks::AttestedRunsEnrollment;
use crate::native_providers::security::imported_sarif::{ImportedSarif, SarifAuthentication};

pub const ARTIFACT_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const ARTIFACT_EVIDENCE_BOUND: &str = "artifactEvidenceV1";
pub const MAX_ENROLLMENT_BYTES: usize = 1024 * 1024;
pub const MAX_RAW_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lower_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty() && !value.contains('\0')
}

/// Strict `YYYY-MM-DDTHH:MM:SSZ` shape; lexicographic order equals time order.
pub fn is_rfc3339_utc_second(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20 || bytes[19] != b'Z' || bytes[10] != b'T' {
        return false;
    }
    let digits = [0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && digits.iter().all(|&index| bytes[index].is_ascii_digit())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportKind {
    Build,
    Test,
    Runtime,
    Performance,
    Artifact,
    Sarif,
    UpstreamReceipt,
}

impl ImportKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Test => "test",
            Self::Runtime => "runtime",
            Self::Performance => "performance",
            Self::Artifact => "artifact",
            Self::Sarif => "sarif",
            Self::UpstreamReceipt => "upstream-receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionMode {
    Executed,
    Replayed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceOutcome {
    Passed,
    Failed,
    Findings,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerBinding {
    pub issuer_id: String,
    pub trust_root_id: String,
    /// SHA-256 fingerprint of the issuer public key; never key material.
    pub key_id: String,
    /// `rustright-receipt` (broker) or `host-ci-provenance` (CI adapter).
    pub attestation_format: String,
    pub attestation_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryBinding {
    pub repository_id: String,
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub snapshot_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandBinding {
    pub adapter_id: String,
    /// Digest of the canonical redacted command; arguments themselves are
    /// never required in the envelope.
    pub command_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectBinding {
    pub repositories: Vec<RepositoryBinding>,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub toolchain: String,
    pub config_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_selection_digest: Option<String>,
    pub dependency_graph_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_digest: Option<String>,
    pub command: CommandBinding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactBinding {
    pub path: String,
    pub digest: String,
    pub bytes: u64,
    /// e.g. `primary`, `sarif`, `test-results`, `deployed-artifact`.
    pub role: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeBinding {
    pub examined: Vec<String>,
    #[serde(default)]
    pub missing: Vec<String>,
}

/// Versioned execution/artifact envelope supplied with imported evidence.
/// The envelope is a claim; only [`verify_artifact_evidence`] can turn it
/// into authenticated evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactEvidenceEnvelope {
    pub schema_version: u32,
    pub evidence_id: String,
    pub kind: ImportKind,
    pub execution_mode: ExecutionMode,
    pub issuer: IssuerBinding,
    pub subject: SubjectBinding,
    pub artifacts: Vec<ArtifactBinding>,
    pub outcome: EvidenceOutcome,
    pub scope: ScopeBinding,
    /// Honest upstream runtime label, e.g. `node-20`, `xcode-16`, `gradle-8`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_runtime: Option<String>,
    pub issued_at: String,
    pub fresh_until: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_of: Option<String>,
}

impl ArtifactEvidenceEnvelope {
    /// Canonical digest over every claim except the attestation digest
    /// itself. This is the value a [`ProvenanceVerifier`] must bind its
    /// attestation check to.
    pub fn canonical_claims_digest(&self) -> Result<String, AuditError> {
        let mut claims =
            serde_json::to_value(self).map_err(|error| AuditError::Invalid(error.to_string()))?;
        if let Some(issuer) = claims.get_mut("issuer").and_then(Value::as_object_mut) {
            issuer.remove("attestationDigest");
        }
        crate::integrity::digest(&claims)
    }

    pub fn from_value(value: &Value) -> Result<Self, AuditError> {
        let envelope: Self = serde_json::from_value(value.clone())
            .map_err(|error| AuditError::Invalid(format!("artifact evidence envelope: {error}")))?;
        if envelope.schema_version != ARTIFACT_EVIDENCE_SCHEMA_VERSION {
            return Err(AuditError::Invalid(
                "unsupported artifact evidence schemaVersion".into(),
            ));
        }
        Ok(envelope)
    }
}

/// Exact expected values frozen in the plan by root before any import runs.
/// Every field is compared for equality; nothing is inferred from the
/// envelope or the scanned repository.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedEvidence {
    pub kind: ImportKind,
    pub repositories: Vec<RepositoryBinding>,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub toolchain: String,
    pub config_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_selection_digest: Option<String>,
    pub dependency_graph_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_digest: Option<String>,
    pub command: CommandBinding,
    pub required_scope: Vec<String>,
    /// Every listed artifact (path, digest, bytes, role) must be present
    /// verbatim; extra artifacts are retained but named in the record.
    #[serde(default)]
    pub required_artifacts: Vec<ArtifactBinding>,
    pub replay_policy: ReplayPolicy,
    /// Optional upstream runtime pin; when set it must match exactly. A Node
    /// upstream value is evidence about CI, never a reason to launch Node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_runtime: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReplayPolicy {
    /// Replayed evidence can never satisfy an obligation.
    Deny,
    /// Identical immutable artifacts may satisfy, but are always reported as
    /// replayed, never as newly executed.
    AllowIdenticalImmutable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedIssuer {
    pub issuer_id: String,
    pub trust_root_id: String,
    pub key_id: String,
    pub attestation_format: String,
    /// Must equal [`ProvenanceVerifier::verifier_id`] of the verifier root
    /// supplies; a different verifier cannot authenticate this issuer.
    pub verifier_id: String,
}

/// Trust enrollment. Loaded only from outside the scanned/scratch roots;
/// contains fingerprints only, never key material or commands.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustEnrollment {
    pub schema_version: u32,
    pub issuers: Vec<TrustedIssuer>,
}

impl TrustEnrollment {
    pub fn validate(&self) -> Result<(), AuditError> {
        let invalid = |reason: &str| AuditError::Invalid(format!("trust enrollment: {reason}"));
        if self.schema_version != ARTIFACT_EVIDENCE_SCHEMA_VERSION {
            return Err(invalid("unsupported schemaVersion"));
        }
        if self.issuers.is_empty() {
            return Err(invalid("no issuers enrolled"));
        }
        let mut seen = BTreeSet::new();
        for issuer in &self.issuers {
            if !non_empty(&issuer.issuer_id)
                || !non_empty(&issuer.trust_root_id)
                || !non_empty(&issuer.verifier_id)
                || !matches!(
                    issuer.attestation_format.as_str(),
                    "rustright-receipt" | "host-ci-provenance"
                )
                || !is_lower_hex64(&issuer.key_id)
            {
                return Err(invalid("issuer entry is malformed"));
            }
            if !seen.insert(issuer.issuer_id.clone()) {
                return Err(invalid("duplicate issuerId"));
            }
        }
        Ok(())
    }

    pub fn issuer(&self, issuer_id: &str) -> Option<&TrustedIssuer> {
        self.issuers
            .iter()
            .find(|issuer| issuer.issuer_id == issuer_id)
    }

    /// Enroll the pinned RustRight broker as an issuer from the existing
    /// attested-runs enrollment (host + key fingerprint). Verification still
    /// requires a root-supplied verifier wrapping the pinned client.
    pub fn from_attested_runs(
        enrollment: &AttestedRunsEnrollment,
        trust_root_id: impl Into<String>,
        verifier_id: impl Into<String>,
    ) -> Result<Self, AuditError> {
        enrollment
            .validate()
            .map_err(|error| AuditError::Invalid(error.to_string()))?;
        let trust = Self {
            schema_version: ARTIFACT_EVIDENCE_SCHEMA_VERSION,
            issuers: vec![TrustedIssuer {
                issuer_id: enrollment.host.clone(),
                trust_root_id: trust_root_id.into(),
                key_id: enrollment.key_id.clone(),
                attestation_format: "rustright-receipt".into(),
                verifier_id: verifier_id.into(),
            }],
        };
        trust.validate()?;
        Ok(trust)
    }
}

/// Load trust enrollment from an absolute regular file outside every
/// forbidden root (scanned repository, scratch, run dir). Symlinks, relative
/// paths, oversized files and any secret-shaped field are rejected; there is
/// no caller override.
pub fn load_trust_enrollment(
    path: &Path,
    forbidden_roots: &[&Path],
) -> Result<TrustEnrollment, AuditError> {
    let invalid = |reason: String| AuditError::Invalid(format!("trust enrollment: {reason}"));
    if !path.is_absolute() {
        return Err(invalid("path must be absolute".into()));
    }
    let canonical = fs::canonicalize(path).map_err(|error| invalid(error.to_string()))?;
    for root in forbidden_roots {
        if let Ok(root) = fs::canonicalize(root) {
            if canonical.starts_with(&root) {
                return Err(invalid("path is inside a scanned or scratch root".into()));
            }
        } else if path.starts_with(root) {
            return Err(invalid("path is inside a scanned or scratch root".into()));
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| invalid(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid("must be a regular file".into()));
    }
    if metadata.len() as usize > MAX_ENROLLMENT_BYTES {
        return Err(invalid("exceeds 1 MiB".into()));
    }
    let bytes = fs::read(path).map_err(|error| invalid(error.to_string()))?;
    if bytes.len() > MAX_ENROLLMENT_BYTES {
        return Err(invalid("exceeds 1 MiB".into()));
    }
    let raw: Value = serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
    if contains_secret_field(&raw) {
        return Err(invalid(
            "secret-shaped field present; enrollment holds fingerprints only".into(),
        ));
    }
    let enrollment: TrustEnrollment =
        serde_json::from_value(raw).map_err(|error| invalid(error.to_string()))?;
    enrollment.validate()?;
    Ok(enrollment)
}

fn secret_shaped_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    [
        "secret",
        "password",
        "passwd",
        "privatekey",
        "signingkey",
        "token",
        "accesstoken",
        "refreshtoken",
        "bearertoken",
        "apikey",
        "authorization",
        "credential",
        "bearer",
        "cookie",
    ]
    .iter()
    .any(|stem| normalized.contains(stem))
}

fn contains_secret_field(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, child)| secret_shaped_key(key) || contains_secret_field(child)),
        Value::Array(items) => items.iter().any(contains_secret_field),
        _ => false,
    }
}

/// Result of a successful provenance check, returned only by the configured
/// verifier. The importer re-checks every field against enrollment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedIssuer {
    pub issuer_id: String,
    pub key_id: String,
    pub claims_digest: String,
}

/// Root-supplied provenance checker (pinned RustRight `verify-receipt`
/// client for `rustright-receipt`, host/CI adapter for
/// `host-ci-provenance`). Implementations must verify `attestation` binds
/// `claims_digest` under the enrolled key; returning `Ok` for anything else
/// is a forgery. This trait is the seam: A03 ships no fake cryptography.
pub trait ProvenanceVerifier {
    fn verifier_id(&self) -> &str;
    fn verify(
        &self,
        envelope: &ArtifactEvidenceEnvelope,
        claims_digest: &str,
        attestation: &[u8],
    ) -> Result<VerifiedIssuer, String>;
}

/// Default when root has enrolled no real issuer infrastructure. Always
/// fails with a named prerequisite; missing issuer support is never clean.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnconfiguredVerifier;

impl ProvenanceVerifier for UnconfiguredVerifier {
    fn verifier_id(&self) -> &str {
        "unconfigured"
    }
    fn verify(
        &self,
        _envelope: &ArtifactEvidenceEnvelope,
        _claims_digest: &str,
        _attestation: &[u8],
    ) -> Result<VerifiedIssuer, String> {
        Err(
            "provenance-verifier-unconfigured: root must enroll a RustRight or host/CI verifier"
                .into(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedArtifact {
    pub path: String,
    pub digest: String,
    pub bytes: u64,
    pub role: String,
    pub immutable: bool,
}

/// Authenticated import consumed by downstream obligation reconciliation
/// (A02 `apply_evidence` via root mapping). Constructed only inside
/// [`verify_artifact_evidence`]; `authenticated` is never caller-settable
/// through deserialization of an envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedEvidenceRecord {
    pub schema_version: u32,
    pub evidence_id: String,
    pub claims_digest: String,
    pub kind: ImportKind,
    pub authenticated: bool,
    pub attestor: String,
    pub trust_root_id: String,
    pub verifier_id: String,
    pub outcome: EvidenceOutcome,
    pub repositories: Vec<RepositoryBinding>,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub toolchain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_runtime: Option<String>,
    pub artifacts: Vec<RetainedArtifact>,
    /// Digest of the primary (`role == "primary"`, else first) artifact.
    pub artifact_digest: String,
    /// Digest over required+examined+missing scope, for A02 denominators.
    pub denominator_digest: String,
    pub examined_scope: Vec<String>,
    pub missing_scope: Vec<String>,
    pub newly_executed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_of: Option<String>,
    pub issued_at: String,
    pub fresh_until: String,
}

impl ImportedEvidenceRecord {
    /// JSON projection for root to build A02 `ObligationEvidence`
    /// (identity + `authenticated` + artifact sha256 + attestor +
    /// denominator digest). Free-form details pass through [`redact_export`]
    /// at the call site; this record contains no secret-shaped fields.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportVerdict {
    pub authenticated: bool,
    /// True only when authenticated, fresh, complete-scope evidence may
    /// satisfy a production obligation.
    pub satisfies_obligation: bool,
    /// Stable reason codes for every failed check; empty iff satisfied.
    pub reasons: Vec<String>,
    pub record: Option<ImportedEvidenceRecord>,
}

fn repo_map(repos: &[RepositoryBinding]) -> BTreeMap<&str, &RepositoryBinding> {
    repos
        .iter()
        .map(|repo| (repo.repository_id.as_str(), repo))
        .collect()
}

fn safe_artifact_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && !path.contains('\\')
        && !path.contains(':')
        && !path.contains('\0')
        && !Path::new(path).is_absolute()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// Verify one imported envelope against frozen expectations, enrolled trust
/// and the configured provenance verifier. `raw_artifacts` maps artifact
/// path to retained immutable bytes; `attestation` is the raw attestation
/// blob whose digest the envelope claims. Collects every mismatch as a
/// named reason instead of failing on the first one.
pub fn verify_artifact_evidence(
    envelope: &ArtifactEvidenceEnvelope,
    raw_artifacts: &BTreeMap<String, Vec<u8>>,
    attestation: &[u8],
    expected: &ExpectedEvidence,
    trust: &TrustEnrollment,
    verifier: &dyn ProvenanceVerifier,
    now_rfc3339_utc: &str,
) -> ImportVerdict {
    let mut reasons: Vec<String> = Vec::new();
    let mut fail = |code: &str| reasons.push(code.to_string());

    if envelope.schema_version != ARTIFACT_EVIDENCE_SCHEMA_VERSION {
        fail("unsupported-schema-version");
    }
    if !non_empty(&envelope.evidence_id) {
        fail("evidence-id-empty");
    }
    if envelope.kind != expected.kind {
        fail("kind-mismatch");
    }
    // Issuer / trust root.
    let trusted = trust.issuer(&envelope.issuer.issuer_id);
    match trusted {
        None => fail("untrusted-issuer"),
        Some(trusted) => {
            if trusted.trust_root_id != envelope.issuer.trust_root_id {
                fail("trust-root-mismatch");
            }
            if trusted.key_id != envelope.issuer.key_id || !is_lower_hex64(&envelope.issuer.key_id)
            {
                fail("issuer-key-mismatch");
            }
            if trusted.attestation_format != envelope.issuer.attestation_format {
                fail("attestation-format-mismatch");
            }
            if trusted.verifier_id != verifier.verifier_id() {
                fail("verifier-not-enrolled-for-issuer");
            }
        }
    }
    if !is_sha256_digest(&envelope.issuer.attestation_digest)
        || sha256_digest(attestation) != envelope.issuer.attestation_digest
    {
        fail("attestation-digest-mismatch");
    }
    // Repositories: exact set equality binds every participating commit, so
    // a single-repo envelope cannot certify unseen sibling revisions.
    let actual_repos = repo_map(&envelope.subject.repositories);
    let expected_repos = repo_map(&expected.repositories);
    if actual_repos.len() != envelope.subject.repositories.len()
        || expected_repos.len() != expected.repositories.len()
    {
        fail("repository-duplicate");
    }
    if actual_repos.keys().collect::<Vec<_>>() != expected_repos.keys().collect::<Vec<_>>() {
        fail("repository-set-mismatch");
    } else {
        for (id, want) in &expected_repos {
            let Some(got) = actual_repos.get(id) else {
                continue;
            };
            if got.revision != want.revision {
                fail("repository-revision-mismatch");
            }
            if got.branch != want.branch {
                fail("repository-branch-mismatch");
            }
            if got.snapshot_digest != want.snapshot_digest
                || !is_sha256_digest(&got.snapshot_digest)
            {
                fail("snapshot-digest-mismatch");
            }
        }
    }
    if envelope.subject.repositories.is_empty() {
        fail("repository-set-empty");
    }
    // Subject: exact frozen-plan values.
    let subject = &envelope.subject;
    if subject.target != expected.target || !non_empty(&subject.target) {
        fail("target-mismatch");
    }
    if subject.variant != expected.variant {
        fail("variant-mismatch");
    }
    if subject.toolchain != expected.toolchain || !non_empty(&subject.toolchain) {
        fail("toolchain-mismatch");
    }
    if subject.config_digest != expected.config_digest || !is_sha256_digest(&subject.config_digest)
    {
        fail("config-digest-mismatch");
    }
    if subject.test_selection_digest != expected.test_selection_digest
        || subject
            .test_selection_digest
            .as_deref()
            .is_some_and(|digest| !is_sha256_digest(digest))
    {
        fail("test-selection-mismatch");
    }
    if subject.dependency_graph_digest != expected.dependency_graph_digest
        || !is_sha256_digest(&subject.dependency_graph_digest)
    {
        fail("dependency-graph-mismatch");
    }
    if subject.workload_digest != expected.workload_digest
        || subject
            .workload_digest
            .as_deref()
            .is_some_and(|digest| !is_sha256_digest(digest))
    {
        fail("workload-digest-mismatch");
    }
    if subject.command != expected.command || !is_sha256_digest(&subject.command.command_digest) {
        fail("command-mismatch");
    }
    if expected.upstream_runtime.is_some() && envelope.upstream_runtime != expected.upstream_runtime
    {
        fail("upstream-runtime-mismatch");
    }
    // Artifacts: retained raw bytes must hash to the claimed digests
    // (substitution), and every required artifact must appear verbatim.
    if envelope.artifacts.is_empty() {
        fail("artifact-set-empty");
    }
    let mut artifact_paths = BTreeSet::new();
    for artifact in &envelope.artifacts {
        if !safe_artifact_path(&artifact.path) || !artifact_paths.insert(artifact.path.clone()) {
            fail("artifact-path-unsafe-or-duplicate");
            continue;
        }
        if !is_sha256_digest(&artifact.digest) {
            fail("artifact-digest-malformed");
            continue;
        }
        match raw_artifacts.get(&artifact.path) {
            None => fail("artifact-raw-bytes-missing"),
            Some(bytes) => {
                if bytes.len() > MAX_RAW_ARTIFACT_BYTES {
                    fail("artifact-exceeds-retention-limit");
                } else if bytes.len() as u64 != artifact.bytes
                    || sha256_digest(bytes) != artifact.digest
                {
                    fail("artifact-substitution");
                }
            }
        }
    }
    for required in &expected.required_artifacts {
        if !envelope.artifacts.contains(required) {
            fail("required-artifact-missing-or-different");
        }
    }
    // Scope: examined must cover required; self-declared missing scope is
    // incomplete scope and can never satisfy.
    let examined: BTreeSet<&str> = envelope.scope.examined.iter().map(String::as_str).collect();
    if examined.len() != envelope.scope.examined.len()
        || examined.iter().any(|item| !non_empty(item))
    {
        fail("examined-scope-malformed");
    }
    if expected
        .required_scope
        .iter()
        .any(|required| !examined.contains(required.as_str()))
    {
        fail("examined-scope-incomplete");
    }
    if !envelope.scope.missing.is_empty() {
        fail("missing-scope-declared");
    }
    // Freshness: strict UTC-second strings compare lexicographically.
    if !is_rfc3339_utc_second(now_rfc3339_utc)
        || !is_rfc3339_utc_second(&envelope.issued_at)
        || !is_rfc3339_utc_second(&envelope.fresh_until)
    {
        fail("timestamp-malformed");
    } else {
        if envelope.issued_at.as_str() > now_rfc3339_utc {
            fail("evidence-from-future");
        }
        if envelope.fresh_until.as_str() < envelope.issued_at.as_str()
            || now_rfc3339_utc > envelope.fresh_until.as_str()
        {
            fail("evidence-stale");
        }
    }
    // Replay: never relabelled as newly executed.
    let replayed = envelope.execution_mode == ExecutionMode::Replayed;
    if replayed {
        if envelope
            .replay_of
            .as_deref()
            .is_none_or(|id| !non_empty(id))
        {
            fail("replay-lineage-missing");
        }
        if expected.replay_policy == ReplayPolicy::Deny {
            fail("replay-not-permitted");
        }
    } else if envelope.replay_of.is_some() {
        fail("replay-lineage-on-executed-evidence");
    }
    if envelope.outcome == EvidenceOutcome::Error {
        fail("outcome-error");
    }
    // Provenance: only the enrolled verifier can authenticate, and its
    // answer is re-checked field by field.
    let claims_digest = envelope.canonical_claims_digest().unwrap_or_default();
    let mut provenance_ok = false;
    if claims_digest.is_empty() {
        fail("claims-digest-unavailable");
    } else {
        match verifier.verify(envelope, &claims_digest, attestation) {
            Ok(verified) => {
                if verified.issuer_id == envelope.issuer.issuer_id
                    && verified.key_id == envelope.issuer.key_id
                    && verified.claims_digest == claims_digest
                {
                    provenance_ok = true;
                } else {
                    fail("provenance-binding-mismatch");
                }
            }
            Err(reason) => {
                let code = format!("provenance-unverified:{reason}");
                fail(&code);
            }
        }
    }

    let authenticated = provenance_ok
        && trusted.is_some()
        && reasons.iter().all(|reason| {
            // Incomplete scope / denied replay / error outcome keep the
            // evidence authenticated-but-not-satisfying only when every
            // binding above still held; any binding failure is forgery-class
            // and strips authentication entirely.
            matches!(
                reason.as_str(),
                "examined-scope-incomplete"
                    | "missing-scope-declared"
                    | "replay-not-permitted"
                    | "outcome-error"
                    | "evidence-stale"
            )
        });
    let satisfies = authenticated && reasons.is_empty();
    let record = authenticated.then(|| {
        let primary = envelope
            .artifacts
            .iter()
            .find(|artifact| artifact.role == "primary")
            .or_else(|| envelope.artifacts.first());
        let denominator_digest = crate::integrity::digest(&json!({
            "required": expected.required_scope,
            "examined": envelope.scope.examined,
            "missing": envelope.scope.missing,
        }))
        .unwrap_or_default();
        ImportedEvidenceRecord {
            schema_version: ARTIFACT_EVIDENCE_SCHEMA_VERSION,
            evidence_id: envelope.evidence_id.clone(),
            claims_digest: claims_digest.clone(),
            kind: envelope.kind,
            authenticated: true,
            attestor: envelope.issuer.issuer_id.clone(),
            trust_root_id: envelope.issuer.trust_root_id.clone(),
            verifier_id: verifier.verifier_id().to_string(),
            outcome: envelope.outcome,
            repositories: envelope.subject.repositories.clone(),
            target: envelope.subject.target.clone(),
            variant: envelope.subject.variant.clone(),
            toolchain: envelope.subject.toolchain.clone(),
            upstream_runtime: envelope.upstream_runtime.clone(),
            artifacts: envelope
                .artifacts
                .iter()
                .map(|artifact| RetainedArtifact {
                    path: artifact.path.clone(),
                    digest: artifact.digest.clone(),
                    bytes: artifact.bytes,
                    role: artifact.role.clone(),
                    immutable: true,
                })
                .collect(),
            artifact_digest: primary.map(|a| a.digest.clone()).unwrap_or_default(),
            denominator_digest,
            examined_scope: envelope.scope.examined.clone(),
            missing_scope: envelope.scope.missing.clone(),
            newly_executed: !replayed,
            replay_of: envelope.replay_of.clone(),
            issued_at: envelope.issued_at.clone(),
            fresh_until: envelope.fresh_until.clone(),
        }
    });
    ImportVerdict {
        authenticated,
        satisfies_obligation: satisfies,
        reasons,
        record,
    }
}

/// Redact secret-shaped values from an exported projection. Canonical
/// evidence hashes are always computed on the original retained bytes
/// before this runs; redaction never feeds back into [`ImportedEvidenceRecord`].
/// Classification is by key meaning (secret/token/password/key/credential/
/// authorization/bearer/cookie stems, any spelling), not an allowlist.
pub fn redact_export(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, child)| {
                    if secret_shaped_key(key) {
                        (
                            key.clone(),
                            json!({"redacted": true, "digest": sha256_digest(
                                &serde_json::to_vec(child).unwrap_or_default()
                            )}),
                        )
                    } else {
                        (key.clone(), redact_export(child))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact_export).collect()),
        other => other.clone(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveMember {
    pub name: String,
    pub expanded_bytes: u64,
    pub is_link: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    pub max_members: usize,
    pub max_total_expanded_bytes: u64,
    pub max_member_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_members: 10_000,
            max_total_expanded_bytes: 512 * 1024 * 1024,
            max_member_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Pre-unpack gate for the rare case root must unpack a retained archive.
/// Pure validation over the member table: links, absolute/escaping paths,
/// duplicates and bombs (count/total/member bounds) are rejected before any
/// byte is written. Verification itself never needs unpacking.
pub fn validate_archive_members(
    members: &[ArchiveMember],
    limits: ArchiveLimits,
) -> Result<(), String> {
    if members.len() > limits.max_members {
        return Err("archive-member-count-exceeded".into());
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for member in members {
        if member.is_link {
            return Err("archive-link-member".into());
        }
        if !safe_artifact_path(&member.name) || !seen.insert(member.name.clone()) {
            return Err("archive-path-unsafe-or-duplicate".into());
        }
        if member.expanded_bytes > limits.max_member_bytes {
            return Err("archive-member-too-large".into());
        }
        total = total.saturating_add(member.expanded_bytes);
        if total > limits.max_total_expanded_bytes {
            return Err("archive-expansion-bomb".into());
        }
    }
    Ok(())
}

/// Upgrade a parsed local SARIF only when an authenticated verdict's
/// retained artifacts include the exact SARIF bytes (same digest). Parser
/// success alone stays candidate evidence and proves no execution.
pub fn authenticate_sarif(sarif: ImportedSarif, verdict: &ImportVerdict) -> ImportedSarif {
    let Some(record) = &verdict.record else {
        return sarif;
    };
    if !verdict.authenticated
        || !record
            .artifacts
            .iter()
            .any(|artifact| artifact.digest == sarif.digest)
    {
        return sarif;
    }
    sarif.with_authentication(SarifAuthentication::Authenticated {
        evidence_digest: record.claims_digest.clone(),
        attestor: record.attestor.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_require_strict_utc_second_form() {
        assert!(is_rfc3339_utc_second("2026-10-23T10:00:00Z"));
        assert!(!is_rfc3339_utc_second("2026-10-23T10:00:00+01:00"));
        assert!(!is_rfc3339_utc_second("2026-10-23 10:00:00Z"));
        assert!(!is_rfc3339_utc_second("2026-10-23T10:00:00.5Z"));
    }

    #[test]
    fn redaction_covers_unenumerated_secret_spellings() {
        let exported = redact_export(&json!({
            "refresh_token_value": "abc",
            "Signing-Key": "abc",
            "note": "kept"
        }));
        assert_eq!(exported["refresh_token_value"]["redacted"], json!(true));
        assert_eq!(exported["Signing-Key"]["redacted"], json!(true));
        assert_eq!(exported["note"], json!("kept"));
    }

    #[test]
    fn archive_gate_rejects_links_escapes_and_bombs() {
        let link = vec![ArchiveMember {
            name: "a".into(),
            expanded_bytes: 1,
            is_link: true,
        }];
        assert!(validate_archive_members(&link, ArchiveLimits::default()).is_err());
        let escape = vec![ArchiveMember {
            name: "../evil".into(),
            expanded_bytes: 1,
            is_link: false,
        }];
        assert!(validate_archive_members(&escape, ArchiveLimits::default()).is_err());
        let bomb = vec![ArchiveMember {
            name: "big".into(),
            expanded_bytes: u64::MAX,
            is_link: false,
        }];
        assert!(validate_archive_members(&bomb, ArchiveLimits::default()).is_err());
    }
}
