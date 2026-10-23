//! `legion-dev audit-assurance`: native validation/reporting for audit
//! assurance qualification records (packet A18). Root owns command
//! registration in `main.rs`; this module only exposes [`run`].
//!
//! Qualification records are trust-bearing. This validator never promotes a
//! record: authored/routing/known-answer fixture success is labelled
//! fixture-scoped, held-out outcomes stay separate, synthetic corpus fixtures
//! are never enrolled, and any scope/version/digest drift invalidates the
//! matching record instead of turning it clean. It spawns no subprocess, so
//! the audit-owned runtime closure stays free of Node/Python.
//!
//! Record schema: `legion-audit-assurance-qualification/1`. The
//! `qualificationDigest` is `sha256:` over the canonical JSON encoding
//! (recursively key-sorted, compact) of the record without that field, the
//! same discipline as `tests/support/accuracy_receipt.rs`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const RECORD_SCHEMA: &str = "legion-audit-assurance-qualification/1";
pub const INDEX_PATH: &str = "qualification/provider-accuracy/index.json";

// ------------------------------------------------------------------- records

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lifecycle {
    Draft,
    Shadow,
    Qualified,
}

impl Lifecycle {
    fn rank(self) -> u8 {
        match self {
            Self::Draft => 0,
            Self::Shadow => 1,
            Self::Qualified => 2,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Shadow => "shadow",
            Self::Qualified => "qualified",
        }
    }
}

/// How the measured outcomes were produced. Only held-out measurement or
/// production observation can support `qualified`; authored, routing and
/// known-answer fixtures prove wiring, not behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BasisKind {
    AuthoredFixture,
    RoutingFixture,
    KnownAnswerFixture,
    Heldout,
    ProductionObservation,
}

impl BasisKind {
    fn qualifies_behaviour(self) -> bool {
        matches!(self, Self::Heldout | Self::ProductionObservation)
    }
    fn label(self) -> &'static str {
        match self {
            Self::AuthoredFixture => "authored-fixture",
            Self::RoutingFixture => "routing-fixture",
            Self::KnownAnswerFixture => "known-answer-fixture",
            Self::Heldout => "heldout",
            Self::ProductionObservation => "production-observation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureSplit {
    Authored,
    Tuning,
    Heldout,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutcomeKind {
    /// Planted/known defect that must be found.
    Positive,
    /// Clean control that must produce no finding.
    Negative,
    /// Input the provider must report as unsupported, never as clean.
    Unsupported,
}

/// Exact measured scope. Wildcards are rejected: a record can never claim an
/// entire platform from one fixture.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QualificationScope {
    pub provider: String,
    pub provider_version: String,
    pub lens: String,
    pub stack: String,
    #[serde(default)]
    pub rule_id: Option<String>,
    pub rule_profile_revision: String,
    pub tool: String,
    pub tool_version: String,
    pub config_digest: String,
    pub platform: String,
    pub toolchain: String,
    pub target: String,
    pub variant: String,
    #[serde(default)]
    pub features: Vec<String>,
    /// Support explicitly excluded from this record's claim.
    #[serde(default)]
    pub excluded_support: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Basis {
    pub kind: BasisKind,
    #[serde(default)]
    pub fixture_ids: Vec<String>,
    /// Held-out fixture ids, kept apart from authored/tuning ids.
    #[serde(default)]
    pub heldout_fixture_ids: Vec<String>,
    /// Count of real production observations; required > 0 for a
    /// production-observation basis.
    #[serde(default)]
    pub production_observations: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvenanceSource {
    /// Captured by the repository CI proof mechanism.
    Ci,
    /// Locally produced; can never enroll as qualified.
    Local,
    /// Imported evidence; authentication is decided by the importer, and an
    /// import alone never enrolls as qualified here.
    Imported,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FileDigest {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Provenance {
    pub source: ProvenanceSource,
    #[serde(default)]
    pub commit: Option<String>,
    #[serde(default)]
    pub workflow: Option<String>,
    #[serde(default)]
    pub run_id: Option<u64>,
    pub attestor: String,
    /// Set only by an authenticated importer/CI capture; never inferred.
    #[serde(default)]
    pub authenticated: bool,
    pub captured_at: String,
    pub fresh_until: String,
    /// Raw tool output retained with digests; missing raw output rejects.
    #[serde(default)]
    pub raw_outputs: Vec<FileDigest>,
    pub source_closure_digest: String,
    pub implementation_digest: String,
    /// Signed digest under an enrolled key. The `source`/`authenticated`
    /// fields are caller-asserted text; only a verified attestation lets a
    /// record claim CI capture.
    #[serde(default)]
    pub attestation: Option<Attestation>,
}

/// Ed25519 signature over [`attestation_message`] by an enrolled key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Attestation {
    pub key_id: String,
    /// Lowercase hex signature (64 bytes).
    pub signature: String,
}

/// A trusted attestor key. Enrollment comes only from host state
/// (`<LEGION state root>/audit-qualification-attestors.json`, owner-only,
/// outside every audited root), never from the repository and never from the
/// record under validation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EnrolledKey {
    pub key_id: String,
    /// Lowercase hex Ed25519 public key (32 bytes).
    pub public_key: String,
    /// Records captured after this instant are not accepted from this key.
    #[serde(default)]
    pub not_after: Option<String>,
}

/// Message the attestor signs: domain tag plus the sealed record digest.
pub fn attestation_message(qualification_digest: &str) -> Vec<u8> {
    format!("legion-audit-assurance-attestation/1\n{qualification_digest}").into_bytes()
}

/// Load enrolled attestor keys from the host enrollment file at `path`. A
/// missing file means none are enrolled. The file must pass the shared
/// host-enrollment hardening and must lie outside `audited_roots` (the
/// repository root among them), so a repository can never enroll a key.
pub fn load_enrolled_keys(
    path: &Path,
    audited_roots: &[PathBuf],
) -> Result<Vec<EnrolledKey>, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        keys: Vec<EnrolledKey>,
    }
    let Some(bytes) = legion_audit::evidence_issuers::read_host_enrollment(path, audited_roots)?
    else {
        return Ok(Vec::new());
    };
    serde_json::from_slice::<File>(&bytes)
        .map(|file| file.keys)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let bytes = hex::decode(value).ok()?;
    bytes.try_into().ok()
}

/// Verify the record's attestation against the enrolled keys.
pub fn verify_attestation(
    record: &AssuranceQualificationRecord,
    enrolled: &[EnrolledKey],
) -> Result<(), String> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let attestation = record
        .provenance
        .attestation
        .as_ref()
        .ok_or_else(|| "no-attestation".to_string())?;
    let key = enrolled
        .iter()
        .find(|key| key.key_id == attestation.key_id)
        .ok_or_else(|| "key-not-enrolled".to_string())?;
    if let Some(not_after) = &key.not_after {
        if record.provenance.captured_at.as_str() > not_after.as_str() {
            return Err("key-expired-for-capture".into());
        }
    }
    let public: [u8; 32] =
        decode_hex(&key.public_key).ok_or_else(|| "key-malformed".to_string())?;
    let signature: [u8; 64] =
        decode_hex(&attestation.signature).ok_or_else(|| "signature-malformed".to_string())?;
    let verifying = VerifyingKey::from_bytes(&public).map_err(|_| "key-malformed".to_string())?;
    // The signed digest must be the recomputed one, not the stored field.
    let digest = record_digest(record);
    if digest != record.qualification_digest {
        return Err("digest-mismatch".into());
    }
    verifying
        .verify_strict(
            &attestation_message(&digest),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| "signature-invalid".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureOutcome {
    pub fixture_id: String,
    pub split: FixtureSplit,
    pub kind: OutcomeKind,
    /// Target the outcome was measured on; must equal the scope target.
    pub target: String,
    pub expected_findings: u32,
    pub emitted_findings: u32,
    pub matched_findings: u32,
    /// Matched findings positioned on the expected site.
    #[serde(default)]
    pub located_findings: u32,
    /// Findings that claimed support the record excludes.
    #[serde(default)]
    pub unsupported_claims: u32,
    /// The run claimed clean for this case.
    #[serde(default)]
    pub claimed_clean: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeclaredMetrics {
    pub method: String,
    pub sample_size: u32,
    pub precision: f64,
    pub recall: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Cost {
    #[serde(default)]
    pub wall_time_ms: u64,
    #[serde(default)]
    pub model_calls: u64,
    #[serde(default)]
    pub tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssuranceQualificationRecord {
    pub schema: String,
    pub lifecycle: Lifecycle,
    /// Synthetic corpus fixtures validate structurally but never enroll.
    #[serde(default)]
    pub synthetic_fixture: bool,
    pub scope: QualificationScope,
    pub basis: Basis,
    pub provenance: Provenance,
    pub outcomes: Vec<FixtureOutcome>,
    #[serde(default)]
    pub metrics: Option<DeclaredMetrics>,
    #[serde(default)]
    pub cost: Cost,
    pub qualification_digest: String,
}

// -------------------------------------------------------------------- digest

/// Recursively key-sorted compact JSON bytes (serde_json may preserve
/// insertion order, so order is never trusted).
pub fn canonical_bytes(value: &Value) -> Vec<u8> {
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut keys: Vec<_> = object.keys().collect();
                keys.sort();
                let mut sorted = serde_json::Map::new();
                for key in keys {
                    sorted.insert(key.clone(), ordered(&object[key]));
                }
                Value::Object(sorted)
            }
            Value::Array(array) => Value::Array(array.iter().map(ordered).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&ordered(value)).expect("JSON value serializes")
}

pub fn sha256_digest(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{hex}")
}

pub fn is_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// Digest over the record without `qualificationDigest`.
pub fn record_digest(record: &AssuranceQualificationRecord) -> String {
    let mut value = serde_json::to_value(record).expect("record serializes");
    if let Some(object) = value.as_object_mut() {
        object.remove("qualificationDigest");
        // The attestation signs this digest, so it cannot be part of it.
        if let Some(provenance) = object.get_mut("provenance").and_then(Value::as_object_mut) {
            provenance.remove("attestation");
        }
    }
    sha256_digest(&canonical_bytes(&value))
}

/// Seal a freshly captured record. Enrollment still requires CI provenance;
/// sealing only binds bytes, it authenticates nothing.
pub fn seal(record: &mut AssuranceQualificationRecord) {
    record.qualification_digest = record_digest(record);
}

// ------------------------------------------------------------------- metrics

/// Per-record measurements recomputed from raw outcome counts. Ratios are
/// never transplanted from an upstream benchmark; `None` stays unknown.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeasuredMetrics {
    pub lens: String,
    pub stack: String,
    pub sample_size: u32,
    pub heldout_sample_size: u32,
    pub true_positives: u32,
    pub false_positives: u32,
    pub false_negatives: u32,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    /// Wilson 95% intervals `[low, high]`; small samples stay visibly wide.
    pub precision_interval_95: Option<[f64; 2]>,
    pub recall_interval_95: Option<[f64; 2]>,
    pub clean_cases: u32,
    pub clean_false_positives: u32,
    pub unsupported_claims: u32,
    /// Located / expected on positive cases (source positioning).
    pub positioning: Option<f64>,
    /// Cases claimed clean although a defect was expected or missed.
    pub false_green_cases: u32,
    pub method: String,
}

fn wilson_95(successes: u32, total: u32) -> Option<[f64; 2]> {
    if total == 0 {
        return None;
    }
    let n = f64::from(total);
    let p = f64::from(successes) / n;
    let z = 1.96_f64;
    let denominator = 1.0 + z * z / n;
    let centre = (p + z * z / (2.0 * n)) / denominator;
    let half = (z / denominator) * ((p * (1.0 - p) + z * z / (4.0 * n)) / n).sqrt();
    Some([(centre - half).max(0.0), (centre + half).min(1.0)])
}

fn ratio(numerator: u32, denominator: u32) -> Option<f64> {
    (denominator > 0).then(|| f64::from(numerator) / f64::from(denominator))
}

pub fn measure(record: &AssuranceQualificationRecord) -> MeasuredMetrics {
    let (mut tp, mut fp, mut fn_) = (0_u32, 0_u32, 0_u32);
    let (mut clean, mut clean_fp, mut unsupported, mut false_green) = (0, 0, 0, 0);
    let (mut located, mut expected_positive) = (0_u32, 0_u32);
    for outcome in &record.outcomes {
        unsupported += outcome.unsupported_claims;
        let matched = outcome.matched_findings.min(outcome.expected_findings);
        match outcome.kind {
            OutcomeKind::Positive => {
                tp += matched;
                fp += outcome.emitted_findings.saturating_sub(matched);
                fn_ += outcome.expected_findings.saturating_sub(matched);
                located += outcome.located_findings.min(matched);
                expected_positive += outcome.expected_findings;
                if outcome.claimed_clean && outcome.expected_findings > matched {
                    false_green += 1;
                }
            }
            OutcomeKind::Negative => {
                clean += 1;
                clean_fp += outcome.emitted_findings;
                fp += outcome.emitted_findings;
            }
            OutcomeKind::Unsupported => {
                if outcome.claimed_clean {
                    false_green += 1;
                }
            }
        }
    }
    MeasuredMetrics {
        lens: record.scope.lens.clone(),
        stack: record.scope.stack.clone(),
        sample_size: record.outcomes.len() as u32,
        heldout_sample_size: record
            .outcomes
            .iter()
            .filter(|outcome| outcome.split == FixtureSplit::Heldout)
            .count() as u32,
        true_positives: tp,
        false_positives: fp,
        false_negatives: fn_,
        precision: ratio(tp, tp + fp),
        recall: ratio(tp, tp + fn_),
        precision_interval_95: wilson_95(tp, tp + fp),
        recall_interval_95: wilson_95(tp, tp + fn_),
        clean_cases: clean,
        clean_false_positives: clean_fp,
        unsupported_claims: unsupported,
        positioning: ratio(located, expected_positive),
        false_green_cases: false_green,
        method: record
            .metrics
            .as_ref()
            .map(|metrics| metrics.method.clone())
            .unwrap_or_else(|| "undeclared".to_string()),
    }
}

// ---------------------------------------------------------------- validation

/// Current code/tool state a record is checked against. Any drift in
/// provider/rule/tool/config/host/target identity invalidates the record.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CurrentContext {
    pub provider_version: String,
    pub rule_profile_revision: String,
    pub tool: String,
    pub tool_version: String,
    pub config_digest: String,
    pub platform: String,
    pub toolchain: String,
    pub target: String,
    pub variant: String,
    #[serde(default)]
    pub features: Vec<String>,
    pub implementation_digest: String,
    pub source_closure_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Structurally valid and eligible at its effective lifecycle.
    Valid,
    /// Valid measurement, but only ever as a fixture-scoped claim.
    FixtureScoped,
    /// Scope/version/source drift or staleness; record no longer applies.
    Invalidated,
    /// Forged, malformed, false-green or otherwise unusable.
    Rejected,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::FixtureScoped => "fixture-scoped",
            Self::Invalidated => "invalidated",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationReport {
    pub provider: String,
    pub verdict: Verdict,
    pub claimed_lifecycle: Lifecycle,
    pub effective_lifecycle: Lifecycle,
    pub basis: String,
    pub claim_scope: String,
    pub reasons: Vec<String>,
    pub metrics: MeasuredMetrics,
    pub cost: Cost,
}

fn blank_or_wildcard(value: &str) -> bool {
    let value = value.trim();
    value.is_empty() || value == "*" || value.eq_ignore_ascii_case("all")
}

/// RFC3339 UTC only, compared lexicographically (same fail-closed rule the
/// A02 assurance layer documents: both sides must end in `Z`).
fn rfc3339_utc(value: &str) -> bool {
    value.len() >= 20 && value.ends_with('Z')
}

fn context_mismatches(
    record: &AssuranceQualificationRecord,
    current: &CurrentContext,
) -> Vec<String> {
    let scope = &record.scope;
    let mut mismatches = Vec::new();
    let mut check = |name: &str, claimed: &str, actual: &str| {
        if claimed != actual {
            mismatches.push(format!("{name}-drift"));
        }
    };
    check(
        "provider-version",
        &scope.provider_version,
        &current.provider_version,
    );
    check(
        "rule-profile-revision",
        &scope.rule_profile_revision,
        &current.rule_profile_revision,
    );
    check("tool", &scope.tool, &current.tool);
    check("tool-version", &scope.tool_version, &current.tool_version);
    check(
        "config-digest",
        &scope.config_digest,
        &current.config_digest,
    );
    check("platform", &scope.platform, &current.platform);
    check("toolchain", &scope.toolchain, &current.toolchain);
    check("target", &scope.target, &current.target);
    check("variant", &scope.variant, &current.variant);
    check(
        "implementation-digest",
        &record.provenance.implementation_digest,
        &current.implementation_digest,
    );
    check(
        "source-closure-digest",
        &record.provenance.source_closure_digest,
        &current.source_closure_digest,
    );
    let claimed: BTreeSet<_> = scope.features.iter().collect();
    let actual: BTreeSet<_> = current.features.iter().collect();
    if claimed != actual {
        mismatches.push("features-drift".to_string());
    }
    mismatches
}

/// Validate one record at `now_rfc3339_utc`, optionally against the current
/// code/tool context. Raw-output file bytes are checked separately by
/// [`validate_raw_outputs`] because they need a repository root.
pub fn validate_record(
    record: &AssuranceQualificationRecord,
    now_rfc3339_utc: &str,
    current: Option<&CurrentContext>,
) -> ValidationReport {
    validate_record_enrolled(record, now_rfc3339_utc, current, &[])
}

/// Like [`validate_record`] with the enrolled attestor keys. A record that
/// claims CI capture or authentication without an attestation verified under
/// an enrolled key is rejected: those fields are caller-asserted.
pub fn validate_record_enrolled(
    record: &AssuranceQualificationRecord,
    now_rfc3339_utc: &str,
    current: Option<&CurrentContext>,
    enrolled: &[EnrolledKey],
) -> ValidationReport {
    let metrics = measure(record);
    let mut rejected: Vec<String> = Vec::new();
    let mut invalidated: Vec<String> = Vec::new();
    let mut capped: Vec<String> = Vec::new();
    let scope = &record.scope;

    if record.schema != RECORD_SCHEMA {
        rejected.push("unknown-schema".into());
    }
    if !is_digest(&record.qualification_digest)
        || record_digest(record) != record.qualification_digest
    {
        rejected.push("qualification-digest-mismatch".into());
    }
    for (name, value) in [
        ("config-digest", &scope.config_digest),
        (
            "source-closure-digest",
            &record.provenance.source_closure_digest,
        ),
        (
            "implementation-digest",
            &record.provenance.implementation_digest,
        ),
    ] {
        if !is_digest(value) {
            rejected.push(format!("{name}-malformed"));
        }
    }
    for (name, value) in [
        ("provider", &scope.provider),
        ("provider-version", &scope.provider_version),
        ("lens", &scope.lens),
        ("stack", &scope.stack),
        ("rule-profile-revision", &scope.rule_profile_revision),
        ("tool", &scope.tool),
        ("tool-version", &scope.tool_version),
        ("platform", &scope.platform),
        ("toolchain", &scope.toolchain),
        ("target", &scope.target),
        ("variant", &scope.variant),
    ] {
        if blank_or_wildcard(value) {
            rejected.push(format!("scope-{name}-unbounded"));
        }
    }
    if record.outcomes.is_empty() {
        rejected.push("zero-input".into());
    }
    let mut fixture_ids = BTreeSet::new();
    for outcome in &record.outcomes {
        if outcome.fixture_id.trim().is_empty() || !fixture_ids.insert(&outcome.fixture_id) {
            rejected.push("fixture-id-missing-or-duplicate".into());
        }
        if outcome.target != scope.target {
            rejected.push("wrong-target-outcome".into());
        }
        if outcome.matched_findings > outcome.emitted_findings
            || outcome.located_findings > outcome.matched_findings
        {
            rejected.push("outcome-counts-inconsistent".into());
        }
    }
    for id in record
        .basis
        .fixture_ids
        .iter()
        .chain(&record.basis.heldout_fixture_ids)
    {
        if !fixture_ids.contains(&id) {
            rejected.push("basis-fixture-not-measured".into());
        }
    }
    if metrics.false_green_cases > 0 {
        rejected.push("false-green-outcome".into());
    }
    if let Some(declared) = &record.metrics {
        let close = |a: f64, b: Option<f64>| b.is_some_and(|b| (a - b).abs() <= 1e-9);
        if declared.method.trim().is_empty()
            || declared.sample_size != metrics.sample_size
            || !close(declared.precision, metrics.precision)
            || !close(declared.recall, metrics.recall)
        {
            rejected.push("declared-metrics-differ-from-outcomes".into());
        }
    } else if record.lifecycle == Lifecycle::Qualified {
        rejected.push("metrics-method-undeclared".into());
    }

    // Provenance & freshness. A checksum is not authentication: enrollment
    // stays with the CI proof mechanism, exactly as the retained
    // registration gate documents.
    let provenance = &record.provenance;
    if provenance.attestor.trim().is_empty() {
        rejected.push("attestor-missing".into());
    }
    if provenance.raw_outputs.is_empty() {
        rejected.push("raw-output-missing".into());
    }
    for raw in &provenance.raw_outputs {
        if !is_digest(&raw.sha256) || !safe_relative_path(&raw.path) {
            rejected.push("raw-output-reference-malformed".into());
        }
    }
    if provenance.source == ProvenanceSource::Ci
        && (provenance.commit.as_deref().is_none_or(|commit| {
            commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) || provenance.run_id.is_none_or(|run| run == 0)
            || provenance
                .workflow
                .as_deref()
                .is_none_or(|name| name.trim().is_empty()))
    {
        rejected.push("ci-provenance-incomplete".into());
    }
    let claims_ci = provenance.source == ProvenanceSource::Ci || provenance.authenticated;
    let attested = verify_attestation(record, enrolled);
    if claims_ci {
        if let Err(why) = &attested {
            rejected.push(format!("ci-attestation-unverified:{why}"));
        }
    }
    if !rfc3339_utc(now_rfc3339_utc)
        || !rfc3339_utc(&provenance.captured_at)
        || !rfc3339_utc(&provenance.fresh_until)
    {
        invalidated.push("freshness-unproven".into());
    } else {
        if provenance.fresh_until.as_str() <= now_rfc3339_utc {
            invalidated.push("stale-record".into());
        }
        if provenance.captured_at.as_str() > now_rfc3339_utc {
            invalidated.push("captured-in-future".into());
        }
    }
    if let Some(current) = current {
        invalidated.extend(context_mismatches(record, current));
    }

    // Lifecycle caps: fixture-only bases, non-CI capture and synthetic
    // corpus records can never be effective `qualified`.
    let mut effective = record.lifecycle;
    let cap =
        |effective: &mut Lifecycle, max: Lifecycle, reason: &str, capped: &mut Vec<String>| {
            if effective.rank() > max.rank() {
                *effective = max;
            }
            // Every triggered cap is named, even when an earlier cap already
            // lowered the effective lifecycle.
            if record.lifecycle.rank() > max.rank() {
                capped.push(reason.to_string());
            }
        };
    if !record.basis.kind.qualifies_behaviour() {
        cap(
            &mut effective,
            Lifecycle::Shadow,
            "fixture-only-basis-capped-shadow",
            &mut capped,
        );
    }
    if record.basis.kind == BasisKind::Heldout {
        let disjoint = record
            .basis
            .heldout_fixture_ids
            .iter()
            .all(|id| !record.basis.fixture_ids.contains(id));
        if record.basis.heldout_fixture_ids.is_empty()
            || metrics.heldout_sample_size == 0
            || !disjoint
        {
            cap(
                &mut effective,
                Lifecycle::Shadow,
                "heldout-split-not-separate",
                &mut capped,
            );
        }
    }
    if record.basis.kind == BasisKind::ProductionObservation
        && record.basis.production_observations == 0
    {
        cap(
            &mut effective,
            Lifecycle::Shadow,
            "production-observation-absent",
            &mut capped,
        );
    }
    if provenance.source != ProvenanceSource::Ci || !provenance.authenticated || attested.is_err() {
        cap(
            &mut effective,
            Lifecycle::Shadow,
            "not-ci-enrolled",
            &mut capped,
        );
    }
    if record.synthetic_fixture {
        cap(
            &mut effective,
            Lifecycle::Shadow,
            "synthetic-fixture-not-enrolled",
            &mut capped,
        );
    }

    let verdict = if !rejected.is_empty() {
        Verdict::Rejected
    } else if !invalidated.is_empty() {
        Verdict::Invalidated
    } else if !record.basis.kind.qualifies_behaviour() || record.synthetic_fixture {
        Verdict::FixtureScoped
    } else {
        Verdict::Valid
    };
    let mut reasons = rejected;
    reasons.extend(invalidated);
    reasons.extend(capped);
    if verdict == Verdict::Rejected || verdict == Verdict::Invalidated {
        effective = Lifecycle::Draft;
    }
    let claim_scope = match verdict {
        Verdict::Valid if effective == Lifecycle::Qualified => {
            "qualified-exact-scope-only".to_string()
        }
        Verdict::FixtureScoped => "fixture-scoped-not-production".to_string(),
        Verdict::Valid => "measured-exact-scope-only".to_string(),
        Verdict::Invalidated => "invalidated-no-claim".to_string(),
        Verdict::Rejected => "rejected-no-claim".to_string(),
    };
    ValidationReport {
        provider: scope.provider.clone(),
        verdict,
        claimed_lifecycle: record.lifecycle,
        effective_lifecycle: effective,
        basis: record.basis.kind.label().to_string(),
        claim_scope,
        reasons,
        metrics,
        cost: record.cost,
    }
}

/// Repository-relative path discipline mirroring the retained registration
/// gate: no absolute, escaping, drive-qualified or backslash paths.
pub fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && !value.contains('\\')
        && !value.contains(':')
        && !value.starts_with('/')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Verify retained raw-output bytes under `root`. Returns named failures;
/// a missing or drifted raw output is a failure, never a skip.
pub fn validate_raw_outputs(root: &Path, record: &AssuranceQualificationRecord) -> Vec<String> {
    let mut failures = Vec::new();
    for raw in &record.provenance.raw_outputs {
        if !safe_relative_path(&raw.path) {
            failures.push(format!("raw-output-unsafe-path:{}", raw.path));
            continue;
        }
        let mut current = root.to_path_buf();
        let mut symlinked = false;
        for part in raw.path.split('/') {
            current.push(part);
            if current
                .symlink_metadata()
                .is_ok_and(|meta| meta.file_type().is_symlink())
            {
                symlinked = true;
            }
        }
        if symlinked {
            failures.push(format!("raw-output-symlink-refused:{}", raw.path));
            continue;
        }
        match fs::read(&current) {
            Ok(bytes) if sha256_digest(&bytes) == raw.sha256 => {}
            Ok(_) => failures.push(format!("raw-output-digest-mismatch:{}", raw.path)),
            Err(_) => failures.push(format!("raw-output-missing:{}", raw.path)),
        }
    }
    failures
}

/// Result of running a provider's real parser over one retained raw tool run.
enum Recomputed {
    /// Parsed cleanly; the number of findings the parser derived.
    Findings(u32),
    /// The parser rejected the output or named gaps: never a clean run.
    Unparseable,
}

/// Registered recompute parsers, keyed by the record's provider id (and
/// linter for the shared JavaScript provider). `None`: no parser is
/// registered, so the record cannot be recomputed and cannot qualify.
fn recompute_parser(scope: &QualificationScope) -> Option<fn(&[u8]) -> Recomputed> {
    use legion_audit::native_providers::code::{android, javascript_native};
    match (
        scope.provider.as_str(),
        scope.tool.to_ascii_lowercase().as_str(),
    ) {
        (javascript_native::PROVIDER_ID, "oxlint") => {
            Some(
                |stdout: &[u8]| match javascript_native::parse_oxlint_report(stdout) {
                    Ok(report) if report.unresolved_lines == 0 => Recomputed::Findings(
                        report
                            .diagnostics
                            .iter()
                            .filter(|d| !d.config_error)
                            .count() as u32,
                    ),
                    _ => Recomputed::Unparseable,
                },
            )
        }
        (javascript_native::PROVIDER_ID, "biome") => {
            Some(
                |stdout: &[u8]| match javascript_native::parse_biome_report(stdout, &|_| None) {
                    Ok(report) if report.unresolved_lines == 0 => Recomputed::Findings(
                        report
                            .diagnostics
                            .iter()
                            .filter(|d| !d.config_error)
                            .count() as u32,
                    ),
                    _ => Recomputed::Unparseable,
                },
            )
        }
        (android::PROVIDER_ID, _) => Some(|stdout: &[u8]| {
            let parsed = if stdout.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{') {
                android::parse_lint_sarif(stdout)
            } else {
                android::parse_lint_xml(stdout)
            };
            if parsed.gaps.is_empty() {
                Recomputed::Findings(parsed.issues.len() as u32)
            } else {
                Recomputed::Unparseable
            }
        }),
        _ => None,
    }
}

/// Recompute the outcomes from the retained raw tool output with the
/// provider's real parser instead of trusting the record. Each digest-bound
/// raw file is a bundle `{"cases":[{"fixtureId","stdout"}]}` of verbatim tool
/// output; the parser derives the finding count per fixture, and the record's
/// `emittedFindings` / `claimedClean` must equal it. Providers without a
/// registered parser are rejected as `outcomes-not-recomputable`. (Expected
/// and matched counts come from the fixture manifest, not tool output; they
/// stay bounded by the recomputed emitted count.)
pub fn validate_recomputed_outcomes(
    root: &Path,
    record: &AssuranceQualificationRecord,
) -> Vec<String> {
    let Some(parser) = recompute_parser(&record.scope) else {
        return vec![format!(
            "outcomes-not-recomputable:{}",
            record.scope.provider
        )];
    };
    let mut cases: std::collections::BTreeMap<String, Vec<u8>> = Default::default();
    for raw in &record.provenance.raw_outputs {
        if !safe_relative_path(&raw.path) {
            continue;
        }
        let Ok(bytes) = fs::read(root.join(&raw.path)) else {
            continue;
        };
        if sha256_digest(&bytes) != raw.sha256 {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            return vec!["raw-output-malformed".into()];
        };
        for case in value
            .get("cases")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(id), Some(stdout)) = (
                case.get("fixtureId").and_then(Value::as_str),
                case.get("stdout").and_then(Value::as_str),
            ) else {
                return vec!["raw-output-case-malformed".into()];
            };
            if cases
                .insert(id.to_owned(), stdout.as_bytes().to_vec())
                .is_some()
            {
                return vec![format!("raw-output-duplicate-case:{id}")];
            }
        }
    }
    if cases.is_empty() {
        return vec!["outcomes-not-recomputable-from-raw-output".into()];
    }
    let mut failures = Vec::new();
    for outcome in &record.outcomes {
        let Some(stdout) = cases.get(&outcome.fixture_id) else {
            failures.push(format!("outcome-without-raw-case:{}", outcome.fixture_id));
            continue;
        };
        match parser(stdout) {
            Recomputed::Findings(count) => {
                if outcome.kind == OutcomeKind::Unsupported
                    || outcome.emitted_findings != count
                    || outcome.claimed_clean != (count == 0)
                {
                    failures.push(format!(
                        "outcomes-differ-from-raw-output:{}",
                        outcome.fixture_id
                    ));
                }
            }
            Recomputed::Unparseable => {
                if outcome.kind != OutcomeKind::Unsupported || outcome.claimed_clean {
                    failures.push(format!("raw-output-unparseable:{}", outcome.fixture_id));
                }
            }
        }
    }
    failures
}

// ------------------------------------------------------- negative evidence

/// Adversarial evidence-pipeline cases (packet item 5). Every defect below
/// must stay unmet/rejected or retain findings; none may become clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NegativeEvidenceKind {
    ForgedImport,
    StaleImport,
    WrongTargetImport,
    ZeroInput,
    SourceDrift,
    InvalidParserOutput,
    SkippedProvider,
    MissingGraph,
    DependencyFormatGap,
    RuntimeClosureMismatch,
    IncompleteReview,
}

impl NegativeEvidenceKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ForgedImport => "forged-import",
            Self::StaleImport => "stale-import",
            Self::WrongTargetImport => "wrong-target-import",
            Self::ZeroInput => "zero-input",
            Self::SourceDrift => "source-drift",
            Self::InvalidParserOutput => "invalid-parser-output",
            Self::SkippedProvider => "skipped-provider",
            Self::MissingGraph => "missing-graph",
            Self::DependencyFormatGap => "dependency-format-gap",
            Self::RuntimeClosureMismatch => "runtime-closure-mismatch",
            Self::IncompleteReview => "incomplete-review",
        }
    }
    pub const ALL: [Self; 11] = [
        Self::ForgedImport,
        Self::StaleImport,
        Self::WrongTargetImport,
        Self::ZeroInput,
        Self::SourceDrift,
        Self::InvalidParserOutput,
        Self::SkippedProvider,
        Self::MissingGraph,
        Self::DependencyFormatGap,
        Self::RuntimeClosureMismatch,
        Self::IncompleteReview,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NegativeEvidenceCase {
    pub id: String,
    pub kind: NegativeEvidenceKind,
    /// What the submitted evidence claims: `clean`, `findings` or `unmet`.
    pub claimed_outcome: String,
    #[serde(default)]
    pub authenticated: bool,
    #[serde(default)]
    pub digest_matches: bool,
    #[serde(default)]
    pub coverage_complete: bool,
    #[serde(default)]
    pub findings: u32,
    /// Corpus oracle only; the classifier never reads it.
    #[serde(default)]
    pub expected_verdict: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceVerdict {
    Unmet,
    Rejected,
    FindingsRetained,
}

impl EvidenceVerdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unmet => "unmet",
            Self::Rejected => "rejected",
            Self::FindingsRetained => "findings-retained",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceClassification {
    pub id: String,
    pub kind: String,
    pub verdict: EvidenceVerdict,
    pub reasons: Vec<String>,
}

/// Classify one adversarial case. The claimed outcome is never trusted:
/// integrity failures reject, coverage/graph/review gaps stay unmet, and
/// real findings are retained even when the surrounding evidence is bad.
pub fn classify_negative_evidence(case: &NegativeEvidenceCase) -> EvidenceClassification {
    let mut reasons = vec![case.kind.label().to_string()];
    let integrity_failure = matches!(
        case.kind,
        NegativeEvidenceKind::ForgedImport
            | NegativeEvidenceKind::WrongTargetImport
            | NegativeEvidenceKind::SourceDrift
            | NegativeEvidenceKind::InvalidParserOutput
            | NegativeEvidenceKind::RuntimeClosureMismatch
    ) || !case.authenticated
        || !case.digest_matches;
    if !case.authenticated {
        reasons.push("unauthenticated".into());
    }
    if !case.digest_matches {
        reasons.push("digest-mismatch".into());
    }
    if !case.coverage_complete {
        reasons.push("coverage-incomplete".into());
    }
    if case.claimed_outcome == "clean" {
        reasons.push("clean-claim-not-accepted".into());
    }
    let verdict = if case.findings > 0 {
        EvidenceVerdict::FindingsRetained
    } else if integrity_failure {
        EvidenceVerdict::Rejected
    } else {
        EvidenceVerdict::Unmet
    };
    EvidenceClassification {
        id: case.id.clone(),
        kind: case.kind.label().to_string(),
        verdict,
        reasons,
    }
}

// ------------------------------------------------------------ retained index

/// Read-only summary of the retained provider-accuracy index. Retained
/// records keep their own family validators; this only refuses entries that
/// expand into a production or whole-provider claim.
pub fn summarize_retained_index(index: &Value) -> Value {
    let entries = index
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut problems = Vec::new();
    for entry in &entries {
        let provider = entry
            .get("provider")
            .and_then(Value::as_str)
            .unwrap_or("<missing-provider>");
        for claim in ["productionQualification", "wholeProviderQualified"] {
            if entry.get(claim).and_then(Value::as_bool) == Some(true) {
                problems.push(format!("{provider}: retained entry claims {claim}"));
            }
        }
        let record = entry.get("record");
        let digest_ok = record
            .and_then(|record| record.get("sha256"))
            .and_then(Value::as_str)
            .is_some_and(is_digest)
            && record
                .and_then(|record| record.get("qualificationDigest"))
                .and_then(Value::as_str)
                .is_some_and(is_digest);
        if !digest_ok {
            problems.push(format!(
                "{provider}: retained record digest missing/malformed"
            ));
        }
    }
    json!({
        "entries": entries.len(),
        "problems": problems,
        "claimScope": "retained-fixture-scoped-only",
    })
}

// ----------------------------------------------------------------------- run

pub struct Options {
    /// Record JSON files (or directories scanned for `*.json` records).
    pub records: Vec<PathBuf>,
    /// Current-context JSON for drift invalidation; optional.
    pub context: Option<PathBuf>,
    /// Negative-evidence corpus JSON (array of cases); optional.
    pub negative_cases: Option<PathBuf>,
    /// RFC3339 UTC instant supplied by the caller (no wall-clock trust).
    pub now: String,
    pub json: bool,
}

fn collect_record_paths(inputs: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for input in inputs {
        if input.is_dir() {
            let mut found: Vec<_> = fs::read_dir(input)
                .map_err(|error| format!("cannot read {}: {error}", input.display()))?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .collect();
            found.sort();
            paths.extend(found);
        } else {
            paths.push(input.clone());
        }
    }
    if paths.is_empty() {
        return Err("no assurance qualification records supplied".into());
    }
    Ok(paths)
}

pub fn report_json(
    reports: &[ValidationReport],
    negative: &[EvidenceClassification],
    retained: &Value,
) -> Value {
    let rejected = reports
        .iter()
        .filter(|report| matches!(report.verdict, Verdict::Rejected | Verdict::Invalidated))
        .count();
    json!({
        "schema": "legion-audit-assurance-report/1",
        "status": if rejected == 0 { "validated-no-production-claim" } else { "records-rejected-or-invalidated" },
        "productionQualification": false,
        "records": reports,
        "negativeEvidence": negative,
        "retainedIndex": retained,
    })
}

/// Entry point for root's `legion-dev audit-assurance` registration.
/// Returns false when any record is rejected/invalidated or any input is
/// unreadable; never writes enrollment or catalog state.
pub fn run(root: &Path, opts: Options) -> bool {
    match run_inner(root, &opts) {
        Ok(ok) => ok,
        Err(error) => {
            eprintln!("legion-dev audit-assurance: {error}");
            false
        }
    }
}

fn run_inner(root: &Path, opts: &Options) -> Result<bool, String> {
    let current: Option<CurrentContext> = match &opts.context {
        Some(path) => Some(
            serde_json::from_slice(
                &fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?,
            )
            .map_err(|e| format!("{}: {e}", path.display()))?,
        ),
        None => None,
    };
    let enrolled = match legion_audit::evidence_issuers::default_qualification_attestors_path() {
        Some(path) => load_enrolled_keys(&path, &[root.to_path_buf()])?,
        None => Vec::new(),
    };
    let mut ok = true;
    let mut reports = Vec::new();
    for path in collect_record_paths(&opts.records)? {
        let bytes = fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let record: AssuranceQualificationRecord =
            serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut report = validate_record_enrolled(&record, &opts.now, current.as_ref(), &enrolled);
        let mut raw_failures = validate_raw_outputs(root, &record);
        if record.provenance.source == ProvenanceSource::Ci
            || record.provenance.authenticated
            || record.lifecycle == Lifecycle::Qualified
        {
            raw_failures.extend(validate_recomputed_outcomes(root, &record));
        }
        if !raw_failures.is_empty() {
            report.reasons.extend(raw_failures);
            report.verdict = Verdict::Rejected;
            report.effective_lifecycle = Lifecycle::Draft;
            report.claim_scope = "rejected-no-claim".to_string();
        }
        if matches!(report.verdict, Verdict::Rejected | Verdict::Invalidated) {
            ok = false;
        }
        reports.push(report);
    }
    let negative: Vec<EvidenceClassification> = match &opts.negative_cases {
        Some(path) => {
            let cases: Vec<NegativeEvidenceCase> = serde_json::from_slice(
                &fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?,
            )
            .map_err(|e| format!("{}: {e}", path.display()))?;
            cases.iter().map(classify_negative_evidence).collect()
        }
        None => Vec::new(),
    };
    let retained = match fs::read(root.join(INDEX_PATH)) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
            .map(|index| summarize_retained_index(&index))
            .unwrap_or_else(|_| json!({"entries": 0, "problems": ["retained-index-malformed"]})),
        Err(_) => json!({"entries": 0, "problems": ["retained-index-missing"]}),
    };
    if retained["problems"]
        .as_array()
        .is_some_and(|p| !p.is_empty())
    {
        ok = false;
    }
    let summary = report_json(&reports, &negative, &retained);
    if opts.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?
        );
    } else {
        for report in &reports {
            println!(
                "{}: {} (claimed {}, effective {}, basis {}, scope {}) reasons=[{}]",
                report.provider,
                report.verdict.label(),
                report.claimed_lifecycle.label(),
                report.effective_lifecycle.label(),
                report.basis,
                report.claim_scope,
                report.reasons.join(", ")
            );
        }
        for case in &negative {
            println!("{} [{}]: {}", case.id, case.kind, case.verdict.label());
        }
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-10-23T00:00:00Z";
    const DIGEST_A: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DIGEST_C: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn outcome(id: &str, split: FixtureSplit, kind: OutcomeKind) -> FixtureOutcome {
        let expected = u32::from(kind == OutcomeKind::Positive);
        FixtureOutcome {
            fixture_id: id.to_string(),
            split,
            kind,
            target: "aarch64-apple-darwin".to_string(),
            expected_findings: expected,
            emitted_findings: expected,
            matched_findings: expected,
            located_findings: expected,
            unsupported_claims: 0,
            claimed_clean: kind == OutcomeKind::Negative,
        }
    }

    const TEST_KEY_SEED: [u8; 32] = [7; 32];

    fn test_enrolled() -> Vec<EnrolledKey> {
        let signing = ed25519_dalek::SigningKey::from_bytes(&TEST_KEY_SEED);
        vec![EnrolledKey {
            key_id: "ci-test".to_string(),
            public_key: hex::encode(signing.verifying_key().to_bytes()),
            not_after: None,
        }]
    }

    fn attest(record: &mut AssuranceQualificationRecord) {
        use ed25519_dalek::Signer;
        let signing = ed25519_dalek::SigningKey::from_bytes(&TEST_KEY_SEED);
        let signature = signing.sign(&attestation_message(&record.qualification_digest));
        record.provenance.attestation = Some(Attestation {
            key_id: "ci-test".to_string(),
            signature: hex::encode(signature.to_bytes()),
        });
    }

    fn reseal(record: &mut AssuranceQualificationRecord) {
        seal(record);
        attest(record);
    }

    fn validate_enrolled(
        record: &AssuranceQualificationRecord,
        now: &str,
        current: Option<&CurrentContext>,
    ) -> ValidationReport {
        validate_record_enrolled(record, now, current, &test_enrolled())
    }

    fn record(basis: BasisKind) -> AssuranceQualificationRecord {
        let mut record = AssuranceQualificationRecord {
            schema: RECORD_SCHEMA.to_string(),
            lifecycle: Lifecycle::Qualified,
            synthetic_fixture: false,
            scope: QualificationScope {
                provider: "code.example".to_string(),
                provider_version: "1.2.3".to_string(),
                lens: "security".to_string(),
                stack: "rust".to_string(),
                rule_id: Some("example.rule".to_string()),
                rule_profile_revision: "rev-7".to_string(),
                tool: "example-tool".to_string(),
                tool_version: "4.5.6".to_string(),
                config_digest: DIGEST_A.to_string(),
                platform: "macos-15".to_string(),
                toolchain: "rustc-1.90".to_string(),
                target: "aarch64-apple-darwin".to_string(),
                variant: "release".to_string(),
                features: vec!["default".to_string()],
                excluded_support: vec!["windows".to_string()],
            },
            basis: Basis {
                kind: basis,
                fixture_ids: vec!["authored-pos".to_string()],
                heldout_fixture_ids: vec!["heldout-pos".to_string(), "heldout-clean".to_string()],
                production_observations: 0,
            },
            provenance: Provenance {
                source: ProvenanceSource::Ci,
                commit: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
                workflow: Some(".github/workflows/ci.yml".to_string()),
                run_id: Some(42),
                attestor: "ci".to_string(),
                authenticated: true,
                captured_at: "2026-10-20T00:00:00Z".to_string(),
                fresh_until: "2027-01-01T00:00:00Z".to_string(),
                raw_outputs: vec![FileDigest {
                    path: "qualification/raw/example.json".to_string(),
                    sha256: DIGEST_B.to_string(),
                }],
                source_closure_digest: DIGEST_B.to_string(),
                implementation_digest: DIGEST_C.to_string(),
                attestation: None,
            },
            outcomes: vec![
                outcome(
                    "authored-pos",
                    FixtureSplit::Authored,
                    OutcomeKind::Positive,
                ),
                outcome("heldout-pos", FixtureSplit::Heldout, OutcomeKind::Positive),
                outcome(
                    "heldout-clean",
                    FixtureSplit::Heldout,
                    OutcomeKind::Negative,
                ),
            ],
            metrics: Some(DeclaredMetrics {
                method: "per-fixture expected/emitted/matched counts".to_string(),
                sample_size: 3,
                precision: 1.0,
                recall: 1.0,
            }),
            cost: Cost {
                wall_time_ms: 25,
                model_calls: 0,
                tokens: None,
            },
            qualification_digest: String::new(),
        };
        seal(&mut record);
        attest(&mut record);
        record
    }

    #[test]
    fn heldout_ci_record_is_valid_at_exact_scope() {
        let report = validate_enrolled(&record(BasisKind::Heldout), NOW, None);
        assert_eq!(report.verdict, Verdict::Valid);
        assert_eq!(report.effective_lifecycle, Lifecycle::Qualified);
        assert_eq!(report.claim_scope, "qualified-exact-scope-only");
        assert_eq!(report.metrics.heldout_sample_size, 2);
        assert!(report.metrics.recall_interval_95.is_some());
    }

    #[test]
    fn caller_asserted_ci_record_is_rejected() {
        // Flags claim CI + authenticated, but nothing proves it.
        let mut unsigned = record(BasisKind::Heldout);
        unsigned.provenance.attestation = None;
        seal(&mut unsigned);
        let report = validate_enrolled(&unsigned, NOW, None);
        assert_eq!(report.verdict, Verdict::Rejected);
        assert!(report
            .reasons
            .iter()
            .any(|r| r.starts_with("ci-attestation-unverified")));
        assert_eq!(report.effective_lifecycle, Lifecycle::Draft);
        // Valid shape but no enrolled key at all.
        let report = validate_record(&record(BasisKind::Heldout), NOW, None);
        assert_eq!(report.verdict, Verdict::Rejected);
        // Signature by an unenrolled/forged key, or over a different digest.
        let mut forged = record(BasisKind::Heldout);
        forged.provenance.attestation = Some(Attestation {
            key_id: "ci-test".to_string(),
            signature: "00".repeat(64),
        });
        assert_eq!(
            validate_enrolled(&forged, NOW, None).verdict,
            Verdict::Rejected
        );
        let mut tampered = record(BasisKind::Heldout);
        tampered.scope.tool_version = "9.9.9".to_string();
        seal(&mut tampered); // resealed but not re-signed
        assert_eq!(
            validate_enrolled(&tampered, NOW, None).verdict,
            Verdict::Rejected
        );
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "legion-dev-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::canonicalize(&dir).unwrap()
    }

    const OX_FINDING: &str = r#"{"diagnostics":[{"message":"m","code":"eslint(no-debugger)","severity":"error","filename":"a.js","labels":[{"span":{"offset":0,"length":1,"line":1,"column":1}}]}],"number_of_files":1}"#;
    const OX_CLEAN: &str = r#"{"diagnostics":[],"number_of_files":1}"#;

    fn oxlint_record(dir: &Path) -> AssuranceQualificationRecord {
        let mut rec = record(BasisKind::Heldout);
        rec.scope.provider = "code.javascript.native".to_string();
        rec.scope.tool = "oxlint".to_string();
        let raw = serde_json::to_vec(&json!({"cases":[
            {"fixtureId":"authored-pos","stdout":OX_FINDING},
            {"fixtureId":"heldout-pos","stdout":OX_FINDING},
            {"fixtureId":"heldout-clean","stdout":OX_CLEAN},
        ]}))
        .unwrap();
        fs::create_dir_all(dir.join("qualification/raw")).unwrap();
        fs::write(dir.join("qualification/raw/example.json"), &raw).unwrap();
        rec.provenance.raw_outputs[0].sha256 = sha256_digest(&raw);
        reseal(&mut rec);
        rec
    }

    #[test]
    fn outcomes_are_recomputed_by_the_real_parser_not_read_from_the_record() {
        let dir = scratch("a18");
        let rec = oxlint_record(&dir);
        assert!(validate_raw_outputs(&dir, &rec).is_empty());
        assert!(validate_recomputed_outcomes(&dir, &rec).is_empty());
        // Tampered outcomes: the record claims a clean run on a fixture whose
        // retained tool output holds a finding.
        let mut tampered = rec.clone();
        tampered.outcomes[1].emitted_findings = 0;
        tampered.outcomes[1].claimed_clean = true;
        reseal(&mut tampered);
        assert_eq!(
            validate_recomputed_outcomes(&dir, &tampered),
            vec!["outcomes-differ-from-raw-output:heldout-pos".to_string()]
        );
        // An `outcomes` array inside the raw file is no longer authority.
        let forged = serde_json::to_vec(&json!({"outcomes": rec.outcomes})).unwrap();
        fs::write(dir.join("qualification/raw/example.json"), &forged).unwrap();
        let mut self_attested = rec.clone();
        self_attested.provenance.raw_outputs[0].sha256 = sha256_digest(&forged);
        reseal(&mut self_attested);
        assert_eq!(
            validate_recomputed_outcomes(&dir, &self_attested),
            vec!["outcomes-not-recomputable-from-raw-output".to_string()]
        );
        // Providers without a registered parser can never qualify.
        let mut unknown = rec.clone();
        unknown.scope.provider = "code.example".to_string();
        reseal(&mut unknown);
        assert_eq!(
            validate_recomputed_outcomes(&dir, &unknown),
            vec!["outcomes-not-recomputable:code.example".to_string()]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn write_enrollment(dir: &Path, name: &str, keys: &[EnrolledKey]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join(name);
        fs::write(&path, serde_json::to_vec(&json!({ "keys": keys })).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn repo_located_enrollment_is_refused_and_host_enrollment_verifies() {
        let repo = scratch("repo");
        let host = scratch("host");
        let keys = test_enrolled();
        // A key enrolled inside the audited repository root is refused.
        let in_repo = write_enrollment(&repo, "qualification-attestors.json", &keys);
        let refused = load_enrolled_keys(&in_repo, &[repo.clone()]);
        assert!(refused.is_err(), "repo-located enrollment must be refused");
        // The same enrollment in host state outside the repo loads and the
        // attested record verifies under it.
        let in_host = write_enrollment(&host, "audit-qualification-attestors.json", &keys);
        let loaded = load_enrolled_keys(&in_host, &[repo.clone()]).unwrap();
        assert_eq!(loaded, keys);
        let rec = record(BasisKind::Heldout);
        assert_eq!(verify_attestation(&rec, &loaded), Ok(()));
        // Missing host file: nothing enrolled, the attestation cannot verify.
        let none = load_enrolled_keys(&host.join("absent.json"), &[repo.clone()]).unwrap();
        assert!(none.is_empty());
        assert!(verify_attestation(&rec, &none).is_err());
        // A group-writable (non-0600) host file is refused.
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&in_host, fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(load_enrolled_keys(&in_host, &[repo.clone()]).is_err());
        let _ = fs::remove_dir_all(&repo);
        let _ = fs::remove_dir_all(&host);
    }

    #[test]
    fn fixture_only_basis_never_qualifies_behaviour() {
        for basis in [
            BasisKind::AuthoredFixture,
            BasisKind::RoutingFixture,
            BasisKind::KnownAnswerFixture,
        ] {
            let report = validate_enrolled(&record(basis), NOW, None);
            assert_eq!(report.verdict, Verdict::FixtureScoped, "{basis:?}");
            assert_eq!(report.effective_lifecycle, Lifecycle::Shadow);
            assert!(report
                .reasons
                .iter()
                .any(|r| r == "fixture-only-basis-capped-shadow"));
        }
    }

    #[test]
    fn forged_digest_and_missing_raw_output_reject() {
        let mut forged = record(BasisKind::Heldout);
        forged.scope.tool_version = "9.9.9".to_string();
        let report = validate_enrolled(&forged, NOW, None);
        assert_eq!(report.verdict, Verdict::Rejected);
        assert!(report
            .reasons
            .iter()
            .any(|r| r == "qualification-digest-mismatch"));

        let mut no_raw = record(BasisKind::Heldout);
        no_raw.provenance.raw_outputs.clear();
        reseal(&mut no_raw);
        let report = validate_enrolled(&no_raw, NOW, None);
        assert_eq!(report.verdict, Verdict::Rejected);
        assert!(report.reasons.iter().any(|r| r == "raw-output-missing"));
    }

    #[test]
    fn stale_and_version_drift_invalidate() {
        let mut stale = record(BasisKind::Heldout);
        stale.provenance.fresh_until = "2026-01-01T00:00:00Z".to_string();
        reseal(&mut stale);
        assert_eq!(
            validate_enrolled(&stale, NOW, None).verdict,
            Verdict::Invalidated
        );

        let sealed = record(BasisKind::Heldout);
        let current = CurrentContext {
            provider_version: "1.2.4".to_string(),
            rule_profile_revision: "rev-8".to_string(),
            tool: "example-tool".to_string(),
            tool_version: "4.5.6".to_string(),
            config_digest: DIGEST_A.to_string(),
            platform: "macos-15".to_string(),
            toolchain: "rustc-1.90".to_string(),
            target: "aarch64-apple-darwin".to_string(),
            variant: "release".to_string(),
            features: vec!["default".to_string()],
            implementation_digest: DIGEST_C.to_string(),
            source_closure_digest: DIGEST_B.to_string(),
        };
        let report = validate_enrolled(&sealed, NOW, Some(&current));
        assert_eq!(report.verdict, Verdict::Invalidated);
        assert!(report
            .reasons
            .iter()
            .any(|r| r == "rule-profile-revision-drift"));
    }

    #[test]
    fn false_green_and_wildcard_scope_reject() {
        let mut green = record(BasisKind::Heldout);
        green.outcomes[1].emitted_findings = 0;
        green.outcomes[1].matched_findings = 0;
        green.outcomes[1].located_findings = 0;
        green.outcomes[1].claimed_clean = true;
        green.metrics = None;
        green.lifecycle = Lifecycle::Shadow;
        reseal(&mut green);
        let report = validate_enrolled(&green, NOW, None);
        assert_eq!(report.verdict, Verdict::Rejected);
        assert!(report.reasons.iter().any(|r| r == "false-green-outcome"));

        let mut wide = record(BasisKind::Heldout);
        wide.scope.target = "*".to_string();
        for outcome in &mut wide.outcomes {
            outcome.target = "*".to_string();
        }
        reseal(&mut wide);
        assert_eq!(
            validate_enrolled(&wide, NOW, None).verdict,
            Verdict::Rejected
        );
    }

    #[test]
    fn negative_evidence_never_becomes_clean() {
        for kind in NegativeEvidenceKind::ALL {
            let case = NegativeEvidenceCase {
                id: kind.label().to_string(),
                kind,
                claimed_outcome: "clean".to_string(),
                authenticated: kind != NegativeEvidenceKind::ForgedImport,
                digest_matches: kind != NegativeEvidenceKind::ForgedImport,
                coverage_complete: false,
                findings: 0,
                expected_verdict: None,
            };
            let classified = classify_negative_evidence(&case);
            assert_ne!(classified.verdict.label(), "clean");
            assert!(matches!(
                classified.verdict,
                EvidenceVerdict::Unmet | EvidenceVerdict::Rejected
            ));
        }
        let findings = classify_negative_evidence(&NegativeEvidenceCase {
            id: "keeps-findings".to_string(),
            kind: NegativeEvidenceKind::IncompleteReview,
            claimed_outcome: "findings".to_string(),
            authenticated: true,
            digest_matches: true,
            coverage_complete: false,
            findings: 2,
            expected_verdict: None,
        });
        assert_eq!(findings.verdict, EvidenceVerdict::FindingsRetained);
    }

    #[test]
    fn retained_index_refuses_production_claims() {
        let summary = summarize_retained_index(&json!({"entries": [{
            "provider": "code.example",
            "productionQualification": true,
            "record": {"sha256": DIGEST_A, "qualificationDigest": DIGEST_B}
        }]}));
        assert_eq!(summary["entries"], 1);
        assert_eq!(summary["problems"].as_array().unwrap().len(), 1);
    }
}
