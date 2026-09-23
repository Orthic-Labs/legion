//! Port of `tools/audit/provider-benchmarks.mjs`'s measurement/qualification
//! core.
//!
//! Ported faithfully: file-content digest bindings, fixture-corpus
//! validation, precision/recall measurement (`measure_fixture_set`),
//! qualification-digest stability, freshness checking against current
//! bindings, and measured-vs-unmeasured provider classification
//! (`qualification_from_results`) — every "metrics are measured, never
//! synthesized" invariant from the source's header comment is preserved
//! (zero-denominator precision/recall is an error, not a default).
//!
//! Not ported: `validateBenchmarkResults`'s frozen-JSON-Schema validation
//! (`references/audit-provider-benchmarks.schema.json`, loaded via
//! `validateSchema` from `src/lib/qualification/schema-validator.mjs` — a
//! schema file and a JSON-Schema validator outside this chunk's owned
//! paths). `assert_valid_results` here does the equivalent *structural*
//! checks this module can name outright (schema version/kind, at least one
//! result, provider id present, `precision`/`recall` bounds) but does not
//! reproduce the frozen schema's exact error-path strings; and the `measure`
//! /`verify`/`status` CLI (dynamic `import()` of a caller-supplied runner
//! module has no Rust equivalent — callers of this port supply `run_provider`
//! as a closure directly, as `measure_fixture_set` already required).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub const BENCHMARK_SCHEMA_VERSION: u32 = 1;
pub const FIXTURES_KIND: &str = "audit-benchmark-fixtures";
pub const RESULTS_KIND: &str = "audit-provider-benchmark-results";
pub const RESULT_KIND: &str = "audit-provider-benchmark-result";
pub const UNMEASURED_GAP_KIND: &str = "unmeasured-rule-pack";

#[derive(Debug, thiserror::Error)]
pub enum BenchmarkError {
    #[error("{0}")]
    Invalid(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, BenchmarkError>;

fn err(msg: impl Into<String>) -> BenchmarkError {
    BenchmarkError::Invalid(msg.into())
}

fn canonical_digest<T: serde::Serialize>(value: &T) -> Result<String> {
    let canonical: serde_json::Value =
        serde_json::to_value(value).map_err(|e| err(format!("not serializable: {e}")))?;
    let bytes = serde_json::to_vec(&canonical).map_err(|e| err(format!("not serializable: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn normalize_rel_path(value: &str) -> String {
    value.replace('\\', "/")
}

// ---------------------------------------------------------------------------
// Digest bindings
// ---------------------------------------------------------------------------

/// `digestFile`: sha256 over raw file bytes, content-addressed and
/// path-independent.
pub fn digest_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Binding {
    pub path: String,
    pub digest: String,
}

/// `fileBindings`: content-bind repo-relative paths, sorted by path. Errors
/// when any named input is missing on disk — an unmeasurable binding must
/// never be silently narrowed to the files that happen to exist.
pub fn file_bindings(paths: &[String], root: &Path) -> Result<Vec<Binding>> {
    let list: Vec<&String> = paths.iter().filter(|p| !p.is_empty()).collect();
    if list.is_empty() {
        return Err(err("fileBindings requires at least one path"));
    }
    let mut out = Vec::with_capacity(list.len());
    for p in list {
        let abs = root.join(p);
        if !abs.exists() {
            return Err(err(format!("binding input missing on disk: {p}")));
        }
        out.push(Binding {
            path: normalize_rel_path(p),
            digest: digest_file(&abs)?,
        });
    }
    out.sort();
    Ok(out)
}

/// `compositeBindingDigest`: stable composite digest over a binding array.
pub fn composite_binding_digest(bindings: &[Binding]) -> Result<String> {
    if bindings.is_empty() {
        return Err(err("compositeBindingDigest requires a non-empty binding array"));
    }
    canonical_digest(&bindings.to_vec())
}

#[derive(Debug, Clone, Default)]
pub struct ProviderRunner {
    pub script: Option<String>,
    pub module: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Provider {
    pub id: String,
    pub runner: ProviderRunner,
}

pub struct BindingInputs {
    pub implementation_paths: Vec<String>,
    pub rule_pack_paths: Vec<String>,
}

/// `bindingInputsForProvider`: map a registry provider onto its measurable
/// binding inputs (runner script = implementation, runner.module = rule
/// pack).
pub fn binding_inputs_for_provider(provider: &Provider) -> Result<BindingInputs> {
    if provider.runner.script.is_none() && provider.runner.module.is_none() {
        return Err(err(format!(
            "provider {} declares no measurable implementation (runner.script/module)",
            provider.id
        )));
    }
    Ok(BindingInputs {
        implementation_paths: provider
            .runner
            .script
            .as_deref()
            .map(|s| vec![normalize_rel_path(s)])
            .unwrap_or_default(),
        rule_pack_paths: provider
            .runner
            .module
            .as_deref()
            .map(|s| vec![normalize_rel_path(s)])
            .unwrap_or_default(),
    })
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProviderBinding {
    #[serde(rename = "implementationDigests")]
    pub implementation_digests: Vec<Binding>,
    #[serde(rename = "rulePackDigests")]
    pub rule_pack_digests: Vec<Binding>,
}

/// `computeProviderBinding`: full digest binding for a registry provider
/// under `root`.
///
/// Faithfully preserves a source quirk: `fileBindings` is called
/// unconditionally on *both* `implementationPaths` and `rulePackPaths`, and
/// `fileBindings([])` always throws ("requires at least one path") — so a
/// provider declaring only a `runner.script` (no `runner.module`), or only a
/// `runner.module` (no `runner.script`), fails here even though
/// `bindingInputsForProvider` alone would have accepted it. Only a provider
/// with *both* a script and a module produces a binding.
pub fn compute_provider_binding(provider: &Provider, root: &Path) -> Result<ProviderBinding> {
    let inputs = binding_inputs_for_provider(provider)?;
    Ok(ProviderBinding {
        implementation_digests: file_bindings(&inputs.implementation_paths, root)?,
        rule_pack_digests: file_bindings(&inputs.rule_pack_paths, root)?,
    })
}

fn assert_bound(binding: &ProviderBinding) -> Result<()> {
    if binding.implementation_digests.is_empty() && binding.rule_pack_digests.is_empty() {
        return Err(err(
            "refusing unbound measurement: at least one implementation or rule-pack digest is required",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixture corpus
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExpectedFinding {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub line: i64,
    #[serde(default)]
    pub file: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FixtureCase {
    pub id: String,
    pub file: String,
    pub text: String,
    pub expected: Vec<ExpectedFinding>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FixturesDoc {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    pub cases: Vec<FixtureCase>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FixtureStats {
    #[serde(rename = "caseCount")]
    pub case_count: usize,
    #[serde(rename = "plantedFindingCount")]
    pub planted_finding_count: usize,
    #[serde(rename = "cleanCaseCount")]
    pub clean_case_count: usize,
}

/// `validateFixtures`: structural validation of a planted-defect fixture
/// set. Ground truth is mandatory per finding; nothing is inferred from
/// text.
pub fn validate_fixtures(fixtures: &FixturesDoc) -> Result<FixtureStats> {
    if fixtures.schema_version != BENCHMARK_SCHEMA_VERSION || fixtures.kind != FIXTURES_KIND {
        return Err(err(format!(
            "benchmark fixtures must be {FIXTURES_KIND} schemaVersion={BENCHMARK_SCHEMA_VERSION}"
        )));
    }
    if fixtures.cases.is_empty() {
        return Err(err("benchmark fixtures must declare at least one case"));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut planted = 0usize;
    let mut clean = 0usize;
    for c in &fixtures.cases {
        if c.id.is_empty() || !seen.insert(c.id.clone()) {
            return Err(err(format!("duplicate or missing fixture case id: {}", c.id)));
        }
        if c.file.is_empty() {
            return Err(err(format!("fixture case {}: file required", c.id)));
        }
        for e in &c.expected {
            if e.rule_id.is_empty() || e.line < 1 {
                return Err(err(format!(
                    "fixture case {}: every expected finding needs ruleId and integer line >= 1",
                    c.id
                )));
            }
            planted += 1;
        }
        if c.expected.is_empty() {
            clean += 1;
        }
    }
    Ok(FixtureStats {
        case_count: fixtures.cases.len(),
        planted_finding_count: planted,
        clean_case_count: clean,
    })
}

/// `computeFixturesDigest`: content digest of the fixture corpus, sorted by
/// case id (order-insensitive).
pub fn compute_fixtures_digest(fixtures: &FixturesDoc) -> Result<String> {
    validate_fixtures(fixtures)?;
    let mut cases = fixtures.cases.clone();
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    #[derive(serde::Serialize)]
    struct Keyed {
        cases: Vec<FixtureCase>,
        kind: String,
    }
    canonical_digest(&Keyed {
        cases,
        kind: fixtures.kind.clone(),
    })
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

fn match_key(rule_id: &str, file: &str, line: i64) -> String {
    format!("{rule_id}\0{file}\0{line}")
}

#[derive(Debug, Clone)]
pub struct RawCandidate {
    pub rule_id: Option<String>,
    pub file: Option<String>,
    pub line: Option<i64>,
}

#[derive(Debug, Clone)]
struct Candidate {
    rule_id: String,
    file: String,
    line: i64,
}

fn normalize_candidate(raw: &RawCandidate, fallback_path: &str, case_id: &str) -> Result<Candidate> {
    let rule_id = raw.rule_id.clone();
    let file = raw.file.clone().unwrap_or_else(|| fallback_path.to_string());
    let line = raw.line;
    match (rule_id, line) {
        (Some(rule_id), Some(line)) if !rule_id.is_empty() && line >= 1 => {
            Ok(Candidate { rule_id, file, line })
        }
        _ => Err(err(format!(
            "provider runner emitted an unlocatable candidate for case {case_id} (needs ruleId, file, integer line >= 1)"
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Metrics {
    #[serde(rename = "truePositives")]
    pub true_positives: u64,
    #[serde(rename = "falsePositives")]
    pub false_positives: u64,
    #[serde(rename = "falseNegatives")]
    pub false_negatives: u64,
    pub precision: f64,
    pub recall: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CaseResult {
    #[serde(rename = "caseId")]
    pub case_id: String,
    #[serde(rename = "expectedFindings")]
    pub expected_findings: usize,
    #[serde(rename = "emittedFindings")]
    pub emitted_findings: usize,
    #[serde(rename = "matchedFindings")]
    pub matched_findings: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderIdentity {
    pub id: String,
    pub version: String,
    #[serde(rename = "rulePack", skip_serializing_if = "Option::is_none")]
    pub rule_pack: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ResultBinding {
    #[serde(rename = "implementationDigests")]
    pub implementation_digests: Vec<Binding>,
    #[serde(rename = "rulePackDigests")]
    pub rule_pack_digests: Vec<Binding>,
    #[serde(rename = "fixturesDigest")]
    pub fixtures_digest: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchmarkResult {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    pub provider: ProviderIdentity,
    pub binding: ResultBinding,
    #[serde(rename = "measuredAt")]
    pub measured_at: String,
    pub fixtures: FixtureStats,
    pub metrics: Metrics,
    pub cases: Vec<CaseResult>,
    #[serde(rename = "qualificationDigest")]
    pub qualification_digest: String,
}

/// `measureFixtureSet`: run `run_provider` across the fixture corpus and
/// measure precision/recall. A prediction matches ground truth when ruleId,
/// file, and line all match; unmatched predictions are false positives,
/// unmatched planted findings are false negatives. Zero denominators error
/// rather than synthesizing a metric.
pub fn measure_fixture_set(
    provider: &ProviderIdentity,
    binding: &ProviderBinding,
    mut run_provider: impl FnMut(&FixtureCase) -> Result<Vec<RawCandidate>>,
    fixtures: &FixturesDoc,
    measured_at: &str,
) -> Result<BenchmarkResult> {
    let stats = validate_fixtures(fixtures)?;
    assert_bound(binding)?;

    let mut cases = Vec::new();
    let mut tp = 0u64;
    let mut fp = 0u64;
    let mut fn_count = 0u64;

    for c in &fixtures.cases {
        let raw = run_provider(c)
            .map_err(|e| err(format!("provider runner failed on fixture case {}: {e}", c.id)))?;
        let emitted = raw
            .iter()
            .map(|r| normalize_candidate(r, &c.file, &c.id))
            .collect::<Result<Vec<_>>>()?;

        let expected_keys: BTreeMap<String, &ExpectedFinding> = c
            .expected
            .iter()
            .map(|e| {
                (
                    match_key(&e.rule_id, e.file.as_deref().unwrap_or(&c.file), e.line),
                    e,
                )
            })
            .collect();
        let mut matched = std::collections::BTreeSet::new();
        let mut case_tp = 0usize;
        for cand in &emitted {
            let key = match_key(&cand.rule_id, &cand.file, cand.line);
            if expected_keys.contains_key(&key) && !matched.contains(&key) {
                matched.insert(key);
                tp += 1;
                case_tp += 1;
            } else {
                fp += 1;
            }
        }
        let case_fn = expected_keys.keys().filter(|k| !matched.contains(*k)).count();
        fn_count += case_fn as u64;
        cases.push(CaseResult {
            case_id: c.id.clone(),
            expected_findings: c.expected.len(),
            emitted_findings: emitted.len(),
            matched_findings: case_tp,
        });
    }

    if tp + fp == 0 {
        return Err(err(
            "precision is undefined: no candidates emitted and none planted; refusing to synthesize a metric",
        ));
    }
    if tp + fn_count == 0 {
        return Err(err(
            "recall is undefined: no planted findings; refusing to synthesize a metric",
        ));
    }

    let mut result = BenchmarkResult {
        schema_version: BENCHMARK_SCHEMA_VERSION,
        kind: RESULT_KIND.to_string(),
        provider: provider.clone(),
        binding: ResultBinding {
            implementation_digests: binding.implementation_digests.clone(),
            rule_pack_digests: binding.rule_pack_digests.clone(),
            fixtures_digest: compute_fixtures_digest(fixtures)?,
        },
        measured_at: measured_at.to_string(),
        fixtures: stats,
        metrics: Metrics {
            true_positives: tp,
            false_positives: fp,
            false_negatives: fn_count,
            precision: tp as f64 / (tp + fp) as f64,
            recall: tp as f64 / (tp + fn_count) as f64,
        },
        cases,
        qualification_digest: String::new(),
    };
    result.qualification_digest = result_qualification_digest(&result)?;
    Ok(result)
}

// ---------------------------------------------------------------------------
// Result documents: freshness, qualification
// ---------------------------------------------------------------------------

/// `resultQualificationDigest`: stable over everything except
/// `qualificationDigest` itself and the volatile `measuredAt` timestamp.
pub fn result_qualification_digest(result: &BenchmarkResult) -> Result<String> {
    #[derive(serde::Serialize)]
    struct Core<'a> {
        #[serde(rename = "schemaVersion")]
        schema_version: u32,
        kind: &'a str,
        provider: &'a ProviderIdentity,
        binding: &'a ResultBinding,
        fixtures: &'a FixtureStats,
        metrics: &'a Metrics,
        cases: &'a [CaseResult],
    }
    canonical_digest(&Core {
        schema_version: result.schema_version,
        kind: &result.kind,
        provider: &result.provider,
        binding: &result.binding,
        fixtures: &result.fixtures,
        metrics: &result.metrics,
        cases: &result.cases,
    })
}

fn normalized_binding_list(list: &[Binding]) -> Vec<Binding> {
    let mut out: Vec<Binding> = list
        .iter()
        .map(|b| Binding {
            path: normalize_rel_path(&b.path),
            digest: b.digest.clone(),
        })
        .collect();
    out.sort();
    out
}

/// `isResultFresh`: the recorded digests must still describe current
/// inputs. Recorded-but-uncomparable current lists are ignored; empty
/// recorded bindings are never fresh.
pub fn is_result_fresh(result: &BenchmarkResult, current: &ProviderBinding) -> bool {
    if result.kind != RESULT_KIND || result.schema_version != BENCHMARK_SCHEMA_VERSION {
        return false;
    }
    let recorded_impl = normalized_binding_list(&result.binding.implementation_digests);
    let recorded_packs = normalized_binding_list(&result.binding.rule_pack_digests);
    if recorded_impl.is_empty() && recorded_packs.is_empty() {
        return false;
    }
    let current_impl = normalized_binding_list(&current.implementation_digests);
    let current_packs = normalized_binding_list(&current.rule_pack_digests);
    if !current_impl.is_empty() && current_impl != recorded_impl {
        return false;
    }
    if !current_packs.is_empty() && current_packs != recorded_packs {
        return false;
    }
    true
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BenchmarkRecord {
    pub status: String,
    #[serde(rename = "requiredForCleanClaim")]
    pub required_for_clean_claim: bool,
    #[serde(rename = "qualificationDigest")]
    pub qualification_digest: Option<String>,
}

pub fn unmeasured_benchmark_record() -> BenchmarkRecord {
    BenchmarkRecord {
        status: "unproven".to_string(),
        required_for_clean_claim: true,
        qualification_digest: None,
    }
}

/// `benchmarkRecordFor`: the benchmark record in the exact shape
/// audit-plan/finalization consumes.
pub fn benchmark_record_for(result: &BenchmarkResult, current: &ProviderBinding) -> BenchmarkRecord {
    if !is_result_fresh(result, current) {
        return unmeasured_benchmark_record();
    }
    BenchmarkRecord {
        status: "measured".to_string(),
        required_for_clean_claim: true,
        qualification_digest: Some(result.qualification_digest.clone()),
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BenchmarkGap {
    pub kind: String,
    pub provider: String,
    #[serde(rename = "benchmarkStatus")]
    pub benchmark_status: String,
}

pub struct Qualification {
    pub records: BTreeMap<String, BenchmarkRecord>,
    pub unmeasured_providers: Vec<String>,
    pub benchmark_gaps: Vec<BenchmarkGap>,
    pub precision_measured: bool,
}

/// `qualificationFromResults`: classify providers into measured vs.
/// unmeasured from a results document. `results` should be pre-validated
/// (schema version/kind) by the caller — this mirrors the JS
/// `assertValidResults(resultsDoc)` call by requiring `results` non-empty
/// only insofar as latest-per-provider selection needs at least one entry
/// per id; an empty `results` with a non-empty `required_providers` is valid
/// (every required id is simply unmeasured).
pub fn qualification_from_results(
    results: &[BenchmarkResult],
    current_by_provider: &BTreeMap<String, ProviderBinding>,
    required_providers: &[String],
) -> Qualification {
    let mut latest: BTreeMap<String, &BenchmarkResult> = BTreeMap::new();
    for r in results {
        match latest.get(&r.provider.id) {
            Some(prior) if prior.measured_at >= r.measured_at => {}
            _ => {
                latest.insert(r.provider.id.clone(), r);
            }
        }
    }
    let mut ids: std::collections::BTreeSet<String> = latest.keys().cloned().collect();
    ids.extend(required_providers.iter().cloned());

    let mut records = BTreeMap::new();
    let mut unmeasured_providers = Vec::new();
    let mut benchmark_gaps = Vec::new();
    let empty_binding = ProviderBinding::default();
    for id in ids {
        let record = match latest.get(&id) {
            Some(result) => {
                let current = current_by_provider.get(&id).unwrap_or(&empty_binding);
                benchmark_record_for(result, current)
            }
            None => unmeasured_benchmark_record(),
        };
        if record.status != "measured" {
            unmeasured_providers.push(id.clone());
            benchmark_gaps.push(BenchmarkGap {
                kind: UNMEASURED_GAP_KIND.to_string(),
                provider: id.clone(),
                benchmark_status: record.status.clone(),
            });
        }
        records.insert(id, record);
    }
    let precision_measured = benchmark_gaps.is_empty();
    Qualification {
        records,
        unmeasured_providers,
        benchmark_gaps,
        precision_measured,
    }
}

/// `measurementEvidence`'s audit-run-integration path when a results file is
/// supplied (the "no `resultsPath`" every-provider-unproven branch is
/// trivially `qualification_from_results(&[], ..., required_providers)`, so
/// only the file-loading half is a distinct function here). Loads and
/// schema-checks (structurally — see module docs) `results_path` before
/// qualifying it.
pub fn measurement_evidence_from_file(
    results_path: &Path,
    current_by_provider: &BTreeMap<String, ProviderBinding>,
    required_providers: &[String],
) -> Result<Qualification> {
    let doc = load_benchmark_results(results_path)?;
    Ok(qualification_from_results(&doc.results, current_by_provider, required_providers))
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ResultsDoc {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    pub results: Vec<BenchmarkResultRaw>,
}

/// Deserialization shape for a `BenchmarkResult` read back from disk
/// (`BenchmarkResult` itself is `Serialize`-only above; results loaded from
/// JSON carry the same fields but arrive as an untyped-ish struct so a
/// missing/extra field is a clear structural-validation failure rather than
/// a silent default).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BenchmarkResultRaw {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    pub provider: ProviderIdentityRaw,
    pub binding: ResultBindingRaw,
    #[serde(rename = "measuredAt")]
    pub measured_at: String,
    pub fixtures: FixtureStats,
    pub metrics: Metrics,
    pub cases: Vec<CaseResultRaw>,
    #[serde(rename = "qualificationDigest")]
    pub qualification_digest: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProviderIdentityRaw {
    pub id: String,
    pub version: String,
    #[serde(rename = "rulePack", default)]
    pub rule_pack: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ResultBindingRaw {
    #[serde(rename = "implementationDigests")]
    pub implementation_digests: Vec<Binding>,
    #[serde(rename = "rulePackDigests")]
    pub rule_pack_digests: Vec<Binding>,
    #[serde(rename = "fixturesDigest")]
    pub fixtures_digest: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct CaseResultRaw {
    #[serde(rename = "caseId")]
    pub case_id: String,
    #[serde(rename = "expectedFindings")]
    pub expected_findings: usize,
    #[serde(rename = "emittedFindings")]
    pub emitted_findings: usize,
    #[serde(rename = "matchedFindings")]
    pub matched_findings: usize,
}

impl From<BenchmarkResultRaw> for BenchmarkResult {
    fn from(r: BenchmarkResultRaw) -> Self {
        BenchmarkResult {
            schema_version: r.schema_version,
            kind: r.kind,
            provider: ProviderIdentity {
                id: r.provider.id,
                version: r.provider.version,
                rule_pack: r.provider.rule_pack,
            },
            binding: ResultBinding {
                implementation_digests: r.binding.implementation_digests,
                rule_pack_digests: r.binding.rule_pack_digests,
                fixtures_digest: r.binding.fixtures_digest,
            },
            measured_at: r.measured_at,
            fixtures: r.fixtures,
            metrics: r.metrics,
            cases: r
                .cases
                .into_iter()
                .map(|c| CaseResult {
                    case_id: c.case_id,
                    expected_findings: c.expected_findings,
                    emitted_findings: c.emitted_findings,
                    matched_findings: c.matched_findings,
                })
                .collect(),
            qualification_digest: r.qualification_digest,
        }
    }
}

pub struct LoadedResultsDoc {
    pub kind: String,
    pub results: Vec<BenchmarkResult>,
}

/// `loadBenchmarkResults` (+ the structural half of `assertValidResults`):
/// parse and validate a results document from disk. Never repairs.
pub fn load_benchmark_results(path: &Path) -> Result<LoadedResultsDoc> {
    let text = fs::read_to_string(path)?;
    let raw: ResultsDoc = serde_json::from_str(&text).map_err(|e| err(format!("invalid results document: {e}")))?;
    assert_valid_results_doc(raw.schema_version, &raw.kind, &raw.results)?;
    Ok(LoadedResultsDoc {
        kind: raw.kind,
        results: raw.results.into_iter().map(BenchmarkResult::from).collect(),
    })
}

fn assert_valid_results_doc(schema_version: u32, kind: &str, results: &[BenchmarkResultRaw]) -> Result<()> {
    if schema_version != BENCHMARK_SCHEMA_VERSION || kind != RESULTS_KIND {
        return Err(err(format!("invalid {RESULTS_KIND}: schemaVersion/kind mismatch")));
    }
    for r in results {
        if r.kind != RESULT_KIND {
            return Err(err(format!("invalid {RESULTS_KIND}: result kind mismatch")));
        }
        if r.provider.id.is_empty() {
            return Err(err(format!("invalid {RESULTS_KIND}: provider.id required")));
        }
        if !(0.0..=1.0).contains(&r.metrics.precision) || !(0.0..=1.0).contains(&r.metrics.recall) {
            return Err(err(format!(
                "invalid {RESULTS_KIND}: {}.metrics.precision/recall must be in [0,1]",
                r.provider.id
            )));
        }
    }
    Ok(())
}

/// Helper for building an absolute results path from a plan root, matching
/// the JS `isAbsolute(resultsPath) ? resultsPath : resolve(root, resultsPath)`.
pub fn resolve_results_path(root: &Path, results_path: &str) -> PathBuf {
    let p = Path::new(results_path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}
