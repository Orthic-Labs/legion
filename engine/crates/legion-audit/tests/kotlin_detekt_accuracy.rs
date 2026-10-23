//! A04 known answers for independent Kotlin detekt source/typed planning &
//! SARIF parsing. Pure planner/parser tests over authored fixtures: no
//! process is launched and no installed-behavior or production
//! qualification claim is made. Root owns execution & verification.
//! checks not run - root owns verification

use legion_audit::{
    native_providers::code::{
        evidence::NativeFinding,
        kotlin_detekt::{
            analyze_source, analyze_typed, classify_run, compute_classpath_digest,
            dedupe_against_jvm, glob_match, normalize_report_path, parse_sarif_report,
            parse_version_output, plan_source, plan_typed, provider_selector,
            select_kotlin_files, validate_pin, validate_typed_evidence, version_gaps,
            ClasspathEntry, DetektExclusion, DetektMode, DetektOptions, DetektStatus,
            DetektToolPin, PluginQualification, ReceiptLink, TypedClasspathEvidence,
            TypedProvenance, EXIT_CLEAN, EXIT_ISSUES_FOUND, MAX_DETEKT_FINDINGS,
            PINNED_DETEKT_VERSION, SOURCE_CONFIG, SOURCE_PROVIDER_ID, TYPED_CONFIG,
            TYPED_PROVIDER_ID,
        },
    },
    InventoryEntry,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{borrow::Cow, fs, path::PathBuf};

const ANSWER: &str = "app/src/main/kotlin/com/example/Answer.kt";
const SMELLY: &str = "app/src/main/kotlin/com/example/Smelly.kt";
const BROKEN: &str = "app/src/main/kotlin/com/example/Broken.kt";
const UNICODE: &str = "app/src/main/kotlin/com/example/Ünïcode Nâme.kt";
const GENERATED: &str = "app/build/generated/Generated.kt";

fn fixture(rel: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/kotlin-detekt")
        .join(rel);
    fs::read(&path).unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn sealed(path: &str, hex_char: char) -> InventoryEntry {
    InventoryEntry {
        path: path.into(),
        symbols: Vec::new(),
        dependencies: Vec::new(),
        package_scripts: Vec::new(),
        source_file: true,
        digest: Some(format!("sha256:{}", hex_char.to_string().repeat(64))),
    }
}

fn plain_repo_entries() -> Vec<InventoryEntry> {
    [
        "app/build.gradle.kts",
        "lib/build.gradle",
        ANSWER,
        SMELLY,
        BROKEN,
        UNICODE,
        GENERATED,
        "lib/src/main/kotlin/com/example/lib/Helper.kt",
        "scripts.kts",
        "README.md",
    ]
    .iter()
    .map(|path| {
        let bytes = fixture(&format!("plain-kotlin/{path}"));
        InventoryEntry {
            path: (*path).into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: Some(sha256(&bytes)),
        }
    })
    .collect()
}

fn pin() -> DetektToolPin {
    let mut pin = DetektToolPin::pinned();
    pin.distribution_digest = format!("sha256:{}", "9".repeat(64));
    pin
}

fn options() -> DetektOptions {
    DetektOptions {
        exclusions: vec![DetektExclusion {
            pattern: "**/build/generated/**".into(),
            reason: "generated sources".into(),
        }],
        ..DetektOptions::default()
    }
}

fn receipt_for(report: &[u8]) -> ReceiptLink {
    ReceiptLink {
        receipt_id: Some("receipt:fixture-detekt-1".into()),
        report_artifact_digest: Some(sha256(report)),
        executable_digest: Some(format!("sha256:{}", "8".repeat(64))),
    }
}

fn parse(
    rel: &str,
    scanned_paths: &[&str],
) -> legion_audit::native_providers::code::kotlin_detekt::DetektOutcome {
    let entries: Vec<InventoryEntry> = scanned_paths
        .iter()
        .enumerate()
        .map(|(index, path)| sealed(path, char::from_digit((index % 10) as u32, 10).unwrap()))
        .collect();
    let plan = plan_source(&entries, &pin(), &DetektOptions::default());
    assert!(plan.is_runnable(), "plan gaps: {:?}", plan.gaps);
    let report = fixture(rel);
    parse_sarif_report(
        &report,
        &plan.scope,
        &pin(),
        &[],
        receipt_for(&report),
        None,
        false,
        MAX_DETEKT_FINDINGS,
    )
}

#[test]
fn plain_kotlin_repo_without_legion_contract_plans_source_mode() {
    let entries = plain_repo_entries();
    assert!(!entries.iter().any(|e| e.path.contains("legion-jvm-sdk")));
    let plan = plan_source(&entries, &pin(), &options());
    assert_eq!(plan.provider_id, SOURCE_PROVIDER_ID);
    assert_eq!(plan.mode, DetektMode::Source);
    assert!(plan.is_runnable(), "gaps: {:?}", plan.gaps);
    let argv = plan.argv.clone().unwrap().join(" ");
    assert!(argv.contains("--config detekt-owned.yml"));
    assert!(argv.contains("--report sarif:detekt.sarif"));
    assert!(argv.contains(&format!("--language-version {}", "2.0")));
    assert!(!argv.contains("gradle") && !argv.contains("legion-jvm-sdk"));
    assert!(!argv.contains("--plugins"), "no repo plugins in source mode");
    // Actual scanned files are frozen, each an explicit --input.
    for file in &plan.scope.scanned {
        assert!(argv.contains(&format!("--input {}", file.path)));
    }
    assert!(!plan.scope.scanned.iter().any(|f| f.path == GENERATED));
    assert_eq!(
        plan.scope.excluded,
        vec![legion_audit::native_providers::code::kotlin_detekt::ExcludedFile {
            path: GENERATED.into(),
            pattern: "**/build/generated/**".into(),
        }]
    );
    assert!(plan.scope.unsupported.iter().any(|p| p == "scripts.kts"));
    assert!(plan
        .gaps
        .iter()
        .any(|gap| gap.contains("detekt-unsupported-syntax:scripts.kts")));
    // Multi-module accountability: app + lib modules stay separate.
    assert!(plan.scope.modules.contains_key("app"));
    assert!(plan.scope.modules.contains_key("lib"));
    assert!(plan.scope.modules["lib"][0].ends_with("Helper.kt"));
    assert_eq!(plan.scope.tool_version, PINNED_DETEKT_VERSION);
    assert!(plan.scope.scope_digest.starts_with("sha256:"));
    assert!(plan.scope.config_digest.starts_with("sha256:"));
}

#[test]
fn source_and_typed_modes_have_independent_ids_selectors_and_context() {
    assert_ne!(SOURCE_PROVIDER_ID, TYPED_PROVIDER_ID);
    assert_eq!(DetektMode::Source.provider_id(), SOURCE_PROVIDER_ID);
    assert_eq!(DetektMode::Typed.provider_id(), TYPED_PROVIDER_ID);
    assert_eq!(
        provider_selector(),
        json!({"op": "anyExtension", "extensions": ["kt", "kts"]})
    );
    assert_eq!(SOURCE_CONFIG.tools, ["detekt"].as_slice());
    assert!(SOURCE_CONFIG.required_context.is_empty());
    assert_eq!(
        TYPED_CONFIG.required_context,
        ["typedClasspath"].as_slice()
    );
    let input = json!({"files": [{"path": "A.kt"}]});
    let source = analyze_source(&input);
    assert_eq!(source["provider"], SOURCE_PROVIDER_ID);
    assert_eq!(source["complete"], false);
    assert!(source["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["tool"] == "detekt"));
    let typed = analyze_typed(&input);
    assert_eq!(typed["provider"], TYPED_PROVIDER_ID);
    assert!(typed["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["context"] == "typedClasspath"));
}

#[test]
fn findings_and_compiler_failure_are_distinct_per_file_diagnostics() {
    let outcome = parse("reports/findings.sarif.json", &[ANSWER, SMELLY]);
    assert_eq!(outcome.status, DetektStatus::Findings);
    assert_eq!(outcome.candidates.len(), 2);
    assert_eq!(
        outcome.candidates[0].rule_id,
        "detekt.empty-blocks.EmptyCatchBlock"
    );
    assert_eq!((outcome.candidates[0].line, outcome.candidates[0].column), (7, 9));
    assert_eq!(
        outcome.candidates[0].receipt_id.as_deref(),
        Some("receipt:fixture-detekt-1")
    );
    assert_eq!(outcome.per_file[SMELLY].rule_findings, 2);
    assert!(outcome.per_file[ANSWER].compiler_errors.is_empty());
    let classified = classify_run(outcome, Some(EXIT_ISSUES_FOUND));
    assert_eq!(classified.status, DetektStatus::Findings);
    assert!(classified.complete, "gaps: {:?}", classified.gaps);

    let broken = parse("reports/compiler-failure.sarif.json", &[BROKEN]);
    assert_eq!(broken.status, DetektStatus::CompilerFailure);
    assert!(broken.candidates.is_empty());
    assert_eq!(broken.per_file[BROKEN].compiler_errors.len(), 1);
    assert!(!broken.complete);
    let broken = classify_run(broken, Some(EXIT_ISSUES_FOUND));
    assert_eq!(broken.status, DetektStatus::CompilerFailure);
    assert!(!broken.complete);
}

#[test]
fn clean_requires_proven_scanned_set_zero_file_is_never_clean() {
    let clean = classify_run(parse("reports/clean.sarif.json", &[ANSWER]), Some(EXIT_CLEAN));
    assert_eq!(clean.status, DetektStatus::Clean);
    assert!(clean.complete);

    let zero = parse("reports/zero-file.sarif.json", &[ANSWER]);
    assert_eq!(zero.status, DetektStatus::ZeroFileScan);
    assert!(!zero.complete);
    assert!(zero
        .gaps
        .iter()
        .any(|gap| gap.contains("detekt-file-not-in-report")));

    // Same clean bytes, but a frozen file the report never scanned.
    let partial = parse("reports/clean.sarif.json", &[ANSWER, SMELLY]);
    assert_eq!(partial.status, DetektStatus::Incomplete);
    assert!(!partial.complete);
}

#[test]
fn unicode_paths_round_trip_through_percent_encoded_uris() {
    let outcome = parse("reports/unicode.sarif.json", &[UNICODE]);
    assert_eq!(outcome.status, DetektStatus::Findings);
    assert_eq!(outcome.candidates.len(), 1);
    assert_eq!(outcome.candidates[0].path, UNICODE);
    assert_eq!(outcome.reported_scanned, vec![UNICODE.to_string()]);
}

#[test]
fn exclusion_of_everything_refuses_and_multi_module_selection_is_frozen() {
    let entries = plain_repo_entries();
    let selection = select_kotlin_files(
        &entries,
        &[DetektExclusion {
            pattern: "**".into(),
            reason: "fixture: exclude all".into(),
        }],
    );
    assert!(selection.scanned.is_empty());
    assert!(selection.excluded.iter().any(|f| f.path == ANSWER));
    let plan = plan_source(
        &entries,
        &pin(),
        &DetektOptions {
            exclusions: vec![DetektExclusion {
                pattern: "**".into(),
                reason: "fixture: exclude all".into(),
            }],
            ..DetektOptions::default()
        },
    );
    assert!(plan.argv.is_none());
    assert!(plan
        .gaps
        .iter()
        .any(|gap| gap.contains("detekt-zero-files-selected")));
    assert!(glob_match("**/build/generated/**", GENERATED));
    assert!(glob_match("app/**/*.kt", SMELLY));
    assert!(!glob_match("lib/**/*.kt", SMELLY));
    assert!(glob_match("**/*.kt", ANSWER));
    assert!(!glob_match("*.kt", SMELLY));
}

fn typed_fixture(rel: &str) -> TypedClasspathEvidence {
    serde_json::from_slice(&fixture(rel))
        .unwrap_or_else(|error| panic!("typed fixture {rel}: {error}"))
}

#[test]
fn typed_wrong_or_missing_classpath_is_incomplete_source_result_remains() {
    let entries = plain_repo_entries();
    let wrong = typed_fixture("typed/wrong-variant.json");
    assert_eq!(
        wrong.classpath_digest,
        compute_classpath_digest(&wrong.classpath)
    );
    let plan = plan_typed(&entries, &pin(), &options(), Some(&wrong), "android-35", "release");
    assert_eq!(plan.provider_id, TYPED_PROVIDER_ID);
    assert!(plan.argv.is_none(), "no silent fallback under the typed id");
    assert!(plan
        .gaps
        .iter()
        .any(|gap| gap.contains("typed-variant-mismatch:debug")));
    // Source result remains usable on the same entries.
    assert!(plan_source(&entries, &pin(), &options()).is_runnable());

    let missing = plan_typed(&entries, &pin(), &options(), None, "android-35", "release");
    assert!(missing.argv.is_none());
    assert!(missing
        .gaps
        .iter()
        .any(|gap| gap.contains("typed-classpath-missing")));

    let valid = typed_fixture("typed/valid-release.json");
    assert!(validate_typed_evidence(
        Some(&valid),
        "android-35",
        "release",
        TYPED_PROVIDER_ID
    )
    .is_empty());
    let typed = plan_typed(&entries, &pin(), &options(), Some(&valid), "android-35", "release");
    assert!(typed.is_runnable(), "gaps: {:?}", typed.gaps);
    let argv = typed.argv.clone().unwrap().join(" ");
    assert!(argv.contains("--classpath"));
    assert!(argv.contains("platforms/android-35/android.jar"));
    assert!(argv.contains(&format!("--input {GENERATED}")));
    assert_eq!(
        typed.scope.typed_classpath_digest.as_deref(),
        Some(valid.classpath_digest.as_str())
    );

    // Unauthenticated imports and unsealed classpaths never validate.
    let imported = TypedClasspathEvidence {
        classpath: vec![ClasspathEntry {
            path: "a.jar".into(),
            digest: "not-a-digest".into(),
        }],
        classpath_digest: String::new(),
        generated_sources: Vec::new(),
        compilation_target: "android-35".into(),
        variant: "release".into(),
        provenance: TypedProvenance::AuthenticatedImport {
            artifact_digest: format!("sha256:{}", "d".repeat(64)),
            attestor: "ci".into(),
            authenticated: false,
        },
    };
    let gaps = validate_typed_evidence(
        Some(&imported),
        "android-35",
        "release",
        TYPED_PROVIDER_ID,
    );
    assert!(gaps.iter().any(|gap| gap.contains("typed-import-unauthenticated")));
    assert!(gaps.iter().any(|gap| gap.contains("typed-classpath-entry-unsealed")));
    assert!(gaps.iter().any(|gap| gap.contains("typed-classpath-digest-mismatch")));
}

#[test]
fn missing_tool_version_mismatch_malformed_and_operational_exit_never_clean() {
    // Unfilled catalog digest (missing JDK/detekt admission) refuses planning.
    let unfilled = DetektToolPin::pinned();
    assert!(validate_pin(&unfilled, SOURCE_PROVIDER_ID)
        .iter()
        .any(|gap| gap.contains("detekt-distribution-digest-missing")));
    let entries = [sealed(ANSWER, 'a')];
    assert!(plan_source(&entries, &unfilled, &DetektOptions::default())
        .argv
        .is_none());
    assert_eq!(parse_version_output(b"1.23.8\n").as_deref(), Some("1.23.8"));
    assert_eq!(
        parse_version_output(b"detekt version 1.23.8\n").as_deref(),
        Some("1.23.8")
    );
    assert_eq!(parse_version_output(b"bash: java: command not found\n"), None);
    assert!(version_gaps(None, &pin(), SOURCE_PROVIDER_ID)
        .iter()
        .any(|gap| gap.contains("detekt-version-unproven")));
    assert!(version_gaps(Some("1.23.7"), &pin(), SOURCE_PROVIDER_ID)
        .iter()
        .any(|gap| gap.contains("detekt-version-mismatch:1.23.7")));

    let wrong = parse("reports/wrong-version.sarif.json", &[ANSWER]);
    assert_eq!(wrong.status, DetektStatus::Incomplete);
    assert!(!wrong.complete);

    let malformed = parse("reports/malformed-truncated.sarif.json", &[ANSWER]);
    assert_eq!(malformed.status, DetektStatus::MalformedReport);
    assert!(!malformed.complete);
    assert!(malformed.candidates.is_empty());

    // Operational nonzero / missing exit overrides even a valid report.
    let failed = classify_run(parse("reports/clean.sarif.json", &[ANSWER]), Some(1));
    assert_eq!(failed.status, DetektStatus::ToolFailure);
    assert!(!failed.complete);
    let killed = classify_run(parse("reports/clean.sarif.json", &[ANSWER]), None);
    assert_eq!(killed.status, DetektStatus::ToolFailure);
    // Clean exit contradicting a findings report is incomplete, not clean.
    let mismatch = classify_run(
        parse("reports/findings.sarif.json", &[ANSWER, SMELLY]),
        Some(EXIT_CLEAN),
    );
    assert!(!mismatch.complete);
    assert!(mismatch
        .gaps
        .iter()
        .any(|gap| gap.contains("detekt-exit-report-mismatch")));
}

#[test]
fn dedupe_against_generic_jvm_keeps_both_provider_records() {
    let outcome = parse("reports/findings.sarif.json", &[ANSWER, SMELLY]);
    let jvm = vec![NativeFinding {
        rule: Cow::Borrowed("empty-catch"),
        severity: "medium",
        path: SMELLY.into(),
        line: 7,
        message: "Empty catch block swallows the error".into(),
    }];
    let deduped = dedupe_against_jvm(outcome.candidates, &jvm);
    assert_eq!(jvm.len(), 1, "generic JVM record is untouched");
    assert_eq!(deduped.duplicates.len(), 1);
    assert_eq!(
        deduped.duplicates[0].detekt_rule_id,
        "detekt.empty-blocks.EmptyCatchBlock"
    );
    assert_eq!(deduped.duplicates[0].generic_rule_id, "empty-catch");
    assert_eq!(deduped.kept.len(), 1);
    assert_eq!(deduped.kept[0].rule_id, "detekt.style.MagicNumber");
}

#[test]
fn coroutine_compose_claims_require_plugin_qualification() {
    let entries = [sealed(ANSWER, 'a')];
    let plan = plan_source(&entries, &pin(), &DetektOptions::default());
    let report = fixture("reports/plugin-unqualified.sarif.json");
    let outcome = parse_sarif_report(
        &report,
        &plan.scope,
        &pin(),
        &[],
        receipt_for(&report),
        None,
        false,
        MAX_DETEKT_FINDINGS,
    );
    assert_eq!(outcome.candidates.len(), 1);
    assert!(!outcome.candidates[0].qualified);
    assert!(outcome.native_findings().is_empty());
    assert!(!outcome.complete);
    assert!(outcome
        .gaps
        .iter()
        .any(|gap| gap.contains("detekt-unqualified-plugin-rule:coroutines")));

    let qualified = [PluginQualification {
        plugin_id: "detekt-rules-coroutines".into(),
        version: PINNED_DETEKT_VERSION.into(),
        distribution_digest: format!("sha256:{}", "7".repeat(64)),
        rules: vec!["detekt.coroutines.GlobalCoroutineUsage".into()],
    }];
    let outcome = parse_sarif_report(
        &report,
        &plan.scope,
        &pin(),
        &qualified,
        receipt_for(&report),
        None,
        false,
        MAX_DETEKT_FINDINGS,
    );
    assert!(outcome.candidates[0].qualified);
    assert_eq!(outcome.native_findings().len(), 1);
}

#[test]
fn receipt_link_and_frozen_scope_digest_are_required_for_evidence() {
    let entries = [sealed(ANSWER, 'a')];
    let plan = plan_source(&entries, &pin(), &DetektOptions::default());
    let report = fixture("reports/clean.sarif.json");
    let unlinked = parse_sarif_report(
        &report,
        &plan.scope,
        &pin(),
        &[],
        ReceiptLink::default(),
        None,
        false,
        MAX_DETEKT_FINDINGS,
    );
    assert!(!unlinked.complete);
    assert!(unlinked
        .gaps
        .iter()
        .any(|gap| gap.contains("detekt-receipt-link-missing")));

    let mut tampered = plan.scope.clone();
    tampered.tool_version = "9.9.9".into();
    let refused = parse_sarif_report(
        &report,
        &tampered,
        &pin(),
        &[],
        receipt_for(&report),
        None,
        false,
        MAX_DETEKT_FINDINGS,
    );
    assert_eq!(refused.status, DetektStatus::Incomplete);
    assert!(refused
        .gaps
        .iter()
        .any(|gap| gap.contains("detekt-scope-digest-mismatch")));
}

#[test]
fn runner_record_is_a_plan_for_root_dispatch_not_a_receipt() {
    let entries = plain_repo_entries();
    let plan = plan_source(&entries, &pin(), &options());
    let record: Value = plan.runner_record();
    assert_eq!(record["providerId"], SOURCE_PROVIDER_ID);
    assert_eq!(record["tool"], "detekt");
    assert_eq!(record["parser"], "detekt-sarif-2.1.0");
    assert_eq!(record["executed"], false);
    assert_eq!(record["acceptedExitCodes"], json!([0, 2]));
    assert_eq!(
        record["scopeDigest"].as_str(),
        Some(plan.scope.scope_digest.as_str())
    );
    assert_eq!(record["explicitInputList"], true);
}

#[test]
fn report_paths_reject_escapes_and_accept_based_absolute_uris() {
    assert_eq!(normalize_report_path("../secret.kt", None), None);
    assert_eq!(normalize_report_path("/etc/passwd.kt", None), None);
    assert_eq!(normalize_report_path("app\\A.kt", None), None);
    assert_eq!(
        normalize_report_path("file:///repo/app/A.kt", Some("/repo")).as_deref(),
        Some("app/A.kt")
    );
    assert_eq!(
        normalize_report_path("./app/A%20B.kt", None).as_deref(),
        Some("app/A B.kt")
    );
}
