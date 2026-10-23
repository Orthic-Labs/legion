//! A05 known answers for `code.android.lint`: applicability, variant
//! enumeration, evidence binding, Lint XML/SARIF parsing, baseline review
//! and platform facts. Pure planner/parser/evaluator tests over authored
//! fixtures; no process runs and no installed-behavior or production
//! qualification is claimed. Root owns execution & verification.
//! checks not run - root owns verification

use legion_audit::{
    artifact_evidence::{EvidenceOutcome, ImportKind, ImportedEvidenceRecord, RetainedArtifact},
    native_providers::code::{
        android::{
            adjacent_obligations, compute_source_set_digest, detekt_typed_binding, evaluate_lint,
            infer_applicability, manifest_facts, parse_baseline_xml, parse_lint_config,
            parse_lint_sarif, parse_lint_xml, parse_xml, plan_lint, webview_source_facts,
            AndroidBuildModel, AndroidLintOptions, AndroidLintPlan, Applicability, AuxFiles,
            ExecutionRoute, LintEvidence, LintEvidenceSource, ModuleModel, ObligationStatus,
            ReportFormat, RequiredVariants, SdkIdentity, SealedPath, SourceSetRef, VariantModel,
            PROVIDER_ID,
        },
        kotlin_detekt::{ReceiptLink, TypedProvenance},
    },
    profiles::AuditProfile,
    InventoryEntry,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf};

const NOW: &str = "2026-10-23T12:00:00Z";
const PROJECT_FILES: &[&str] = &[
    "settings.gradle.kts",
    "app/build.gradle.kts",
    "lib/build.gradle.kts",
    "app/src/main/AndroidManifest.xml",
    "app/src/main/res/layout/activity_main.xml",
    "app/src/main/kotlin/com/example/MainActivity.kt",
    "app/src/phone/res/values/strings.xml",
    "app/src/tablet/res/values/strings.xml",
    "app/src/release/res/values/config.xml",
    "lib/src/main/AndroidManifest.xml",
    "lib/src/main/res/values/lib.xml",
];
/// Index of `app/src/release/res/values/config.xml` in `PROJECT_FILES`.
const RELEASE_CONFIG_INDEX: usize = 8;

fn fixture(rel: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/android-lint")
        .join(rel);
    fs::read(&path).unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()))
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn entry(path: &str, digest: String) -> InventoryEntry {
    InventoryEntry {
        path: path.into(),
        symbols: Vec::new(),
        dependencies: Vec::new(),
        package_scripts: Vec::new(),
        source_file: true,
        digest: Some(digest),
    }
}

fn entries() -> Vec<InventoryEntry> {
    PROJECT_FILES
        .iter()
        .map(|path| entry(path, sha(&fixture(&format!("project/{path}")))))
        .collect()
}

fn build_texts() -> BTreeMap<String, String> {
    PROJECT_FILES
        .iter()
        .filter(|path| path.ends_with("build.gradle.kts"))
        .map(|path| {
            (
                (*path).to_string(),
                String::from_utf8(fixture(&format!("project/{path}"))).unwrap(),
            )
        })
        .collect()
}

fn variant(
    entries: &[InventoryEntry],
    module: &str,
    name: &str,
    build_type: &str,
    flavors: &[&str],
    dirs: &[(&str, &str)],
) -> VariantModel {
    let cap = format!("{}{}", &name[..1].to_uppercase(), &name[1..]);
    VariantModel {
        name: name.into(),
        build_type: build_type.into(),
        flavors: flavors.iter().map(|f| (*f).to_string()).collect(),
        lint_task: format!("{module}:lint{cap}"),
        min_sdk: 24,
        target_sdk: 35,
        source_sets: dirs
            .iter()
            .map(|(set, dir)| SourceSetRef {
                name: (*set).into(),
                dir: (*dir).into(),
                digest: compute_source_set_digest(entries, dir).unwrap(),
            })
            .collect(),
        generated_resources: vec![SealedPath {
            path: format!("{}/build/generated/res/{name}", &module[1..]),
            digest: format!("sha256:{}", "6".repeat(64)),
        }],
        // The redirected location the init script reports (owner output root).
        report_xml_path: format!("build/{}/reports/lint-results-{name}.xml", &module[1..]),
        report_root: "owner-output".into(),
        report_sarif_path: None,
    }
}

fn build_model(entries: &[InventoryEntry]) -> AndroidBuildModel {
    let main = ("main", "app/src/main");
    let release = ("release", "app/src/release");
    AndroidBuildModel {
        schema_version: 1,
        agp_version: "8.5.0".into(),
        gradle_version: "8.7".into(),
        jdk_version: "21.0.9+10".into(),
        lint_version: "31.5.0".into(),
        gradle_program: "gradlew-from-model-receipt".into(),
        sdk: Some(SdkIdentity {
            compile_sdk: 35,
            platform_digest: format!("sha256:{}", "7".repeat(64)),
            build_tools_version: "35.0.0".into(),
        }),
        modules: vec![
            ModuleModel {
                path: ":app".into(),
                dir: "app".into(),
                kind: "application".into(),
                lint_excluded: false,
                exclusion_reason: None,
                resolution_failure: None,
                baseline: None,
                lint_config: None,
                variants: vec![
                    variant(
                        entries,
                        ":app",
                        "phoneRelease",
                        "release",
                        &["phone"],
                        &[main, ("phone", "app/src/phone"), release],
                    ),
                    variant(
                        entries,
                        ":app",
                        "tabletRelease",
                        "release",
                        &["tablet"],
                        &[main, ("tablet", "app/src/tablet"), release],
                    ),
                    variant(
                        entries,
                        ":app",
                        "phoneDebug",
                        "debug",
                        &["phone"],
                        &[main, ("phone", "app/src/phone")],
                    ),
                ],
            },
            ModuleModel {
                path: ":lib".into(),
                dir: "lib".into(),
                kind: "library".into(),
                lint_excluded: false,
                exclusion_reason: None,
                resolution_failure: None,
                baseline: None,
                lint_config: None,
                variants: vec![variant(
                    entries,
                    ":lib",
                    "release",
                    "release",
                    &[],
                    &[("main", "lib/src/main")],
                )],
            },
        ],
        provenance: TypedProvenance::AdmittedBuild {
            receipt_id: "receipt:model-1".into(),
            artifact_digest: format!("sha256:{}", "5".repeat(64)),
        },
    }
}

fn admitted(profile: AuditProfile) -> AndroidLintOptions {
    AndroidLintOptions::new(
        profile,
        ExecutionRoute::AdmittedProject {
            admission_receipt_id: "admission:fixture-1".into(),
        },
    )
}

fn plan_with(model: Option<&AndroidBuildModel>, options: &AndroidLintOptions) -> AndroidLintPlan {
    plan_lint(&entries(), &build_texts(), model, options)
}

fn local_run(
    plan: &AndroidLintPlan,
    module: &str,
    variant: &str,
    report_fixture: &str,
    exit_code: Option<i32>,
) -> LintEvidence {
    let obligation = plan
        .obligations
        .iter()
        .find(|o| o.module == module && o.variant == variant)
        .unwrap_or_else(|| panic!("no obligation {module}:{variant}"));
    let report = fixture(&format!("reports/{report_fixture}"));
    LintEvidence {
        module: module.into(),
        variant: variant.into(),
        lint_task: obligation.lint_task.clone(),
        toolchain: plan.toolchain.clone().unwrap(),
        examined_scope: obligation.expected_scope(),
        format: ReportFormat::Xml,
        source: LintEvidenceSource::LocalRun {
            receipt: ReceiptLink {
                receipt_id: Some(format!("receipt:{module}:{variant}")),
                report_artifact_digest: Some(sha(&report)),
                executable_digest: Some(format!("sha256:{}", "8".repeat(64))),
            },
            exit_code,
        },
        report,
    }
}

fn import_record(
    plan: &AndroidLintPlan,
    module: &str,
    variant: &str,
    report: &[u8],
    authenticated: bool,
) -> ImportedEvidenceRecord {
    let obligation = plan
        .obligations
        .iter()
        .find(|o| o.module == module && o.variant == variant)
        .unwrap();
    ImportedEvidenceRecord {
        schema_version: 1,
        evidence_id: format!("evidence:{module}:{variant}"),
        claims_digest: format!("sha256:{}", "a".repeat(64)),
        kind: ImportKind::Sarif,
        authenticated,
        attestor: "host-ci-provenance".into(),
        trust_root_id: "root-1".into(),
        verifier_id: "verifier-1".into(),
        outcome: EvidenceOutcome::Passed,
        repositories: Vec::new(),
        target: obligation.obligation_target(),
        variant: Some(module.into()),
        toolchain: plan.toolchain.clone().unwrap(),
        upstream_runtime: Some("gradle-8".into()),
        artifacts: vec![RetainedArtifact {
            path: "lint-results.xml".into(),
            digest: sha(report),
            bytes: report.len() as u64,
            role: "primary".into(),
            immutable: true,
        }],
        artifact_digest: sha(report),
        denominator_digest: format!("sha256:{}", "b".repeat(64)),
        examined_scope: obligation.expected_scope(),
        missing_scope: Vec::new(),
        newly_executed: true,
        replay_of: None,
        issued_at: "2026-10-23T10:00:00Z".into(),
        fresh_until: "2026-10-24T10:00:00Z".into(),
    }
}

fn import_evidence(
    plan: &AndroidLintPlan,
    module: &str,
    variant: &str,
    report_fixture: &str,
    authenticated: bool,
) -> LintEvidence {
    let obligation = plan
        .obligations
        .iter()
        .find(|o| o.module == module && o.variant == variant)
        .unwrap();
    let report = fixture(&format!("reports/{report_fixture}"));
    LintEvidence {
        module: module.into(),
        variant: variant.into(),
        lint_task: obligation.lint_task.clone(),
        toolchain: plan.toolchain.clone().unwrap(),
        examined_scope: Vec::new(),
        format: ReportFormat::Xml,
        source: LintEvidenceSource::Import {
            record: import_record(plan, module, variant, &report, authenticated),
        },
        report,
    }
}

fn full_local_evidence(plan: &AndroidLintPlan) -> Vec<LintEvidence> {
    vec![
        local_run(plan, ":app", "phoneRelease", "phone-release.xml", Some(1)),
        local_run(plan, ":app", "tabletRelease", "tablet-release.xml", Some(0)),
        local_run(plan, ":lib", "release", "lib-release.xml", Some(0)),
    ]
}

fn has_gap(gaps: &[String], needle: &str) -> bool {
    gaps.iter().any(|gap| gap.contains(needle))
}

fn import_options() -> AndroidLintOptions {
    AndroidLintOptions::new(AuditProfile::Release, ExecutionRoute::AuthenticatedImport)
}

// ---------------------------------------------------------------------------
// Applicability
// ---------------------------------------------------------------------------

#[test]
fn applicability_is_inferred_from_agp_manifest_and_resources() {
    let decision = infer_applicability(&entries(), &build_texts());
    assert_eq!(decision.applicability, Applicability::Applicable);
    assert_eq!(decision.manifests.len(), 2);
    assert_eq!(decision.agp_build_files.len(), 2);
    assert!(decision.gaps.is_empty(), "{:?}", decision.gaps);
}

#[test]
fn plain_kotlin_is_not_applicable_and_partial_evidence_is_ambiguous() {
    let plain = vec![
        entry(
            "build.gradle.kts",
            sha(&fixture("plain-kotlin/build.gradle.kts")),
        ),
        entry("Main.kt", sha(&fixture("plain-kotlin/Main.kt"))),
    ];
    let texts = BTreeMap::from([(
        "build.gradle.kts".to_string(),
        String::from_utf8(fixture("plain-kotlin/build.gradle.kts")).unwrap(),
    )]);
    let decision = infer_applicability(&plain, &texts);
    assert_eq!(decision.applicability, Applicability::NotApplicable);
    let plan = plan_lint(&plain, &texts, None, &admitted(AuditProfile::Release));
    assert!(!plan.is_applicable());
    assert!(plan.gaps.is_empty() && plan.obligations.is_empty());

    // A manifest without any AGP evidence is ambiguity, never "not applicable".
    let manifest_only: Vec<InventoryEntry> = entries()
        .into_iter()
        .filter(|e| !e.path.ends_with("build.gradle.kts"))
        .collect();
    let ambiguous = infer_applicability(&manifest_only, &BTreeMap::new());
    assert_eq!(ambiguous.applicability, Applicability::Ambiguous);
    assert!(has_gap(&ambiguous.gaps, "android-applicability-ambiguous"));

    // An unread build file can still carry the plugin: ambiguous.
    let unread = infer_applicability(&plain, &BTreeMap::new());
    assert_eq!(unread.applicability, Applicability::Ambiguous);
    assert!(has_gap(&unread.gaps, "android-build-file-unread"));
}

// ---------------------------------------------------------------------------
// Variant enumeration & planning
// ---------------------------------------------------------------------------

#[test]
fn variants_are_enumerated_from_the_model_with_exact_task_identity() {
    let entries = entries();
    let model = build_model(&entries);
    let plan = plan_with(Some(&model), &admitted(AuditProfile::Release));
    assert!(plan.gaps.is_empty(), "{:?}", plan.gaps);
    let ids: Vec<&str> = plan.obligations.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "android-lint::app:phoneRelease",
            "android-lint::app:tabletRelease",
            "android-lint::lib:release"
        ]
    );
    // Debug is not a required release variant and gets no obligation.
    assert!(plan.obligations.iter().all(|o| o.variant != "phoneDebug"));
    let phone = &plan.obligations[0];
    let tablet = &plan.obligations[1];
    assert_eq!(phone.lint_task, ":app:lintPhoneRelease");
    assert_eq!(tablet.lint_task, ":app:lintTabletRelease");
    assert_ne!(phone.scope_digest, tablet.scope_digest);
    assert_eq!(phone.compile_sdk, Some(35));
    assert_eq!(phone.obligation_target(), "android:phoneRelease");
    assert_eq!(phone.obligation_variant(), ":app");
    // Argv comes from the model task identity, never a whole-product lint.
    let runner = phone
        .runner
        .as_ref()
        .expect("admitted route plans a runner");
    assert_eq!(runner.program, "gradlew-from-model-receipt");
    assert_eq!(runner.argv[0], ":app:lintPhoneRelease");
    assert!(!runner.argv.iter().any(|arg| arg == "lint"));
    let records = plan.runner_records();
    assert!(records.iter().all(|r| r["executed"] == false));
    assert_eq!(
        detekt_typed_binding(&model, "phoneRelease"),
        Some(("android-35".to_string(), "phoneRelease".to_string()))
    );
}

#[test]
fn explicit_required_variants_and_unknown_pairs() {
    let entries = entries();
    let model = build_model(&entries);
    let mut options = admitted(AuditProfile::Release);
    options.required = RequiredVariants::Explicit(vec![
        (":app".into(), "phoneDebug".into()),
        (":app".into(), "nonexistent".into()),
    ]);
    let plan = plan_with(Some(&model), &options);
    assert_eq!(plan.obligations.len(), 1);
    assert!(has_gap(
        &plan.gaps,
        "android-required-variant-unknown::app:nonexistent"
    ));
}

#[test]
fn missing_model_is_an_explicit_gap_not_a_whole_product_lint() {
    let plan = plan_with(None, &admitted(AuditProfile::Release));
    assert!(plan.obligations.is_empty());
    assert!(has_gap(&plan.gaps, "android-model-missing"));
    let evaluation = evaluate_lint(&plan, &entries(), &[], &AuxFiles::default(), NOW);
    assert!(!evaluation.complete && !evaluation.clean && !evaluation.profile_satisfied);
}

#[test]
fn missing_sdk_resolution_failure_exclusion_and_absent_module_are_gaps() {
    let entries = entries();
    let mut broken = build_model(&entries);
    broken.sdk = None;
    let plan = plan_with(Some(&broken), &admitted(AuditProfile::Release));
    assert!(has_gap(&plan.gaps, "android-sdk-missing"));
    assert!(plan
        .obligations
        .iter()
        .all(|o| has_gap(&o.plan_gaps, "android-sdk-missing")));
    assert!(plan.obligations.iter().all(|o| o.runner.is_none()));
    let evaluation = evaluate_lint(
        &plan,
        &entries,
        &full_local_evidence(&plan),
        &AuxFiles::default(),
        NOW,
    );
    assert!(!evaluation.complete && !evaluation.clean);

    let mut broken = build_model(&entries);
    broken.modules[1].resolution_failure = Some("Could not resolve androidx.core:core:1.13".into());
    broken.modules[0].lint_excluded = true;
    broken.modules[0].exclusion_reason = Some("disabled in build.gradle".into());
    let plan = plan_with(Some(&broken), &admitted(AuditProfile::Release));
    let lib = plan
        .obligations
        .iter()
        .find(|o| o.module == ":lib")
        .unwrap();
    assert!(has_gap(
        &lib.plan_gaps,
        "android-gradle-resolution-failed::lib"
    ));
    let app = plan
        .obligations
        .iter()
        .find(|o| o.module == ":app")
        .unwrap();
    assert!(has_gap(
        &app.plan_gaps,
        "android-module-excluded::app:disabled in build.gradle"
    ));
    let evaluation = evaluate_lint(
        &plan,
        &entries,
        &full_local_evidence(&plan),
        &AuxFiles::default(),
        NOW,
    );
    assert!(!evaluation.complete);
    assert!(evaluation
        .obligations
        .iter()
        .all(|r| r.status == ObligationStatus::Rejected));

    // The repository has a manifest-bearing module the model never listed.
    let mut partial = build_model(&entries);
    partial.modules.retain(|m| m.path != ":lib");
    let plan = plan_with(Some(&partial), &admitted(AuditProfile::Release));
    assert!(has_gap(&plan.gaps, "android-module-missing-from-model:lib"));
}

#[test]
fn drifted_source_set_or_bad_task_identity_blocks_the_obligation() {
    let mut drifted = entries();
    let model = build_model(&drifted);
    drifted[RELEASE_CONFIG_INDEX].digest = Some(format!("sha256:{}", "c".repeat(64)));
    let plan = plan_lint(
        &drifted,
        &build_texts(),
        Some(&model),
        &admitted(AuditProfile::Release),
    );
    let phone = &plan.obligations[0];
    assert!(has_gap(
        &phone.plan_gaps,
        "android-source-set-digest-mismatch::app:phoneRelease:release"
    ));

    let entries = entries();
    let mut renamed = build_model(&entries);
    renamed.modules[0].variants[0].lint_task = ":app:lintVitalPhoneRelease".into();
    let plan = plan_with(Some(&renamed), &admitted(AuditProfile::Release));
    assert!(has_gap(
        &plan.obligations[0].plan_gaps,
        "android-lint-task-identity-mismatch"
    ));
}

#[test]
fn not_admitted_route_keeps_execution_an_explicit_gap() {
    let entries = entries();
    let model = build_model(&entries);
    let options = AndroidLintOptions::new(AuditProfile::Release, ExecutionRoute::NotAdmitted);
    let plan = plan_with(Some(&model), &options);
    assert!(has_gap(&plan.gaps, "android-lint-execution-not-admitted"));
    assert!(plan.obligations.iter().all(|o| o.runner.is_none()));
}

// ---------------------------------------------------------------------------
// Evidence binding
// ---------------------------------------------------------------------------

#[test]
fn full_admitted_evidence_for_every_variant_is_complete_but_not_clean_with_findings() {
    let entries = entries();
    let model = build_model(&entries);
    let plan = plan_with(Some(&model), &admitted(AuditProfile::Release));
    let evidence = full_local_evidence(&plan);
    let evaluation = evaluate_lint(&plan, &entries, &evidence, &AuxFiles::default(), NOW);
    assert!(evaluation.gaps.is_empty(), "{:?}", evaluation.gaps);
    assert!(evaluation.complete);
    assert!(!evaluation.clean, "phone variant carries findings");
    assert!(evaluation.profile_satisfied);
    let phone = &evaluation.obligations[0];
    assert_eq!(phone.status, ObligationStatus::Findings);
    assert_eq!(phone.candidates.len(), 3);
    assert!(phone.candidates.iter().any(|c| c.generated));
    assert_eq!(
        evaluation.obligations[1].status,
        ObligationStatus::Satisfied
    );
    assert_eq!(evaluation.native_findings().len(), 3);
    assert!(evaluation
        .native_findings()
        .iter()
        .any(|f| f.severity == "error"));
    // Lint success never claims compile/tests/device/package coverage.
    assert!(evaluation.claim_limits.contains(&"device-lifecycle"));
    assert_eq!(
        adjacent_obligations(&plan).len(),
        plan.obligations.len() * 4
    );
    assert_eq!(evaluation.to_value()["providerId"], PROVIDER_ID);
}

#[test]
fn clean_only_when_every_variant_is_qualified_and_finding_free() {
    let entries = entries();
    let model = build_model(&entries);
    let plan = plan_with(Some(&model), &admitted(AuditProfile::Release));
    let evidence = vec![
        local_run(&plan, ":app", "phoneRelease", "tablet-release.xml", Some(0)),
        local_run(
            &plan,
            ":app",
            "tabletRelease",
            "tablet-release.xml",
            Some(0),
        ),
        local_run(&plan, ":lib", "release", "lib-release.xml", Some(0)),
    ];
    let evaluation = evaluate_lint(&plan, &entries, &evidence, &AuxFiles::default(), NOW);
    assert!(
        evaluation.complete && evaluation.clean,
        "{:?}",
        evaluation.gaps
    );
}

#[test]
fn scanning_one_variant_cannot_certify_both() {
    let entries = entries();
    let model = build_model(&entries);
    let plan = plan_with(Some(&model), &admitted(AuditProfile::Release));
    let evidence = vec![
        local_run(&plan, ":app", "phoneRelease", "phone-release.xml", Some(1)),
        local_run(&plan, ":lib", "release", "lib-release.xml", Some(0)),
    ];
    let evaluation = evaluate_lint(&plan, &entries, &evidence, &AuxFiles::default(), NOW);
    let tablet = evaluation
        .obligations
        .iter()
        .find(|r| r.variant == "tabletRelease")
        .unwrap();
    assert_eq!(tablet.status, ObligationStatus::Missing);
    assert!(!evaluation.complete && !evaluation.clean && !evaluation.profile_satisfied);
    assert!(has_gap(
        &evaluation.gaps,
        "android-lint-evidence-missing:android-lint::app:tabletRelease"
    ));

    // Evidence whose task names the other variant cannot discharge this one.
    let mut crossed = full_local_evidence(&plan);
    crossed[1].lint_task = ":app:lintPhoneRelease".into();
    let evaluation = evaluate_lint(&plan, &entries, &crossed, &AuxFiles::default(), NOW);
    assert!(!evaluation.complete);
    assert!(has_gap(&evaluation.gaps, "android-lint-task-mismatch"));

    // A scope claim lacking this variant's source sets is incomplete.
    let mut narrow = full_local_evidence(&plan);
    narrow[1]
        .examined_scope
        .retain(|item| !item.starts_with("source-set:tablet"));
    let evaluation = evaluate_lint(&plan, &entries, &narrow, &AuxFiles::default(), NOW);
    assert!(has_gap(&evaluation.gaps, "android-lint-scope-incomplete"));
    assert!(!evaluation.complete);

    // Evidence for a variant the plan never froze is named, not absorbed.
    let mut extra = full_local_evidence(&plan);
    extra.push(local_run(
        &plan,
        ":app",
        "phoneRelease",
        "phone-release.xml",
        Some(1),
    ));
    extra[3].variant = "phoneDebug".into();
    let evaluation = evaluate_lint(&plan, &entries, &extra, &AuxFiles::default(), NOW);
    assert!(has_gap(
        &evaluation.gaps,
        "android-lint-evidence-unmatched::app:phoneDebug"
    ));
    assert!(!evaluation.complete);
}

#[test]
fn unsigned_local_file_and_unauthenticated_import_never_satisfy() {
    let entries = entries();
    let model = build_model(&entries);
    let plan = plan_with(Some(&model), &import_options());
    let mut evidence = vec![
        import_evidence(&plan, ":app", "phoneRelease", "phone-release.xml", true),
        import_evidence(&plan, ":app", "tabletRelease", "tablet-release.xml", false),
        local_run(&plan, ":lib", "release", "lib-release.xml", Some(0)),
    ];
    evidence[2].source = LintEvidenceSource::UnsignedFile;
    let evaluation = evaluate_lint(&plan, &entries, &evidence, &AuxFiles::default(), NOW);
    assert!(!evaluation.complete);
    assert_eq!(evaluation.obligations[0].status, ObligationStatus::Findings);
    assert!(evaluation.obligations[0].authenticated);
    for index in [1, 2] {
        assert_eq!(
            evaluation.obligations[index].status,
            ObligationStatus::Rejected
        );
        assert!(!evaluation.obligations[index].authenticated);
        assert!(has_gap(
            &evaluation.obligations[index].gaps,
            "android-lint-evidence-unauthenticated"
        ));
    }
    assert!(evaluation
        .native_findings()
        .iter()
        .all(|f| f.path.starts_with("app/")));
}

#[test]
fn authenticated_import_satisfies_the_exact_obligation() {
    let entries = entries();
    let model = build_model(&entries);
    let plan = plan_with(Some(&model), &import_options());
    assert!(plan.obligations.iter().all(|o| o.runner.is_none()));
    assert!(!has_gap(&plan.gaps, "execution-not-admitted"));
    let evidence = vec![
        import_evidence(&plan, ":app", "phoneRelease", "phone-release.xml", true),
        import_evidence(&plan, ":app", "tabletRelease", "tablet-release.xml", true),
        import_evidence(&plan, ":lib", "release", "lib-release.xml", true),
    ];
    let evaluation = evaluate_lint(&plan, &entries, &evidence, &AuxFiles::default(), NOW);
    assert!(evaluation.gaps.is_empty(), "{:?}", evaluation.gaps);
    assert!(evaluation.complete && evaluation.profile_satisfied);
    assert!(evaluation.obligations.iter().all(|r| r.authenticated));
}

#[test]
fn stale_replayed_wrong_subject_and_wrong_artifact_imports_are_rejected() {
    let entries = entries();
    let model = build_model(&entries);
    let plan = plan_with(Some(&model), &import_options());
    let mut stale = import_evidence(&plan, ":app", "tabletRelease", "tablet-release.xml", true);
    if let LintEvidenceSource::Import { record } = &mut stale.source {
        record.fresh_until = "2026-10-01T00:00:00Z".into();
        record.newly_executed = false;
        record.target = "android:phoneRelease".into();
        record.missing_scope = vec!["source-set:tablet".into()];
        record.artifacts[0].digest = format!("sha256:{}", "d".repeat(64));
    }
    let evaluation = evaluate_lint(&plan, &entries, &[stale], &AuxFiles::default(), NOW);
    let tablet = evaluation
        .obligations
        .iter()
        .find(|r| r.variant == "tabletRelease")
        .unwrap();
    assert_eq!(tablet.status, ObligationStatus::Rejected);
    for needle in [
        "android-lint-evidence-stale",
        "android-lint-replayed-evidence",
        "android-lint-import-subject-mismatch",
        "android-lint-scope-missing",
        "android-lint-import-artifact-mismatch",
    ] {
        assert!(has_gap(&tablet.gaps, needle), "{needle}: {:?}", tablet.gaps);
    }
}

#[test]
fn local_run_exit_and_receipt_semantics() {
    let entries = entries();
    let model = build_model(&entries);
    let plan = plan_with(Some(&model), &admitted(AuditProfile::Release));
    // Exit 1 with only a warning is a build/compile failure, not lint findings.
    let mut run = local_run(
        &plan,
        ":app",
        "tabletRelease",
        "exit-without-errors.xml",
        Some(1),
    );
    let evaluation = evaluate_lint(&plan, &entries, &[run.clone()], &AuxFiles::default(), NOW);
    let tablet = evaluation
        .obligations
        .iter()
        .find(|r| r.variant == "tabletRelease")
        .unwrap();
    assert!(has_gap(&tablet.gaps, "android-lint-exit-without-errors"));
    assert_eq!(tablet.status, ObligationStatus::Rejected);

    if let LintEvidenceSource::LocalRun { exit_code, .. } = &mut run.source {
        *exit_code = Some(137);
    }
    let evaluation = evaluate_lint(&plan, &entries, &[run.clone()], &AuxFiles::default(), NOW);
    assert!(has_gap(&evaluation.gaps, "android-lint-tool-failed"));

    if let LintEvidenceSource::LocalRun { exit_code, receipt } = &mut run.source {
        *exit_code = Some(0);
        receipt.report_artifact_digest = Some(format!("sha256:{}", "e".repeat(64)));
    }
    let evaluation = evaluate_lint(&plan, &entries, &[run], &AuxFiles::default(), NOW);
    assert!(has_gap(
        &evaluation.gaps,
        "android-lint-receipt-link-missing"
    ));

    // A local run is rejected when the plan never admitted execution.
    let options = AndroidLintOptions::new(AuditProfile::Release, ExecutionRoute::NotAdmitted);
    let unadmitted = plan_with(Some(&model), &options);
    let evidence = full_local_evidence(&unadmitted);
    let evaluation = evaluate_lint(&unadmitted, &entries, &evidence, &AuxFiles::default(), NOW);
    assert!(has_gap(
        &evaluation.gaps,
        "android-lint-local-run-not-admitted"
    ));
    assert!(!evaluation.complete);
}

#[test]
fn wrong_toolchain_lint_version_and_unresolved_locations_are_gaps() {
    let entries = entries();
    let model = build_model(&entries);
    let plan = plan_with(Some(&model), &admitted(AuditProfile::Release));
    let mut wrong_toolchain = local_run(
        &plan,
        ":app",
        "tabletRelease",
        "tablet-release.xml",
        Some(0),
    );
    wrong_toolchain.toolchain = "agp-7.0.0+gradle-7.0+jdk-17+lint-30.0.0+compileSdk-33".into();
    let evaluation = evaluate_lint(
        &plan,
        &entries,
        &[wrong_toolchain],
        &AuxFiles::default(),
        NOW,
    );
    assert!(has_gap(&evaluation.gaps, "android-lint-toolchain-mismatch"));

    let wrong_version = local_run(
        &plan,
        ":app",
        "tabletRelease",
        "wrong-lint-version.xml",
        Some(0),
    );
    let evaluation = evaluate_lint(&plan, &entries, &[wrong_version], &AuxFiles::default(), NOW);
    assert!(has_gap(&evaluation.gaps, "android-lint-version-mismatch"));

    let absolute = local_run(
        &plan,
        ":app",
        "tabletRelease",
        "absolute-unresolved.xml",
        Some(1),
    );
    let evaluation = evaluate_lint(&plan, &entries, &[absolute], &AuxFiles::default(), NOW);
    let tablet = evaluation
        .obligations
        .iter()
        .find(|r| r.variant == "tabletRelease")
        .unwrap();
    assert!(tablet.candidates.is_empty());
    assert!(has_gap(&tablet.gaps, "android-lint-location-unresolved"));
    assert_eq!(tablet.status, ObligationStatus::Rejected);
}

#[test]
fn pre_pr_defers_lint_but_release_stays_incomplete() {
    let entries = entries();
    let model = build_model(&entries);
    let pre_pr = plan_with(Some(&model), &admitted(AuditProfile::PrePr));
    let deferred = evaluate_lint(&pre_pr, &entries, &[], &AuxFiles::default(), NOW);
    assert!(deferred.profile_satisfied);
    assert!(!deferred.complete && !deferred.clean);
    assert_eq!(deferred.deferred.len(), 3);

    let release = plan_with(Some(&model), &admitted(AuditProfile::Release));
    let evaluation = evaluate_lint(&release, &entries, &[], &AuxFiles::default(), NOW);
    assert!(!evaluation.profile_satisfied && !evaluation.complete);
    assert!(evaluation.deferred.is_empty());

    // A rejected (not merely missing) obligation is never deferrable.
    let mut unsigned = local_run(
        &pre_pr,
        ":app",
        "tabletRelease",
        "tablet-release.xml",
        Some(0),
    );
    unsigned.source = LintEvidenceSource::UnsignedFile;
    let evaluation = evaluate_lint(&pre_pr, &entries, &[unsigned], &AuxFiles::default(), NOW);
    assert!(!evaluation.profile_satisfied);
}

// ---------------------------------------------------------------------------
// Baseline & suppression review
// ---------------------------------------------------------------------------

fn with_baseline(entries: &[InventoryEntry], baseline: &[u8]) -> AndroidBuildModel {
    let mut model = build_model(entries);
    model.modules[0].baseline = Some(SealedPath {
        path: "app/lint-baseline.xml".into(),
        digest: sha(baseline),
    });
    model.modules[0].lint_config = Some(SealedPath {
        path: "app/lint.xml".into(),
        digest: sha(&fixture("baselines/lint-config.xml")),
    });
    model
}

#[test]
fn baseline_suppressions_stay_visible_and_changes_trigger_review() {
    let entries = entries();
    let clean = fixture("baselines/baseline-clean.xml");
    let model = with_baseline(&entries, &clean);
    let plan = plan_with(Some(&model), &admitted(AuditProfile::Release));
    let evidence = full_local_evidence(&plan);
    let mut aux = AuxFiles::default();
    aux.baselines.insert(":app".into(), clean.clone());
    aux.lint_configs
        .insert(":app".into(), fixture("baselines/lint-config.xml"));
    aux.approved_baseline_digests
        .insert(":app".into(), sha(&clean));
    let evaluation = evaluate_lint(&plan, &entries, &evidence, &aux, NOW);
    assert!(evaluation.gaps.is_empty(), "{:?}", evaluation.gaps);
    let phone = &evaluation.obligations[0];
    assert_eq!(phone.baseline_suppressed.len(), 1);
    assert_eq!(phone.baseline_suppressed[0].rule_id, "HardcodedText");
    assert_eq!(phone.config_suppressions.len(), 2);
    assert!(evaluation.to_value()["obligations"][0]["baselineSuppressed"] == 1);

    // Changed baseline vs the previously reviewed digest.
    let mut changed = aux.clone();
    changed
        .approved_baseline_digests
        .insert(":app".into(), format!("sha256:{}", "1".repeat(64)));
    let evaluation = evaluate_lint(&plan, &entries, &evidence, &changed, NOW);
    assert!(has_gap(
        &evaluation.gaps,
        "android-lint-baseline-changed::app"
    ));
    assert!(!evaluation.complete);

    // No prior review at all is also a review gap.
    let mut unreviewed = aux.clone();
    unreviewed.approved_baseline_digests.clear();
    let evaluation = evaluate_lint(&plan, &entries, &evidence, &unreviewed, NOW);
    assert!(has_gap(
        &evaluation.gaps,
        "android-lint-baseline-unreviewed::app"
    ));

    // Baseline and config declared but never read.
    let evaluation = evaluate_lint(&plan, &entries, &evidence, &AuxFiles::default(), NOW);
    assert!(has_gap(
        &evaluation.gaps,
        "android-lint-baseline-unread::app"
    ));
    assert!(has_gap(&evaluation.gaps, "android-lint-config-unread::app"));
}

#[test]
fn stale_baseline_entries_and_digest_drift_leave_gaps() {
    let entries = entries();
    let stale = fixture("baselines/baseline-stale.xml");
    let model = with_baseline(&entries, &stale);
    let plan = plan_with(Some(&model), &admitted(AuditProfile::Release));
    let evidence = full_local_evidence(&plan);
    let mut aux = AuxFiles::default();
    aux.baselines.insert(":app".into(), stale.clone());
    aux.lint_configs
        .insert(":app".into(), fixture("baselines/lint-config.xml"));
    aux.approved_baseline_digests
        .insert(":app".into(), sha(&stale));
    let evaluation = evaluate_lint(&plan, &entries, &evidence, &aux, NOW);
    assert!(has_gap(
        &evaluation.gaps,
        "android-lint-baseline-stale::app:UnusedResources:src/main/res/layout/removed_screen.xml"
    ));
    assert!(!evaluation.complete);

    // Bytes that differ from the digest frozen in the model.
    let mut drift = aux.clone();
    drift
        .baselines
        .insert(":app".into(), fixture("baselines/baseline-clean.xml"));
    let evaluation = evaluate_lint(&plan, &entries, &evidence, &drift, NOW);
    assert!(has_gap(
        &evaluation.gaps,
        "android-lint-baseline-mismatch::app"
    ));

    // A baseline present in the repository but undeclared by the model.
    let mut with_file = entries.clone();
    with_file.push(entry("app/lint-baseline.xml", sha(&stale)));
    let plain_model = build_model(&with_file);
    let plan = plan_lint(
        &with_file,
        &build_texts(),
        Some(&plain_model),
        &admitted(AuditProfile::Release),
    );
    assert!(has_gap(
        &plan.obligations[0].plan_gaps,
        "android-lint-baseline-undeclared::app"
    ));
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[test]
fn xml_parser_rejects_dtd_entities_truncation_and_bombs() {
    assert!(parse_xml(&fixture("reports/doctype-entity.xml")).is_err());
    let parsed = parse_lint_xml(&fixture("reports/doctype-entity.xml"));
    assert!(parsed.issues.is_empty());
    assert!(has_gap(&parsed.gaps, "doctype-or-entity-forbidden"));

    let truncated = parse_lint_xml(&fixture("reports/malformed-truncated.xml"));
    assert!(truncated.issues.is_empty());
    assert!(has_gap(&truncated.gaps, "android-lint-malformed-report"));

    let unsupported = parse_lint_xml(&fixture("reports/unsupported-format.xml"));
    assert!(has_gap(
        &unsupported.gaps,
        "android-lint-unsupported-report-format:3"
    ));

    let deep = format!("{}{}", "<a>".repeat(200), "</a>".repeat(200));
    assert_eq!(parse_xml(deep.as_bytes()), Err("too-deep".to_string()));
    assert!(parse_xml(b"<a x=\"1\" x=\"2\"/>").is_err());
    assert!(parse_xml(b"<a x=\"&bogus;\"/>").is_err());
    assert_eq!(
        parse_xml(b"<a x=\"1 &lt; 2\"/>").unwrap().attr("x"),
        Some("1 < 2")
    );
}

#[test]
fn lint_xml_report_yields_locations_severities_and_version() {
    let parsed = parse_lint_xml(&fixture("reports/phone-release.xml"));
    assert!(parsed.gaps.is_empty(), "{:?}", parsed.gaps);
    assert_eq!(parsed.lint_version.as_deref(), Some("31.5.0"));
    assert_eq!(parsed.issues.len(), 3);
    let receiver = parsed
        .issues
        .iter()
        .find(|i| i.rule_id == "ExportedReceiver")
        .unwrap();
    assert_eq!(receiver.severity, "error");
    assert_eq!(receiver.line, 23);
    let text = parsed
        .issues
        .iter()
        .find(|i| i.rule_id == "HardcodedText")
        .unwrap();
    assert_eq!(text.severity, "warning");
    assert!(text.message.contains("\"Hello\""));
}

#[test]
fn sarif_report_parses_and_wrong_driver_is_malformed() {
    let parsed = parse_lint_sarif(&fixture("reports/phone-release.sarif.json"));
    assert!(parsed.gaps.is_empty(), "{:?}", parsed.gaps);
    assert_eq!(parsed.issues.len(), 1);
    assert_eq!(parsed.lint_version.as_deref(), Some("31.5.0"));
    let wrong = parse_lint_sarif(&fixture("reports/wrong-driver.sarif.json"));
    assert!(has_gap(&wrong.gaps, "driver-not-android-lint"));
    assert!(wrong.issues.is_empty());
    assert!(has_gap(&parse_lint_sarif(b"{").gaps, "invalid-json"));
}

#[test]
fn baseline_and_lint_config_parsers() {
    let entries = parse_baseline_xml(&fixture("baselines/baseline-stale.xml")).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(parse_baseline_xml(b"<lint/>").is_err());
    let config = parse_lint_config(&fixture("baselines/lint-config.xml")).unwrap();
    assert_eq!(config.len(), 2);
    assert!(config.iter().any(|c| c.kind == "severity-ignore"));
    assert!(config
        .iter()
        .any(|c| c.kind == "path-ignore" && c.detail == "**/legacy/**"));
}

// ---------------------------------------------------------------------------
// Platform facts for security/platform lenses
// ---------------------------------------------------------------------------

#[test]
fn manifest_and_webview_facts_feed_existing_lenses() {
    let path = "app/src/main/AndroidManifest.xml";
    let facts = manifest_facts(path, &fixture("project/app/src/main/AndroidManifest.xml")).unwrap();
    let kinds: Vec<&str> = facts.iter().map(|f| f.kind.as_str()).collect();
    for expected in [
        "permission-requested",
        "cleartext-traffic",
        "backup",
        "exported-component",
        "exported-without-permission",
        "implicit-export-undeclared",
        "deep-link",
    ] {
        assert!(kinds.contains(&expected), "{expected}: {kinds:?}");
    }
    let deep = facts.iter().find(|f| f.kind == "deep-link").unwrap();
    assert_eq!(deep.detail, "https://example.com autoVerify=true");
    assert!(manifest_facts(path, b"<!DOCTYPE manifest []><manifest/>").is_err());

    let source = String::from_utf8(fixture(
        "project/app/src/main/kotlin/com/example/MainActivity.kt",
    ))
    .unwrap();
    let web = webview_source_facts("app/src/main/kotlin/com/example/MainActivity.kt", &source);
    let kinds: Vec<&str> = web.iter().map(|f| f.kind.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "webview-javascript-enabled",
            "webview-javascript-interface",
            "webview-cleartext-url"
        ]
    );
    assert!(web.iter().all(|f| f.line.is_some() && f.lens == "security"));
}

// ---------------------------------------------------------------------------
// Owner-contained Gradle model extraction (mocked contained runtime)
// ---------------------------------------------------------------------------
#[cfg(unix)]
mod gradle_owner {
    use super::*;
    use async_trait::async_trait;
    use legion_audit::{
        host_owner::{HostPolicyOwner, OwnerRequestContext, POLICY_FILE},
        native_providers::code::{
            android::plan_with_owner,
            gradle_model::{extract_android_model, GradlePins, WRAPPER_JAR, WRAPPER_PROPERTIES},
        },
    };
    use legion_effects::{
        platform::ProcessFuture, receipt::ProcessTreeEvidence, PlatformProcess, ProcessLaunch,
        ProcessOutput,
    };
    use legion_provider_sdk::{
        ExecutionReceipt, ExecutionState, ExternalProjectTool, ExternalToolRequest,
    };
    use std::{
        collections::BTreeSet,
        os::unix::fs::PermissionsExt,
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Mutex,
        },
    };
    use tokio_util::sync::CancellationToken;

    static SEQ: AtomicU64 = AtomicU64::new(0);
    const JAR: &[u8] = b"pinned-wrapper-jar";
    const DIST_SUM: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    struct Env {
        root: PathBuf,
        out: PathBuf,
        java: PathBuf,
        ctx: OwnerRequestContext,
    }

    fn env(properties_sum: Option<&str>) -> Env {
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "legion-gradle-model-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
        let root = base.join("project");
        let out = base.join("out");
        let state = base.join("state");
        let tools = base.join("tools");
        for dir in [&root, &out, &state, &tools, &root.join("gradle/wrapper")] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join(WRAPPER_JAR), JAR).unwrap();
        let props = match properties_sum {
            Some(sum) => format!("distributionUrl=x\ndistributionSha256Sum={sum}\n"),
            None => "distributionUrl=x\n".to_string(),
        };
        fs::write(root.join(WRAPPER_PROPERTIES), props).unwrap();
        let java = tools.join("java");
        fs::write(&java, b"#!/bin/sh\n").unwrap();
        let policy = state.join(POLICY_FILE);
        fs::write(
            &policy,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 1,
                "policyRevision": "t1",
                "tools": [{
                    "providers": [PROVIDER_ID],
                    "executable": java,
                    "sha256": sha(b"#!/bin/sh\n"),
                    "class": "project-executing",
                    "environmentNames": []
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
        let owner = HostPolicyOwner::load(&policy, &[root.clone(), out.clone()])
            .unwrap()
            .unwrap();
        let config = owner.owner_config("plan-1", &root, &out).unwrap();
        let ctx = owner.request_context(&config);
        Env {
            root,
            out,
            java,
            ctx,
        }
    }

    fn pins(env: &Env) -> GradlePins {
        GradlePins {
            java: env.java.clone(),
            wrapper_jar_sha256: [sha(JAR)].into_iter().collect::<BTreeSet<_>>(),
            distribution_sha256: [DIST_SUM.to_string()].into_iter().collect(),
            dependency_cache_root: None,
        }
    }

    struct Mock {
        json: Option<Vec<u8>>,
        exit: i32,
        /// Real platform launches (what an unadmitted path would start).
        launches: AtomicUsize,
        /// Submitted owner requests, in order.
        requests: Mutex<Vec<ExternalToolRequest>>,
        /// Whether the owner authorizer admits requests.
        admit: bool,
    }

    impl Mock {
        fn new(json: Option<Vec<u8>>, exit: i32) -> Self {
            Self {
                json,
                exit,
                launches: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
                admit: true,
            }
        }
        fn denying() -> Self {
            Self {
                admit: false,
                ..Self::new(Some(Vec::new()), 0)
            }
        }
    }

    /// Stands in for the owner-backed executor: authorizes every request, and
    /// only an admitted one reaches the (counting) platform process.
    #[async_trait]
    impl ExternalProjectTool for Mock {
        async fn execute(
            &self,
            request: ExternalToolRequest,
            _cancellation: CancellationToken,
        ) -> ExecutionReceipt {
            self.requests.lock().unwrap().push(request.clone());
            if !self.admit {
                return ExecutionReceipt::failure(
                    &request,
                    ExecutionState::UnauthorizedEffect,
                    "owner-denied",
                );
            }
            let launch = ProcessLaunch {
                executable: request.executable.clone(),
                args: request.args.clone(),
                cwd: request.cwd.clone(),
                environment: request.environment.clone(),
                stdout_limit: request.stdout_limit,
                stderr_limit: request.stderr_limit,
                timeout_ms: request.timeout_ms,
                termination_grace_ms: 2_000,
                cancellation: CancellationToken::new(),
            };
            match self.run(launch).await {
                Ok(output) => {
                    let mut receipt =
                        ExecutionReceipt::failure(&request, ExecutionState::Completed, "");
                    receipt.gaps.clear();
                    receipt.complete = output
                        .exit_code
                        .is_some_and(|c| request.accepted_exit_codes.contains(&c));
                    if !receipt.complete {
                        receipt.state = ExecutionState::Failed;
                    }
                    receipt.exit_code = output.exit_code;
                    receipt.process_tree = output.process_tree;
                    receipt
                }
                Err(_) => ExecutionReceipt::failure(&request, ExecutionState::SpawnFailed, "spawn"),
            }
        }
    }

    impl PlatformProcess for Mock {
        fn run<'a>(&'a self, launch: ProcessLaunch) -> ProcessFuture<'a> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                assert!(launch.args.iter().any(|a| a == "--offline"));
                assert!(!launch.executable.ends_with("gradlew"));
                let target = launch
                    .args
                    .iter()
                    .find_map(|a| a.strip_prefix("-Dlegion.model.out="))
                    .unwrap();
                if let Some(json) = &self.json {
                    fs::write(target, json).unwrap();
                }
                Ok(ProcessOutput {
                    stdout: vec![],
                    stderr: vec![],
                    exit_code: Some(self.exit),
                    signal: None,
                    timed_out: false,
                    cancelled: false,
                    output_limited: false,
                    kill_succeeded: true,
                    process_tree: ProcessTreeEvidence {
                        started: true,
                        terminated: true,
                        hard_killed: false,
                        reaped: true,
                        detail: None,
                    },
                    started_at_ms: 1,
                    completed_at_ms: 2,
                })
            })
        }
    }

    fn model_json(with_provenance: bool) -> Vec<u8> {
        let model = build_model(&entries());
        let mut value = serde_json::to_value(&model).unwrap();
        if !with_provenance {
            value.as_object_mut().unwrap().remove("provenance");
        }
        let typed = serde_json::json!({
            ":app:phoneRelease": {
                "classpath": [{"path": "libs/a.jar", "digest": sha(b"a")}],
                "generatedSources": [],
                "compilationTarget": "android-35",
                "variant": "phoneRelease"
            }
        });
        serde_json::to_vec(&serde_json::json!({"model": value, "typedClasspath": typed})).unwrap()
    }

    fn run(
        env: &Env,
        mock: &Mock,
        pins: Option<&GradlePins>,
        with_ctx: bool,
    ) -> Result<
        legion_audit::native_providers::code::gradle_model::ExtractedAndroidModel,
        Vec<String>,
    > {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(extract_android_model(
                with_ctx.then_some(&env.ctx),
                with_ctx.then_some(mock as &dyn ExternalProjectTool),
                "plan-1",
                &env.root,
                &env.out,
                pins,
                &entries(),
            ))
    }

    fn gap_plan(gaps: &[String]) -> AndroidLintPlan {
        plan_with_owner(
            &entries(),
            &build_texts(),
            Err(gaps),
            &admitted(AuditProfile::Release),
        )
    }

    #[test]
    fn unpinned_wrapper_is_a_gap_and_nothing_runs() {
        let mock = Mock::new(Some(model_json(false)), 0);
        // Distribution sum absent.
        let e = env(None);
        let gaps = run(&e, &mock, Some(&pins(&e)), true).unwrap_err();
        assert_eq!(
            gaps,
            vec!["code.android.lint:gradle-wrapper-unpinned".to_string()]
        );
        // Distribution sum present but not pinned.
        let e = env(Some(&"2".repeat(64)));
        let gaps = run(&e, &mock, Some(&pins(&e)), true).unwrap_err();
        assert_eq!(
            gaps,
            vec!["code.android.lint:gradle-wrapper-unpinned".to_string()]
        );
        // Jar digest not pinned.
        let e = env(Some(DIST_SUM));
        let mut p = pins(&e);
        p.wrapper_jar_sha256.clear();
        let gaps = run(&e, &mock, Some(&p), true).unwrap_err();
        assert_eq!(
            gaps,
            vec!["code.android.lint:gradle-wrapper-unpinned".to_string()]
        );
        let plan = gap_plan(&gaps);
        assert!(plan.obligations.is_empty());
        assert!(plan
            .gaps
            .iter()
            .any(|g| g.ends_with("android-model-missing")));
        assert!(plan
            .gaps
            .iter()
            .any(|g| g.ends_with("gradle-wrapper-unpinned")));
    }

    #[test]
    fn missing_owner_is_a_gap() {
        let e = env(Some(DIST_SUM));
        let mock = Mock::new(None, 0);
        let gaps = run(&e, &mock, Some(&pins(&e)), false).unwrap_err();
        assert_eq!(
            gaps,
            vec!["code.android.lint:gradle-owner-missing".to_string()]
        );
    }

    #[test]
    fn contained_model_binds_receipt_and_plans_pinned_offline_runner() {
        let e = env(Some(DIST_SUM));
        let mock = Mock::new(Some(model_json(false)), 0);
        let extracted = run(&e, &mock, Some(&pins(&e)), true).unwrap();
        match &extracted.model.provenance {
            TypedProvenance::AdmittedBuild {
                receipt_id,
                artifact_digest,
            } => {
                assert!(receipt_id.ends_with(":gradle-model"));
                assert_eq!(
                    *artifact_digest,
                    sha(&fs::read(e.out.join("legion-android-model.json")).unwrap())
                );
            }
            other => panic!("unexpected provenance {other:?}"),
        }
        let typed = extracted.typed_classpath(":app", "phoneRelease").unwrap();
        assert_eq!(typed.compilation_target, "android-35");
        assert!(matches!(
            typed.provenance,
            TypedProvenance::AdmittedBuild { .. }
        ));
        let plan = plan_with_owner(
            &entries(),
            &build_texts(),
            Ok(&extracted),
            &admitted(AuditProfile::Release),
        );
        assert!(!plan.obligations.is_empty());
        let runner = plan
            .obligations
            .iter()
            .find(|o| o.variant == "phoneRelease")
            .and_then(|o| o.runner.as_ref())
            .expect("runner");
        assert_eq!(runner.program, e.java.to_string_lossy());
        assert!(runner.argv.iter().any(|a| a == "--offline"));
        assert!(runner.argv.iter().any(|a| a == ":app:lintPhoneRelease"));
        assert!(!plan
            .gaps
            .iter()
            .any(|g| g.ends_with("android-model-missing")));
    }

    #[test]
    fn denied_admission_is_a_gap_and_no_process_launches() {
        let e = env(Some(DIST_SUM));
        let mock = Mock::denying();
        let gaps = run(&e, &mock, Some(&pins(&e)), true).unwrap_err();
        assert!(
            gaps.iter()
                .any(|g| g.contains("gradle-model-admission-denied")),
            "{gaps:?}"
        );
        assert_eq!(
            mock.launches.load(Ordering::SeqCst),
            0,
            "denied request must not launch"
        );
        // The denied request was still a typed, owner-shaped request.
        assert_eq!(mock.requests.lock().unwrap().len(), 1);
        let plan = gap_plan(&gaps);
        assert!(plan.obligations.is_empty());
        assert!(plan
            .gaps
            .iter()
            .any(|g| g.contains("gradle-model-admission-denied")));
    }

    #[test]
    fn admitted_request_carries_owner_shape_and_runtime_output_is_used() {
        let e = env(Some(DIST_SUM));
        let mock = Mock::new(Some(model_json(false)), 0);
        let extracted = run(&e, &mock, Some(&pins(&e)), true).unwrap();
        assert_eq!(mock.launches.load(Ordering::SeqCst), 1);
        let requests = mock.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.provider_id, PROVIDER_ID);
        assert_eq!(request.plan_id, "plan-1");
        assert_eq!(
            request.policy_id,
            legion_audit::execution_policy::OWNER_POLICY_ID
        );
        assert_eq!(request.executable, e.java.to_string_lossy());
        assert_eq!(
            request.expected_digest.as_deref(),
            Some(sha(b"#!/bin/sh\n").as_str())
        );
        assert!(request.requires_network_sandbox && request.skip_version_probe && !request.shell);
        assert_eq!(
            request.sandbox.as_ref().unwrap().id,
            e.ctx.sandbox_receipt().id
        );
        assert_eq!(
            extracted.model.modules.len(),
            build_model(&entries()).modules.len()
        );
    }

    #[test]
    fn report_paths_come_from_the_model_and_the_lint_run_reuses_the_redirect() {
        let e = env(Some(DIST_SUM));
        let mock = Mock::new(Some(model_json(false)), 0);
        let extracted = run(&e, &mock, Some(&pins(&e)), true).unwrap();
        let variant = &extracted.model.modules[0].variants[0];
        assert_eq!(variant.report_root, "owner-output");
        assert!(
            variant.report_xml_path.starts_with("build/"),
            "{}",
            variant.report_xml_path
        );
        let plan = plan_with_owner(
            &entries(),
            &build_texts(),
            Ok(&extracted),
            &admitted(AuditProfile::Release),
        );
        let obligation = plan
            .obligations
            .iter()
            .find(|o| o.variant == "phoneRelease")
            .expect("obligation");
        let runner = obligation.runner.as_ref().expect("runner");
        let expected = format!(
            "build/{}/reports/lint-results-phoneRelease.xml",
            &obligation.module[1..]
        );
        assert_eq!(obligation.report_xml_path, expected);
        assert_eq!(runner.report_path, expected);
        assert_eq!(runner.report_root, "owner-output");
        assert!(!runner
            .report_path
            .starts_with(&format!("{}/build", obligation.module_dir)));
        // The lint run replays the init script's build-dir redirect, no re-emit.
        assert!(runner.argv.iter().any(|a| a == "-I"));
        assert!(runner.argv.iter().any(|a| a == "-Dlegion.model.emit=false"));
        let records = plan.runner_records();
        assert!(records
            .iter()
            .any(|r| r["reportRoot"] == "owner-output" && r["reportPath"] == expected.as_str()));
    }

    #[test]
    fn malformed_failed_or_self_attested_models_are_gaps() {
        let e = env(Some(DIST_SUM));
        let p = pins(&e);
        for (json, exit, expect) in [
            (Some(b"{not json".to_vec()), 0, "gradle-model-malformed"),
            (
                Some(br#"{"model":{"schemaVersion":1}}"#.to_vec()),
                0,
                "gradle-model-malformed",
            ),
            (Some(model_json(true)), 0, "gradle-model-self-attested"),
            (Some(model_json(false)), 1, "gradle-model-execution-failed"),
            (None, 0, "gradle-model-output-missing"),
        ] {
            let mock = Mock::new(json, exit);
            let gaps = run(&e, &mock, Some(&p), true).unwrap_err();
            assert!(
                gaps.iter().any(|g| g.contains(expect)),
                "{gaps:?} vs {expect}"
            );
            assert!(gap_plan(&gaps).obligations.is_empty());
        }
    }
}

mod adapter_without_owner {
    use super::*;
    use legion_audit::{
        native_providers::code::ProviderExecutorAdapter, AuditProvider, InventoryEnvelope,
        ProviderExecutor, ProviderKind,
    };

    fn provider(id: &str) -> AuditProvider {
        AuditProvider {
            id: id.into(),
            version: "1.0.0".into(),
            role: "diagnose".into(),
            phase: "p1".into(),
            lens_ids: Vec::new(),
            dependencies: Vec::new(),
            kind: ProviderKind::RustAlgorithm,
            configuration: BTreeMap::from([(
                "selector".into(),
                serde_json::json!({"op": "always"}),
            )]),
            bounds: BTreeMap::new(),
            clean_claim: "evidence-only".into(),
            benchmark_status: "unproven".into(),
            benchmark_required_for_clean_claim: false,
            qualification_digest: None,
            required: false,
        }
    }

    fn project_root() -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("legion-android-adapter-{}", std::process::id()));
        for path in PROJECT_FILES {
            let full = root.join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, fixture(&format!("project/{path}"))).unwrap();
        }
        root
    }

    #[test]
    fn no_owner_keeps_the_model_missing_gap_and_runs_nothing() {
        let root = project_root();
        let inventory = InventoryEnvelope::new("app", "generation", entries()).unwrap();
        let adapter = ProviderExecutorAdapter::new().with_root(&root);
        for id in ["code.android.lint", "code.kotlin.detekt-typed"] {
            let result = adapter.execute(&provider(id), &inventory).expect("result");
            assert!(!result.complete, "{id}");
            let gaps = result.coverage_gaps.join("\n");
            if id == "code.android.lint" {
                assert!(gaps.contains("android-model-missing"), "{gaps}");
                let produced = result.details.get("nativeProducer").unwrap();
                assert_eq!(produced["modelExtracted"], serde_json::json!(false));
                assert_eq!(produced["executed"], serde_json::json!(false));
            } else {
                assert!(gaps.contains("typed-classpath-missing"), "{gaps}");
            }
            assert!(!gaps.contains("gradle-"), "{gaps}");
        }
        let _ = fs::remove_dir_all(&root);
    }
}
