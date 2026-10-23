//! A06 acceptance coverage for Xcode/iOS target obligations. Authored, never
//! run by the packet worker; root executes. Requires root to add
//! `pub mod xcode_targets;` to `native_providers/code/mod.rs`.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use legion_audit::artifact_evidence::{
    CommandBinding, EvidenceOutcome, ImportKind, ImportedEvidenceRecord, ReplayPolicy,
    RepositoryBinding, RetainedArtifact,
};
use legion_audit::native_providers::code::xcode_targets::*;
use sha2::{Digest, Sha256};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/xcode-targets")
}

fn collect(dir: &Path, prefix: &str, out: &mut SnapshotFiles) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("dir")
        .map(|e| e.expect("entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if path.is_dir() {
            collect(&path, &relative, out);
        } else {
            out.insert(relative, fs::read(&path).expect("fixture"));
        }
    }
}

fn load(subdir: &str) -> SnapshotFiles {
    let mut files = SnapshotFiles::new();
    collect(&fixtures().join(subdir), "", &mut files);
    files
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn ios_obligation() -> XcodeObligation {
    XcodeObligation {
        id: "ios-app-tests".into(),
        container: "App/App.xcodeproj".into(),
        scheme: "App".into(),
        configuration: "Debug".into(),
        destination: DestinationSpec {
            platform: "iOS Simulator".into(),
            sdk: "iphonesimulator".into(),
            name: Some("iPhone 16".into()),
            os: Some("18.2".into()),
        },
        test_plan: Some("App".into()),
        required_concurrency: Some("complete".into()),
        require_entitlements: true,
        require_privacy_manifest: true,
    }
}

fn codes(gaps: &[Gap]) -> Vec<String> {
    gaps.iter().map(|g| g.code.clone()).collect()
}

fn has(gaps: &[Gap], code: &str) -> bool {
    gaps.iter().any(|g| g.code == code)
}

fn context() -> ExpectedContext {
    ExpectedContext {
        kind: ImportKind::Test,
        repositories: vec![RepositoryBinding {
            repository_id: "app".into(),
            revision: "a".repeat(40),
            branch: None,
            snapshot_digest: format!("sha256:{}", "1".repeat(64)),
        }],
        toolchain: "xcode-16.2/iphonesimulator18.2".into(),
        command: CommandBinding {
            adapter_id: "apple.project.test".into(),
            command_digest: format!("sha256:{}", "2".repeat(64)),
            executable_digest: None,
        },
        required_scope: vec!["App".into(), "AppTests".into()],
        replay_policy: ReplayPolicy::Deny,
        upstream_runtime: None,
    }
}

fn record_for(
    obligation: &XcodeObligation,
    summary: &[u8],
    target: Option<&str>,
) -> ImportedEvidenceRecord {
    ImportedEvidenceRecord {
        schema_version: 1,
        evidence_id: "ev-1".into(),
        claims_digest: format!("sha256:{}", "3".repeat(64)),
        kind: ImportKind::Test,
        authenticated: true,
        attestor: "ci".into(),
        trust_root_id: "root".into(),
        verifier_id: "v".into(),
        outcome: EvidenceOutcome::Passed,
        repositories: context().repositories,
        target: target
            .map(str::to_string)
            .unwrap_or_else(|| obligation.evidence_target()),
        variant: Some(obligation.evidence_variant()),
        toolchain: context().toolchain,
        upstream_runtime: None,
        artifacts: vec![
            RetainedArtifact {
                path: "results/App.xcresult.zip".into(),
                digest: format!("sha256:{}", "4".repeat(64)),
                bytes: 10,
                role: ROLE_XCRESULT.into(),
                immutable: true,
            },
            RetainedArtifact {
                path: "results/summary.json".into(),
                digest: sha(summary),
                bytes: summary.len() as u64,
                role: ROLE_TEST_SUMMARY.into(),
                immutable: true,
            },
        ],
        artifact_digest: format!("sha256:{}", "4".repeat(64)),
        denominator_digest: format!("sha256:{}", "5".repeat(64)),
        examined_scope: vec!["App".into(), "AppTests".into()],
        missing_scope: vec![],
        newly_executed: true,
        replay_of: None,
        issued_at: "2026-10-23T00:00:00Z".into(),
        fresh_until: "2026-12-31T00:00:00Z".into(),
    }
}

fn raw(summary: &[u8]) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([("results/summary.json".to_string(), summary.to_vec())])
}

fn summary_bytes(name: &str) -> Vec<u8> {
    fs::read(fixtures().join("diagnostics").join(name)).expect("summary")
}

fn replace_in(files: &mut SnapshotFiles, path: &str, from: &str, to: &str) {
    let text = String::from_utf8(files.get(path).expect("path").clone()).unwrap();
    assert!(text.contains(from), "fixture lacks {from}");
    files.insert(path.to_string(), text.replace(from, to).into_bytes());
}

const PBX: &str = "App/App.xcodeproj/project.pbxproj";

#[test]
fn inventory_binds_project_scheme_plan_settings_and_packages() {
    let files = load("ios-app");
    let inventory = inventory_xcode(&files);
    assert!(inventory.issues.is_empty(), "{:?}", inventory.issues);
    let project = &inventory.projects[0];
    assert_eq!(project.path, "App/App.xcodeproj");
    assert_eq!(project.configurations, vec!["Debug", "Release"]);
    let app = project.targets.iter().find(|t| t.name == "App").unwrap();
    assert!(app.is_app && app.membership_exact);
    assert_eq!(
        app.source_files,
        vec!["App/App/AppMain.swift", "App/App/Isolated.swift"]
    );
    assert_eq!(app.settings["Debug"]["IPHONEOS_DEPLOYMENT_TARGET"], "17.0");
    assert_eq!(effective_concurrency(&app.settings["Debug"]), "complete");
    assert!(project.unreferenced_swift_sources.is_empty());
    let scheme = &inventory.schemes[0];
    assert!(scheme.shared);
    assert_eq!(scheme.test_configuration.as_deref(), Some("Debug"));
    assert_eq!(
        scheme.test_plans,
        vec![("container:App.xctestplan".to_string(), true)]
    );
    assert_eq!(inventory.test_plans[0].test_targets, vec!["AppTests"]);
    assert_eq!(inventory.package_resolved[0].pins.len(), 1);
}

#[test]
fn bound_inputs_are_unmet_until_execution_evidence_exists() {
    let files = load("ios-app");
    let inventory = inventory_xcode(&files);
    let coverage = evaluate_static(&inventory, &files, &ios_obligation());
    assert!(coverage.gaps.is_empty(), "{:?}", coverage.gaps);
    assert!(coverage.config_digest.is_some() && coverage.test_selection_digest.is_some());
    assert!(coverage
        .bound_inputs
        .contains_key("App/App/App.entitlements"));
    assert!(coverage
        .bound_inputs
        .contains_key("App/App/PrivacyInfo.xcprivacy"));
    let report = analyze_targets(&files, &[ios_obligation()]);
    assert_eq!(report["status"], "inventoried");
    assert_eq!(report["obligations"][0]["status"], "unmet");
}

#[test]
fn macos_swiftpm_pass_leaves_ios_scheme_obligation_unmet() {
    let files = load("ios-app");
    let obligation = ios_obligation();
    let coverage = evaluate_static(&inventory_xcode(&files), &files, &obligation);
    let expected = expected_evidence(&obligation, &coverage, &context()).expect("expected");
    let summary = summary_bytes("xcresult-summary-macos.json");
    let mut record = record_for(&obligation, &summary, Some("swiftpm:Tool"));
    record.variant = Some("debug|macosx".into());
    let gaps = link_evidence(
        &obligation,
        &expected,
        &record,
        &raw(&summary),
        "2026-10-24T00:00:00Z",
    );
    assert!(
        has(&gaps, "swiftpm-evidence-cannot-discharge-xcode-scheme"),
        "{:?}",
        codes(&gaps)
    );
    assert!(has(&gaps, "evidence-target-mismatch"));
    assert!(has(&gaps, "evidence-variant-mismatch"));
    assert!(has(&gaps, "wrong-destination-evidence"));

    // The SwiftPM package itself inventories no Xcode container at all.
    let swiftpm = load("macos-swiftpm");
    let coverage = evaluate_static(&inventory_xcode(&swiftpm), &swiftpm, &obligation);
    assert!(has(&coverage.gaps, "container-missing"));
}

#[test]
fn wrong_sdk_destination_test_plan_or_missing_entitlements_cannot_satisfy() {
    let base = load("ios-app");
    let obligation = ios_obligation();

    // Wrong SDK: project only supports macOS.
    let mut files = base.clone();
    replace_in(&mut files, PBX, "SDKROOT = iphoneos;", "SDKROOT = macosx;");
    let gaps = evaluate_static(&inventory_xcode(&files), &files, &obligation).gaps;
    assert!(has(&gaps, "target-sdk-mismatch"), "{:?}", codes(&gaps));

    // Wrong destination OS below the deployment target.
    let mut wrong_os = obligation.clone();
    wrong_os.destination.os = Some("16.0".into());
    let gaps = evaluate_static(&inventory_xcode(&base), &base, &wrong_os).gaps;
    assert!(has(&gaps, "deployment-target-above-destination"));

    // Wrong or absent test plan selection.
    let mut other_plan = obligation.clone();
    other_plan.test_plan = Some("Nightly".into());
    let gaps = evaluate_static(&inventory_xcode(&base), &base, &other_plan).gaps;
    assert!(has(&gaps, "test-plan-not-in-scheme") && has(&gaps, "test-plan-missing"));
    let mut no_plan = obligation.clone();
    no_plan.test_plan = None;
    let gaps = evaluate_static(&inventory_xcode(&base), &base, &no_plan).gaps;
    assert!(has(&gaps, "test-plan-unspecified"));

    // Wrong configuration versus the scheme's test action.
    let mut release = obligation.clone();
    release.configuration = "Release".into();
    let gaps = evaluate_static(&inventory_xcode(&base), &base, &release).gaps;
    assert!(has(&gaps, "scheme-configuration-mismatch"));

    // Missing entitlements / privacy manifest inputs.
    let mut files = base.clone();
    files.remove("App/App/App.entitlements");
    files.remove("App/App/PrivacyInfo.xcprivacy");
    let gaps = evaluate_static(&inventory_xcode(&files), &files, &obligation).gaps;
    assert!(has(&gaps, "entitlements-input-missing"));
    assert!(has(&gaps, "privacy-manifest-missing"));
    assert!(expected_evidence(
        &obligation,
        &evaluate_static(&inventory_xcode(&files), &files, &obligation),
        &context()
    )
    .is_err());

    // Concurrency mode weaker than required.
    let mut files = base.clone();
    replace_in(
        &mut files,
        PBX,
        "SWIFT_STRICT_CONCURRENCY = complete;",
        "SWIFT_STRICT_CONCURRENCY = minimal;",
    );
    let gaps = evaluate_static(&inventory_xcode(&files), &files, &obligation).gaps;
    assert!(has(&gaps, "concurrency-mode-mismatch"));
}

#[test]
fn unsupported_destination_is_explicit() {
    let files = load("ios-app");
    let mut obligation = ios_obligation();
    obligation.destination = DestinationSpec {
        platform: "watchOS Simulator".into(),
        sdk: "watchsimulator".into(),
        name: None,
        os: None,
    };
    let gaps = evaluate_static(&inventory_xcode(&files), &files, &obligation).gaps;
    assert!(has(&gaps, "unsupported-destination"));
    let mut device = ios_obligation();
    device.destination.platform = "iOS".into();
    device.destination.sdk = "iphoneos".into();
    assert!(has(
        &evaluate_static(&inventory_xcode(&files), &files, &device).gaps,
        "unsupported-destination"
    ));
}

#[test]
fn strict_concurrency_finding_and_clean_actor_control_keep_context() {
    let context = |mode: &str| DiagnosticContext {
        scheme: "App".into(),
        configuration: "Debug".into(),
        sdk: "iphonesimulator".into(),
        concurrency_mode: mode.into(),
    };
    let finding_text =
        fs::read_to_string(fixtures().join("diagnostics/strict-concurrency.txt")).unwrap();
    let report = parse_swift_diagnostics(&finding_text, "/build/src", context("complete"));
    assert_eq!(report.status, "concurrency-findings");
    assert_eq!(report.concurrency_findings, 2);
    assert_eq!(report.findings.len(), 3);
    assert_eq!(report.outside_source_root, 1);
    assert_eq!(report.findings[0].path, "App/App/Isolated.swift");
    assert_eq!(
        report.findings[0].category.as_deref(),
        Some("ActorIsolation")
    );
    assert!(!report.findings[2].concurrency);
    assert_eq!(report.context.sdk, "iphonesimulator");

    let clean_text =
        fs::read_to_string(fixtures().join("diagnostics/clean-actor-isolation.txt")).unwrap();
    let clean = parse_swift_diagnostics(&clean_text, "/build/src", context("complete"));
    assert_eq!(clean.status, "no-concurrency-findings-observed");
    assert!(clean.absence_is_evidence);
    let weak = parse_swift_diagnostics(&clean_text, "/build/src", context("minimal"));
    assert_eq!(weak.status, "no-evidence-concurrency-not-complete");
    assert!(!weak.absence_is_evidence);
}

#[test]
fn valid_xcresult_envelope_links_tests_to_exact_scheme_and_artifact() {
    let files = load("ios-app");
    let obligation = ios_obligation();
    let coverage = evaluate_static(&inventory_xcode(&files), &files, &obligation);
    let expected = expected_evidence(&obligation, &coverage, &context()).expect("expected");
    assert_eq!(expected.target, "xcode:App/App.xcodeproj#App");
    let summary = summary_bytes("xcresult-summary-ios-sim.json");
    let record = record_for(&obligation, &summary, None);
    let now = "2026-10-24T00:00:00Z";
    assert!(link_evidence(&obligation, &expected, &record, &raw(&summary), now).is_empty());

    // Summary bytes that differ from the retained digest do not link.
    let tampered = summary_bytes("xcresult-summary-macos.json");
    let gaps = link_evidence(&obligation, &expected, &record, &raw(&tampered), now);
    assert!(has(&gaps, "xcresult-summary-digest-mismatch"));
    assert!(has(&gaps, "wrong-destination-evidence"));

    // Missing summary or xcresult artifact never links.
    let gaps = link_evidence(&obligation, &expected, &record, &BTreeMap::new(), now);
    assert!(has(&gaps, "xcresult-summary-missing"));

    // Stale evidence is a gap, not a pass.
    let gaps = link_evidence(
        &obligation,
        &expected,
        &record,
        &raw(&summary),
        "2027-01-01T00:00:00Z",
    );
    assert!(has(&gaps, "evidence-stale"));
}

#[test]
fn unconfigured_bridge_leaves_obligation_unmet_with_explicit_gap() {
    let files = load("ios-app");
    let obligation = ios_obligation();
    let coverage = evaluate_static(&inventory_xcode(&files), &files, &obligation);
    let request = request_for(&obligation, AppleOperation::Test);
    assert_eq!(request.code_signing, CodeSigningPosture::Disabled);
    let gap = UnconfiguredAppleBridge
        .execute(&request)
        .err()
        .expect("gap");
    assert_eq!(gap.code, "apple-bridge-unconfigured");
    assert!(coverage.gaps.is_empty());
}

#[test]
fn swiftlint_requires_exact_pin_and_periphery_stays_candidate() {
    let lint = fs::read(fixtures().join("diagnostics/swiftlint.json")).unwrap();
    let pin = SwiftLintPin {
        version: "0.57.0".into(),
        executable_digest: format!("sha256:{}", "a".repeat(64)),
        config_digest: format!("sha256:{}", "b".repeat(64)),
    };
    let run = SwiftLintRun {
        version: pin.version.clone(),
        executable_digest: pin.executable_digest.clone(),
        config_digest: pin.config_digest.clone(),
    };
    let report = parse_swiftlint_json(&lint, "/build/src", &run, &pin).unwrap();
    assert!(report.qualified);
    assert_eq!(report.status, "findings");
    assert_eq!(report.findings[0].path, "App/App/AppMain.swift");
    let mut drifted = run.clone();
    drifted.version = "0.58.0".into();
    let report = parse_swiftlint_json(b"[]", "/build/src", &drifted, &pin).unwrap();
    assert_eq!(report.status, "unqualified");
    assert!(has(&report.gaps, "swiftlint-version-unpinned"));

    let periphery = fs::read(fixtures().join("diagnostics/periphery.json")).unwrap();
    let bare = PeripheryContext {
        scheme: "App".into(),
        variant: ios_obligation().evidence_variant(),
        index_store_digest: None,
        build_evidence_id: None,
    };
    let report = parse_periphery_json(&periphery, "/build/src", &bare).unwrap();
    assert!(!report.qualified);
    assert_eq!(report.status, "unqualified-candidates");
    assert_eq!(report.candidates[0].confidence, "candidate");
    assert_eq!(report.candidates[0].path, "App/App/Isolated.swift");
    assert_eq!(report.candidates[0].line, 9);
    let indexed = PeripheryContext {
        index_store_digest: Some(format!("sha256:{}", "c".repeat(64))),
        build_evidence_id: Some("ev-1".into()),
        ..bare
    };
    let report = parse_periphery_json(b"[]", "/build/src", &indexed).unwrap();
    assert_eq!(report.status, "no-candidates-in-qualified-run");
}
