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

// ---------------------------------------------------------------------------
// Owner-backed Apple bridge
// ---------------------------------------------------------------------------

use legion_audit::native_providers::code::xcode_bridge::OwnedXcodeBridge;

fn request_with(obligation: &XcodeObligation, operation: AppleOperation) -> AppleOperationRequest {
    request_for(obligation, operation)
}

fn valid_argv(request: &AppleOperationRequest, out: &Path) -> Vec<String> {
    xcodebuild_argv(
        request,
        Path::new("/frozen/App/App.xcodeproj"),
        &out.join("r.xcresult"),
        &out.join("DerivedData"),
    )
    .expect("argv")
}

#[test]
fn bridge_argv_is_build_or_test_only_with_signing_disabled() {
    let obligation = ios_obligation();
    let out = Path::new("/owner/out");
    let request = request_with(&obligation, AppleOperation::Test);
    let argv = valid_argv(&request, out);
    assert!(validate_xcodebuild_argv(&request, &argv, out).is_ok());
    assert!(argv.iter().any(|a| a == "CODE_SIGNING_ALLOWED=NO"));
    assert!(argv.iter().any(|a| a == "CODE_SIGN_IDENTITY="));
    let destination = argv
        .iter()
        .position(|a| a == "-destination")
        .map(|i| argv[i + 1].clone())
        .unwrap();
    assert_eq!(destination, "platform=iOS Simulator,name=iPhone 16,OS=18.2");

    // archive / export / install are not build|test.
    for forbidden in ["archive", "exportArchive", "install", "-exportArchive"] {
        let mut bad = argv.clone();
        bad[0] = forbidden.into();
        let gap = validate_xcodebuild_argv(&request, &bad, out).expect_err(forbidden);
        assert!(
            gap.code == "xcodebuild-argument-not-allowed"
                || gap.code == "xcodebuild-action-mismatch",
            "{forbidden}: {}",
            gap.code
        );
    }
    let mut extra = argv.clone();
    extra.push("archive".into());
    assert!(validate_xcodebuild_argv(&request, &extra, out).is_err());

    // Signing enabled or provisioning requested.
    for signing in [
        "CODE_SIGNING_ALLOWED=YES",
        "CODE_SIGN_IDENTITY=Apple Development",
        "-allowProvisioningUpdates",
        "PROVISIONING_PROFILE_SPECIFIER=x",
    ] {
        let mut bad: Vec<String> = argv
            .iter()
            .filter(|a| *a != "CODE_SIGNING_ALLOWED=NO")
            .cloned()
            .collect();
        bad.push(signing.into());
        assert!(
            validate_xcodebuild_argv(&request, &bad, out).is_err(),
            "{signing}"
        );
    }
    let mut unsigned_missing = argv.clone();
    unsigned_missing.retain(|a| a != "CODE_SIGN_IDENTITY=");
    assert_eq!(
        validate_xcodebuild_argv(&request, &unsigned_missing, out)
            .unwrap_err()
            .code,
        "signing-not-disabled"
    );

    // Destination must be exactly the obligation's.
    let mut wrong = argv.clone();
    let index = wrong.iter().position(|a| a == "-destination").unwrap() + 1;
    wrong[index] = "platform=iOS Simulator,name=iPhone 15,OS=18.2".into();
    assert_eq!(
        validate_xcodebuild_argv(&request, &wrong, out)
            .unwrap_err()
            .code,
        "destination-mismatch"
    );
    wrong[index] = format!("{destination},id=SMUGGLED");
    assert_eq!(
        validate_xcodebuild_argv(&request, &wrong, out)
            .unwrap_err()
            .code,
        "destination-mismatch"
    );

    // Outputs must stay inside the owner output root.
    let escaping = xcodebuild_argv(
        &request,
        Path::new("/frozen/App/App.xcodeproj"),
        Path::new("/elsewhere/r.xcresult"),
        &out.join("DerivedData"),
    )
    .unwrap();
    assert_eq!(
        validate_xcodebuild_argv(&request, &escaping, out)
            .unwrap_err()
            .code,
        "output-outside-owner-root"
    );

    // Unsupported or free-form destinations never produce an argv.
    let mut device = ios_obligation();
    device.destination.platform = "iOS".into();
    device.destination.sdk = "iphoneos".into();
    assert!(xcodebuild_argv(
        &request_with(&device, AppleOperation::Build),
        Path::new("/frozen/App/App.xcodeproj"),
        &out.join("r.xcresult"),
        &out.join("DerivedData"),
    )
    .is_err());
    let mut injected = ios_obligation();
    injected.destination.name = Some("iPhone 16,id=X".into());
    assert!(destination_string(&injected.destination).is_err());
}

#[test]
fn no_owner_means_unconfigured_gap_and_unmet_obligation() {
    let files = load("ios-app");
    let obligation = ios_obligation();
    let coverage = evaluate_static(&inventory_xcode(&files), &files, &obligation);
    let bridge = UnconfiguredAppleBridge;
    let request = request_with(&obligation, AppleOperation::Test);
    assert_eq!(
        bridge.execute(&request).err().expect("gap").code,
        "apple-bridge-unconfigured"
    );
    let outcome = discharge_via_bridge(
        &bridge,
        &obligation,
        &coverage,
        &context(),
        &legion_audit::artifact_evidence::TrustEnrollment {
            schema_version: 1,
            issuers: vec![],
        },
        &legion_audit::artifact_evidence::UnconfiguredVerifier,
        "2026-10-24T00:00:00Z",
    );
    assert_eq!(outcome.status, "unmet");
    assert!(has(&outcome.gaps, "apple-bridge-unconfigured"));
    assert!(outcome.evidence_basis.is_none());
}

fn host_binding() -> HostEvidenceBinding {
    HostEvidenceBinding {
        repositories: vec![RepositoryBinding {
            repository_id: "app".into(),
            revision: "generation-1".into(),
            branch: None,
            snapshot_digest: format!("sha256:{}", "7".repeat(64)),
        }],
        xcodebuild_version: "xcode-16.2".into(),
        xcodebuild_digest: format!("sha256:{}", "9".repeat(64)),
    }
}

#[test]
fn host_derived_context_is_deterministic_and_command_bound() {
    let files = load("ios-app");
    let obligation = ios_obligation();
    let coverage = evaluate_static(&inventory_xcode(&files), &files, &obligation);
    let first = host_expected_context(&obligation, &coverage, &host_binding()).expect("context");
    let second = host_expected_context(&obligation, &coverage, &host_binding()).expect("context");
    assert_eq!(first, second);
    assert_eq!(first.toolchain, "xcode-16.2/iphonesimulator18.2");
    assert_eq!(first.command.adapter_id, ADAPTER_ID_TEST);
    assert_eq!(
        first.command.command_digest,
        canonical_command_digest(&request_for(&obligation, AppleOperation::Test)).unwrap()
    );
    assert_eq!(
        first.command.executable_digest.as_deref(),
        Some(host_binding().xcodebuild_digest.as_str())
    );
    assert_eq!(first.replay_policy, ReplayPolicy::Deny);
    assert_eq!(first.repositories, host_binding().repositories);
    assert!(!first.required_scope.is_empty());
    // A different scheme changes the bound command.
    let mut other = ios_obligation();
    other.scheme = "Other".into();
    assert_ne!(
        canonical_command_digest(&request_for(&other, AppleOperation::Test)).unwrap(),
        first.command.command_digest
    );
}

#[test]
fn executed_command_digest_normalises_paths_and_binds_everything_else() {
    let obligation = ios_obligation();
    let request = request_with(&obligation, AppleOperation::Test);
    let canonical = canonical_command_digest(&request).unwrap();
    let argv = valid_argv(&request, Path::new("/scratch/run-1"));
    assert_eq!(
        executed_command_digest(&request, &argv).as_deref(),
        Some(canonical.as_str())
    );
    // Output location is run-specific and does not change the digest.
    let moved = valid_argv(&request, Path::new("/scratch/run-2"));
    assert_eq!(
        executed_command_digest(&request, &moved),
        Some(canonical.clone())
    );
    // Any other argument change does.
    let mut changed = argv.clone();
    for arg in &mut changed {
        if arg == "Debug" {
            *arg = "Release".into();
        }
    }
    assert_ne!(executed_command_digest(&request, &changed), Some(canonical));
    // A dangling value flag is not a digest.
    assert_eq!(
        executed_command_digest(&request, &["test".into(), "-resultBundlePath".into()]),
        None
    );
}

#[test]
fn adapter_without_owner_ignores_supplied_context_and_stays_unconfigured() {
    use legion_audit::{
        native_providers::code::ProviderExecutorAdapter, AuditProvider, InventoryEntry,
        InventoryEnvelope, ProviderExecutor, ProviderKind,
    };
    let files = load("ios-app");
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("legion-xcode-adapter-{}", std::process::id()));
    let mut entries = Vec::new();
    for (path, bytes) in &files {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(&full, bytes).unwrap();
        entries.push(InventoryEntry {
            path: path.clone(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: false,
            digest: Some(sha(bytes)),
        });
    }
    let inventory = InventoryEnvelope::new("app", "generation", entries).unwrap();
    let provider = AuditProvider {
        id: "code.apple.targets".into(),
        version: "1.0.0".into(),
        role: "diagnose".into(),
        phase: "p1".into(),
        lens_ids: Vec::new(),
        dependencies: Vec::new(),
        kind: ProviderKind::RustAlgorithm,
        configuration: BTreeMap::from([("selector".into(), serde_json::json!({"op": "always"}))]),
        bounds: BTreeMap::new(),
        clean_claim: "evidence-only".into(),
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: false,
    };
    // Repository-style input trying to supply its own evidence context.
    let input = serde_json::json!({
        "xcodeObligations": [ios_obligation()],
        "xcodeEvidenceContext": context(),
    });
    let result = ProviderExecutorAdapter::new()
        .with_root(&root)
        .with_input("code.apple.targets", input)
        .execute(&provider, &inventory)
        .expect("result");
    assert!(!result.complete);
    let gaps = result.coverage_gaps.join("\n");
    assert!(
        gaps.contains("input-ignored:xcodeEvidenceContext"),
        "{gaps}"
    );
    assert!(gaps.contains("obligation-unmet:ios-app-tests"), "{gaps}");
    let executed = result
        .details
        .get("nativeProducer")
        .and_then(|value| value.get("executed"))
        .and_then(serde_json::Value::as_bool);
    assert_eq!(executed, Some(false));
    let _ = fs::remove_dir_all(&root);
}

#[cfg(target_os = "macos")]
mod owned_bridge {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
    };

    use legion_audit::{
        host_owner::{HostPolicyOwner, OWNER_ID, POLICY_FILE},
        owner_admission::{NativeAuthorizer, PlanBinding},
        profiles::RuntimeConstraint,
    };
    use legion_effects::{
        owner_process::{ContainedRuntime, ContainmentProfile, InvocationClass, OwnerProcess},
        platform::{ProcessFuture, ProcessLaunch, ProcessOutput},
        receipt::ProcessTreeEvidence,
        ArtifactWriter, EffectExecutor,
    };

    const XCODEBUILD: &str = "/usr/bin/xcodebuild";
    const XCRUN: &str = "/usr/bin/xcrun";
    const PROVIDER: &str = "code.apple.targets";
    const PLAN: &str = "sha256:frozen-xcode-plan";

    type Launches = Arc<Mutex<Vec<(String, Vec<String>)>>>;

    struct MockRuntime {
        summary: Vec<u8>,
        build_exit: i32,
        launches: Launches,
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    impl ContainedRuntime for MockRuntime {
        fn owner_id(&self) -> &str {
            OWNER_ID
        }

        fn run_contained<'a>(
            &'a self,
            launch: ProcessLaunch,
            _profile: &'a ContainmentProfile,
        ) -> ProcessFuture<'a> {
            Box::pin(async move {
                self.launches
                    .lock()
                    .unwrap()
                    .push((launch.executable.clone(), launch.args.clone()));
                let mut stdout = Vec::new();
                let mut exit = 0;
                if launch.args.first().map(String::as_str) == Some("xcresulttool") {
                    stdout = self.summary.clone();
                } else {
                    exit = self.build_exit;
                    let at = launch
                        .args
                        .iter()
                        .position(|a| a == "-resultBundlePath")
                        .expect("result bundle arg");
                    let bundle = PathBuf::from(&launch.args[at + 1]);
                    fs::create_dir_all(&bundle).unwrap();
                    fs::write(bundle.join("Info.plist"), b"fixture-xcresult").unwrap();
                }
                let started = now_ms();
                Ok(ProcessOutput {
                    stdout,
                    stderr: Vec::new(),
                    exit_code: Some(exit),
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
                    started_at_ms: started,
                    completed_at_ms: started + 1,
                })
            })
        }
    }

    struct Rig {
        bridge: OwnedXcodeBridge,
        launches: Launches,
    }

    fn sha256_file(path: &str) -> String {
        sha(&fs::read(path).expect("tool"))
    }

    fn rig(pin_xcrun: bool, build_exit: i32, summary: Vec<u8>) -> Rig {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "legion-xcode-bridge-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
        let (frozen, out, artifacts, state) = (
            base.join("frozen"),
            base.join("out"),
            base.join("artifacts"),
            base.join("state"),
        );
        for dir in [&frozen, &out, &artifacts, &state] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::create_dir_all(frozen.join("App/App.xcodeproj")).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let mut tools = vec![serde_json::json!({
            "providers": [PROVIDER], "executable": XCODEBUILD,
            "sha256": sha256_file(XCODEBUILD), "class": "project-executing",
            "environmentNames": [], "version": "xcode-16.2"
        })];
        if pin_xcrun {
            tools.push(serde_json::json!({
                "providers": [PROVIDER], "executable": XCRUN,
                "sha256": sha256_file(XCRUN), "class": "project-executing",
                "environmentNames": []
            }));
        }
        let policy_path = state.join(POLICY_FILE);
        fs::write(
            &policy_path,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 1, "policyRevision": "xcode-r1", "tools": tools
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();
        let owner = HostPolicyOwner::load(&policy_path, &[frozen.clone(), out.clone()])
            .unwrap()
            .unwrap();
        let cfg = owner
            .owner_config_bound(PlanBinding::unbound(), &frozen, &out)
            .unwrap()
            .with_runtime_constraint(RuntimeConstraint::Unrestricted);
        let ctx = owner.request_context(&cfg);
        let executables = [XCODEBUILD, XCRUN].iter().map(PathBuf::from).collect();
        let profile =
            cfg.containment_profile(OWNER_ID, InvocationClass::ProjectExecuting, executables);
        let launches: Launches = Arc::new(Mutex::new(Vec::new()));
        let process = OwnerProcess::new(
            MockRuntime {
                summary,
                build_exit,
                launches: launches.clone(),
            },
            profile,
        )
        .expect("owner process");
        let authorizer = NativeAuthorizer::resolve(Some(owner.into_trusted()), Some(cfg));
        assert!(authorizer.is_owner_backed());
        let tool = EffectExecutor::new(process, ArtifactWriter::new(artifacts.clone()), authorizer);
        let bridge = OwnedXcodeBridge::new(
            Arc::new(tool),
            Arc::new(ctx),
            PLAN,
            &frozen,
            &out,
            &artifacts,
        )
        .expect("bridge");
        Rig { bridge, launches }
    }

    /// Context derived on the host (policy xcodebuild pin + canonical command),
    /// exactly as the producer does it.
    fn host_context(
        bridge: &dyn AppleTargetBridge,
        obligation: &XcodeObligation,
    ) -> ExpectedContext {
        let files = load("ios-app");
        let coverage = evaluate_static(&inventory_xcode(&files), &files, obligation);
        let (version, digest) = bridge.host_binding().expect("host pin");
        let mut binding = super::host_binding();
        binding.xcodebuild_version = version;
        binding.xcodebuild_digest = digest;
        host_expected_context(obligation, &coverage, &binding).expect("context")
    }

    fn discharge(
        bridge: &dyn AppleTargetBridge,
        obligation: &XcodeObligation,
        now: &str,
    ) -> ObligationOutcome {
        discharge_with(bridge, obligation, &host_context(bridge, obligation), now)
    }

    fn discharge_with(
        bridge: &dyn AppleTargetBridge,
        obligation: &XcodeObligation,
        context: &ExpectedContext,
        now: &str,
    ) -> ObligationOutcome {
        let files = load("ios-app");
        let coverage = evaluate_static(&inventory_xcode(&files), &files, obligation);
        discharge_via_bridge(
            bridge,
            obligation,
            &coverage,
            context,
            &legion_audit::artifact_evidence::TrustEnrollment {
                schema_version: 1,
                issuers: vec![],
            },
            &legion_audit::artifact_evidence::UnconfiguredVerifier,
            now,
        )
    }

    fn now_utc() -> String {
        legion_audit::p12_pipeline::store::utc_now()
    }

    #[test]
    fn mocked_contained_runtime_with_fixture_xcresult_satisfies_linkage() {
        let rig = rig(true, 0, summary_bytes("xcresult-summary-ios-sim.json"));
        let obligation = ios_obligation();
        let outcome = discharge(&rig.bridge, &obligation, &now_utc());
        assert_eq!(outcome.status, "satisfied", "{:?}", outcome.gaps);
        assert!(outcome.newly_executed);
        assert_eq!(outcome.evidence_basis.as_deref(), Some("host-executed"));
        let digest = outcome.owner_receipt_digest.expect("owner receipt digest");
        assert!(digest.starts_with("sha256:"));
        assert!(outcome.evidence_id.unwrap().contains(&digest));

        let launches = rig.launches.lock().unwrap();
        assert_eq!(launches.len(), 2, "exactly xcodebuild then xcresulttool");
        assert_eq!(launches[0].0, XCODEBUILD);
        assert_eq!(launches[0].1[0], "test");
        assert!(launches[0].1.iter().any(|a| a == "CODE_SIGNING_ALLOWED=NO"));
        assert_eq!(launches[1].0, XCRUN);
        assert_eq!(&launches[1].1[..2], ["xcresulttool", "get"]);
    }

    #[test]
    fn command_digest_mismatch_is_unmet() {
        let rig = rig(true, 0, summary_bytes("xcresult-summary-ios-sim.json"));
        let obligation = ios_obligation();
        // Repository-supplied style context: toolchain right, command digest
        // arbitrary. The host-executed argv digest must not match it.
        let mut supplied = host_context(&rig.bridge, &obligation);
        supplied.command.command_digest = format!("sha256:{}", "2".repeat(64));
        let outcome = discharge_with(&rig.bridge, &obligation, &supplied, &now_utc());
        assert_eq!(outcome.status, "unmet");
        assert!(
            has(&outcome.gaps, "command-digest-mismatch"),
            "{:?}",
            outcome.gaps
        );
        assert!(outcome.evidence_basis.is_none());
    }

    #[test]
    fn failing_test_run_is_unmet_not_satisfied() {
        let failing = String::from_utf8(summary_bytes("xcresult-summary-ios-sim.json"))
            .unwrap()
            .replace("\"Passed\"", "\"Failed\"")
            .replace("\"passed\"", "\"failed\"");
        let rig = rig(true, 65, failing.into_bytes());
        let outcome = discharge(&rig.bridge, &ios_obligation(), &now_utc());
        assert_eq!(outcome.status, "unmet");
        assert!(has(&outcome.gaps, "evidence-outcome-not-passed"));
    }

    #[test]
    fn missing_pin_or_unadmitted_xcode_path_is_a_gap_and_nothing_runs() {
        // xcresulttool not pinned: owner-policy gap before any process starts.
        let rig = rig(false, 0, summary_bytes("xcresult-summary-ios-sim.json"));
        let outcome = discharge(&rig.bridge, &ios_obligation(), &now_utc());
        assert_eq!(outcome.status, "unmet");
        assert!(has(&outcome.gaps, "owner-policy-missing-tool"));
        assert!(rig.launches.lock().unwrap().is_empty());

        // A path that is neither /usr/bin/xcodebuild nor an Xcode.app one.
        let other = self::rig(true, 0, Vec::new());
        assert_eq!(
            other
                .bridge
                .with_xcodebuild("/tmp/evil/xcodebuild")
                .err()
                .unwrap()
                .code,
            "xcodebuild-path-not-admitted"
        );
    }

    #[test]
    fn selected_xcode_not_in_host_policy_is_refused_by_owner_policy() {
        let rig = rig(true, 0, summary_bytes("xcresult-summary-ios-sim.json"));
        let launches = rig.launches.clone();
        // The evidence context is derived from the host's pinned xcodebuild;
        // the selected (unpinned) Xcode has no host pin of its own.
        let context = host_context(&rig.bridge, &ios_obligation());
        let selected = rig
            .bridge
            .with_xcodebuild("/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild")
            .expect("shape admitted");
        let outcome = discharge_with(&selected, &ios_obligation(), &context, &now_utc());
        assert_eq!(outcome.status, "unmet");
        assert!(has(&outcome.gaps, "owner-policy-missing-tool"));
        assert!(launches.lock().unwrap().is_empty());
    }

    struct Tampering<'a> {
        inner: &'a OwnedXcodeBridge,
        mutate: fn(&mut HostExecutionReceipt),
    }

    impl AppleTargetBridge for Tampering<'_> {
        fn bridge_id(&self) -> &str {
            "tampering"
        }
        fn host_binding(&self) -> Option<(String, String)> {
            self.inner.host_binding()
        }
        fn execute(&self, request: &AppleOperationRequest) -> Result<AppleBridgeResult, Gap> {
            match self.inner.execute(request)? {
                AppleBridgeResult::HostExecuted(mut host) => {
                    (self.mutate)(&mut host.receipt);
                    Ok(AppleBridgeResult::HostExecuted(host))
                }
                other => Ok(other),
            }
        }
    }

    #[test]
    fn host_receipt_tampering_never_satisfies() {
        let rig = rig(true, 0, summary_bytes("xcresult-summary-ios-sim.json"));
        let obligation = ios_obligation();
        let signing_on = Tampering {
            inner: &rig.bridge,
            mutate: |receipt| {
                for arg in &mut receipt.args {
                    if arg == "CODE_SIGNING_ALLOWED=NO" {
                        *arg = "CODE_SIGNING_ALLOWED=YES".into();
                    }
                }
            },
        };
        let outcome = discharge(&signing_on, &obligation, &now_utc());
        assert_eq!(outcome.status, "unmet");
        assert!(has(&outcome.gaps, "host-receipt-digest-mismatch"));
        assert!(has(&outcome.gaps, "signing-enabled"));

        let wrong_destination = Tampering {
            inner: &rig.bridge,
            mutate: |receipt| receipt.variant = "Debug|macOS|macosx|-|-|-".into(),
        };
        let outcome = discharge(&wrong_destination, &obligation, &now_utc());
        assert_eq!(outcome.status, "unmet");
        assert!(has(&outcome.gaps, "host-receipt-binding-mismatch"));

        let imported_basis = Tampering {
            inner: &rig.bridge,
            mutate: |receipt| receipt.basis = "imported-attestation".into(),
        };
        assert_eq!(
            discharge(&imported_basis, &obligation, &now_utc()).status,
            "unmet"
        );
    }
}
