//! Rust port of `tests/windows-release-qualification.test.mjs`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

use super::lifecycle::{qualify_windows_release, QualifyWindowsOptions};
use super::tree::{CommandOptions, CommandOutcome};
use crate::windows_release_support::{sha256_hex, sha256_prefixed};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("legion-win-qualification-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
    fs::create_dir_all(&dir).expect("create temp root");
    dir
}

fn write_fixture(root: &Path, version: &str, marker: &str) {
    let bin = root.join("bin");
    let share = root.join("share").join("legion");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&share).unwrap();
    let runtime = format!("fixture legion {version} {marker}\n").into_bytes();
    let runtime_digest = sha256_prefixed(&runtime);
    let generation = format!("{version}:{}", &runtime_digest["sha256:".len()..]);
    fs::write(bin.join("legion.exe"), &runtime).unwrap();
    fs::write(bin.join("legion-hook.exe"), format!("hook {marker}\n")).unwrap();
    fs::write(bin.join("legion-mcp.exe"), format!("mcp {marker}\n")).unwrap();
    fs::write(
        share.join("release.json"),
        serde_json::to_string(&json!({
            "releaseVersion": version,
            "runtime": { "platform": "windows", "architecture": "x86_64", "sha256": runtime_digest },
            "generation": generation,
        }))
        .unwrap(),
    )
    .unwrap();
}

struct FixtureSet {
    root: PathBuf,
    current_zip: PathBuf,
    prior_zip: Option<PathBuf>,
    codex_executable: PathBuf,
}

fn qualification_fixture(with_prior: bool) -> FixtureSet {
    let root = temp_root();
    let current_tree = root.join("current-tree");
    let prior_tree = root.join("prior-tree");
    let current_zip = root.join("current.zip");
    let prior_zip = root.join("prior.zip");
    write_fixture(&current_tree, "1.2.3", "current");
    write_fixture(&prior_tree, "1.2.2", "prior");
    let codex_executable = root.join("codex.exe");
    fs::write(&codex_executable, "fixture codex\n").unwrap();
    fs::write(&current_zip, "current archive fixture\n").unwrap();
    fs::write(&prior_zip, "prior archive fixture\n").unwrap();
    FixtureSet {
        root,
        current_zip,
        prior_zip: if with_prior { Some(prior_zip) } else { None },
        codex_executable,
    }
}

fn copy_dir(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn archive_extractor(fixture_root: PathBuf, current_zip: PathBuf, current_tree: PathBuf, prior_zip: Option<PathBuf>, prior_tree: PathBuf) -> Box<dyn Fn(&Path, &Path) -> Result<(), String>> {
    let _ = fixture_root;
    Box::new(move |archive: &Path, destination: &Path| {
        let source = if archive == current_zip {
            &current_tree
        } else if Some(archive.to_path_buf()) == prior_zip {
            &prior_tree
        } else {
            return Err(format!("unexpected archive in test extractor: {}", archive.display()));
        };
        copy_dir(source, destination);
        Ok(())
    })
}

fn command_runner(codex_executable: PathBuf) -> Box<dyn Fn(&str, &[String], &CommandOptions) -> CommandOutcome> {
    Box::new(move |command: &str, args: &[String], options: &CommandOptions| -> CommandOutcome {
        assert!(!options.env.contains_key("LEGION_M1_CONFIG"));
        assert!(!options.env.contains_key("LEGION_NATIVE_APPLICATION_CONFIG"));
        let home = options.env.get("HOME").cloned().unwrap_or_default();
        let expected_codex_home = Path::new(&home).join(".codex");
        assert_eq!(options.env.get("CODEX_HOME").cloned().unwrap_or_default(), expected_codex_home.to_string_lossy());
        let codex_dir = fs::canonicalize(codex_executable.parent().unwrap()).unwrap_or_else(|_| codex_executable.parent().unwrap().to_path_buf());
        let path_value = options.env.get("PATH").cloned().unwrap_or_default();
        assert!(path_value.split(';').any(|p| p == codex_dir.to_string_lossy()), "PATH must include codex dir: {path_value} vs {}", codex_dir.display());

        let installed_launcher = options.cwd.join("bin").join("legion.exe");
        let release_json = fs::read_to_string(options.cwd.join("share").join("legion").join("release.json")).unwrap();
        let active_metadata: Value = serde_json::from_str(&release_json).unwrap();
        let active_version = active_metadata.get("releaseVersion").and_then(|v| v.as_str()).unwrap().to_string();
        let install_root = options.cwd.parent().unwrap().to_path_buf();
        let versions_dir = install_root.join("versions");
        let active_version_name = fs::read_dir(&versions_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .find(|name| name.starts_with(&format!("{active_version}-")))
            .expect("version root must be retained");
        let resolved_manifest_path = versions_dir.join(&active_version_name).join("share").join("legion").join("release.json");

        if args.first().map(String::as_str) == Some("--version") {
            return CommandOutcome { exit_code: Some(0), stdout: format!("legion {active_version}\n"), stderr: String::new(), error: None, signal: None };
        }

        let installed_digest = sha256_hex(&fs::read(&installed_launcher).unwrap());
        let codex_digest = sha256_prefixed(&fs::read(&codex_executable).unwrap());
        let state_root = options.env.get("LEGION_STATE_ROOT").cloned().unwrap_or_default();
        let qualification_root = PathBuf::from(&state_root).join("qualification");
        let command_proof_path = qualification_root.join("codex-command.json");
        let qualification_proof_path = qualification_root.join("codex-qualification.json");
        let generation = active_metadata.get("generation").cloned().unwrap_or(Value::Null);
        let client = json!({
            "clientId": "codex",
            "installed": true,
            "fidelity": "Full",
            "commandProofRef": command_proof_path,
            "qualificationEvidenceRef": qualification_proof_path,
        });
        let live_identity = json!({
            "origin": "installed",
            "executablePath": installed_launcher,
            "installRoot": install_root,
            "generation": generation,
            "executable": {
                "path": installed_launcher,
                "manifestPath": resolved_manifest_path,
                "origin": "installed",
                "installRoot": install_root,
                "generation": generation,
                "releaseVersion": active_version,
                "expectedReleaseVersion": active_version,
                "state": "current",
                "runtimeDigest": installed_digest,
                "runtimePlatform": "windows",
                "runtimeArchitecture": "x86_64",
            },
            "projections": { "codexSkills": { "state": "current" } },
        });

        if args.iter().any(|a| a == "repair") {
            fs::create_dir_all(&qualification_root).unwrap();
            fs::write(
                &command_proof_path,
                serde_json::to_string(&json!({
                    "schemaVersion": 2,
                    "kind": "legion-command-resolution-proof",
                    "clientId": "codex",
                    "mechanism": "agent-plugins-bare-command",
                    "release": { "releaseVersion": active_version, "runtimeDigest": installed_digest },
                    "launcherPath": codex_executable,
                    "launcherSha256": codex_digest,
                    "resolved": true,
                    "exitCode": 0,
                    "outputSha256": "a".repeat(64),
                    "legionCommand": "legion --version",
                    "legionResolved": true,
                    "legionExitCode": 0,
                    "legionLauncherPath": installed_launcher,
                    "legionLauncherSha256": installed_digest,
                    "legionOutputSha256": "b".repeat(64),
                    "mcpCommand": "legion",
                    "mcpArgs": ["serve", "--stdio"],
                }))
                .unwrap(),
            )
            .unwrap();
            fs::write(
                &qualification_proof_path,
                serde_json::to_string(&json!({
                    "schemaVersion": 2,
                    "kind": "legion-real-client-qualification",
                    "clientId": "codex",
                    "mechanism": "agent-plugins-bare-command",
                    "release": { "releaseVersion": active_version, "runtimeDigest": installed_digest },
                    "launcherPath": codex_executable,
                    "mcpServer": "legion",
                    "mcpTool": "legion_m1_status",
                    "invocationStatus": "complete",
                    "observedReleaseVersion": active_version,
                    "capabilityCount": 1,
                    "hostRequirements": [],
                    "capabilities": [{ "capabilityId": "fixture" }],
                    "degradedCount": 0,
                    "completed": true,
                    "outputSha256": "c".repeat(64),
                    "legionLauncherPath": installed_launcher,
                    "legionLauncherSha256": installed_digest,
                    "mcpCommand": "legion",
                    "mcpArgs": ["serve", "--stdio"],
                }))
                .unwrap(),
            )
            .unwrap();
            let stdout = format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "schemaVersion": 1,
                    "kind": "legion-setup-execution",
                    "status": "complete",
                    "execution": { "clients": [client] },
                    "hostIntegrations": { "codexSkills": { "state": "current" } },
                    "liveIdentity": live_identity,
                }))
                .unwrap()
            );
            return CommandOutcome { exit_code: Some(0), stdout, stderr: String::new(), error: None, signal: None };
        }
        if args.iter().any(|a| a == "status") {
            let stdout = format!(
                "{}\n",
                serde_json::to_string(&json!({
                    "schemaVersion": 1,
                    "kind": "legion-setup-status",
                    "status": "complete",
                    "clients": [client],
                    "hostIntegrations": { "codexSkills": { "state": "current" } },
                    "liveIdentity": live_identity,
                }))
                .unwrap()
            );
            return CommandOutcome { exit_code: Some(0), stdout, stderr: String::new(), error: None, signal: None };
        }
        CommandOutcome { exit_code: Some(1), stdout: String::new(), stderr: format!("unexpected command {command}"), error: None, signal: None }
    })
}

fn options_for(fixture: &FixtureSet, source_revision: &str, with_prior: bool) -> QualifyWindowsOptions {
    let current_tree = fixture.root.join("current-tree");
    let prior_tree = fixture.root.join("prior-tree");
    let work_root = fixture.root.join("work");
    let output = fixture.root.join("qualification.json");
    QualifyWindowsOptions {
        current_zip: Some(fixture.current_zip.clone()),
        prior_zip: if with_prior { fixture.prior_zip.clone() } else { None },
        architecture: Some("x86_64".to_string()),
        source_revision: Some(source_revision.to_string()),
        output: Some(output),
        work_root: Some(work_root),
        platform: Some("win32".to_string()),
        runner_architecture: Some("x64".to_string()),
        archive_extractor: Some(archive_extractor(fixture.root.clone(), fixture.current_zip.clone(), current_tree, fixture.prior_zip.clone(), prior_tree)),
        command_runner: Some(command_runner(fixture.codex_executable.clone())),
        codex_executable: Some(fixture.codex_executable.clone()),
        allow_downgrade: false,
    }
}

fn cleanup(fixture: &FixtureSet) {
    let _ = fs::remove_dir_all(&fixture.root);
}

#[test]
fn windows_qualification_exercises_native_lifecycle_through_injected_seams() {
    let fixture = qualification_fixture(true);
    let receipt = qualify_windows_release(options_for(&fixture, &"a".repeat(40), true)).expect("qualification succeeds");
    assert_eq!(receipt["status"], "blocked");
    assert_eq!(receipt["nativeExecution"], false);
    assert_eq!(receipt["executionMode"], "simulated");
    assert_eq!(receipt["runner"]["simulated"], true);
    assert_eq!(receipt["archive"]["prior"]["sha256"], receipt["priorArchiveSha256"]);
    assert_ne!(receipt["archive"]["current"]["sha256"], receipt["archive"]["prior"]["sha256"]);
    assert_ne!(receipt["runtimeSha256"], receipt["priorRuntimeSha256"]);
    let current_path = receipt["install"]["currentPath"].as_str().unwrap();
    assert!(current_path.replace('\\', "/").ends_with("Orthic Labs/Legion/current"));
    assert_eq!(receipt["install"]["origin"], "installed");
    assert_eq!(receipt["origin"], "installed");
    assert_eq!(receipt["installRoot"], receipt["install"]["root"]);
    assert_eq!(receipt["executable"], receipt["install"]["executable"]);
    assert_eq!(receipt["generation"], receipt["install"]["generation"]);
    assert_eq!(receipt["integrationJournal"]["kind"], "legion-integration-journal");
    assert_eq!(receipt["integrationJournal"]["origin"], "installed");
    assert_eq!(receipt["integrationJournal"]["executable"], receipt["install"]["executable"]);
    assert_eq!(receipt["integrationJournal"]["generation"], receipt["install"]["generation"]);
    assert_eq!(receipt["integrationJournal"]["binding"]["resolvedVersionRoot"], receipt["install"]["currentVersionRoot"]);
    assert_eq!(receipt["integrationJournal"]["state"], "ready-for-uninstall");
    assert_eq!(receipt["gates"]["update"]["stableCurrentPath"], receipt["install"]["currentPath"]);
    assert_eq!(receipt["gates"]["rollback"]["integrationsRestored"], true);
    assert_eq!(receipt["gates"]["rollback"]["priorHealthRestored"], true);
    assert_eq!(receipt["gates"]["installed-product"]["activationPath"], receipt["install"]["executable"]);
    for name in ["installed-product", "command-resolution", "client-integration", "update", "rollback", "uninstall"] {
        assert_eq!(receipt["gates"][name]["status"], "pass", "{name} must pass: {:?}", receipt["gates"][name]);
    }
    assert_eq!(receipt["gates"]["rollback"]["injectedFailure"], true);
    assert_eq!(receipt["gates"]["uninstall"]["foreignMarkerPreserved"], true);
    cleanup(&fixture);
}

#[test]
fn missing_prior_archive_is_typed_unproven_and_cannot_qualify() {
    let fixture = qualification_fixture(false);
    let receipt = qualify_windows_release(options_for(&fixture, &"b".repeat(40), false)).expect("qualification succeeds");
    assert_eq!(receipt["status"], "blocked");
    assert_eq!(receipt["gates"]["update"]["status"], "unproven");
    assert_eq!(receipt["gates"]["rollback"]["status"], "unproven");
    cleanup(&fixture);
}

#[test]
fn identical_prior_archive_cannot_pass_update_or_rollback() {
    let fixture = qualification_fixture(true);
    fs::copy(&fixture.current_zip, fixture.prior_zip.as_ref().unwrap()).unwrap();
    let receipt = qualify_windows_release(options_for(&fixture, &"d".repeat(40), true)).expect("qualification succeeds");
    assert_eq!(receipt["status"], "blocked");
    assert_eq!(receipt["gates"]["update"]["status"], "fail");
    assert_eq!(receipt["gates"]["rollback"]["status"], "fail");
    assert_eq!(receipt["gates"]["update"]["archivesDiffer"], false);
    assert_eq!(receipt["gates"]["rollback"]["archivesDiffer"], false);
    cleanup(&fixture);
}

#[test]
fn qualification_refuses_non_windows_hosts_and_runner_architecture_mismatches() {
    let error = qualify_windows_release(QualifyWindowsOptions {
        platform: Some("linux".to_string()),
        architecture: Some("x86_64".to_string()),
        ..Default::default()
    })
    .unwrap_err();
    assert!(error.contains("Windows qualification requires a Windows host"), "{error}");

    let error = qualify_windows_release(QualifyWindowsOptions {
        platform: Some("win32".to_string()),
        runner_architecture: Some("x64".to_string()),
        architecture: Some("arm64".to_string()),
        ..Default::default()
    })
    .unwrap_err();
    assert!(error.contains("architecture mismatch"), "{error}");
}

// Unused import guard for BTreeMap kept available to future test helpers.
#[allow(dead_code)]
fn _unused(_: BTreeMap<String, String>) {}
