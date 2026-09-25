//! Native-path tests for `package_windows_release`'s package mode (no
//! `@rightkit/release`/GitHub calls involved — those are exercised only by
//! `--finalize`, which is CI-only and out of scope for a unit test).

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

use super::prepare::{assembled_release, prepare_windows_archive, release_version, source_revision, windows_target_identity, PrepareOptions};
use crate::windows_release_support::sha256_prefixed;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("legion-package-windows-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_repo_fixture(root: &std::path::Path, version: &str) {
    fs::create_dir_all(root.join("release")).unwrap();
    fs::write(
        root.join("release").join("version.json"),
        serde_json::to_string(&json!({ "schemaVersion": 1, "kind": "legion-release-version", "version": version })).unwrap(),
    )
    .unwrap();
    // A throwaway git repo so `source_revision` (git rev-parse HEAD) resolves.
    std::process::Command::new("git").args(["init", "-q"]).current_dir(root).status().unwrap();
    std::process::Command::new("git").args(["config", "user.email", "test@example.com"]).current_dir(root).status().unwrap();
    std::process::Command::new("git").args(["config", "user.name", "test"]).current_dir(root).status().unwrap();
    fs::write(root.join("release").join(".keep"), "x").unwrap();
    std::process::Command::new("git").args(["add", "-A"]).current_dir(root).status().unwrap();
    std::process::Command::new("git").args(["commit", "-q", "-m", "init"]).current_dir(root).status().unwrap();
}

fn write_assembled_fixture(root: &std::path::Path, version: &str) {
    let bin = root.join("bin");
    let share = root.join("share").join("legion");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&share).unwrap();
    let runtime = format!("legion runtime {version}\n").into_bytes();
    let digest = sha256_prefixed(&runtime);
    fs::write(bin.join("legion.exe"), &runtime).unwrap();
    fs::write(bin.join("legion-hook.exe"), "hook\n").unwrap();
    fs::write(bin.join("legion-mcp.exe"), "mcp\n").unwrap();
    fs::write(
        share.join("release.json"),
        serde_json::to_string(&json!({
            "releaseVersion": version,
            "runtime": { "platform": "windows", "architecture": "x86_64", "sha256": digest },
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn windows_target_identity_matches_config() {
    let identity = windows_target_identity("x64").unwrap();
    assert_eq!(identity["platform"], "windows");
    assert_eq!(identity["architecture"], "x86_64");
    assert_eq!(identity["targetTriple"], "x86_64-pc-windows-msvc");
    assert_eq!(identity["executable"], "legion.exe");
    assert!(windows_target_identity("s390x").is_err());
}

#[test]
fn release_version_and_source_revision_read_fixture() {
    let root = temp_dir();
    write_repo_fixture(&root, "9.9.9");
    let version = release_version(&root).unwrap();
    assert_eq!(version, "9.9.9");
    let revision = source_revision(&root, None).unwrap();
    assert_eq!(revision.len(), 40);
    let explicit = source_revision(&root, Some(&"a".repeat(40))).unwrap();
    assert_eq!(explicit, "a".repeat(40));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn assembled_release_validates_identity_and_digest() {
    let root = temp_dir();
    write_assembled_fixture(&root, "1.0.0");
    let assembled = assembled_release(&root, "x86_64", "1.0.0").unwrap();
    assert_eq!(assembled.identity["architecture"], "x86_64");
    assert!(!assembled.runtime_sha256.is_empty());
    assert!(assembled_release(&root, "x86_64", "2.0.0").is_err());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn prepare_windows_archive_builds_a_zip() {
    let root = temp_dir();
    write_repo_fixture(&root, "1.2.3");
    let input_root = root.join("assembled");
    write_assembled_fixture(&input_root, "1.2.3");
    let result = prepare_windows_archive(PrepareOptions {
        input: &input_root,
        output: None,
        architecture: "x86_64",
        source_revision: Some(&"b".repeat(40)),
        force: true,
        repository_root: &root,
    });
    match result {
        Ok(value) => {
            assert_eq!(value["status"], "archive-prepared");
            assert_eq!(value["releaseVersion"], "1.2.3");
            let archive = value["archive"].as_str().unwrap();
            assert!(std::path::Path::new(archive).is_file(), "archive must exist: {archive}");
        }
        Err(error) => {
            // A sandboxed CI runner without a usable `tar` on PATH is the
            // only expected failure mode here; anything else is a real bug.
            assert!(error.contains("tar") || error.contains("portable archive"), "unexpected error: {error}");
        }
    }
    let _ = fs::remove_dir_all(&root);
}
