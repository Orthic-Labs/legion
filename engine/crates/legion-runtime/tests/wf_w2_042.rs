//! Integration tests for ported chunk w2_042 (`src/lib/core/{repository-binding,
//! run-manifest,verify-run}.mjs` — see `legion_runtime::wf_port::w2_042` doc
//! comment for the full disposition of all three files in the chunk).
//!
//! NOTE: this test file assumes the integrator has wired
//! `pub mod wf_port;` (already present in `lib.rs`) and `pub mod w2_042;`
//! inside `src/wf_port/mod.rs`. Until that lands this file will not compile.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use legion_runtime::wf_port::w2_042::{
    bind_repository, build_canonical_manifest, validate_run_manifest, verify_sealed_run,
    BindOptions, CurrentRepository,
};
use serde_json::json;

fn tempdir(prefix: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    let unique = format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    dir.push(unique);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(root)
        .status()
        .expect("git available");
    assert!(status.success(), "git {args:?} failed");
}

// ---- repository-binding.mjs -------------------------------------------

#[test]
fn repository_binding_digest_is_stable_across_equivalent_runs() {
    let root = tempdir("legion-w2_042-repo-binding");
    fs::write(root.join("a.txt"), "hello\n").unwrap();
    let first = bind_repository(&root, BindOptions::default()).unwrap();
    let second = bind_repository(&root, BindOptions::default()).unwrap();
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.dirty_overlay_digest, second.dirty_overlay_digest);
    assert_eq!(first.schema_version, 1);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn repository_binding_excludes_runtime_state_directories_without_git() {
    let root = tempdir("legion-w2_042-repo-binding-fallback");
    fs::create_dir_all(root.join(".legion")).unwrap();
    fs::write(root.join(".legion/state.json"), "runtime\n").unwrap();
    fs::write(root.join("source.txt"), "source v1\n").unwrap();
    let before = bind_repository(&root, BindOptions::default()).unwrap();

    fs::write(root.join(".legion/state.json"), "runtime mutated\n").unwrap();
    let after_runtime_mutation = bind_repository(&root, BindOptions::default()).unwrap();
    assert_eq!(before.digest, after_runtime_mutation.digest);

    fs::write(root.join("source.txt"), "source v2\n").unwrap();
    let after_source_mutation = bind_repository(&root, BindOptions::default()).unwrap();
    assert_ne!(before.digest, after_source_mutation.digest);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn repository_binding_git_backed_respects_gitignore() {
    let root = tempdir("legion-w2_042-repo-binding-git");
    run_git(&root, &["init", "--quiet"]);
    run_git(&root, &["config", "user.email", "legion-tests@example.invalid"]);
    run_git(&root, &["config", "user.name", "Legion Tests"]);
    fs::write(root.join(".gitignore"), "engine/target/\n").unwrap();
    fs::write(root.join("tracked.txt"), "tracked v1\n").unwrap();
    run_git(&root, &["add", ".gitignore", "tracked.txt"]);
    run_git(&root, &["commit", "--quiet", "-m", "baseline"]);
    fs::create_dir_all(root.join("engine/target")).unwrap();
    fs::write(root.join("engine/target/generated.bin"), "generated\n").unwrap();

    let bound = bind_repository(&root, BindOptions::default()).unwrap();
    assert_eq!(bound.file_count, 2); // .gitignore + tracked.txt
    fs::remove_dir_all(&root).ok();
}

// ---- run-manifest.mjs ---------------------------------------------------

#[test]
fn run_manifest_round_trips_through_validate() {
    let binding = json!({"repositoryRevision": "rev-1", "sourceRevision": "rev-1"});
    let records = vec![
        json!({"path": "present.txt", "status": "present", "digest": "sha256:aaa"}),
        json!({"path": "gone.txt", "status": "missing", "digest": "sha256:bbb"}),
    ];
    let artifact = build_canonical_manifest(records, binding.clone());
    assert_eq!(artifact.value.terminal_absences, vec!["gone.txt"]);

    let manifest_value = artifact.value.to_value();
    let files = vec![json!({"path": "present.txt", "digest": "sha256:aaa"})];
    let issues = validate_run_manifest(&manifest_value, &files, Some(&binding));
    assert!(issues.is_empty(), "expected clean validation, got {issues:?}");
}

#[test]
fn run_manifest_validate_flags_binding_drift_orphans_and_drifted_digests() {
    let binding = json!({"repositoryRevision": "rev-1", "sourceRevision": "rev-1"});
    let records = vec![json!({"path": "a.txt", "status": "present", "digest": "sha256:aaa"})];
    let artifact = build_canonical_manifest(records, binding);
    let manifest_value = artifact.value.to_value();

    let drifted_binding = json!({"repositoryRevision": "rev-2"});
    let files = vec![
        json!({"path": "a.txt", "digest": "sha256:DIFFERENT"}),
        json!({"path": "orphan.txt", "digest": "sha256:ccc"}),
    ];
    let issues = validate_run_manifest(&manifest_value, &files, Some(&drifted_binding));
    assert!(issues.contains(&"binding:mismatch".to_string()));
    assert!(issues.contains(&"orphan:orphan.txt".to_string()));
    assert!(issues.contains(&"missing-or-drifted:a.txt".to_string()));
}

// ---- verify-run.mjs -----------------------------------------------------

#[test]
fn verify_sealed_run_passes_for_identical_prior_and_current() {
    let prior = json!({
        "binding": {"repositoryRevision": "rev-1"},
        "plan": {"providers": []},
        "receipts": [],
        "judgments": [],
    });
    let current_repository = CurrentRepository {
        binding: Some(json!({"repositoryRevision": "rev-1"})),
        snapshot: Some(json!({
            "binding": {"repositoryRevision": "rev-1"},
            "plan": {"providers": []},
            "receipts": [],
            "judgments": [],
        })),
    };
    let receipt = verify_sealed_run(&prior, &current_repository, "2026-01-01T00:00:00.000Z");
    assert!(receipt.valid, "unexpected gaps: {:?}", receipt.gaps);
    assert_eq!(receipt.status, "pass");
}

#[test]
fn verify_sealed_run_end_to_end_from_repository_binding_and_manifest() {
    // Exercises the three ported files together: bind a repository, build a
    // manifest from it, then verify a "sealed run" against the same binding.
    let root = tempdir("legion-w2_042-e2e");
    fs::write(root.join("only.txt"), "content\n").unwrap();
    let binding = bind_repository(&root, BindOptions::default()).unwrap();
    let binding_value = binding.to_value();

    let manifest_artifact =
        build_canonical_manifest(vec![], json!({"repositoryRevision": binding.digest.clone()}));
    assert_eq!(manifest_artifact.value.kind, "legion-run-manifest");

    let prior = json!({"binding": binding_value.clone()});
    let current_repository = CurrentRepository {
        binding: Some(binding_value.clone()),
        snapshot: Some(json!({"binding": binding_value})),
    };
    let receipt = verify_sealed_run(&prior, &current_repository, "2026-01-01T00:00:00.000Z");
    assert!(receipt.valid, "unexpected gaps: {:?}", receipt.gaps);
    fs::remove_dir_all(&root).ok();
}

#[test]
fn verify_sealed_run_reports_semantic_replay_unavailable_without_current_snapshot() {
    let prior = json!({"binding": {"repositoryRevision": "rev-1"}});
    let current_repository = CurrentRepository {
        binding: Some(json!({"repositoryRevision": "rev-1"})),
        snapshot: None,
    };
    let receipt = verify_sealed_run(&prior, &current_repository, "2026-01-01T00:00:00.000Z");
    assert!(!receipt.valid);
    assert!(receipt
        .gaps
        .iter()
        .any(|g| g["kind"] == "semantic-replay-unavailable"));
}
