//! wf014: port of `src/lib/qualification/{book-receipt,schema-validator,
//! source-revision,source-slice}.mjs`.
//!
//! These are integration tests against the real filesystem and a real git
//! checkout (the ported functions shell out to `git`), so each test builds
//! its own throwaway repository under the system temp directory rather than
//! using a fixture checked into this repo (fixtures/wf_wf014/ is kept only
//! as this chunk's designated fixture location and currently holds nothing
//! beyond a `.gitkeep`, since every scenario needs a *fresh* git history).

use legion_audit::wf_port::wf014::{
    book_receipt::{validate_book_receipt, BookReceiptOptions},
    source_revision::{committed_source_revision, current_source_revision},
    source_slice::source_slice_qualification,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

struct TempRepo {
    path: PathBuf,
}

impl TempRepo {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "legion-wf014-{name}-{}-{}",
            std::process::id(),
            ((std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()).wrapping_shl(20) | ({ static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0); u128::from(SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) }))
        ));
        std::fs::create_dir_all(&path).expect("create temp repo dir");
        run(&path, &["init", "-q"]);
        run(&path, &["config", "user.email", "test@example.com"]);
        run(&path, &["config", "user.name", "wf014 test"]);
        Self { path }
    }

    fn write(&self, rel: &str, contents: &str) {
        let target = self.path.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(target, contents).expect("write file");
    }

    fn commit_all(&self, message: &str) {
        run(&self.path, &["add", "-A"]);
        run(&self.path, &["commit", "-q", "-m", message]);
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn run(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .expect("spawn git");
    assert!(status.success(), "git {args:?} failed in {}", dir.display());
}

// ---------------------------------------------------------------------
// source_revision
// ---------------------------------------------------------------------

#[test]
fn clean_checkout_current_matches_committed() {
    let repo = TempRepo::new("clean");
    repo.write("a.txt", "hello");
    repo.commit_all("initial");

    assert_eq!(
        current_source_revision(&repo.path),
        committed_source_revision(&repo.path)
    );
    assert!(current_source_revision(&repo.path).starts_with("content.sha256:"));
    assert!(!current_source_revision(&repo.path).ends_with("+dirty"));
}

#[test]
fn dirty_working_tree_changes_current_but_not_committed() {
    let repo = TempRepo::new("dirty");
    repo.write("a.txt", "hello");
    repo.commit_all("initial");
    let committed_before = committed_source_revision(&repo.path);

    repo.write("a.txt", "hello, modified");
    let current_dirty = current_source_revision(&repo.path);
    let committed_after = committed_source_revision(&repo.path);

    assert!(current_dirty.ends_with("+dirty"));
    assert_ne!(current_dirty, committed_before);
    assert_eq!(committed_before, committed_after, "committed revision ignores dirty working tree");
}

#[test]
fn qualification_directory_is_excluded_from_the_revision() {
    let repo = TempRepo::new("excluded");
    repo.write("a.txt", "hello");
    repo.write("qualification/receipt.json", "{}");
    repo.commit_all("initial");
    let before = committed_source_revision(&repo.path);

    repo.write("qualification/receipt.json", "{\"changed\": true}");
    repo.commit_all("seal receipt");
    let after = committed_source_revision(&repo.path);

    assert_eq!(before, after, "a commit touching only qualification/ must not move the revision");
}

// ---------------------------------------------------------------------
// source_slice_qualification
// ---------------------------------------------------------------------

#[test]
fn source_slice_reports_source_complete_when_every_record_matches() {
    let repo = TempRepo::new("slice-complete");
    repo.write("src/thing.mjs", "export const thing = 1;\n");
    repo.commit_all("initial");
    let blob = std::process::Command::new("git")
        .args(["hash-object", "src/thing.mjs"])
        .current_dir(&repo.path)
        .output()
        .unwrap();
    let blob = String::from_utf8_lossy(&blob.stdout).trim().to_string();

    let input = json!({
        "book": 1,
        "expectedTaskCount": 1,
        "tasks": [{ "id": "B1-001", "status": "mapped" }],
        "sourceRecords": [{ "status": "mapped", "path": "src/thing.mjs", "currentBlob": blob }],
        "root": repo.path.to_string_lossy(),
    });
    let result = source_slice_qualification(&input);

    assert_eq!(result["decision"], "SOURCE_COMPLETE");
    assert_eq!(result["sourceCompletion"]["mapped"], 1);
    assert_eq!(result["sourceCompletion"]["blocked"], 0);
    assert!(result.get("sourceBlockers").is_none());
}

#[test]
fn source_slice_blocks_on_stale_blob_and_missing_path() {
    let repo = TempRepo::new("slice-blocked");
    repo.write("src/thing.mjs", "export const thing = 1;\n");
    repo.commit_all("initial");

    let input = json!({
        "book": 2,
        "expectedTaskCount": 1,
        "tasks": [{ "id": "B2-001", "status": "mapped" }],
        "sourceRecords": [
            { "status": "mapped", "path": "src/thing.mjs", "currentBlob": "0".repeat(40) },
            { "status": "mapped", "path": "src/missing.mjs", "currentBlob": "0".repeat(40) },
        ],
        "root": repo.path.to_string_lossy(),
    });
    let result = source_slice_qualification(&input);

    assert_eq!(result["decision"], "BLOCKED");
    let blockers = result["sourceBlockers"].as_array().unwrap();
    assert!(blockers.iter().any(|b| b["reason"] == "current-blob-oid-mismatch"));
    assert!(blockers.iter().any(|b| b["reason"] == "source-path-not-found"));
    assert_eq!(result["sourceCompletion"]["blocked"], 2);
}

#[test]
#[should_panic(expected = "task id missing or duplicated")]
fn source_slice_panics_on_duplicate_task_id() {
    let repo = TempRepo::new("slice-dup");
    repo.write("a.txt", "x");
    repo.commit_all("initial");
    let input = json!({
        "book": 1,
        "expectedTaskCount": 2,
        "tasks": [{ "id": "B1-001", "status": "mapped" }, { "id": "B1-001", "status": "mapped" }],
        "root": repo.path.to_string_lossy(),
    });
    source_slice_qualification(&input);
}

// ---------------------------------------------------------------------
// book_receipt (schema version 1)
// ---------------------------------------------------------------------

#[test]
fn v1_receipt_with_evidence_files_present_is_valid() {
    let repo = TempRepo::new("receipt-v1-ok");
    repo.write("proof/note.txt", "evidence");
    repo.commit_all("initial");

    let receipt = json!({
        "schemaVersion": 1,
        "kind": "legion-book-qualification",
        "book": 1,
        "expectedTaskCount": 1,
        "decision": "SOURCE_COMPLETE",
        "tasks": [{ "id": "B1-001", "evidence": ["proof/note.txt"] }],
    });
    let options = BookReceiptOptions { root: repo.path.clone(), source_revision: None };
    let result = validate_book_receipt(&receipt, &options);

    assert_eq!(result["valid"], true, "{result:?}");
    assert_eq!(result["taskCount"], 1);
}

#[test]
fn v1_receipt_flags_missing_evidence_and_absent_file() {
    let repo = TempRepo::new("receipt-v1-bad");
    repo.write("keep.txt", "x");
    repo.commit_all("initial");
    let receipt = json!({
        "schemaVersion": 1,
        "kind": "legion-book-qualification",
        "book": 1,
        "expectedTaskCount": 2,
        "decision": "NOT-A-DECISION",
        "tasks": [
            { "id": "B1-001", "evidence": [] },
            { "id": "B1-002", "evidence": ["nope.txt"] },
        ],
    });
    let options = BookReceiptOptions { root: repo.path.clone(), source_revision: None };
    let result = validate_book_receipt(&receipt, &options);

    let issues: Vec<&str> = result["issues"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(issues.contains(&"invalid-decision"));
    assert!(issues.contains(&"B1-001:missing-evidence"));
    assert!(issues.iter().any(|i| i.starts_with("B1-002:absent:")));
    assert_eq!(result["valid"], false);
}

#[test]
fn v2_receipt_missing_contract_fields_is_invalid() {
    let repo = TempRepo::new("receipt-v2-bad");
    repo.write("a.txt", "x");
    repo.commit_all("initial");

    let receipt = json!({ "schemaVersion": 2, "kind": "legion-book-qualification", "book": 1 });
    let options = BookReceiptOptions { root: repo.path.clone(), source_revision: None };
    let result = validate_book_receipt(&receipt, &options);

    assert_eq!(result["valid"], false);
    let issues: Vec<&str> = result["issues"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    // Missing required top-level fields must surface as schema `required` issues.
    assert!(issues.iter().any(|i| i.contains(":required")));
}

#[test]
fn invalid_book_number_and_contract_are_reported() {
    let repo = TempRepo::new("receipt-bad-contract");
    repo.write("a.txt", "x");
    repo.commit_all("initial");

    let receipt = json!({ "schemaVersion": 3, "kind": "not-legion", "book": 99 });
    let options = BookReceiptOptions { root: repo.path.clone(), source_revision: None };
    let result = validate_book_receipt(&receipt, &options);

    let issues: Vec<&str> = result["issues"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(issues.contains(&"invalid-contract"));
    assert!(issues.contains(&"invalid-book"));
}
