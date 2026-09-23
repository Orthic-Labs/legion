//! Port of `src/lib/qualification/source-slice.mjs`.
//!
//! Builds a schema-version-1 `legion-book-qualification` receipt for a
//! "source slice": a book whose tasks are graded against source records
//! (mapped file -> blob) rather than executed evidence. Mirrors the JS
//! `sourceSliceQualification` exactly, including its `throw new Error(...)`
//! panics for malformed task input (the JS function is a validating
//! constructor, not a fallible one — callers are expected to pass
//! already-shaped input).

use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const MISSING_REASONS: [&str; 2] = ["source-path-missing", "source-path-not-found"];

fn blob_oid_re() -> Regex {
    Regex::new(r"^[0-9a-f]{40}$").unwrap()
}

/// Strip a Windows `\\?\` verbatim prefix (as produced by
/// `fs::canonicalize`) so the path is safe to hand to external processes
/// like `git`, which do not understand the verbatim-path convention.
/// No-op on non-Windows paths and on paths that never had the prefix.
fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    match path.components().next() {
        Some(std::path::Component::Prefix(prefix)) => match prefix.kind() {
            std::path::Prefix::VerbatimDisk(disk) => {
                let mut stripped = PathBuf::from(format!("{}:\\", disk as char));
                stripped.extend(path.components().skip(2));
                stripped
            }
            std::path::Prefix::VerbatimUNC(server, share) => {
                let mut stripped = PathBuf::from(format!(
                    "\\\\{}\\{}\\",
                    server.to_string_lossy(),
                    share.to_string_lossy()
                ));
                stripped.extend(path.components().skip(3));
                stripped
            }
            _ => path.to_path_buf(),
        },
        _ => path.to_path_buf(),
    }
}

fn git_blob_oid(file: &Path, repository_root: &Path) -> String {
    let file = strip_verbatim_prefix(file);
    let repository_root = strip_verbatim_prefix(repository_root);
    let output = Command::new("git")
        .arg("hash-object")
        .arg(&file)
        .current_dir(&repository_root)
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn git hash-object: {error}"));
    if !output.status.success() {
        panic!(
            "git hash-object failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Lexically join + normalize (`.`/`..` collapsed), without touching the
/// filesystem — mirrors Node's `path.resolve`.
fn resolve_within(root: &Path, rel: &str) -> PathBuf {
    let joined = root.join(rel);
    let mut out = PathBuf::new();
    for component in joined.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn is_contained(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root)
}

struct Blocker {
    index: usize,
    path: Option<String>,
    reason: &'static str,
    status: Option<Value>,
    actual_blob: Option<String>,
}

impl Blocker {
    fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("index".into(), json!(self.index));
        object.insert(
            "path".into(),
            self.path.clone().map(Value::String).unwrap_or(Value::Null),
        );
        object.insert("reason".into(), json!(self.reason));
        if let Some(status) = &self.status {
            object.insert("status".into(), status.clone());
        }
        if let Some(actual_blob) = &self.actual_blob {
            object.insert("actualBlob".into(), json!(actual_blob));
        }
        Value::Object(object)
    }
}

fn source_record_blockers(record: &Value, index: usize, repository_root: &Path) -> Vec<Blocker> {
    let path = record
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let mut blockers = Vec::new();
    let push = |blockers: &mut Vec<Blocker>, reason, status: Option<Value>, actual_blob: Option<String>| {
        blockers.push(Blocker {
            index,
            path: if path.is_empty() { None } else { Some(path.to_string()) },
            reason,
            status,
            actual_blob,
        });
    };

    if !record.is_object() {
        push(&mut blockers, "source-record-invalid", None, None);
    }
    let status = record.get("status").cloned();
    if status.as_ref().and_then(Value::as_str) != Some("mapped") {
        push(&mut blockers, "source-status-not-mapped", Some(status.unwrap_or(Value::Null)), None);
    }
    if path.is_empty() {
        push(&mut blockers, "source-path-missing", None, None);
    }

    let mut file: Option<PathBuf> = None;
    if !path.is_empty() {
        if Path::new(path).is_absolute() {
            push(&mut blockers, "source-path-not-relative", None, None);
        } else {
            let resolved = resolve_within(repository_root, path);
            if !is_contained(repository_root, &resolved) {
                push(&mut blockers, "source-path-outside-root", None, None);
            } else if !resolved.exists() {
                push(&mut blockers, "source-path-not-found", None, None);
            } else if !resolved.is_file() {
                push(&mut blockers, "source-path-not-regular-file", None, None);
            } else {
                match std::fs::canonicalize(&resolved) {
                    Ok(real_file) if is_contained(repository_root, &real_file) => {
                        file = Some(real_file);
                    }
                    _ => push(&mut blockers, "source-path-outside-root", None, None),
                }
            }
        }
    }

    let current_blob = record.get("currentBlob").and_then(Value::as_str).unwrap_or("");
    if !blob_oid_re().is_match(current_blob) {
        push(&mut blockers, "current-blob-oid-invalid", None, None);
    } else if let Some(file) = &file {
        let actual_blob = git_blob_oid(file, repository_root);
        if current_blob != actual_blob {
            push(&mut blockers, "current-blob-oid-mismatch", None, Some(actual_blob));
        }
    }

    blockers
}

/// Input mirrors the JS destructured argument object. Fields absent from
/// the caller's JSON should be passed as their JS defaults (`[]` for the
/// array fields).
pub fn source_slice_qualification(input: &Value) -> Value {
    let book = input.get("book").cloned().unwrap_or(Value::Null);
    let expected_task_count = input
        .get("expectedTaskCount")
        .and_then(Value::as_i64)
        .filter(|value| *value >= 1)
        .unwrap_or_else(|| panic!("expectedTaskCount must be a positive integer"));
    let tasks: Vec<Value> = input
        .get("tasks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let checks = input.get("checks").cloned().unwrap_or_else(|| json!([]));
    let blockers_in = input.get("blockers").cloned().unwrap_or_else(|| json!([]));
    let root = input
        .get("root")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("current dir"));

    if tasks.len() as i64 != expected_task_count {
        panic!(
            "book {} task accounting mismatch: expected {}, received {}",
            book, expected_task_count, tasks.len()
        );
    }

    let mut task_ids: HashSet<String> = HashSet::new();
    for task in &tasks {
        let id = task.get("id").and_then(Value::as_str);
        match id {
            Some(id) if !task_ids.contains(id) => {
                task_ids.insert(id.to_string());
            }
            _ => panic!("book {} task id missing or duplicated", book),
        }
        let status = task.get("status").and_then(Value::as_str).unwrap_or("");
        if !["implemented", "mapped", "blocked"].contains(&status) {
            panic!("book {} invalid task status: {}", book, status);
        }
    }

    let records: Vec<Value> = match input.get("sourceRecords") {
        Some(Value::Array(records)) => records.clone(),
        Some(other) => vec![other.clone()],
        None => Vec::new(),
    };
    let repository_root = if records.is_empty() {
        None
    } else {
        Some(std::fs::canonicalize(&root).unwrap_or_else(|error| {
            panic!("failed to resolve root {}: {error}", root.display())
        }))
    };

    let source_blockers: Vec<Blocker> = records
        .iter()
        .enumerate()
        .flat_map(|(index, record)| {
            source_record_blockers(record, index, repository_root.as_deref().unwrap())
        })
        .collect();
    let blocked_indexes: HashSet<usize> = source_blockers.iter().map(|blocker| blocker.index).collect();
    let missing_indexes: HashSet<usize> = source_blockers
        .iter()
        .filter(|blocker| MISSING_REASONS.contains(&blocker.reason))
        .map(|blocker| blocker.index)
        .collect();

    let source_completion = if !records.is_empty() {
        Some(json!({
            "total": records.len(),
            "mapped": records.len() - blocked_indexes.len(),
            "blocked": blocked_indexes.len(),
            "missing": missing_indexes.len(),
        }))
    } else {
        None
    };

    let source_blocked = !source_blockers.is_empty();
    let any_task_blocked = tasks
        .iter()
        .any(|task| task.get("status").and_then(Value::as_str) == Some("blocked"));
    let decision = if any_task_blocked || source_blocked {
        "BLOCKED"
    } else {
        "SOURCE_COMPLETE"
    };

    let external_gates: Vec<Value> = blockers_in
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|blocker| blocker.get("id").cloned().unwrap_or(Value::Null))
        .collect();

    let mut result = Map::new();
    result.insert("schemaVersion".into(), json!(1));
    result.insert("kind".into(), json!("legion-book-qualification"));
    result.insert("book".into(), book);
    result.insert("expectedTaskCount".into(), json!(expected_task_count));
    result.insert("decision".into(), json!(decision));
    result.insert("claimLevel".into(), json!("source"));
    result.insert("tasks".into(), json!(tasks));
    result.insert("checks".into(), checks);
    result.insert("blockers".into(), blockers_in);
    result.insert("externalGates".into(), json!(external_gates));
    result.insert("receiptType".into(), json!("source-slice"));
    if let Some(source_completion) = source_completion {
        result.insert("sourceCompletion".into(), source_completion);
    }
    if !source_blockers.is_empty() {
        result.insert(
            "sourceBlockers".into(),
            json!(source_blockers.iter().map(Blocker::to_json).collect::<Vec<_>>()),
        );
    }
    Value::Object(result)
}
