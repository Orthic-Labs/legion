//! Port of `src/lib/qualification/book-receipt.mjs`.
//!
//! Validates a `legion-book-qualification` receipt (schema version 1 or 2)
//! against the recorded filesystem evidence: file digests/byte counts,
//! symbol/assertion presence, TAP-style proof-log counts, and — for v2 —
//! the JSON-Schema shape and the current source revision. Returns the same
//! `{ valid, issues, taskCount, sourceAccounting }` shape as the JS
//! `validateBookReceipt`, with `issues` deduplicated exactly like the JS
//! `[...new Set(issues)]` (first-seen order preserved).

use super::schema_validator::validate_schema;
use super::source_revision::current_source_revision;
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const TASK_STATES: [&str; 3] = ["implemented", "mapped", "source-blocked"];
const V1_DECISIONS: [&str; 3] = ["QUALIFIED", "SOURCE_COMPLETE", "BLOCKED"];

/// Embeds the v2 schema at compile time, mirroring the JS
/// `JSON.parse(readFileSync(new URL('../../schemas/qualification/book-qualification-v2.schema.json', ...)))`.
fn schema_v2() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../../src/schemas/qualification/book-qualification-v2.schema.json"
    ))
    .expect("book-qualification-v2 schema is valid JSON")
}

fn digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    format!("sha256:{:x}", hash.finalize())
}

fn resolve_path(root: &Path, rel: &str) -> PathBuf {
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

/// JS `validateFileRecord`.
fn validate_file_record(record: &Value, root: &Path, task_id: &str, kind: &str, needle: Option<&str>) -> Vec<String> {
    let path = record.get("path").and_then(Value::as_str).unwrap_or("");
    let resolved = resolve_path(root, path);
    if path.is_empty() || !resolved.exists() {
        return vec![format!("{task_id}:{kind}:absent:{path}")];
    }
    let mut issues = Vec::new();
    let bytes = match std::fs::read(&resolved) {
        Ok(bytes) => bytes,
        Err(_) => return vec![format!("{task_id}:{kind}:absent:{path}")],
    };
    let record_bytes = record.get("bytes").and_then(Value::as_i64);
    if record_bytes != Some(bytes.len() as i64) {
        issues.push(format!("{task_id}:{kind}:bytes-mismatch"));
    }
    let record_digest = record.get("digest").and_then(Value::as_str).unwrap_or("");
    if record_digest != digest(&bytes) {
        issues.push(format!("{task_id}:{kind}:digest-mismatch"));
    }
    if let Some(needle) = needle {
        if !needle.is_empty() && !String::from_utf8_lossy(&bytes).contains(needle) {
            let label = if kind == "test" { "assertion" } else { "symbol" };
            issues.push(format!("{task_id}:{kind}:{label}-absent"));
        }
    }
    issues
}

/// JS `summary`: pulls `ℹ tests N` / `# tests N` style counters out of a TAP
/// log's free text.
fn summary(bytes: &[u8]) -> Value {
    let text = String::from_utf8_lossy(bytes);
    let pick = |name: &str| -> Value {
        let re = Regex::new(&format!(r"(?:\x{{2139}}|#) {name} (\d+)")).unwrap();
        match re.captures(&text).and_then(|c| c.get(1)).and_then(|m| m.as_str().parse::<i64>().ok()) {
            Some(value) => json!(value),
            None => Value::Null,
        }
    };
    json!({ "total": pick("tests"), "pass": pick("pass"), "fail": pick("fail") })
}

/// JS `assertionStatus`.
fn assertion_status(text: &str, assertion: &str) -> Option<&'static str> {
    let ok_re = Regex::new(r"^ok \d+ - ").unwrap();
    let not_ok_re = Regex::new(r"^not ok \d+ - ").unwrap();
    for line in text.split(['\n', '\r']) {
        if !line.contains(assertion) {
            continue;
        }
        let value = line.trim();
        if let Some(stripped) = value.strip_prefix("\u{2714} ") {
            let _ = stripped;
            return Some("pass");
        }
        if ok_re.is_match(value) {
            return Some("pass");
        }
        if let Some(stripped) = value.strip_prefix("\u{2716} ") {
            let _ = stripped;
            return Some("fail");
        }
        if not_ok_re.is_match(value) {
            return Some("fail");
        }
    }
    None
}

/// JS `validateV1`.
fn validate_v1(receipt: &Value, root: &Path) -> Vec<String> {
    let mut issues = Vec::new();
    let decision = receipt.get("decision").and_then(Value::as_str).unwrap_or("");
    if !V1_DECISIONS.contains(&decision) {
        issues.push("invalid-decision".to_string());
    }
    for task in receipt.get("tasks").and_then(Value::as_array).cloned().unwrap_or_default() {
        let id = task.get("id").and_then(Value::as_str).unwrap_or("");
        let evidence = task.get("evidence").and_then(Value::as_array);
        let mapping_empty = task
            .get("mapping")
            .and_then(Value::as_str)
            .map(|m| m.trim().is_empty())
            .unwrap_or(true);
        let evidence_empty = evidence.map(|e| e.is_empty()).unwrap_or(true);
        if evidence_empty && mapping_empty {
            issues.push(format!("{id}:missing-evidence"));
        }
        for path in evidence.into_iter().flatten() {
            if let Some(path) = path.as_str() {
                if !resolve_path(root, path).exists() {
                    issues.push(format!("{id}:absent:{path}"));
                }
            }
        }
    }
    issues
}

/// Options mirroring the JS `{ root = process.cwd(), sourceRevision }`
/// destructured second argument. `source_revision` is unused by the JS
/// implementation itself (it always recomputes `currentSourceRevision`),
/// but is kept here for interface parity.
pub struct BookReceiptOptions {
    pub root: PathBuf,
    pub source_revision: Option<String>,
}

impl Default for BookReceiptOptions {
    fn default() -> Self {
        Self {
            root: std::env::current_dir().expect("current dir"),
            source_revision: None,
        }
    }
}

/// Faithful port of `validateBookReceipt`.
pub fn validate_book_receipt(receipt: &Value, options: &BookReceiptOptions) -> Value {
    let root = &options.root;
    let mut issues: Vec<String> = Vec::new();

    let version = receipt.get("schemaVersion").and_then(Value::as_i64);
    let kind = receipt.get("kind").and_then(Value::as_str);
    if !matches!(version, Some(1) | Some(2)) || kind != Some("legion-book-qualification") {
        issues.push("invalid-contract".to_string());
    }
    let book = receipt.get("book").and_then(Value::as_i64);
    if !matches!(book, Some(b) if (1..=8).contains(&b)) {
        issues.push("invalid-book".to_string());
    }
    if version == Some(1) {
        issues.extend(validate_v1(receipt, root));
    }
    if version == Some(2) {
        issues.extend(validate_schema(&schema_v2(), receipt));
    }

    let tasks: Vec<Value> = receipt.get("tasks").and_then(Value::as_array).cloned().unwrap_or_default();
    let expected_task_count = receipt.get("expectedTaskCount").and_then(Value::as_i64).unwrap_or(0);
    let expected: Vec<String> = (0..expected_task_count)
        .map(|index| format!("B{}-{:03}", book.unwrap_or(0), index + 1))
        .collect();
    let ids: Vec<String> = tasks
        .iter()
        .map(|task| task.get("id").and_then(Value::as_str).unwrap_or("").to_string())
        .collect();
    let unique_ids: HashSet<&String> = ids.iter().collect();
    if unique_ids.len() != ids.len() {
        issues.push("duplicate-task".to_string());
    }
    if ids != expected {
        issues.push("task-denominator-mismatch".to_string());
    }

    for (index, task) in tasks.iter().enumerate() {
        let task_id = task.get("id").and_then(Value::as_str).unwrap_or("");
        let status = task.get("status").and_then(Value::as_str).unwrap_or("");
        if !TASK_STATES.contains(&status) && version == Some(2) {
            issues.push(format!("{task_id}:invalid-status"));
        }
        if version != Some(2) {
            continue;
        }
        let mut seen_dependencies: HashSet<String> = HashSet::new();
        for dependency in task.get("dependsOn").and_then(Value::as_array).cloned().unwrap_or_default() {
            let Some(dependency) = dependency.as_str() else { continue };
            if seen_dependencies.contains(dependency) {
                issues.push(format!("{task_id}:duplicate-dependency:{dependency}"));
            }
            seen_dependencies.insert(dependency.to_string());
            let dependency_index = ids.iter().position(|id| id == dependency);
            let dependency_book: Option<i64> = Regex::new(r"^B(\d+)-")
                .unwrap()
                .captures(dependency)
                .and_then(|c| c.get(1))
                .and_then(|m| m.as_str().parse().ok());
            match dependency_index {
                None => {
                    if let (Some(dependency_book), Some(book)) = (dependency_book, book) {
                        if dependency_book >= book {
                            issues.push(format!("{task_id}:unknown-dependency:{dependency}"));
                        }
                    }
                }
                Some(dependency_index) => {
                    if dependency_index >= index {
                        issues.push(format!("{task_id}:forward-dependency:{dependency}"));
                    }
                }
            }
        }

        let Some(evidence) = task.get("evidence").filter(|e| e.is_object()) else {
            continue;
        };
        let test = evidence.get("test").cloned().unwrap_or(Value::Null);
        let test_assertion = test.get("assertion").and_then(Value::as_str);
        issues.extend(validate_file_record(&test, root, task_id, "test", test_assertion));
        for implementation in evidence.get("implementation").and_then(Value::as_array).cloned().unwrap_or_default() {
            let symbol = implementation.get("symbol").and_then(Value::as_str);
            issues.extend(validate_file_record(&implementation, root, task_id, "implementation", symbol));
        }
        for color in ["red", "green"] {
            let Some(proof) = evidence.get("proof").and_then(|p| p.get(color)) else {
                continue;
            };
            issues.extend(validate_file_record(proof, root, task_id, &format!("{color}-proof"), None));
            let proof_path = proof.get("path").and_then(Value::as_str).unwrap_or("");
            let resolved = resolve_path(root, proof_path);
            if !proof_path.is_empty() && resolved.exists() {
                if let Ok(bytes) = std::fs::read(&resolved) {
                    let observed = summary(&bytes);
                    let expected_counts = proof.get("counts").cloned().unwrap_or(Value::Null);
                    if observed != expected_counts {
                        issues.push(format!("{task_id}:{color}-proof:tap-counts-mismatch"));
                    }
                    let text = String::from_utf8_lossy(&bytes);
                    let status = test_assertion.and_then(|assertion| assertion_status(&text, assertion));
                    match status {
                        None => issues.push(format!("{task_id}:{color}-proof:task-assertion-absent")),
                        Some(status) => {
                            let expected_status = if color == "red" { "fail" } else { "pass" };
                            if status != expected_status {
                                let label = if color == "red" { "not-failed" } else { "not-passed" };
                                issues.push(format!("{task_id}:{color}-proof:task-assertion-{label}"));
                            }
                        }
                    }
                }
            }
        }
    }

    let implemented = tasks.iter().filter(|t| t.get("status").and_then(Value::as_str) == Some("implemented")).count();
    let mapped = tasks.iter().filter(|t| t.get("status").and_then(Value::as_str) == Some("mapped")).count();
    let source_blocked = tasks.iter().filter(|t| t.get("status").and_then(Value::as_str) == Some("source-blocked")).count();
    let counts = json!({ "implemented": implemented, "mapped": mapped, "sourceBlocked": source_blocked });

    if version == Some(2) {
        let observed_source_revision = current_source_revision(root);
        let receipt_source_revision = receipt.get("sourceRevision").and_then(Value::as_str).unwrap_or("");
        if receipt_source_revision != observed_source_revision {
            issues.push("source-revision-mismatch".to_string());
        }
        let receipt_accounting = receipt.get("sourceAccounting").cloned().unwrap_or(Value::Null);
        if receipt_accounting != counts {
            issues.push("source-accounting-mismatch".to_string());
        }
        let decision = receipt.get("decision").and_then(Value::as_str);
        if decision == Some("SOURCE_IMPLEMENTED") && (mapped != 0 || source_blocked != 0) {
            issues.push("source-implemented-with-source-gaps".to_string());
        }
        for check in receipt.get("checks").and_then(Value::as_array).cloned().unwrap_or_default() {
            let check_id = check.get("id").and_then(Value::as_str).unwrap_or("");
            let file_record = json!({
                "path": check.get("log").cloned().unwrap_or(Value::Null),
                "digest": check.get("digest").cloned().unwrap_or(Value::Null),
                "bytes": check.get("bytes").cloned().unwrap_or(Value::Null),
            });
            issues.extend(validate_file_record(&file_record, root, check_id, "check-log", None));
            let log_path = check.get("log").and_then(Value::as_str).unwrap_or("");
            let resolved = resolve_path(root, log_path);
            if !log_path.is_empty() && resolved.exists() {
                if let Ok(bytes) = std::fs::read(&resolved) {
                    if summary(&bytes) != check.get("counts").cloned().unwrap_or(Value::Null) {
                        issues.push(format!("{check_id}:tap-counts-mismatch"));
                    }
                }
            }
        }
    }

    // JS `[...new Set(issues)]`: first-seen order preserved, duplicates
    // dropped.
    let mut seen = HashSet::new();
    let deduped: Vec<String> = issues.into_iter().filter(|issue| seen.insert(issue.clone())).collect();

    json!({
        "valid": deduped.is_empty(),
        "issues": deduped,
        "taskCount": tasks.len(),
        "sourceAccounting": counts,
    })
}

/// Faithful port of `loadBookReceipt`.
pub fn load_book_receipt(path: &Path, options: &BookReceiptOptions) -> Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let receipt: Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {} as JSON: {error}", path.display()));
    validate_book_receipt(&receipt, options)
}
