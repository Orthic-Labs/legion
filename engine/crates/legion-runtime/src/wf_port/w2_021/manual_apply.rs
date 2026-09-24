//! Port of `skills/designer/engine/scripts/live/manual-apply.mjs`.
//!
//! Packet r29 extends this module to close the w2_021 gap noted in its
//! `mod.rs` header (and in `full-Q2.md`): `createManualApplyController`'s
//! stateful queue/deferred-result wiring is now ported as
//! [`ManualApplyController`]. It is generic over a [`ManualApplyCallbacks`]
//! implementation, matching the JS constructor's injected `enqueueEvent`,
//! `acknowledgePendingEvent`, `flushPendingPolls`, and
//! `recordManualEditActivity` callbacks (owned by `live.mjs`, outside this
//! chunk's files, so still not reimplemented here — only their call sites
//! are).
//!
//! The one piece that stays a documented gap: JS's `pushApplyEventAndWait`
//! resolves via a Node event-loop `setTimeout` + `Promise`, driven by an HTTP
//! reply arriving on a *different* request than the one that dispatched the
//! event. This port models that with a blocking `mpsc` channel and
//! `recv_timeout`, so [`ManualApplyController::push_apply_event_and_wait`]
//! must be called from a thread that is not also the one expected to call
//! `resolve_deferred`/`reject_deferred` for the same event (matching the
//! real system, where those are always different execution contexts: the
//! live-server thread dispatching to the browser vs. the coding agent's
//! reply hitting the HTTP route).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;

use crate::wf_port::w2_016::impeccable_paths::get_live_dir;
use crate::wf_port::w2_021::manual_edits_buffer::read_buffer as read_manual_edits_buffer;

const MANUAL_APPLY_COMPACT_TEXT_LIMIT: usize = 240;
const MANUAL_APPLY_COMPACT_NEARBY_LIMIT: usize = 4;

const DEFAULT_MANUAL_EDIT_APPLY_CHUNK_SIZE: i64 = 3;
const MIN_MANUAL_EDIT_APPLY_CHUNK_SIZE: i64 = 1;
const MAX_MANUAL_EDIT_APPLY_CHUNK_SIZE: i64 = 20;

/// Port of `APPLY_EVENT_HARD_TIMEOUT_MS` default (150_000 ms).
pub const APPLY_EVENT_HARD_TIMEOUT_MS_DEFAULT: u64 = 150_000;
/// Port of `APPLY_EVENT_SOFT_DEADLINE_MS` default (120_000 ms).
pub const APPLY_EVENT_SOFT_DEADLINE_MS_DEFAULT: u64 = 120_000;

// ---------------------------------------------------------------------
// Pure helpers (already-ported, unchanged)
// ---------------------------------------------------------------------

/// Port of `manualEditApplyChunkSize(env)`. `raw` is the parsed
/// `IMPECCABLE_LIVE_MANUAL_EDIT_CHUNK_SIZE` env value (`None` when unset or
/// non-numeric, matching JS `Number.isFinite` on `Number(undefined)` = NaN).
pub fn manual_edit_apply_chunk_size(raw: Option<f64>) -> i64 {
    let raw = match raw {
        Some(v) if v.is_finite() => v,
        _ => return DEFAULT_MANUAL_EDIT_APPLY_CHUNK_SIZE,
    };
    let size = raw.trunc() as i64;
    size.clamp(
        MIN_MANUAL_EDIT_APPLY_CHUNK_SIZE,
        MAX_MANUAL_EDIT_APPLY_CHUNK_SIZE,
    )
}

/// Port of `countManualApplyOps(entriesOrBatch)`: accepts either a bare
/// entries array or `{ entries }`.
pub fn count_manual_apply_ops(batch: &Value) -> usize {
    let entries = if batch.is_array() {
        batch.as_array().cloned().unwrap_or_default()
    } else {
        batch
            .get("entries")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    entries
        .iter()
        .map(|entry| {
            entry
                .get("ops")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0)
        })
        .sum()
}

/// Port of `truncateManualApplyText(value, max)`.
pub fn truncate_manual_apply_text(value: Option<&str>, max: usize) -> Option<String> {
    value.map(|v| {
        if v.chars().count() > max {
            v.chars().take(max).collect()
        } else {
            v.to_string()
        }
    })
}

/// Port of `compactManualApplyContext(value)`.
pub fn compact_manual_apply_context(value: Option<&Value>) -> Option<Value> {
    let value = value?;
    if !value.is_object() {
        return None;
    }
    let text = value
        .get("textContent")
        .and_then(Value::as_str)
        .and_then(|s| truncate_manual_apply_text(Some(s), MANUAL_APPLY_COMPACT_TEXT_LIMIT));
    Some(serde_json::json!({
        "ref": value.get("ref").cloned().unwrap_or(Value::Null),
        "tagName": value.get("tagName").or_else(|| value.get("tag")).cloned().unwrap_or(Value::Null),
        "id": value.get("id").cloned().unwrap_or(Value::Null),
        "classes": value.get("classes").and_then(Value::as_array).cloned().unwrap_or_default(),
        "textContent": text,
    }))
}

/// Port of `summarizeManualLogFile(file, cwd)`. Returns `None` for
/// non-string/empty input, matching the JS `undefined` return.
pub fn summarize_manual_log_file(file: Option<&str>, cwd: &Path) -> Option<String> {
    let file = file?;
    if file.is_empty() {
        return None;
    }
    let path = Path::new(file);
    // `Path::is_absolute` requires a drive-letter prefix on Windows, so a
    // POSIX-style `/proj/root/...` fixture/test path (rooted but prefixless)
    // reads as relative there and skips relativization entirely. JS only
    // cares whether the path is rooted, so use `has_root` instead, which
    // agrees with `is_absolute` on Unix and on real Windows `C:\...` paths.
    if !path.has_root() {
        return Some(file.to_string());
    }
    match path.strip_prefix(cwd) {
        Ok(rel) if !rel.as_os_str().is_empty() => {
            let rel_str = rel.to_string_lossy().to_string();
            if !rel_str.starts_with("..") {
                Some(rel_str)
            } else {
                Some(file.to_string())
            }
        }
        _ => Some(file.to_string()),
    }
}

/// Port of `compactManualLogText(value, max = 200)`. Collapses runs of
/// whitespace to single spaces and trims, then truncates with the same
/// `"... [truncated N chars]"` suffix.
pub fn compact_manual_log_text(value: Option<&str>, max: usize) -> Option<String> {
    let value = value?;
    let normalized: String = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let normalized = normalized.trim().to_string();
    if normalized.chars().count() <= max {
        return Some(normalized);
    }
    let truncated_len = normalized.chars().count() - max;
    let head: String = normalized.chars().take(max).collect();
    Some(format!("{head}... [truncated {truncated_len} chars]"))
}

// ---------------------------------------------------------------------
// r29: batch compaction (compactManualApplyBatch and friends)
// ---------------------------------------------------------------------

/// Port of `compactManualApplyBatch(batch, cwd)`.
pub fn compact_manual_apply_batch(batch: &Value, cwd: &Path) -> Value {
    let raw_entries: Vec<Value> = batch
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let entries: Vec<Value> = raw_entries.iter().map(compact_manual_apply_entry).collect();

    let candidates = compact_manual_apply_candidates(
        batch.get("candidates").and_then(Value::as_array),
        cwd,
    );

    let ops: Vec<Value> = entries
        .iter()
        .flat_map(|entry| {
            let entry_id = entry.get("id").cloned().unwrap_or(Value::Null);
            entry
                .get("ops")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(move |mut op| {
                    if let Value::Object(map) = &mut op {
                        map.insert("entryId".to_string(), entry_id.clone());
                    }
                    op
                })
        })
        .collect();

    let context = batch.get("context").and_then(Value::as_object).map(|ctx| {
        serde_json::json!({
            "bufferPath": ctx.get("bufferPath").cloned().unwrap_or(Value::Null),
            "totalEntries": ctx.get("totalEntries").cloned().unwrap_or(Value::Null),
            "totalOps": ctx.get("totalOps").cloned().unwrap_or(Value::Null),
            "chunkIndex": ctx.get("chunkIndex").cloned().unwrap_or(Value::Null),
            "chunkTotal": ctx.get("chunkTotal").cloned().unwrap_or(Value::Null),
            "totalApplyOps": ctx.get("totalApplyOps").cloned().unwrap_or(Value::Null),
        })
    });

    let mut out = serde_json::json!({
        "version": batch.get("version").cloned().unwrap_or(Value::Null),
        "pageUrl": batch.get("pageUrl").cloned().unwrap_or(Value::Null),
        "count": batch.get("count").cloned().unwrap_or(Value::Null),
        "entries": entries,
        "ops": ops,
    });
    if !candidates.is_empty() {
        out["candidates"] = Value::Array(candidates);
    }
    if let Some(ctx) = context {
        out["context"] = ctx;
    }
    out
}

/// Port of `compactManualApplyCandidates(candidates, cwd)`.
pub fn compact_manual_apply_candidates(
    candidates: Option<&Vec<Value>>,
    cwd: &Path,
) -> Vec<Value> {
    candidates
        .map(|c| c.as_slice())
        .unwrap_or(&[])
        .iter()
        .take(24)
        .map(|candidate| {
            serde_json::json!({
                "entryId": candidate.get("entryId").cloned().unwrap_or(Value::Null),
                "ref": candidate.get("ref").cloned().unwrap_or(Value::Null),
                "sourceHint": compact_manual_apply_source_match(candidate.get("sourceHint"), cwd),
                "textMatches": compact_manual_apply_source_matches(candidate.get("textMatches").and_then(Value::as_array), 8, cwd),
                "objectKeyMatches": compact_manual_apply_source_matches(candidate.get("objectKeyMatches").and_then(Value::as_array), 8, cwd),
                "contextTextMatches": compact_manual_apply_source_matches(candidate.get("contextTextMatches").and_then(Value::as_array), 8, cwd),
                "locatorMatches": compact_manual_apply_source_matches(candidate.get("locatorMatches").and_then(Value::as_array), 6, cwd),
            })
        })
        .collect()
}

fn compact_manual_apply_source_matches(
    matches: Option<&Vec<Value>>,
    limit: usize,
    cwd: &Path,
) -> Vec<Value> {
    matches
        .map(|m| m.as_slice())
        .unwrap_or(&[])
        .iter()
        .take(limit)
        .filter_map(|m| compact_manual_apply_source_match(Some(m), cwd))
        .collect()
}

/// Port of `compactManualApplySourceMatch(match, cwd)`.
fn compact_manual_apply_source_match(m: Option<&Value>, cwd: &Path) -> Option<Value> {
    let m = m?;
    if !m.is_object() {
        return None;
    }
    let file = m
        .get("relativeFile")
        .and_then(Value::as_str)
        .or_else(|| m.get("file").and_then(Value::as_str));
    let line = m.get("line");
    let has_line = line.map(|v| !v.is_null()).unwrap_or(false);
    if file.is_none() && !has_line {
        return None;
    }
    Some(serde_json::json!({
        "file": summarize_manual_log_file(file, cwd),
        "line": m.get("line").cloned().filter(|v| !v.is_null()).unwrap_or(Value::Null),
        "column": m.get("column").cloned().filter(|v| !v.is_null()).unwrap_or(Value::Null),
        "reason": m.get("reason").cloned().or_else(|| m.get("kind").cloned()).unwrap_or(Value::Null),
        "status": m.get("status").cloned().unwrap_or(Value::Null),
    }))
}

/// Port of `compactManualApplyEntry(entry)`.
fn compact_manual_apply_entry(entry: &Value) -> Value {
    let ops: Vec<Value> = entry
        .get("ops")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(compact_manual_apply_op)
        .collect();
    serde_json::json!({
        "id": entry.get("id").cloned().unwrap_or(Value::Null),
        "pageUrl": entry.get("pageUrl").cloned().unwrap_or(Value::Null),
        "stagedAt": entry.get("stagedAt").cloned().filter(|v| !v.is_null()).unwrap_or(Value::Null),
        "element": compact_manual_apply_context(entry.get("element")).unwrap_or(Value::Null),
        "ops": ops,
    })
}

/// Port of `compactManualApplyOp(op)`.
fn compact_manual_apply_op(op: &Value) -> Value {
    let mut out = serde_json::json!({
        "entryId": op.get("entryId").cloned().unwrap_or(Value::Null),
        "ref": op.get("ref").cloned().unwrap_or(Value::Null),
        "contextRef": op.get("contextRef").cloned().unwrap_or(Value::Null),
        "tag": op.get("tag").cloned().unwrap_or(Value::Null),
        "elementId": op.get("elementId").cloned().unwrap_or(Value::Null),
        "classes": op.get("classes").and_then(Value::as_array).cloned().unwrap_or_default(),
        "originalText": op.get("originalText").cloned().unwrap_or(Value::Null),
        "newText": op.get("newText").cloned().unwrap_or(Value::Null),
        "sourceHint": op.get("sourceHint").cloned().unwrap_or(Value::Null),
        "leaf": compact_manual_apply_context(op.get("leaf")).unwrap_or(Value::Null),
        "nearbyEditableTexts": compact_nearby_manual_edit_texts(op.get("nearbyEditableTexts").and_then(Value::as_array)),
        "container": compact_manual_apply_context(op.get("container")).unwrap_or(Value::Null),
    });
    let deleted = op.get("deleted").and_then(Value::as_bool).unwrap_or(false);
    if deleted {
        out["deleted"] = Value::Bool(true);
    }
    if let Some(hints) = op.get("contextHints").and_then(Value::as_array) {
        out["contextHints"] = Value::Array(hints.iter().take(8).cloned().collect());
    }
    out
}

/// Port of `compactNearbyManualEditTexts(items)`.
fn compact_nearby_manual_edit_texts(items: Option<&Vec<Value>>) -> Vec<Value> {
    items
        .map(|i| i.as_slice())
        .unwrap_or(&[])
        .iter()
        .take(MANUAL_APPLY_COMPACT_NEARBY_LIMIT)
        .map(|item| {
            if let Some(s) = item.as_str() {
                serde_json::json!({ "text": truncate_manual_apply_text(Some(s), MANUAL_APPLY_COMPACT_TEXT_LIMIT) })
            } else {
                serde_json::json!({
                    "ref": item.get("ref").cloned().unwrap_or(Value::Null),
                    "tag": item.get("tag").cloned().unwrap_or(Value::Null),
                    "classes": item.get("classes").and_then(Value::as_array).cloned().unwrap_or_default(),
                    "text": truncate_manual_apply_text(item.get("text").and_then(Value::as_str), MANUAL_APPLY_COMPACT_TEXT_LIMIT),
                })
            }
        })
        .collect()
}

// ---------------------------------------------------------------------
// r29: file collection / project-relative path guards
// ---------------------------------------------------------------------

/// Port of `normalizeProjectFile(file, cwd)`.
pub fn normalize_project_file(file: Option<&str>, cwd: &Path) -> Option<String> {
    let file = file?;
    if file.is_empty() {
        return None;
    }
    let absolute = if Path::new(file).is_absolute() {
        PathBuf::from(file)
    } else {
        cwd.join(file)
    };
    let relative = pathdiff_relative(&absolute, cwd)?;
    if relative.as_os_str().is_empty()
        || relative.to_string_lossy().starts_with("..")
        || relative.is_absolute()
    {
        return None;
    }
    Some(relative.to_string_lossy().to_string())
}

/// Minimal `path.relative`-equivalent for two paths that (after joining
/// against `cwd`) may not both exist on disk, so `Path::strip_prefix` (which
/// requires a literal component match) is used directly since callers always
/// build `absolute` by joining onto `cwd`.
fn pathdiff_relative(absolute: &Path, cwd: &Path) -> Option<PathBuf> {
    absolute
        .strip_prefix(cwd)
        .map(PathBuf::from)
        .ok()
        .or_else(|| Some(absolute.to_path_buf()))
}

/// Port of `collectManualApplyFiles(batch, extraFiles, cwd)`.
pub fn collect_manual_apply_files(batch: &Value, extra_files: &[String], cwd: &Path) -> Vec<String> {
    let mut files: Vec<String> = Vec::new();
    for entry in batch.get("entries").and_then(Value::as_array).into_iter().flatten() {
        for op in entry.get("ops").and_then(Value::as_array).into_iter().flatten() {
            if let Some(f) = op
                .get("sourceHint")
                .and_then(|sh| sh.get("file"))
                .and_then(Value::as_str)
            {
                files.push(f.to_string());
            }
        }
    }
    for candidate in batch.get("candidates").and_then(Value::as_array).into_iter().flatten() {
        if let Some(sh) = candidate.get("sourceHint") {
            if let Some(f) = sh.get("relativeFile").and_then(Value::as_str) {
                files.push(f.to_string());
            }
            if let Some(f) = sh.get("file").and_then(Value::as_str) {
                files.push(f.to_string());
            }
        }
        for key in ["textMatches", "objectKeyMatches", "locatorMatches", "contextTextMatches"] {
            for item in candidate.get(key).and_then(Value::as_array).into_iter().flatten() {
                if let Some(f) = item.get("file").and_then(Value::as_str) {
                    files.push(f.to_string());
                }
            }
        }
    }
    files.extend(extra_files.iter().cloned());

    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for f in files {
        if seen.insert(f.clone()) {
            if let Some(rel) = normalize_project_file(Some(&f), cwd) {
                out.push(rel);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------
// r29: evidence file I/O
// ---------------------------------------------------------------------

/// Port of `manualApplyEvidenceDir(cwd)`.
pub fn manual_apply_evidence_dir(cwd: &Path) -> PathBuf {
    get_live_dir(cwd).join("manual-edit-evidence")
}

/// Port of `writeManualApplyEvidence(eventId, batch, cwd)`.
pub fn write_manual_apply_evidence(event_id: &str, batch: &Value, cwd: &Path) -> std::io::Result<PathBuf> {
    let dir = manual_apply_evidence_dir(cwd);
    fs::create_dir_all(&dir)?;
    let evidence_path = dir.join(format!("{event_id}.json"));
    let mut text = serde_json::to_string_pretty(batch).unwrap();
    text.push('\n');
    fs::write(&evidence_path, text)?;
    Ok(evidence_path)
}

/// Port of `normalizeManualApplyEvidencePath(evidencePath, cwd)`.
pub fn normalize_manual_apply_evidence_path(evidence_path: Option<&str>, cwd: &Path) -> Option<PathBuf> {
    let evidence_path = evidence_path?;
    if evidence_path.is_empty() {
        return None;
    }
    let full_path = if Path::new(evidence_path).is_absolute() {
        PathBuf::from(evidence_path)
    } else {
        cwd.join(evidence_path)
    };
    let evidence_dir = manual_apply_evidence_dir(cwd);
    let relative = pathdiff_relative(&full_path, &evidence_dir)?;
    if relative.as_os_str().is_empty()
        || relative.to_string_lossy().starts_with("..")
        || relative.is_absolute()
    {
        return None;
    }
    if full_path.extension().and_then(|e| e.to_str()) != Some("json") {
        return None;
    }
    Some(full_path)
}

/// Port of `removeManualApplyEvidence(evidencePath, cwd)`.
pub fn remove_manual_apply_evidence(evidence_path: Option<&str>, cwd: &Path) -> bool {
    match normalize_manual_apply_evidence_path(evidence_path, cwd) {
        Some(full_path) => fs::remove_file(full_path).is_ok(),
        None => false,
    }
}

// ---------------------------------------------------------------------
// r29: file snapshot / rollback
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SnapshotFile {
    pub exists: bool,
    pub content: String,
}

/// Port of `snapshotApplyEventFiles(batch, cwd)`.
pub fn snapshot_apply_event_files(batch: &Value, cwd: &Path) -> HashMap<String, SnapshotFile> {
    let mut snapshot = HashMap::new();
    for relative_file in collect_manual_apply_files(batch, &[], cwd) {
        let absolute = cwd.join(&relative_file);
        let exists = absolute.exists();
        let content = if exists {
            fs::read_to_string(&absolute).unwrap_or_default()
        } else {
            String::new()
        };
        snapshot.insert(relative_file, SnapshotFile { exists, content });
    }
    snapshot
}

#[derive(Debug, Clone, Default)]
pub struct RollbackResult {
    pub rolled_back_files: Vec<String>,
    pub rollback_failures: Vec<Value>,
}

/// Port of `rollbackApplySnapshot(batch, rollbackSnapshot, extraFiles, reason, cwd)`.
pub fn rollback_apply_snapshot(
    batch: &Value,
    rollback_snapshot: &HashMap<String, SnapshotFile>,
    extra_files: &[String],
    cwd: &Path,
) -> RollbackResult {
    let scope = collect_manual_apply_files(batch, extra_files, cwd);
    let mut result = RollbackResult::default();
    for relative_file in scope {
        let Some(before) = rollback_snapshot.get(&relative_file) else {
            continue;
        };
        let absolute = cwd.join(&relative_file);
        let outcome = (|| -> std::io::Result<()> {
            if before.exists {
                if let Some(parent) = absolute.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&absolute, &before.content)?;
            } else if absolute.exists() {
                fs::remove_file(&absolute)?;
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => result.rolled_back_files.push(relative_file),
            Err(err) => result.rollback_failures.push(serde_json::json!({
                "file": relative_file,
                "reason": "restore_failed",
                "message": err.to_string(),
            })),
        }
    }
    result
}

// ---------------------------------------------------------------------
// r29: transaction file I/O
// ---------------------------------------------------------------------

/// Port of `manualApplyTransactionPath(cwd)`.
pub fn manual_apply_transaction_path(cwd: &Path) -> PathBuf {
    get_live_dir(cwd).join("manual-edit-apply-transaction.json")
}

/// Port of `readManualApplyTransaction(cwd)`.
pub fn read_manual_apply_transaction(cwd: &Path) -> Option<Value> {
    let file = manual_apply_transaction_path(cwd);
    let raw = fs::read_to_string(file).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Port of `writeManualApplyTransaction({ cwd, pageUrl, batch })`.
pub fn write_manual_apply_transaction(cwd: &Path, page_url: Option<&str>, batch: &Value) -> std::io::Result<Value> {
    let file = manual_apply_transaction_path(cwd);
    let files = collect_manual_apply_files(batch, &[], cwd);
    let file_entries: Vec<Value> = files
        .iter()
        .map(|relative_file| {
            let absolute = cwd.join(relative_file);
            let exists = absolute.exists();
            let content = if exists {
                fs::read_to_string(&absolute).unwrap_or_default()
            } else {
                String::new()
            };
            serde_json::json!({ "file": relative_file, "exists": exists, "content": content })
        })
        .collect();
    let entry_ids: Vec<Value> = batch
        .get("entries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|e| e.get("id").cloned())
        .filter(|v| !v.is_null())
        .collect();
    let transaction = serde_json::json!({
        "version": 1,
        "id": new_short_id(),
        "createdAt": crate::wf_port::w2_021::manual_edits_buffer::now_iso(),
        "pageUrl": page_url,
        "entryIds": entry_ids,
        "files": file_entries,
    });
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = file.with_extension("json.tmp");
    let mut text = serde_json::to_string_pretty(&transaction).unwrap();
    text.push('\n');
    fs::write(&tmp, text)?;
    fs::rename(&tmp, &file)?;
    Ok(transaction)
}

/// Port of `clearManualApplyTransaction(cwd, transactionId)`.
pub fn clear_manual_apply_transaction(cwd: &Path, transaction_id: Option<&str>) -> bool {
    let file = manual_apply_transaction_path(cwd);
    if !file.exists() {
        return false;
    }
    if let Some(tid) = transaction_id {
        if let Some(existing) = read_manual_apply_transaction(cwd) {
            if let Some(existing_id) = existing.get("id").and_then(Value::as_str) {
                if existing_id != tid {
                    return false;
                }
            }
        }
    }
    fs::remove_file(file).is_ok()
}

/// Port of `rollbackManualApplyTransaction({ cwd, pageUrl, reason })`. The
/// `recordManualEditActivity` callback is invoked when supplied, mirroring
/// the JS optional-callback (`recordManualEditActivity?.(...)`) pattern.
pub fn rollback_manual_apply_transaction(
    cwd: &Path,
    page_url: Option<&str>,
    reason: &str,
    mut record_activity: Option<&mut dyn FnMut(&str, Value)>,
) -> Option<Value> {
    let transaction = read_manual_apply_transaction(cwd)?;
    let tx_page_url = transaction.get("pageUrl").and_then(Value::as_str);
    if let (Some(pu), Some(tx_pu)) = (page_url, tx_page_url) {
        if pu != tx_pu {
            return None;
        }
    }

    let tx_entry_ids: Vec<String> = transaction
        .get("entryIds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    let pending_ids: std::collections::HashSet<String> = {
        let buffer = read_manual_edits_buffer(cwd);
        buffer.entries.into_iter().filter_map(|e| e.id).collect()
    };
    let tx_id = transaction.get("id").and_then(Value::as_str).map(str::to_string);
    let should_rollback = tx_entry_ids.iter().any(|id| pending_ids.contains(id));
    if !should_rollback {
        clear_manual_apply_transaction(cwd, tx_id.as_deref());
        return Some(serde_json::json!({
            "id": tx_id,
            "reason": reason,
            "rolledBackFiles": [],
            "rollbackFailures": [],
            "skipped": "entries_not_pending",
        }));
    }

    let mut rolled_back_files = Vec::new();
    let mut rollback_failures = Vec::new();
    for item in transaction.get("files").and_then(Value::as_array).into_iter().flatten() {
        let Some(relative_file) = item.get("file").and_then(Value::as_str).and_then(|f| normalize_project_file(Some(f), cwd)) else {
            continue;
        };
        let absolute = cwd.join(&relative_file);
        let exists_flag = item.get("exists").and_then(Value::as_bool).unwrap_or(false);
        let content = item.get("content").and_then(Value::as_str).unwrap_or("");
        let outcome = (|| -> std::io::Result<()> {
            if exists_flag {
                if let Some(parent) = absolute.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&absolute, content)?;
            } else if absolute.exists() {
                fs::remove_file(&absolute)?;
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => rolled_back_files.push(relative_file),
            Err(err) => rollback_failures.push(serde_json::json!({
                "file": relative_file,
                "reason": "restore_failed",
                "message": err.to_string(),
            })),
        }
    }
    clear_manual_apply_transaction(cwd, tx_id.as_deref());

    if let Some(cb) = record_activity.as_deref_mut() {
        cb(
            "manual_edit_transaction_rolled_back",
            serde_json::json!({
                "id": tx_id,
                "pageUrl": transaction.get("pageUrl").cloned().unwrap_or(Value::Null),
                "reason": reason,
                "entryIds": tx_entry_ids,
                "rolledBackFiles": rolled_back_files.iter().filter_map(|f| summarize_manual_log_file(Some(f), cwd)).collect::<Vec<_>>(),
                "rollbackFailures": summarize_manual_diagnostics(&rollback_failures, cwd),
            }),
        );
    }

    Some(serde_json::json!({
        "id": tx_id,
        "reason": reason,
        "rolledBackFiles": rolled_back_files,
        "rollbackFailures": rollback_failures,
    }))
}

// ---------------------------------------------------------------------
// r29: chunk splitting
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ManualApplyChunk {
    pub batch: Value,
    pub meta: Option<Value>,
    pub entry_ids: std::collections::HashSet<String>,
    pub op_counts_by_entry: HashMap<String, usize>,
}

struct ChunkBuilder {
    entries: Vec<Value>,
    entry_index_by_id: HashMap<String, usize>,
    entry_ids: Vec<String>,
    ops: Vec<Value>,
    refs_by_entry: HashMap<String, std::collections::HashSet<String>>,
    op_counts_by_entry: HashMap<String, usize>,
    op_count: usize,
}

impl ChunkBuilder {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            entry_index_by_id: HashMap::new(),
            entry_ids: Vec::new(),
            ops: Vec::new(),
            refs_by_entry: HashMap::new(),
            op_counts_by_entry: HashMap::new(),
            op_count: 0,
        }
    }

    fn add(&mut self, entry: &Value, op: &Value) {
        let entry_id = entry.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        let idx = if let Some(&idx) = self.entry_index_by_id.get(&entry_id) {
            idx
        } else {
            let mut chunk_entry = entry.clone();
            chunk_entry["ops"] = Value::Array(vec![]);
            self.entries.push(chunk_entry);
            let idx = self.entries.len() - 1;
            self.entry_index_by_id.insert(entry_id.clone(), idx);
            self.entry_ids.push(entry_id.clone());
            idx
        };
        if let Some(arr) = self.entries[idx].get_mut("ops").and_then(Value::as_array_mut) {
            arr.push(op.clone());
        }
        let mut op_with_entry_id = op.clone();
        if let Value::Object(map) = &mut op_with_entry_id {
            let has_entry_id = map.get("entryId").map(|v| !v.is_null()).unwrap_or(false);
            if !has_entry_id {
                map.insert("entryId".to_string(), Value::String(entry_id.clone()));
            }
        }
        self.ops.push(op_with_entry_id);
        let refs = self.refs_by_entry.entry(entry_id.clone()).or_default();
        if let Some(r) = op.get("ref").and_then(Value::as_str) {
            refs.insert(r.to_string());
        }
        *self.op_counts_by_entry.entry(entry_id).or_insert(0) += 1;
        self.op_count += 1;
    }
}

fn filter_manual_apply_chunk_candidates(
    batch: &Value,
    refs_by_entry: &HashMap<String, std::collections::HashSet<String>>,
) -> Vec<Value> {
    batch
        .get("candidates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|candidate| {
            let entry_id = candidate.get("entryId").and_then(Value::as_str).unwrap_or("");
            let Some(refs) = refs_by_entry.get(entry_id) else {
                return false;
            };
            match candidate.get("ref").and_then(Value::as_str) {
                None => true,
                Some(r) => refs.contains(r),
            }
        })
        .cloned()
        .collect()
}

/// Port of `splitManualApplyBatch(batch, maxOps)`.
pub fn split_manual_apply_batch(batch: &Value, max_ops: usize) -> Vec<ManualApplyChunk> {
    let total_op_count = count_manual_apply_ops(batch);
    let entries: Vec<Value> = batch
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if total_op_count <= max_ops {
        let entry_ids: std::collections::HashSet<String> = entries
            .iter()
            .filter_map(|e| e.get("id").and_then(Value::as_str).map(str::to_string))
            .collect();
        let op_counts_by_entry: HashMap<String, usize> = entries
            .iter()
            .map(|e| {
                let id = e.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                let n = e.get("ops").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
                (id, n)
            })
            .collect();
        return vec![ManualApplyChunk {
            batch: batch.clone(),
            meta: None,
            entry_ids,
            op_counts_by_entry,
        }];
    }

    let mut raw_chunks: Vec<ChunkBuilder> = Vec::new();
    let mut current = ChunkBuilder::new();
    for entry in &entries {
        let ops: Vec<Value> = entry.get("ops").and_then(Value::as_array).cloned().unwrap_or_default();
        if ops.len() <= max_ops {
            if current.op_count > 0 && current.op_count + ops.len() > max_ops {
                raw_chunks.push(current);
                current = ChunkBuilder::new();
            }
            for op in &ops {
                current.add(entry, op);
            }
            continue;
        }
        if current.op_count > 0 {
            raw_chunks.push(current);
            current = ChunkBuilder::new();
        }
        for op in &ops {
            if current.op_count >= max_ops {
                raw_chunks.push(current);
                current = ChunkBuilder::new();
            }
            current.add(entry, op);
        }
    }
    if current.op_count > 0 {
        raw_chunks.push(current);
    }

    let raw_total = raw_chunks.len();
    raw_chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            let candidates = filter_manual_apply_chunk_candidates(batch, &chunk.refs_by_entry);
            let mut chunk_batch = batch.clone();
            chunk_batch["count"] = Value::from(chunk.op_count);
            chunk_batch["entries"] = Value::Array(chunk.entries.clone());
            chunk_batch["ops"] = Value::Array(chunk.ops.clone());
            chunk_batch["candidates"] = Value::Array(candidates);
            let base_context = batch.get("context").cloned().unwrap_or_else(|| serde_json::json!({}));
            let mut context = base_context;
            context["totalEntries"] = Value::from(chunk.entries.len());
            context["totalOps"] = Value::from(chunk.op_count);
            context["chunkIndex"] = Value::from(index + 1);
            context["chunkTotal"] = Value::from(raw_total);
            context["totalApplyOps"] = Value::from(total_op_count);
            chunk_batch["context"] = context;

            let meta = serde_json::json!({
                "index": index + 1,
                "total": raw_total,
                "opCount": chunk.op_count,
                "totalOpCount": total_op_count,
            });

            ManualApplyChunk {
                batch: chunk_batch,
                meta: Some(meta),
                entry_ids: chunk.entry_ids.into_iter().collect(),
                op_counts_by_entry: chunk.op_counts_by_entry,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------
// r29: result validation
// ---------------------------------------------------------------------

/// Port of `manualApplyResultShapeHint(eventId)`.
pub fn manual_apply_result_shape_hint(event_id: &str) -> String {
    format!(
        "Use live-poll.mjs --reply {event_id} done --data '{{\"status\":\"done\",\"appliedEntryIds\":[\"ENTRY_ID\"],\"failed\":[],\"files\":[\"src/page.html\"],\"notes\":[]}}'"
    )
}

/// Port of `invalidManualApplyResult(reason, eventId, extra)`.
pub fn invalid_manual_apply_result(reason: &str, event_id: &str, extra: Value) -> Value {
    let mut body = serde_json::json!({
        "error": "invalid_manual_apply_result",
        "reason": reason,
        "hint": manual_apply_result_shape_hint(event_id),
    });
    if let (Value::Object(base), Value::Object(more)) = (&mut body, &extra) {
        for (k, v) in more {
            base.insert(k.clone(), v.clone());
        }
    }
    serde_json::json!({ "ok": false, "body": body })
}

/// Port of `validateManualApplyResultMessage(msg, deferred)`. `deferred`'s
/// batch is passed as `deferred_batch` since the full deferred bookkeeping
/// object is ported separately as [`DeferredApply`].
pub fn validate_manual_apply_result_message(
    msg: &Value,
    deferred_event_id: Option<&str>,
    deferred_batch: Option<&Value>,
) -> Result<Value, Value> {
    let msg_id = msg.get("id").and_then(Value::as_str);
    let event_id = msg_id.or(deferred_event_id).unwrap_or("EVENT_ID");
    let data = msg.get("data");
    let data = match data {
        Some(d) if d.is_object() => d,
        _ => return Err(invalid_manual_apply_result("missing_result_data", event_id, Value::Null)),
    };
    if data.get("entries").is_some() || data.get("ops").is_some() {
        return Err(invalid_manual_apply_result("summary_result_not_allowed", event_id, Value::Null));
    }
    let status = data.get("status").and_then(Value::as_str);
    if !matches!(status, Some("done") | Some("partial") | Some("error")) {
        return Err(invalid_manual_apply_result(
            "invalid_status",
            event_id,
            serde_json::json!({ "status": data.get("status").cloned().unwrap_or(Value::Null) }),
        ));
    }
    let status = status.unwrap();

    for key in ["appliedEntryIds", "failed", "files", "notes"] {
        if !matches!(data.get(key), Some(Value::Array(_))) {
            return Err(invalid_manual_apply_result(&format!("{key}_must_be_array"), event_id, Value::Null));
        }
    }

    let applied_entry_ids = data.get("appliedEntryIds").and_then(Value::as_array).unwrap();
    for (index, value) in applied_entry_ids.iter().enumerate() {
        if !matches!(value, Value::String(s) if !s.is_empty()) {
            return Err(invalid_manual_apply_result(
                "appliedEntryIds_must_contain_strings",
                event_id,
                serde_json::json!({ "index": index }),
            ));
        }
    }
    let files = data.get("files").and_then(Value::as_array).unwrap();
    for (index, value) in files.iter().enumerate() {
        if !matches!(value, Value::String(s) if !s.is_empty()) {
            return Err(invalid_manual_apply_result(
                "files_must_contain_strings",
                event_id,
                serde_json::json!({ "index": index }),
            ));
        }
    }
    let notes = data.get("notes").and_then(Value::as_array).unwrap();
    for (index, value) in notes.iter().enumerate() {
        if !value.is_string() {
            return Err(invalid_manual_apply_result(
                "notes_must_contain_strings",
                event_id,
                serde_json::json!({ "index": index }),
            ));
        }
    }
    let failed = data.get("failed").and_then(Value::as_array).unwrap();
    for (index, item) in failed.iter().enumerate() {
        if !item.is_object() {
            return Err(invalid_manual_apply_result(
                "failed_must_contain_objects",
                event_id,
                serde_json::json!({ "index": index }),
            ));
        }
        if !matches!(item.get("entryId"), Some(Value::String(s)) if !s.is_empty()) {
            return Err(invalid_manual_apply_result(
                "failed_entryId_required",
                event_id,
                serde_json::json!({ "index": index }),
            ));
        }
        if !matches!(item.get("reason"), Some(Value::String(s)) if !s.is_empty()) {
            return Err(invalid_manual_apply_result(
                "failed_reason_required",
                event_id,
                serde_json::json!({ "index": index }),
            ));
        }
    }

    let event_entry_ids: std::collections::HashSet<&str> = deferred_batch
        .and_then(|b| b.get("entries"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|e| e.get("id").and_then(Value::as_str))
        .collect();
    for entry_id in applied_entry_ids.iter().filter_map(Value::as_str) {
        if !event_entry_ids.is_empty() && !event_entry_ids.contains(entry_id) {
            return Err(invalid_manual_apply_result(
                "applied_entry_id_not_in_event",
                event_id,
                serde_json::json!({ "entryId": entry_id }),
            ));
        }
    }
    for item in failed {
        let entry_id = item.get("entryId").and_then(Value::as_str).unwrap_or("");
        if !event_entry_ids.is_empty() && !event_entry_ids.contains(entry_id) {
            return Err(invalid_manual_apply_result(
                "failed_entry_id_not_in_event",
                event_id,
                serde_json::json!({ "entryId": entry_id }),
            ));
        }
    }

    if status == "done" {
        if !failed.is_empty() {
            return Err(invalid_manual_apply_result("done_result_has_failed_entries", event_id, Value::Null));
        }
        let batch_op_count = deferred_batch.map(count_manual_apply_ops).unwrap_or(0);
        if batch_op_count > 0 && applied_entry_ids.is_empty() {
            return Err(invalid_manual_apply_result(
                "done_result_missing_applied_entry_ids",
                event_id,
                Value::Null,
            ));
        }
    }
    if status == "partial" && applied_entry_ids.is_empty() && failed.is_empty() {
        return Err(invalid_manual_apply_result("partial_result_has_no_entries", event_id, Value::Null));
    }
    if status == "error" && !applied_entry_ids.is_empty() {
        return Err(invalid_manual_apply_result("error_result_has_applied_entries", event_id, Value::Null));
    }

    Ok(serde_json::json!({
        "status": status,
        "message": data.get("message").and_then(Value::as_str),
        "appliedEntryIds": applied_entry_ids,
        "failed": failed,
        "files": files,
        "notes": notes,
    }))
}

/// Port of `normalizeApplyChunkResult(result)`.
pub fn normalize_apply_chunk_result(result: &Value) -> Value {
    let status = match result.get("status").and_then(Value::as_str) {
        Some("partial") => "partial",
        Some("error") => "error",
        _ => "done",
    };
    let message = result.get("message").and_then(Value::as_str);
    let applied_entry_ids: Vec<Value> = result
        .get("appliedEntryIds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|v| v.is_string())
        .cloned()
        .collect();
    let failed: Vec<Value> = result
        .get("failed")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|v| !v.is_null())
        .cloned()
        .collect();
    let files: Vec<Value> = result
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|v| v.is_string())
        .cloned()
        .collect();
    let notes: Vec<Value> = result
        .get("notes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|v| v.is_string())
        .cloned()
        .collect();
    serde_json::json!({
        "status": status,
        "message": message,
        "appliedEntryIds": applied_entry_ids,
        "failed": failed,
        "files": files,
        "notes": notes,
    })
}

fn first_failure_reason(result: &Value) -> Option<String> {
    result
        .get("failed")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|v| !v.is_null())
        .and_then(|item| {
            item.get("reason")
                .and_then(Value::as_str)
                .or_else(|| item.get("message").and_then(Value::as_str))
        })
        .map(str::to_string)
}

// ---------------------------------------------------------------------
// r29: agent-action / summary helpers
// ---------------------------------------------------------------------

/// Port of `manualApplyReplyCommand(eventOrId)`.
pub fn manual_apply_reply_command(event_id: &str) -> String {
    format!("live-poll.mjs --reply {event_id} done --data '<json>'")
}

/// Port of `buildManualApplyAgentAction(eventOrId)`.
pub fn build_manual_apply_agent_action(event_id: &str) -> Value {
    serde_json::json!({
        "kind": "manual_edit_apply",
        "required": "apply_source_edits_then_reply",
        "replyCommand": manual_apply_reply_command(event_id),
        "warning": "Polling only leases this work item; it does not commit source edits.",
    })
}

/// Port of `summarizeManualApplyEvent(event, batch, cwd)`.
pub fn summarize_manual_apply_event(event: &Value, batch: &Value, cwd: &Path) -> Value {
    let entries = batch.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();
    let op_count: usize = entries
        .iter()
        .map(|e| e.get("ops").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0))
        .sum();
    serde_json::json!({
        "pageUrl": event.get("pageUrl").cloned().unwrap_or(Value::Null),
        "chunk": event.get("chunk").cloned().unwrap_or(Value::Null),
        "entryCount": entries.len(),
        "opCount": op_count,
        "files": collect_manual_apply_files(batch, &[], cwd),
    })
}

/// Port of `summarizeManualDiagnostics(items, cwd)`. Returns `None` for an
/// empty/missing list, matching JS `undefined`.
pub fn summarize_manual_diagnostics(items: &[Value], cwd: &Path) -> Option<Vec<Value>> {
    if items.is_empty() {
        return None;
    }
    Some(
        items
            .iter()
            .take(12)
            .map(|item| {
                serde_json::json!({
                    "reason": item.get("reason").cloned().or_else(|| item.get("kind").cloned()),
                    "detail": compact_manual_log_text(item.get("detail").and_then(Value::as_str), 220),
                    "message": compact_manual_log_text(item.get("message").and_then(Value::as_str), 300),
                    "file": summarize_manual_log_file(item.get("file").and_then(Value::as_str).or_else(|| item.get("relativeFile").and_then(Value::as_str)), cwd),
                    "line": item.get("line").cloned(),
                    "ref": compact_manual_log_text(item.get("ref").and_then(Value::as_str), 180),
                    "marker": compact_manual_log_text(item.get("marker").and_then(Value::as_str), 120),
                    "files": item.get("files").and_then(Value::as_array).map(|fs_| {
                        fs_.iter().take(8).filter_map(|f| summarize_manual_log_file(f.as_str(), cwd)).collect::<Vec<_>>()
                    }),
                })
            })
            .collect(),
    )
}

/// Port of `summarizeManualApplyFailures(failed, cwd)`.
pub fn summarize_manual_apply_failures(failed: &[Value], cwd: &Path) -> Vec<Value> {
    failed
        .iter()
        .take(20)
        .map(|item| {
            serde_json::json!({
                "id": item.get("id").cloned().or_else(|| item.get("entryId").cloned()),
                "reason": item.get("reason").and_then(Value::as_str).or_else(|| item.get("message").and_then(Value::as_str)).unwrap_or("failed"),
                "message": compact_manual_log_text(item.get("message").and_then(Value::as_str), 300),
                "files": item.get("files").and_then(Value::as_array).map(|fs_| {
                    fs_.iter().take(12).filter_map(|f| summarize_manual_log_file(f.as_str(), cwd)).collect::<Vec<_>>()
                }),
                "checks": item.get("checks").and_then(Value::as_array).map(|c| summarize_manual_diagnostics(c, cwd)),
                "failures": item.get("failures").and_then(Value::as_array).map(|c| summarize_manual_diagnostics(c, cwd)),
                "candidates": item.get("candidates").and_then(Value::as_array).map(|c| summarize_manual_diagnostics(c, cwd)),
            })
        })
        .collect()
}

fn new_short_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as u128;
    format!("{:08x}", (nanos ^ (pid << 32) ^ (seq as u128)) as u32)
}

// ---------------------------------------------------------------------
// r29: the stateful controller (createManualApplyController)
// ---------------------------------------------------------------------

/// Injected side effects, matching the JS constructor's
/// `{ enqueueEvent, acknowledgePendingEvent, flushPendingPolls,
/// recordManualEditActivity }` callbacks (owned by `live.mjs`, outside this
/// chunk). Implementations used in tests are fakes recording calls; the real
/// wiring (HTTP long-poll queue, activity log) stays outside this crate.
pub trait ManualApplyCallbacks: Send + Sync {
    fn enqueue_event(&self, event: &Value);
    fn acknowledge_pending_event(&self, event_id: &str);
    fn flush_pending_polls(&self);
    fn record_manual_edit_activity(&self, kind: &str, data: Value);
}

/// Port of a `pendingEvents` queue slot (`{ event }`, mirroring the JS
/// array-of-objects the original iterates with `.event`).
#[derive(Debug, Clone)]
pub struct PendingEventEntry {
    pub event: Value,
}

/// Port of one `pendingApplyDeferreds` map value.
struct DeferredApply {
    sender: mpsc::Sender<DeferredOutcome>,
    event: Value,
    batch: Value,
    page_url: Option<String>,
    rollback_snapshot: HashMap<String, SnapshotFile>,
    cwd: PathBuf,
}

enum DeferredOutcome {
    Resolve(Value),
    Reject(String),
}

/// Port of `timedOutApplyIds` map values.
#[derive(Debug, Clone)]
pub struct TimedOutDetails {
    pub batch: Value,
    pub rollback_snapshot: HashMap<String, SnapshotFile>,
    pub cwd: PathBuf,
    pub reason: Option<String>,
}

struct ControllerState {
    pending_events: Vec<PendingEventEntry>,
    pending_apply_deferreds: HashMap<String, DeferredApply>,
    timed_out_apply_ids: HashMap<String, TimedOutDetails>,
}

/// Port of `createManualApplyController({...})`. Construct with
/// [`ManualApplyController::new`], supplying the project `cwd` (JS's
/// `cwd = () => process.cwd()` option) and a [`ManualApplyCallbacks`] impl.
pub struct ManualApplyController<C: ManualApplyCallbacks> {
    state: Mutex<ControllerState>,
    callbacks: C,
    cwd: PathBuf,
    hard_timeout: Duration,
    soft_deadline_ms: u64,
}

impl<C: ManualApplyCallbacks> ManualApplyController<C> {
    pub fn new(cwd: PathBuf, callbacks: C) -> Self {
        Self::with_timeouts(
            cwd,
            callbacks,
            Duration::from_millis(APPLY_EVENT_HARD_TIMEOUT_MS_DEFAULT),
            APPLY_EVENT_SOFT_DEADLINE_MS_DEFAULT,
        )
    }

    pub fn with_timeouts(cwd: PathBuf, callbacks: C, hard_timeout: Duration, soft_deadline_ms: u64) -> Self {
        Self {
            state: Mutex::new(ControllerState {
                pending_events: Vec::new(),
                pending_apply_deferreds: HashMap::new(),
                timed_out_apply_ids: HashMap::new(),
            }),
            callbacks,
            cwd,
            hard_timeout,
            soft_deadline_ms,
        }
    }

    fn tombstone_timed_out_apply_id(state: &mut ControllerState, event_id: &str, details: TimedOutDetails) {
        state.timed_out_apply_ids.insert(event_id.to_string(), details);
        if state.timed_out_apply_ids.len() > 200 {
            if let Some(oldest) = state.timed_out_apply_ids.keys().next().cloned() {
                state.timed_out_apply_ids.remove(&oldest);
            }
        }
    }

    /// Port of `pushApplyEventAndWait(batch, pageUrl, chunk, repair)`.
    /// Blocks the calling thread until `resolve_deferred`/`reject_deferred`
    /// is called for this event from elsewhere, or the hard timeout elapses
    /// (see module docs for the JS `setTimeout`/`Promise` vs. Rust
    /// `mpsc::recv_timeout` mapping).
    pub fn push_apply_event_and_wait(
        &self,
        batch: &Value,
        page_url: Option<&str>,
        chunk: Option<&Value>,
        repair: Option<&Value>,
    ) -> Result<Value, String> {
        let event_id = new_short_id();
        let evidence_path = write_manual_apply_evidence(&event_id, batch, &self.cwd)
            .ok()
            .map(|p| p.to_string_lossy().to_string());
        let compacted = compact_manual_apply_batch(batch, &self.cwd);
        let mut event = serde_json::json!({
            "type": "manual_edit_apply",
            "id": event_id,
            "pageUrl": page_url,
            "batch": compacted,
            "evidencePath": evidence_path,
            "agentAction": build_manual_apply_agent_action(&event_id),
            "schemaVersion": 1,
            "deadlineMs": self.soft_deadline_ms,
        });
        if let Some(c) = chunk {
            event["chunk"] = c.clone();
        }
        if let Some(r) = repair {
            event["repair"] = r.clone();
        }

        let rollback_snapshot = snapshot_apply_event_files(batch, &self.cwd);

        self.callbacks.record_manual_edit_activity(
            "manual_edit_apply_dispatched",
            serde_json::json!({
                "id": event_id,
                "pageUrl": page_url,
                "chunk": chunk,
                "repair": repair,
                "entryCount": batch.get("entries").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                "opCount": count_manual_apply_ops(batch),
                "fileCount": collect_manual_apply_files(batch, &[], &self.cwd).len(),
            }),
        );

        let (tx, rx) = mpsc::channel();
        {
            let mut state = self.state.lock().unwrap();
            state.pending_apply_deferreds.insert(
                event_id.clone(),
                DeferredApply {
                    sender: tx,
                    event: event.clone(),
                    batch: batch.clone(),
                    page_url: page_url.map(str::to_string),
                    rollback_snapshot: rollback_snapshot.clone(),
                    cwd: self.cwd.clone(),
                },
            );
        }
        self.callbacks.enqueue_event(&event);

        match rx.recv_timeout(self.hard_timeout) {
            Ok(DeferredOutcome::Resolve(body)) => Ok(body),
            Ok(DeferredOutcome::Reject(reason)) => Err(reason),
            Err(_timeout) => {
                let mut state = self.state.lock().unwrap();
                // Remove regardless of whether it is still present: if
                // `resolve_deferred`/`reject_deferred` raced us and already
                // removed it, this is a no-op, matching JS's
                // fire-and-forget `setTimeout` (it always fires once
                // scheduled, even if the promise settled just before).
                state.pending_apply_deferreds.remove(&event_id);
                Self::tombstone_timed_out_apply_id(
                    &mut state,
                    &event_id,
                    TimedOutDetails {
                        batch: batch.clone(),
                        rollback_snapshot,
                        cwd: self.cwd.clone(),
                        reason: None,
                    },
                );
                drop(state);
                self.callbacks.acknowledge_pending_event(&event_id);
                remove_manual_apply_evidence(event["evidencePath"].as_str(), &self.cwd);
                self.callbacks.record_manual_edit_activity(
                    "manual_edit_apply_timeout",
                    serde_json::json!({
                        "id": event_id,
                        "pageUrl": page_url,
                        "chunk": chunk,
                        "entryCount": batch.get("entries").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                        "opCount": count_manual_apply_ops(batch),
                    }),
                );
                Err("chat_agent_timeout".to_string())
            }
        }
    }

    /// Port of `pushBatchInChunksAndWait(batch, pageUrl, context)`.
    pub fn push_batch_in_chunks_and_wait(&self, batch: &Value, page_url: Option<&str>, repair: Option<&Value>) -> Value {
        let repair = repair.cloned().or_else(|| batch.get("repair").cloned()).filter(|v| !v.is_null());
        if let Some(repair) = &repair {
            return match self.push_apply_event_and_wait(batch, page_url, None, Some(repair)) {
                Ok(body) => body,
                Err(reason) => serde_json::json!({ "status": "error", "message": reason }),
            };
        }

        let chunk_size = manual_edit_apply_chunk_size(None) as usize;
        let chunks = split_manual_apply_batch(batch, chunk_size);
        if chunks.len() <= 1 {
            return match self.push_apply_event_and_wait(batch, page_url, None, None) {
                Ok(body) => body,
                Err(reason) => serde_json::json!({ "status": "error", "message": reason }),
            };
        }

        let mut expected_ops_by_entry: HashMap<String, usize> = HashMap::new();
        for entry in batch.get("entries").and_then(Value::as_array).into_iter().flatten() {
            let id = entry.get("id").and_then(Value::as_str).unwrap_or("").to_string();
            let n = entry.get("ops").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
            expected_ops_by_entry.insert(id, n);
        }

        let mut applied_ops_by_entry: HashMap<String, usize> = HashMap::new();
        let mut failed_by_entry: HashMap<String, Value> = HashMap::new();
        let mut files: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut notes: Vec<Value> = Vec::new();
        let mut aborted = false;

        let mark_chunk_failed = |failed_by_entry: &mut HashMap<String, Value>, chunk: &ManualApplyChunk, reason: &str| {
            for entry_id in &chunk.entry_ids {
                failed_by_entry.entry(entry_id.clone()).or_insert_with(|| {
                    serde_json::json!({ "entryId": entry_id, "reason": reason, "candidates": [] })
                });
            }
        };

        for chunk in &chunks {
            if aborted {
                mark_chunk_failed(&mut failed_by_entry, chunk, "manual_edit_chunk_aborted");
                continue;
            }

            let result = match self.push_apply_event_and_wait(&chunk.batch, page_url, chunk.meta.as_ref(), None) {
                Ok(body) => normalize_apply_chunk_result(&body),
                Err(err) => {
                    mark_chunk_failed(&mut failed_by_entry, chunk, &err);
                    aborted = true;
                    continue;
                }
            };

            for f in result.get("files").and_then(Value::as_array).into_iter().flatten() {
                if let Some(s) = f.as_str() {
                    files.insert(s.to_string());
                }
            }
            for n in result.get("notes").and_then(Value::as_array).into_iter().flatten() {
                notes.push(n.clone());
            }

            let mut chunk_failed_ids = std::collections::HashSet::new();
            for item in result.get("failed").and_then(Value::as_array).into_iter().flatten() {
                let entry_id = item
                    .get("entryId")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("id").and_then(Value::as_str));
                let Some(entry_id) = entry_id else { continue };
                chunk_failed_ids.insert(entry_id.to_string());
                failed_by_entry.entry(entry_id.to_string()).or_insert_with(|| {
                    serde_json::json!({
                        "entryId": entry_id,
                        "reason": item.get("reason").cloned().or_else(|| item.get("message").cloned()).unwrap_or_else(|| Value::String("failed".into())),
                        "candidates": item.get("candidates").cloned().unwrap_or_else(|| Value::Array(vec![])),
                    })
                });
            }

            if result.get("status").and_then(Value::as_str) == Some("error") {
                let reason = result
                    .get("message")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| first_failure_reason(&result))
                    .unwrap_or_else(|| "chat_agent_error".to_string());
                mark_chunk_failed(&mut failed_by_entry, chunk, &reason);
                aborted = true;
                continue;
            }

            let reported_applied_ids: std::collections::HashSet<String> = result
                .get("appliedEntryIds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            for entry_id in &reported_applied_ids {
                if !chunk.entry_ids.contains(entry_id) || chunk_failed_ids.contains(entry_id) {
                    continue;
                }
                let add = chunk.op_counts_by_entry.get(entry_id).copied().unwrap_or(0);
                *applied_ops_by_entry.entry(entry_id.clone()).or_insert(0) += add;
            }

            for entry_id in &chunk.entry_ids {
                if reported_applied_ids.contains(entry_id) || chunk_failed_ids.contains(entry_id) {
                    continue;
                }
                failed_by_entry.entry(entry_id.clone()).or_insert_with(|| {
                    serde_json::json!({ "entryId": entry_id, "reason": "not_reported_applied", "candidates": [] })
                });
            }
        }

        let mut applied_entry_ids: Vec<String> = Vec::new();
        for (entry_id, expected_ops) in &expected_ops_by_entry {
            if failed_by_entry.contains_key(entry_id) {
                continue;
            }
            let applied = applied_ops_by_entry.get(entry_id).copied().unwrap_or(0);
            if applied == *expected_ops && *expected_ops > 0 {
                applied_entry_ids.push(entry_id.clone());
            } else {
                failed_by_entry.entry(entry_id.clone()).or_insert_with(|| {
                    serde_json::json!({ "entryId": entry_id, "reason": "not_reported_applied", "candidates": [] })
                });
            }
        }

        let failed: Vec<Value> = failed_by_entry.into_values().collect();
        let status = if failed.is_empty() {
            "done"
        } else if !applied_entry_ids.is_empty() {
            "partial"
        } else {
            "error"
        };

        serde_json::json!({
            "status": status,
            "appliedEntryIds": applied_entry_ids,
            "failed": failed,
            "files": files.into_iter().collect::<Vec<_>>(),
            "notes": notes,
        })
    }

    /// Port of `getDeferred(eventId)` batch/page_url accessors (JS returns
    /// the whole closure-captured object; here we hand back the pieces
    /// downstream callers in the original file actually use).
    pub fn get_deferred_batch(&self, event_id: &str) -> Option<Value> {
        self.state
            .lock()
            .unwrap()
            .pending_apply_deferreds
            .get(event_id)
            .map(|d| d.batch.clone())
    }

    /// Port of `hasTimedOutId(eventId)`.
    pub fn has_timed_out_id(&self, event_id: &str) -> bool {
        self.state.lock().unwrap().timed_out_apply_ids.contains_key(event_id)
    }

    /// Port of `resolveDeferred(eventId, body)`.
    pub fn resolve_deferred(&self, event_id: &str, body: Value) -> bool {
        let deferred = {
            let mut state = self.state.lock().unwrap();
            state.pending_apply_deferreds.remove(event_id)
        };
        let Some(deferred) = deferred else {
            return false;
        };
        remove_manual_apply_evidence(deferred.event.get("evidencePath").and_then(Value::as_str), &deferred.cwd);
        let _ = deferred.sender.send(DeferredOutcome::Resolve(body));
        true
    }

    /// Port of `rejectDeferred(eventId, reason)`.
    pub fn reject_deferred(&self, event_id: &str, reason: Option<&str>) -> bool {
        let deferred = {
            let mut state = self.state.lock().unwrap();
            state.pending_apply_deferreds.remove(event_id)
        };
        let Some(deferred) = deferred else {
            return false;
        };
        remove_manual_apply_evidence(deferred.event.get("evidencePath").and_then(Value::as_str), &deferred.cwd);
        let _ = deferred
            .sender
            .send(DeferredOutcome::Reject(reason.unwrap_or("chat_agent_error").to_string()));
        true
    }

    /// Port of `referencedManualApplyEvidencePaths(cwd)`.
    pub fn referenced_manual_apply_evidence_paths(&self) -> std::collections::HashSet<PathBuf> {
        let state = self.state.lock().unwrap();
        let mut referenced = std::collections::HashSet::new();
        let mut add = |event: &Value| {
            if let Some(p) = normalize_manual_apply_evidence_path(
                event.get("evidencePath").and_then(Value::as_str),
                &self.cwd,
            ) {
                referenced.insert(p);
            }
        };
        for entry in &state.pending_events {
            add(&entry.event);
        }
        for deferred in state.pending_apply_deferreds.values() {
            add(&deferred.event);
        }
        referenced
    }

    /// Port of `pruneStaleEvidence(cwd)`.
    pub fn prune_stale_evidence(&self) -> Vec<PathBuf> {
        let dir = manual_apply_evidence_dir(&self.cwd);
        if !dir.exists() {
            return Vec::new();
        }
        let referenced = self.referenced_manual_apply_evidence_paths();
        let mut removed = Vec::new();
        let Ok(read_dir) = fs::read_dir(&dir) else {
            return removed;
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if referenced.contains(&path) {
                continue;
            }
            if fs::remove_file(&path).is_ok() {
                removed.push(path);
            }
        }
        removed
    }

    /// Port of `rollbackTimedOutReply(msg)`.
    pub fn rollback_timed_out_reply(&self, event_id: &str) -> RollbackResult {
        let details = {
            let mut state = self.state.lock().unwrap();
            state.timed_out_apply_ids.remove(event_id)
        };
        let Some(details) = details else {
            return RollbackResult::default();
        };
        rollback_apply_snapshot(&details.batch, &details.rollback_snapshot, &[], &details.cwd)
    }

    /// Port of `cancelPendingEvents(pageUrl, reason)`.
    pub fn cancel_pending_events(&self, page_url: Option<&str>, reason: &str) -> Vec<Value> {
        let mut canceled: HashMap<String, Value> = HashMap::new();
        let mut state = self.state.lock().unwrap();

        let should_cancel = |event: &Value| -> bool {
            event.get("type").and_then(Value::as_str) == Some("manual_edit_apply")
                && match page_url {
                    None => true,
                    Some(p) => event.get("pageUrl").and_then(Value::as_str) == Some(p),
                }
        };

        let mut i = state.pending_events.len();
        while i > 0 {
            i -= 1;
            let cancel = should_cancel(&state.pending_events[i].event);
            if !cancel {
                continue;
            }
            let removed = state.pending_events.remove(i);
            let event = removed.event;
            remove_manual_apply_evidence(event.get("evidencePath").and_then(Value::as_str), &self.cwd);
            let event_id = event.get("id").and_then(Value::as_str).unwrap_or("").to_string();
            canceled.insert(
                event_id,
                serde_json::json!({
                    "id": event.get("id").cloned().unwrap_or(Value::Null),
                    "pageUrl": event.get("pageUrl").cloned().unwrap_or(Value::Null),
                    "entryCount": event.get("batch").and_then(|b| b.get("entries")).and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                }),
            );
        }

        let deferred_ids: Vec<String> = state
            .pending_apply_deferreds
            .iter()
            .filter(|(_, d)| should_cancel(&d.event))
            .map(|(id, _)| id.clone())
            .collect();
        for event_id in deferred_ids {
            let Some(deferred) = state.pending_apply_deferreds.remove(&event_id) else {
                continue;
            };
            let rollback = rollback_apply_snapshot(&deferred.batch, &deferred.rollback_snapshot, &[], &deferred.cwd);
            Self::tombstone_timed_out_apply_id(
                &mut state,
                &event_id,
                TimedOutDetails {
                    batch: deferred.batch.clone(),
                    rollback_snapshot: deferred.rollback_snapshot.clone(),
                    cwd: deferred.cwd.clone(),
                    reason: Some(reason.to_string()),
                },
            );
            remove_manual_apply_evidence(deferred.event.get("evidencePath").and_then(Value::as_str), &deferred.cwd);
            canceled.insert(
                event_id.clone(),
                serde_json::json!({
                    "id": event_id,
                    "pageUrl": deferred.page_url,
                    "entryCount": deferred.batch.get("entries").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
                    "rolledBackFiles": rollback.rolled_back_files,
                    "rollbackFailures": rollback.rollback_failures,
                }),
            );
            let _ = deferred.sender.send(DeferredOutcome::Reject(reason.to_string()));
        }

        drop(state);
        if !canceled.is_empty() {
            self.callbacks.flush_pending_polls();
        }
        canceled.into_values().collect()
    }

    /// Port of pushing a plain (non-apply-and-wait) event onto
    /// `pendingEvents`, the one queue this controller owns.
    pub fn push_pending_event(&self, event: Value) {
        self.state.lock().unwrap().pending_events.push(PendingEventEntry { event });
    }

    pub fn clear_transaction(&self, transaction_id: Option<&str>) -> bool {
        clear_manual_apply_transaction(&self.cwd, transaction_id)
    }

    pub fn read_transaction(&self) -> Option<Value> {
        read_manual_apply_transaction(&self.cwd)
    }

    pub fn write_transaction(&self, page_url: Option<&str>, batch: &Value) -> std::io::Result<Value> {
        write_manual_apply_transaction(&self.cwd, page_url, batch)
    }

    pub fn rollback_transaction(&self, page_url: Option<&str>, reason: &str) -> Option<Value> {
        let callbacks = &self.callbacks;
        let mut record = |kind: &str, data: Value| callbacks.record_manual_edit_activity(kind, data);
        rollback_manual_apply_transaction(&self.cwd, page_url, reason, Some(&mut record))
    }

    pub fn count_ops(&self, batch: &Value) -> usize {
        count_manual_apply_ops(batch)
    }

    pub fn summarize_event(&self, event: &Value, batch: &Value) -> Value {
        summarize_manual_apply_event(event, batch, &self.cwd)
    }

    pub fn build_agent_action(&self, event_id: &str) -> Value {
        build_manual_apply_agent_action(event_id)
    }

    pub fn validate_result_message(&self, msg: &Value, event_id: &str) -> Result<Value, Value> {
        let batch = self.get_deferred_batch(event_id);
        validate_manual_apply_result_message(msg, Some(event_id), batch.as_ref())
    }
}
