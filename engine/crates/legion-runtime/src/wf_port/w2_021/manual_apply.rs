//! Port of `skills/designer/engine/scripts/live/manual-apply.mjs`.
//!
//! `createManualApplyController` is a stateful controller wired to the live
//! server's pending-event queue, deferred-promise map, and
//! `recordManualEditActivity`/`enqueueEvent` callbacks supplied by
//! `live.mjs` (outside this chunk). That queue-driving orchestration,
//! transaction-file I/O helpers (`writeManualApplyTransaction`,
//! `rollbackManualApplyTransaction`, ...), and evidence-file I/O
//! (`writeManualApplyEvidence`, ...) are frontier and not ported. Only the
//! pure data-shaping/summarizing helpers are ported here.

use std::path::Path;

use serde_json::Value;

const MANUAL_APPLY_COMPACT_TEXT_LIMIT: usize = 240;

const DEFAULT_MANUAL_EDIT_APPLY_CHUNK_SIZE: i64 = 3;
const MIN_MANUAL_EDIT_APPLY_CHUNK_SIZE: i64 = 1;
const MAX_MANUAL_EDIT_APPLY_CHUNK_SIZE: i64 = 20;

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

/// Port of `summarizeManualApplyFailures(failed, cwd)`. Non-array input
/// returns an empty vec (matching JS `return []`), not `None`.
pub fn summarize_manual_apply_failures(failed: &Value, cwd: &Path) -> Vec<Value> {
    let Some(items) = failed.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .take(20)
        .map(|item| {
            let files = item.get("files").and_then(Value::as_array).map(|arr| {
                arr.iter()
                    .take(12)
                    .filter_map(|f| {
                        summarize_manual_log_file(f.as_str(), cwd).map(Value::from)
                    })
                    .collect::<Vec<_>>()
            });
            serde_json::json!({
                "id": item.get("id").or_else(|| item.get("entryId")).cloned().unwrap_or(Value::Null),
                "reason": item.get("reason").and_then(Value::as_str)
                    .or_else(|| item.get("message").and_then(Value::as_str))
                    .unwrap_or("failed"),
                "message": compact_manual_log_text(item.get("message").and_then(Value::as_str), 300),
                "files": files,
                "checks": summarize_manual_diagnostics(item.get("checks").unwrap_or(&Value::Null), cwd),
                "failures": summarize_manual_diagnostics(item.get("failures").unwrap_or(&Value::Null), cwd),
                "candidates": summarize_manual_diagnostics(item.get("candidates").unwrap_or(&Value::Null), cwd),
            })
        })
        .collect()
}

/// Port of `summarizeManualDiagnostics(items, cwd)`. Returns `Value::Null`
/// (mapped from JS `undefined`, which `JSON.stringify` drops from objects)
/// for non-array or empty input.
pub fn summarize_manual_diagnostics(items: &Value, cwd: &Path) -> Value {
    let Some(arr) = items.as_array() else {
        return Value::Null;
    };
    if arr.is_empty() {
        return Value::Null;
    }
    let out: Vec<Value> = arr
        .iter()
        .take(12)
        .map(|item| {
            let files = item.get("files").and_then(Value::as_array).map(|files| {
                files
                    .iter()
                    .take(8)
                    .filter_map(|f| summarize_manual_log_file(f.as_str(), cwd).map(Value::from))
                    .collect::<Vec<_>>()
            });
            let file = item
                .get("file")
                .and_then(Value::as_str)
                .or_else(|| item.get("relativeFile").and_then(Value::as_str));
            serde_json::json!({
                "reason": item.get("reason").or_else(|| item.get("kind")).cloned().unwrap_or(Value::Null),
                "detail": compact_manual_log_text(item.get("detail").and_then(Value::as_str), 220),
                "message": compact_manual_log_text(item.get("message").and_then(Value::as_str), 300),
                "file": summarize_manual_log_file(file, cwd),
                "line": item.get("line").cloned().unwrap_or(Value::Null),
                "ref": compact_manual_log_text(item.get("ref").and_then(Value::as_str), 180),
                "marker": compact_manual_log_text(item.get("marker").and_then(Value::as_str), 120),
                "files": files,
            })
        })
        .collect();
    Value::Array(out)
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
