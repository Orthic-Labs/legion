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
    if !path.is_absolute() {
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
