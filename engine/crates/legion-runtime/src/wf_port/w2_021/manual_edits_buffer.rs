//! Port of `skills/designer/engine/scripts/live/manual-edits-buffer.mjs`.
//!
//! Shared helpers for the pending-manual-edits buffer on disk.
//!
//! Location: `.impeccable/live/pending-manual-edits.json` (project-local).
//! Schema:   `{ version: 1, entries: [{ id, pageUrl, element, ops, stagedAt }] }`
//!
//! Each entry corresponds to one Save action from the browser. Ops merge by
//! `(pageUrl, ref)`: if the user re-edits the same element before committing,
//! the existing entry's `newText` is replaced and `originalText` is kept (it
//! holds the real source state).
//!
//! `resolveProjectRoot`'s project-root-walk (`../context.mjs`, outside this
//! chunk) is not reimplemented: callers pass the resolved project root
//! directly as `cwd`, exactly as `manual-edit-routes.mjs` does in the
//! original (`projectCwd()` there is always an already-resolved directory).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const BUFFER_VERSION: u32 = 1;
pub const BUFFER_FILENAME: &str = "pending-manual-edits.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManualEditOp {
    #[serde(rename = "ref")]
    pub ref_: Option<String>,
    #[serde(rename = "originalText", skip_serializing_if = "Option::is_none")]
    pub original_text: Option<String>,
    #[serde(rename = "newText", skip_serializing_if = "Option::is_none")]
    pub new_text: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    /// Any other op fields (sourceHint, tag, classes, ...) are passed through
    /// opaquely, matching the JS object-spread behaviour.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl ManualEditOp {
    fn ref_value(&self) -> Option<&str> {
        self.ref_.as_deref()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManualEditEntry {
    pub id: Option<String>,
    #[serde(rename = "pageUrl")]
    pub page_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub element: Option<Value>,
    #[serde(default)]
    pub ops: Vec<ManualEditOp>,
    #[serde(rename = "stagedAt", default, skip_serializing_if = "Option::is_none")]
    pub staged_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualEditBuffer {
    pub version: u32,
    pub entries: Vec<ManualEditEntry>,
}

impl Default for ManualEditBuffer {
    fn default() -> Self {
        Self {
            version: BUFFER_VERSION,
            entries: Vec::new(),
        }
    }
}

/// Mirrors `new Date().toISOString()` closely enough for buffer bookkeeping
/// (millisecond-precision UTC timestamp); exact JS `toISOString` formatting
/// is not required by any caller in this chunk, which only round-trips the
/// value through JSON.
pub fn now_iso() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let days = secs / 86_400;
    let mut rem = secs % 86_400;
    let hour = rem / 3600;
    rem %= 3600;
    let min = rem / 60;
    let sec = rem % 60;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z"
    )
}

/// Howard Hinnant's civil_from_days algorithm (days since 1970-01-01 -> y/m/d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn get_buffer_path(cwd: &Path) -> PathBuf {
    cwd.join(".impeccable").join("live").join(BUFFER_FILENAME)
}

pub fn read_buffer(cwd: &Path) -> ManualEditBuffer {
    read_buffer_internal(cwd, false).unwrap_or_default()
}

/// Returns `Err` when the file exists but is unreadable or its JSON schema
/// is invalid, matching `readBufferStrict`'s thrown errors.
pub fn read_buffer_strict(cwd: &Path) -> Result<ManualEditBuffer, String> {
    read_buffer_internal(cwd, true)
}

fn read_buffer_internal(cwd: &Path, strict: bool) -> Result<ManualEditBuffer, String> {
    let file_path = get_buffer_path(cwd);
    let raw = match fs::read_to_string(&file_path) {
        Ok(raw) => raw,
        Err(err) => {
            if strict && err.kind() != std::io::ErrorKind::NotFound {
                return Err(format!("manual_edit_buffer_unreadable: {err}"));
            }
            return Ok(ManualEditBuffer::default());
        }
    };
    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(err) => {
            if strict {
                return Err(format!("manual_edit_buffer_unreadable: {err}"));
            }
            return Ok(ManualEditBuffer::default());
        }
    };
    let entries_value = parsed.get("entries");
    if !parsed.is_object() || !matches!(entries_value, Some(Value::Array(_))) {
        if strict {
            return Err("manual_edit_buffer_invalid_schema".to_string());
        }
        return Ok(ManualEditBuffer::default());
    }
    let entries: Vec<ManualEditEntry> =
        serde_json::from_value(entries_value.cloned().unwrap_or(Value::Array(vec![])))
            .map_err(|err| format!("manual_edit_buffer_unreadable: {err}"))?;
    Ok(ManualEditBuffer {
        version: BUFFER_VERSION,
        entries,
    })
}

pub fn write_buffer(cwd: &Path, buffer: &ManualEditBuffer) -> std::io::Result<()> {
    let file_path = get_buffer_path(cwd);
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let out = serde_json::json!({ "version": BUFFER_VERSION, "entries": buffer.entries });
    fs::write(file_path, serde_json::to_string_pretty(&out).unwrap())
}

/// Merge a new entry into the buffer. For each op in the new entry, if
/// there's already a buffered op for the same `(pageUrl, ref)`, update that
/// op's `newText` and keep its original `originalText` (the true source
/// state). Otherwise add the op (creating an entry if needed).
///
/// Multiple ops in one Save are allowed; each is keyed by `(pageUrl, ref)`.
pub fn stage_entry(
    cwd: &Path,
    new_id: &str,
    page_url: &str,
    element: Option<Value>,
    ops: Vec<ManualEditOp>,
) -> Result<ManualEditBuffer, String> {
    let mut buf = read_buffer_strict(cwd)?;
    for new_op in ops {
        let mut merged_into_existing = false;
        'outer: for existing in buf.entries.iter_mut() {
            if existing.page_url.as_deref() != Some(page_url) {
                continue;
            }
            if let Some(idx) = existing
                .ops
                .iter()
                .position(|op| op.ref_value() == new_op.ref_value())
            {
                let original_text = existing.ops[idx].original_text.clone();
                let mut updated = new_op.clone();
                updated.original_text = original_text;
                updated.deleted = new_op.deleted;
                existing.ops[idx] = updated;
                if element.is_some() {
                    existing.element = element.clone();
                }
                existing.staged_at = Some(now_iso());
                merged_into_existing = true;
                break 'outer;
            }
        }
        if merged_into_existing {
            continue;
        }
        // No existing op for this (pageUrl, ref). Find or create an entry to
        // hold it.
        let entry_idx = buf
            .entries
            .iter()
            .position(|e| e.page_url.as_deref() == Some(page_url) && e.id.as_deref() == Some(new_id));
        let idx = match entry_idx {
            Some(idx) => idx,
            None => {
                buf.entries.push(ManualEditEntry {
                    id: Some(new_id.to_string()),
                    page_url: Some(page_url.to_string()),
                    element: element.clone(),
                    ops: Vec::new(),
                    staged_at: Some(now_iso()),
                });
                buf.entries.len() - 1
            }
        };
        buf.entries[idx].ops.push(new_op);
        buf.entries[idx].staged_at = Some(now_iso());
    }
    write_buffer(cwd, &buf).map_err(|err| err.to_string())?;
    Ok(buf)
}

/// Remove entries matching `predicate`. Returns the count of removed *ops*
/// (not entries) so callers report a unit consistent with `truncate_buffer`
/// and the pill's per-page op count. Empty entries (no ops left) are also
/// pruned.
pub fn remove_entries<F>(cwd: &Path, predicate: F) -> usize
where
    F: Fn(&ManualEditEntry) -> bool,
{
    let mut buf = read_buffer(cwd);
    let mut removed_ops = 0usize;
    let mut kept = Vec::new();
    for entry in buf.entries.drain(..) {
        if predicate(&entry) {
            removed_ops += entry.ops.len();
        } else if !entry.ops.is_empty() {
            kept.push(entry);
        }
    }
    buf.entries = kept;
    let _ = write_buffer(cwd, &buf);
    removed_ops
}

/// Count by page for the counter UI.
pub struct PageCounts {
    pub total_count: usize,
    pub per_page: std::collections::HashMap<String, usize>,
}

pub fn count_by_page(cwd: &Path) -> PageCounts {
    let buf = read_buffer(cwd);
    let mut per_page = std::collections::HashMap::new();
    let mut total_count = 0usize;
    for entry in &buf.entries {
        let n = entry.ops.len();
        if let Some(page_url) = &entry.page_url {
            *per_page.entry(page_url.clone()).or_insert(0) += n;
        }
        total_count += n;
    }
    PageCounts {
        total_count,
        per_page,
    }
}

/// Truncate the buffer to empty (used by discard-all). Returns the count of
/// removed ops.
pub fn truncate_buffer(cwd: &Path) -> usize {
    let buf = read_buffer(cwd);
    let removed = buf.entries.iter().map(|e| e.ops.len()).sum();
    let _ = write_buffer(cwd, &ManualEditBuffer::default());
    removed
}
