//! Port of `skills/designer/engine/scripts/live/manual-edits-buffer.mjs`
//! (chunk w2_018).
//!
//! Shared helpers for the pending-manual-edits buffer on disk at
//! `.impeccable/live/pending-manual-edits.json`. Schema:
//! `{ version: 1, entries: [{ id, pageUrl, element, ops, stagedAt }] }`.
//!
//! Only the operations needed by `live-discard-manual-edits.mjs` and
//! `live-manual-edit-evidence.mjs` (`readBuffer`, `getBufferPath`,
//! `removeEntries`, `truncateBuffer`) are ported; `stageEntry` and
//! `countByPage` (used only by the browser Save path, not by this chunk's
//! scripts) are left unported.

use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

const BUFFER_VERSION: u64 = 1;
const BUFFER_FILENAME: &str = "pending-manual-edits.json";

/// One buffered manual-edit entry. Kept as a raw JSON object (rather than a
/// strongly-typed struct) to mirror the JS's schema-agnostic pass-through of
/// `element`/`ops`, and because downstream ports (the browser Save path,
/// `live-commit-manual-edits.mjs`) are out of this chunk's scope.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub id: Option<String>,
    pub page_url: Option<String>,
    pub ops: Vec<Value>,
    /// The full raw JSON object, preserved for round-tripping unknown
    /// fields (`element`, `stagedAt`, ...) exactly as read.
    pub raw: Map<String, Value>,
}

impl Entry {
    fn from_value(value: &Value) -> Option<Entry> {
        let obj = value.as_object()?;
        let ops = match obj.get("ops") {
            Some(Value::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        Some(Entry {
            id: obj.get("id").and_then(Value::as_str).map(String::from),
            page_url: obj.get("pageUrl").and_then(Value::as_str).map(String::from),
            ops,
            raw: obj.clone(),
        })
    }

    fn to_value(&self) -> Value {
        let mut obj = self.raw.clone();
        obj.insert("ops".to_string(), Value::Array(self.ops.clone()));
        Value::Object(obj)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Buffer {
    pub entries: Vec<Entry>,
}

pub fn get_buffer_path(live_dir: &Path) -> PathBuf {
    live_dir.join(BUFFER_FILENAME)
}

/// Mirrors `readBuffer(cwd)`: lenient — any read/parse failure or schema
/// mismatch yields an empty buffer, never an error.
pub fn read_buffer(live_dir: &Path) -> Buffer {
    let file_path = get_buffer_path(live_dir);
    let raw = match fs::read_to_string(&file_path) {
        Ok(raw) => raw,
        Err(_) => return Buffer::default(),
    };
    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(_) => return Buffer::default(),
    };
    let entries = match parsed.get("entries").and_then(Value::as_array) {
        Some(items) => items.iter().filter_map(Entry::from_value).collect(),
        None => return Buffer::default(),
    };
    Buffer { entries }
}

pub fn write_buffer(live_dir: &Path, buffer: &Buffer) -> io::Result<()> {
    let file_path = get_buffer_path(live_dir);
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let entries: Vec<Value> = buffer.entries.iter().map(Entry::to_value).collect();
    let payload = serde_json::json!({ "version": BUFFER_VERSION, "entries": entries });
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
    fs::write(&file_path, text)
}

use std::io;

/// Mirrors `removeEntries(cwd, predicate)`: removes entries matching
/// `predicate`, returns the count of removed *ops* (not entries), and prunes
/// any surviving entry left with zero ops.
pub fn remove_entries<F>(live_dir: &Path, predicate: F) -> io::Result<usize>
where
    F: Fn(&Entry) -> bool,
{
    let mut buffer = read_buffer(live_dir);
    let mut removed_ops = 0usize;
    let mut kept = Vec::with_capacity(buffer.entries.len());
    for entry in buffer.entries.drain(..) {
        if predicate(&entry) {
            removed_ops += entry.ops.len();
        } else if !entry.ops.is_empty() {
            kept.push(entry);
        }
    }
    buffer.entries = kept;
    write_buffer(live_dir, &buffer)?;
    Ok(removed_ops)
}

/// Mirrors `truncateBuffer(cwd)`: empties the buffer, returns the count of
/// removed ops.
pub fn truncate_buffer(live_dir: &Path) -> io::Result<usize> {
    let buffer = read_buffer(live_dir);
    let removed: usize = buffer.entries.iter().map(|e| e.ops.len()).sum();
    write_buffer(live_dir, &Buffer::default())?;
    Ok(removed)
}
