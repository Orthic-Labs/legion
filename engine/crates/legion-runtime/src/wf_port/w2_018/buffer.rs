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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn live_dir(tmp: &std::path::Path) -> PathBuf {
        tmp.join(".impeccable").join("live")
    }

    fn write_raw_buffer(live_dir: &Path, value: &Value) {
        fs::create_dir_all(live_dir).unwrap();
        fs::write(
            get_buffer_path(live_dir),
            serde_json::to_string(value).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn read_buffer_missing_file_is_empty() {
        let tmp = tempdir();
        let dir = live_dir(tmp.path());
        assert_eq!(read_buffer(&dir), Buffer::default());
    }

    #[test]
    fn read_buffer_invalid_schema_is_empty() {
        let tmp = tempdir();
        let dir = live_dir(tmp.path());
        write_raw_buffer(&dir, &json!({ "not_entries": true }));
        assert_eq!(read_buffer(&dir), Buffer::default());
    }

    #[test]
    fn truncate_buffer_empties_and_counts_ops() {
        let tmp = tempdir();
        let dir = live_dir(tmp.path());
        write_raw_buffer(
            &dir,
            &json!({
                "version": 1,
                "entries": [
                    { "id": "a", "pageUrl": "/", "ops": [{"ref": "1"}, {"ref": "2"}] },
                    { "id": "b", "pageUrl": "/x", "ops": [{"ref": "3"}] },
                ]
            }),
        );
        let removed = truncate_buffer(&dir).unwrap();
        assert_eq!(removed, 3);
        assert_eq!(read_buffer(&dir), Buffer::default());
    }

    #[test]
    fn remove_entries_by_page_url_prunes_empty_entries_only() {
        let tmp = tempdir();
        let dir = live_dir(tmp.path());
        write_raw_buffer(
            &dir,
            &json!({
                "version": 1,
                "entries": [
                    { "id": "a", "pageUrl": "/", "ops": [{"ref": "1"}] },
                    { "id": "b", "pageUrl": "/x", "ops": [{"ref": "2"}, {"ref": "3"}] },
                ]
            }),
        );
        let removed = remove_entries(&dir, |e| e.page_url.as_deref() == Some("/")).unwrap();
        assert_eq!(removed, 1);
        let after = read_buffer(&dir);
        assert_eq!(after.entries.len(), 1);
        assert_eq!(after.entries[0].page_url.as_deref(), Some("/x"));
        assert_eq!(after.entries[0].ops.len(), 2);
    }

    fn tempdir() -> tempfile_shim::TempDir {
        tempfile_shim::TempDir::new()
    }

    /// Minimal self-contained temp-dir helper so this module needs no new
    /// dev-dependency (`legion-runtime` does not currently depend on the
    /// `tempfile` crate).
    mod tempfile_shim {
        use std::path::{Path, PathBuf};

        pub struct TempDir(PathBuf);

        impl TempDir {
            pub fn new() -> Self {
                let mut dir = std::env::temp_dir();
                let unique = format!(
                    "legion-w2_018-buffer-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                );
                dir.push(unique);
                std::fs::create_dir_all(&dir).unwrap();
                TempDir(dir)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
