//! Port of `skills/designer/engine/scripts/live-discard-manual-edits.mjs`
//! (chunk w2_018).
//!
//! CLI helper: discard pending manual edits from the buffer without
//! applying. Reads `.impeccable/live/pending-manual-edits.json`, drops
//! entries, writes back. No source-file writes.

use super::buffer::{self, Entry};
use serde_json::Value;
use std::io;
use std::path::Path;

/// Mirrors the script's JSON stdout payload:
/// `{ discarded, entries: [...discardedEntries], totalCount }`.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscardResult {
    pub discarded: usize,
    pub entries: Vec<Value>,
    pub total_count: usize,
}

/// Mirrors the script body: with `page_url_filter`, discard only entries for
/// that page and report just those entries; without it, discard everything
/// and report all the entries that were discarded.
pub fn discard_manual_edits(
    live_dir: &Path,
    page_url_filter: Option<&str>,
) -> io::Result<DiscardResult> {
    let buf = buffer::read_buffer(live_dir);
    let (discarded, entries) = if let Some(page_url) = page_url_filter {
        let matches = |e: &Entry| e.page_url.as_deref() == Some(page_url);
        let entries: Vec<Value> = buf
            .entries
            .iter()
            .filter(|e| matches(e))
            .map(entry_to_value)
            .collect();
        let discarded = buffer::remove_entries(live_dir, matches)?;
        (discarded, entries)
    } else {
        let entries: Vec<Value> = buf.entries.iter().map(entry_to_value).collect();
        let discarded = buffer::truncate_buffer(live_dir)?;
        (discarded, entries)
    };

    let total_count: usize = buffer::read_buffer(live_dir)
        .entries
        .iter()
        .map(|e| e.ops.len())
        .sum();

    Ok(DiscardResult {
        discarded,
        entries,
        total_count,
    })
}

fn entry_to_value(entry: &Entry) -> Value {
    let mut obj = entry.raw.clone();
    obj.insert("ops".to_string(), Value::Array(entry.ops.clone()));
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "legion-w2_018-discard-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn seed(live_dir: &Path) {
        fs::create_dir_all(live_dir).unwrap();
        fs::write(
            buffer::get_buffer_path(live_dir),
            serde_json::to_string(&json!({
                "version": 1,
                "entries": [
                    { "id": "a", "pageUrl": "/", "ops": [{"ref": "1"}] },
                    { "id": "b", "pageUrl": "/x", "ops": [{"ref": "2"}, {"ref": "3"}] },
                ]
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn discard_all_reports_every_entry_and_empties_buffer() {
        let tmp = TempDir::new();
        let live_dir = tmp.0.join("live");
        seed(&live_dir);

        let result = discard_manual_edits(&live_dir, None).unwrap();
        assert_eq!(result.discarded, 3);
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.total_count, 0);
        assert_eq!(buffer::read_buffer(&live_dir).entries.len(), 0);
    }

    #[test]
    fn discard_by_page_url_only_removes_matching_entries() {
        let tmp = TempDir::new();
        let live_dir = tmp.0.join("live");
        seed(&live_dir);

        let result = discard_manual_edits(&live_dir, Some("/")).unwrap();
        assert_eq!(result.discarded, 1);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.total_count, 2);

        let remaining = buffer::read_buffer(&live_dir);
        assert_eq!(remaining.entries.len(), 1);
        assert_eq!(remaining.entries[0].page_url.as_deref(), Some("/x"));
    }

    #[test]
    fn discard_by_page_url_with_no_matches_is_a_no_op() {
        let tmp = TempDir::new();
        let live_dir = tmp.0.join("live");
        seed(&live_dir);

        let result = discard_manual_edits(&live_dir, Some("/missing")).unwrap();
        assert_eq!(result.discarded, 0);
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.total_count, 3);
    }
}
