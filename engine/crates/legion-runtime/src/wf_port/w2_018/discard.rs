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
