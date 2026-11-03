//! Port of the pure logic in
//! `skills/designer/engine/scripts/live-resume.mjs`.
//!
//! See [`crate::wf_port::w2_019`] for what is and isn't ported from this
//! file.

use serde_json::Value;
use std::collections::BTreeSet;

/// A `manual_edit_apply` event's fields as read by
/// `summarizeManualApplyEvent`/`manualApplyResumeHint`. Mirrors the
/// destructured `event.{id, pageUrl, chunk, batch}` shape.
#[derive(Debug, Clone, Default)]
pub struct ManualApplyEvent {
    pub id: Option<String>,
    pub page_url: Option<String>,
    /// Mirrors `event.chunk` (`{ index, total }` or absent).
    pub chunk: Option<ChunkRef>,
    pub batch: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRef {
    pub index: i64,
    pub total: i64,
}

/// Port of `summarizeManualApplyEvent(event = {})`'s return shape.
#[derive(Debug, Clone, PartialEq)]
pub struct ManualApplySummary {
    pub page_url: Option<String>,
    pub chunk: Option<ChunkRef>,
    pub entry_count: usize,
    pub op_count: usize,
    pub files: Vec<String>,
}

/// Port of `manualApplyReplyCommand(eventOrId = 'EVENT_ID')`.
pub fn manual_apply_reply_command(event_id: Option<&str>) -> String {
    format!(
        "legion script designer/live-poll --reply {} done --data '<json>'",
        event_id.unwrap_or("EVENT_ID")
    )
}

/// Port of `collectManualApplyFiles(batch)`: gathers every `file` /
/// `relativeFile` string referenced by `batch.entries[].ops[].sourceHint`
/// and `batch.candidates[].{sourceHint,textMatches,objectKeyMatches,
/// locatorMatches,contextTextMatches}`, dedupes, and sorts.
pub fn collect_manual_apply_files(batch: Option<&Value>) -> Vec<String> {
    let mut files: BTreeSet<String> = BTreeSet::new();
    let Some(batch) = batch else {
        return Vec::new();
    };

    if let Some(entries) = batch.get("entries").and_then(Value::as_array) {
        for entry in entries {
            if let Some(ops) = entry.get("ops").and_then(Value::as_array) {
                for op in ops {
                    if let Some(file) = op
                        .get("sourceHint")
                        .and_then(|h| h.get("file"))
                        .and_then(Value::as_str)
                    {
                        if !file.is_empty() {
                            files.insert(file.to_string());
                        }
                    }
                }
            }
        }
    }

    if let Some(candidates) = batch.get("candidates").and_then(Value::as_array) {
        for candidate in candidates {
            for path in [
                candidate
                    .get("sourceHint")
                    .and_then(|h| h.get("relativeFile")),
                candidate.get("sourceHint").and_then(|h| h.get("file")),
            ]
            .into_iter()
            .flatten()
            {
                if let Some(s) = path.as_str() {
                    if !s.is_empty() {
                        files.insert(s.to_string());
                    }
                }
            }
            for list_key in [
                "textMatches",
                "objectKeyMatches",
                "locatorMatches",
                "contextTextMatches",
            ] {
                if let Some(items) = candidate.get(list_key).and_then(Value::as_array) {
                    for item in items {
                        if let Some(s) = item.get("file").and_then(Value::as_str) {
                            if !s.is_empty() {
                                files.insert(s.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    files.into_iter().collect()
}

/// Port of `summarizeManualApplyEvent(event = {})`.
pub fn summarize_manual_apply_event(event: &ManualApplyEvent) -> ManualApplySummary {
    let entries = event
        .batch
        .as_ref()
        .and_then(|b| b.get("entries"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let entry_count = entries.len();
    let op_count: usize = entries
        .iter()
        .map(|entry| {
            entry
                .get("ops")
                .and_then(Value::as_array)
                .map(|ops| ops.len())
                .unwrap_or(0)
        })
        .sum();
    ManualApplySummary {
        page_url: event.page_url.clone(),
        chunk: event.chunk,
        entry_count,
        op_count,
        files: collect_manual_apply_files(event.batch.as_ref()),
    }
}

/// Port of `manualApplyResumeHint(event = {})`.
pub fn manual_apply_resume_hint(event: &ManualApplyEvent) -> String {
    let summary = summarize_manual_apply_event(event);
    let mut parts: Vec<String> = Vec::new();
    if let Some(page_url) = &summary.page_url {
        parts.push(format!("page {page_url}"));
    }
    if let Some(chunk) = summary.chunk {
        parts.push(format!("chunk {}/{}", chunk.index, chunk.total));
    }
    parts.push(format!("{} op(s)", summary.op_count));
    let entry_word = if summary.entry_count == 1 {
        "entry"
    } else {
        "entries"
    };
    parts.push(format!("{} {entry_word}", summary.entry_count));
    if !summary.files.is_empty() {
        parts.push(format!("likely files: {}", summary.files.join(", ")));
    }
    let scope = if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    };
    let reply_cmd = manual_apply_reply_command(event.id.as_deref());
    format!(
        "Manual Apply pending{scope}. If you have not already leased it, run legion script designer/live-poll. \
         Apply the source edits from the manual_edit_apply batch, then reply with {reply_cmd}. \
         Polling only leases this work item; it does not commit source edits. Do not run \
         legion script designer/live-commit-manual-edits for this leased event. Do not poll again before replying."
    )
}

/// Port of `--id`/`--id=...` argv parsing in `resumeCli`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResumeArgs {
    pub id: Option<String>,
    pub help: bool,
}

/// Port of `parseArgs(argv)`.
pub fn parse_args(argv: &[String]) -> ResumeArgs {
    let mut out = ResumeArgs::default();
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        if arg == "--id" {
            i += 1;
            out.id = argv.get(i).cloned();
        } else if let Some(rest) = arg.strip_prefix("--id=") {
            out.id = Some(rest.to_string());
        } else if arg == "--help" || arg == "-h" {
            out.help = true;
        }
        i += 1;
    }
    out
}
