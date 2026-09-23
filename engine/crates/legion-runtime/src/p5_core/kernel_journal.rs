//! Ported from src/packages/kernel/lib/journal.mjs (packet P5d).
//!
//! JS serializes concurrent appends through a promise tail on a single
//! `JsonlJournal` instance; this port achieves the same "one writer at a
//! time, sequence-numbered" guarantee synchronously — callers hold `&mut
//! JsonlJournal` for the duration of an append, which the borrow checker
//! already serializes within a process.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use legion_catalog::json::{self, Value};

use crate::p5_core::kernel_errors::{KernelError, KernelErrorOptions};

fn integrity_error(message: impl Into<String>) -> KernelError {
    KernelError::new(
        "JOURNAL_CORRUPT",
        message,
        KernelErrorOptions {
            category: Some("integrity".to_string()),
            ..Default::default()
        },
    )
}

/// Port of `class JsonlJournal`.
#[derive(Debug)]
pub struct JsonlJournal {
    pub file_path: PathBuf,
    pub records: Vec<Value>,
}

impl JsonlJournal {
    /// Port of `static async open(filePath)`.
    pub fn open(file_path: impl AsRef<Path>) -> Result<Self, KernelError> {
        let file_path = file_path.as_ref().to_path_buf();
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).map_err(|cause| {
                KernelError::new(
                    "JOURNAL_IO_FAILED",
                    format!("failed to create journal directory: {cause}"),
                    KernelErrorOptions {
                        category: Some("resource".to_string()),
                        ..Default::default()
                    },
                )
            })?;
        }
        let text = match fs::read_to_string(&file_path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(cause) => {
                return Err(KernelError::new(
                    "JOURNAL_IO_FAILED",
                    format!("failed to read journal: {cause}"),
                    KernelErrorOptions {
                        category: Some("resource".to_string()),
                        ..Default::default()
                    },
                ))
            }
        };

        let mut records = Vec::new();
        for (index, line) in text.split('\n').enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = json::from_str(line)
                .map_err(|cause| integrity_error(format!("invalid JSONL record at line {}: {cause}", index + 1)))?;
            records.push(value);
        }
        for (index, record) in records.iter().enumerate() {
            let sequence = record.get("sequence").and_then(Value::as_u64);
            if sequence != Some((index + 1) as u64) {
                return Err(integrity_error(format!("invalid journal sequence at line {}", index + 1)));
            }
        }

        Ok(JsonlJournal { file_path, records })
    }

    /// Port of `all()` (JS deep-clones via `structuredClone`; `Vec<Value>`
    /// clone is already a deep clone).
    pub fn all(&self) -> Vec<Value> {
        self.records.clone()
    }

    /// Port of `append(record)` / `appendNow(record)`, collapsed to a single
    /// synchronous call since Rust's `&mut self` already serializes callers.
    pub fn append(&mut self, mut record: Value) -> Result<Value, KernelError> {
        let sequence = (self.records.len() + 1) as u64;
        record
            .as_object_mut()
            .ok_or_else(|| integrity_error("journal record must be an object"))?
            .insert("sequence".to_string(), json::json!(sequence));

        let line = json::to_string(&record)
            .map_err(|cause| integrity_error(format!("failed to serialize journal record: {cause}")))?;
        // Ensure the parent directory still exists before opening for
        // append. `open()` creates it once, but on Windows a
        // just-created directory can transiently fail to resolve for a
        // subsequent open (ERROR_PATH_NOT_FOUND) — re-asserting it here
        // is cheap and matches JS, which recreates the directory on every
        // write via `fs.mkdir(..., { recursive: true })`.
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent).map_err(|cause| {
                KernelError::new(
                    "JOURNAL_IO_FAILED",
                    format!("failed to create journal directory: {cause}"),
                    KernelErrorOptions {
                        category: Some("resource".to_string()),
                        ..Default::default()
                    },
                )
            })?;
        }
        let mut handle = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)
            .map_err(|cause| {
                KernelError::new(
                    "JOURNAL_IO_FAILED",
                    format!("failed to open journal for append: {cause}"),
                    KernelErrorOptions {
                        category: Some("resource".to_string()),
                        ..Default::default()
                    },
                )
            })?;
        writeln!(handle, "{line}").map_err(|cause| {
            KernelError::new(
                "JOURNAL_IO_FAILED",
                format!("failed to write journal record: {cause}"),
                KernelErrorOptions {
                    category: Some("resource".to_string()),
                    ..Default::default()
                },
            )
        })?;
        handle.sync_all().ok();

        self.records.push(record.clone());
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_creates_directory_and_starts_empty() {
        let dir = std::env::temp_dir().join(format!("p5d-journal-{}", kernel_test_nonce()));
        let path = dir.join("journal.jsonl");
        let journal = JsonlJournal::open(&path).unwrap();
        assert!(journal.records.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn append_assigns_sequence_and_persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!("p5d-journal-{}", kernel_test_nonce()));
        let path = dir.join("journal.jsonl");
        {
            let mut journal = JsonlJournal::open(&path).unwrap();
            let first = journal.append(json::json!({"eventType": "task.created"})).unwrap();
            assert_eq!(first["sequence"], 1);
            let second = journal.append(json::json!({"eventType": "task.started"})).unwrap();
            assert_eq!(second["sequence"], 2);
        }
        let reopened = JsonlJournal::open(&path).unwrap();
        assert_eq!(reopened.records.len(), 2);
        assert_eq!(reopened.records[1]["eventType"], "task.started");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_rejects_out_of_sequence_records() {
        let dir = std::env::temp_dir().join(format!("p5d-journal-{}", kernel_test_nonce()));
        let path = dir.join("journal.jsonl");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "{\"sequence\":2}\n").unwrap();
        let error = JsonlJournal::open(&path).unwrap_err();
        assert_eq!(error.code, "JOURNAL_CORRUPT");
        assert_eq!(error.category, "integrity");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_rejects_invalid_json_lines() {
        let dir = std::env::temp_dir().join(format!("p5d-journal-{}", kernel_test_nonce()));
        let path = dir.join("journal.jsonl");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "not json\n").unwrap();
        let error = JsonlJournal::open(&path).unwrap_err();
        assert_eq!(error.code, "JOURNAL_CORRUPT");
        std::fs::remove_dir_all(&dir).ok();
    }

    pub(crate) fn kernel_test_nonce() -> u128 {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() ^ (std::process::id() as u128))
            .wrapping_add(NEXT_ID.fetch_add(1, Ordering::Relaxed) as u128)
    }
}
