use legion_contracts::canonical_digest;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct ReceiptStore {
    receipts_path: PathBuf,
    head_path: PathBuf,
}

impl ReceiptStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root.as_ref();
        fs::create_dir_all(root).map_err(|error| error.to_string())?;
        fs::create_dir_all(root.join("objects")).map_err(|error| error.to_string())?;
        let store = Self {
            receipts_path: root.join("receipts.jsonl"),
            head_path: root.join("chain-head.json"),
        };
        if !store.receipts_path.is_file() {
            fs::write(&store.receipts_path, "").map_err(|error| error.to_string())?;
        }
        let quarantine_path = root.join("quarantine.jsonl");
        if !quarantine_path.is_file() {
            fs::write(quarantine_path, "").map_err(|error| error.to_string())?;
        }
        Ok(store)
    }

    fn read_lines(&self) -> Vec<String> {
        fs::read_to_string(&self.receipts_path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    pub fn list(&self) -> Vec<Value> {
        let mut out = Vec::new();
        for line in self.read_lines() {
            let entry = serde_json::from_str::<Value>(&line).ok();
            if let Some(entry) = entry {
                if entry.get("quarantined").and_then(Value::as_bool) == Some(true) {
                    continue;
                }
                if let Some(record) = entry.get("record") {
                    out.push(record.clone());
                }
            }
        }
        out
    }

    pub fn append(&self, record: &Value) -> Value {
        let lines = self.read_lines();
        let next_sequence = lines.len() + 1;
        let prev_digest = if let Some(last) = lines.last() {
            let entry = serde_json::from_str::<Value>(last).unwrap_or(Value::Null);
            canonical_digest(&entry).ok()
        } else {
            None
        };
        let record_digest = canonical_digest(record).unwrap_or_default();
        let entry = json!({
            "sequence": next_sequence,
            "at": chrono_like_now(),
            "recordDigest": record_digest,
            "prevDigest": prev_digest,
            "record": record,
        });
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.receipts_path)
            .map_err(|error| error.to_string())
            .unwrap();
        let line = serde_json::to_string(&entry).unwrap_or_default();
        let _ = writeln!(file, "{line}");
        let _ = fs::write(
            &self.head_path,
            serde_json::to_string(&json!({
                "sequence": next_sequence,
                "entryDigest": canonical_digest(&entry).unwrap_or_default(),
            }))
            .unwrap_or_default(),
        );
        json!({
            "sequence": next_sequence,
            "recordDigest": record_digest,
            "prevDigest": prev_digest,
        })
    }

    pub fn verify_chain(&self) -> Value {
        let lines = self.read_lines();
        let mut prev_expected: Option<String> = None;
        for (index, line) in lines.iter().enumerate() {
            let seq_expected = index + 1;
            let entry = match serde_json::from_str::<Value>(line) {
                Ok(value) => value,
                Err(_) => {
                    return json!({
                        "ok": false,
                        "length": index,
                        "corruptAt": seq_expected,
                        "reason": "unparseable JSONL line",
                    });
                }
            };
            if entry.get("quarantined").and_then(Value::as_bool) == Some(true) {
                prev_expected = None;
                continue;
            }
            if entry.get("sequence").and_then(Value::as_u64) != Some(seq_expected as u64) {
                return json!({
                    "ok": false,
                    "length": index,
                    "corruptAt": seq_expected,
                    "reason": "sequence regression",
                });
            }
            if let Some(prev) = prev_expected.as_ref() {
                if entry.get("prevDigest").and_then(Value::as_str) != Some(prev.as_str()) {
                    return json!({
                        "ok": false,
                        "length": index,
                        "corruptAt": seq_expected,
                        "reason": "prevDigest mismatch",
                    });
                }
            }
            prev_expected = canonical_digest(&entry).ok();
        }
        json!({ "ok": true, "length": lines.len(), "corruptAt": Value::Null, "reason": Value::Null })
    }
}

fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!("{millis}")
}
