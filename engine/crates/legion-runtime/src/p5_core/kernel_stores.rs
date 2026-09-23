//! Ported from src/packages/kernel/lib/stores.mjs (packet P5d).
//!
//! Faithful port of `digestContent`, `EventStore`, and `ArtifactStore`.
//! Hashing uses `legion_catalog::hex_digest` (SHA-256) instead of pulling in
//! the `sha2` crate directly, since `legion-catalog` is already a
//! `legion-runtime` dependency and exposes exactly that primitive.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use legion_catalog::json::{self, Value};

use crate::p5_core::kernel_contracts::assert_contract;
use crate::p5_core::kernel_errors::{KernelError, KernelErrorOptions};
use crate::p5_core::kernel_ids::{mint_id, now_millis, random_entropy, validate_id};
use crate::p5_core::kernel_journal::JsonlJournal;

fn integrity_error(code: &str, message: impl Into<String>) -> KernelError {
    KernelError::new(
        code,
        message,
        KernelErrorOptions {
            category: Some("integrity".to_string()),
            ..Default::default()
        },
    )
}

fn usage_error(message: impl Into<String>) -> KernelError {
    KernelError::new(
        "INVALID_ARGUMENT",
        message,
        KernelErrorOptions {
            category: Some("usage".to_string()),
            ..Default::default()
        },
    )
}

/// Minimal RFC 3339 UTC timestamp, good enough for journal `recordedAt`
/// fields (JS uses `new Date().toISOString()`).
pub fn system_time_to_iso8601(time: SystemTime) -> String {
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let millis_total = duration.as_millis();
    let secs = (millis_total / 1000) as i64;
    let millis = (millis_total % 1000) as u32;
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Howard Hinnant's days-from-civil algorithm, inverted, to avoid a chrono
/// dependency for a single timestamp formatter.
fn civil_from_unix(unix_secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let h = (secs_of_day / 3600) as u32;
    let mi = ((secs_of_day % 3600) / 60) as u32;
    let s = (secs_of_day % 60) as u32;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, s)
}

/// Canonical JSON serialization: object keys sorted, matching the JS
/// `canonical()` helper used for event digesting.
fn canonical(value: &Value) -> String {
    match value {
        Value::Array(items) => format!("[{}]", items.iter().map(canonical).collect::<Vec<_>>().join(",")),
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            let body = sorted
                .into_iter()
                .map(|(k, v)| format!("{}:{}", json::to_string(k).unwrap(), canonical(v)))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
        other => json::to_string(other).unwrap_or_else(|_| "null".to_string()),
    }
}

/// Port of `digestContent(content)`.
pub fn digest_content(content: &[u8]) -> String {
    format!("sha256:{}", legion_catalog::hex_digest(content))
}

fn event_digest(record: &Value) -> String {
    let mut unsigned = record.clone();
    if let Some(object) = unsigned.as_object_mut() {
        object.remove("eventDigest");
    }
    digest_content(canonical(&unsigned).as_bytes())
}

/// Port of `class EventStore`.
#[derive(Debug)]
pub struct EventStore {
    pub journal: JsonlJournal,
}

impl EventStore {
    pub fn open(file_path: impl AsRef<Path>) -> Result<Self, KernelError> {
        let journal = JsonlJournal::open(file_path)?;
        let mut previous: Option<String> = None;
        for event in journal.all() {
            let previous_digest = event.get("previousEventDigest").and_then(Value::as_str).map(str::to_string);
            if previous_digest != previous {
                let sequence = event.get("sequence").cloned().unwrap_or(Value::Null);
                return Err(integrity_error(
                    "EVENT_CHAIN_INVALID",
                    format!("event chain mismatch at sequence {sequence}"),
                ));
            }
            let actual = event_digest(&event);
            let stated = event.get("eventDigest").and_then(Value::as_str).unwrap_or_default();
            if stated != actual {
                let sequence = event.get("sequence").cloned().unwrap_or(Value::Null);
                return Err(integrity_error(
                    "EVENT_DIGEST_INVALID",
                    format!("event digest mismatch at sequence {sequence}"),
                ));
            }
            previous = Some(stated.to_string());
        }
        Ok(EventStore { journal })
    }

    pub fn all(&self) -> Vec<Value> {
        self.journal.all()
    }

    /// Port of `append(event)` / `appendNow(event)`.
    pub fn append(&mut self, event: Value) -> Result<Value, KernelError> {
        let run_id = event.get("runId").and_then(Value::as_str).unwrap_or_default();
        validate_id("run", run_id)?;
        if let Some(task_id) = event.get("taskId").and_then(Value::as_str) {
            validate_id("task", task_id)?;
        }
        let event_type_ok = event.get("type").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
        let actor_ok = event.get("actor").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
        if !event_type_ok || !actor_ok {
            return Err(usage_error("event type and actor are required"));
        }

        let previous = self.journal.records.last().and_then(|r| r.get("eventDigest")).cloned().unwrap_or(Value::Null);

        let mut record = json::json!({
            "schemaVersion": 1,
            "kind": "legion-kernel-event",
            "eventId": mint_id("event", now_millis(), &random_entropy())?,
            "recordedAt": system_time_to_iso8601(SystemTime::now()),
            "previousEventDigest": previous,
        });
        if let (Some(target), Some(extra)) = (record.as_object_mut(), event.as_object()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
        let sequence = (self.journal.records.len() + 1) as u64;
        record
            .as_object_mut()
            .expect("record is an object")
            .insert("sequence".to_string(), json::json!(sequence));
        let digest = event_digest(&record);
        record
            .as_object_mut()
            .expect("record is an object")
            .insert("eventDigest".to_string(), json::json!(digest));
        self.journal.append(record)
    }
}

fn exists(path: &Path) -> bool {
    path.exists()
}

/// Port of `class ArtifactStore`.
pub struct ArtifactStore {
    pub root: PathBuf,
    pub journal: JsonlJournal,
    records: BTreeMap<String, Value>,
}

impl ArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, KernelError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("blobs")).map_err(|cause| {
            KernelError::new(
                "ARTIFACT_STORE_IO_FAILED",
                format!("failed to create blobs directory: {cause}"),
                KernelErrorOptions {
                    category: Some("resource".to_string()),
                    ..Default::default()
                },
            )
        })?;
        let journal = JsonlJournal::open(root.join("artifacts.jsonl"))?;
        let mut records = BTreeMap::new();
        for entry in journal.all() {
            let artifact = entry.get("artifact").cloned().unwrap_or(Value::Null);
            assert_contract("artifact-v1", &artifact, Some("artifact record"))?;
            let artifact_id = artifact.get("artifactId").and_then(Value::as_str).unwrap_or_default().to_string();
            if records.contains_key(&artifact_id) {
                return Err(integrity_error(
                    "ARTIFACT_INDEX_CORRUPT",
                    format!("duplicate artifact ID: {artifact_id}"),
                ));
            }
            records.insert(artifact_id, artifact);
        }
        Ok(ArtifactStore { root, journal, records })
    }

    /// Port of `put(record, content)` / `putNow(record, bytes)`.
    pub fn put(&mut self, record: Value, content: &[u8]) -> Result<Value, KernelError> {
        let actual_digest = digest_content(content);
        let stated_digest = record.get("digest").and_then(Value::as_str).unwrap_or_default();
        if stated_digest != actual_digest {
            return Err(integrity_error("ARTIFACT_DIGEST_MISMATCH", "artifact digest mismatch"));
        }
        let stated_bytes = record.get("bytes").and_then(Value::as_u64);
        if stated_bytes != Some(content.len() as u64) {
            return Err(integrity_error("ARTIFACT_SIZE_MISMATCH", "artifact byte count mismatch"));
        }
        assert_contract("artifact-v1", &record, Some("artifact record"))?;
        if record.get("immutable") != Some(&Value::Bool(true)) {
            return Err(usage_error("artifact must be immutable"));
        }
        let artifact_id = record.get("artifactId").and_then(Value::as_str).unwrap_or_default().to_string();
        if self.records.contains_key(&artifact_id) {
            return Err(KernelError::new(
                "SCOPE_CONFLICT",
                format!("artifact already exists: {artifact_id}"),
                KernelErrorOptions {
                    category: Some("conflict".to_string()),
                    ..Default::default()
                },
            ));
        }
        let hex = actual_digest.strip_prefix("sha256:").unwrap_or(&actual_digest);
        let target = self.root.join("blobs").join(hex);
        if !exists(&target) {
            let temporary = self.root.join("blobs").join(format!(
                "{hex}.{}.{}.tmp",
                std::process::id(),
                now_millis()
            ));
            fs::write(&temporary, content).map_err(|cause| {
                KernelError::new(
                    "ARTIFACT_STORE_IO_FAILED",
                    format!("failed to write artifact blob: {cause}"),
                    KernelErrorOptions {
                        category: Some("resource".to_string()),
                        ..Default::default()
                    },
                )
            })?;
            fs::rename(&temporary, &target).map_err(|cause| {
                KernelError::new(
                    "ARTIFACT_STORE_IO_FAILED",
                    format!("failed to seal artifact blob: {cause}"),
                    KernelErrorOptions {
                        category: Some("resource".to_string()),
                        ..Default::default()
                    },
                )
            })?;
        }
        self.journal.append(json::json!({"artifact": record}))?;
        self.records.insert(artifact_id, record.clone());
        Ok(record)
    }

    pub fn get(&self, artifact_id: &str) -> Result<Value, KernelError> {
        validate_id("artifact", artifact_id)?;
        self.records.get(artifact_id).cloned().ok_or_else(|| {
            KernelError::new(
                "ARTIFACT_NOT_FOUND",
                format!("unknown artifact: {artifact_id}"),
                KernelErrorOptions {
                    category: Some("precondition".to_string()),
                    ..Default::default()
                },
            )
        })
    }

    pub fn get_content(&self, artifact_id: &str) -> Result<Vec<u8>, KernelError> {
        let record = self.get(artifact_id)?;
        let digest = record.get("digest").and_then(Value::as_str).unwrap_or_default();
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        let content = fs::read(self.root.join("blobs").join(hex)).map_err(|cause| {
            KernelError::new(
                "ARTIFACT_STORE_IO_FAILED",
                format!("failed to read artifact blob: {cause}"),
                KernelErrorOptions {
                    category: Some("resource".to_string()),
                    ..Default::default()
                },
            )
        })?;
        let expected_bytes = record.get("bytes").and_then(Value::as_u64);
        if Some(content.len() as u64) != expected_bytes || digest_content(&content) != digest {
            return Err(integrity_error(
                "ARTIFACT_DIGEST_MISMATCH",
                "artifact content no longer matches its digest binding",
            ));
        }
        Ok(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce() -> u128 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() ^ (std::process::id() as u128)
    }

    #[test]
    fn digest_content_is_sha256_prefixed() {
        let digest = digest_content(b"hello");
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), "sha256:".len() + 64);
    }

    #[test]
    fn iso8601_formatter_matches_known_instant() {
        // 2021-01-01T00:00:00.000Z == unix millis 1609459200000
        let time = UNIX_EPOCH + std::time::Duration::from_millis(1_609_459_200_000);
        assert_eq!(system_time_to_iso8601(time), "2021-01-01T00:00:00.000Z");
    }

    #[test]
    fn event_store_chains_and_validates_digests() {
        let dir = std::env::temp_dir().join(format!("p5d-events-{}", nonce()));
        let path = dir.join("events.jsonl");
        let run_id = "run_01ARZ3NDEKTSV4RRFFQ69G5FAV";
        {
            let mut store = EventStore::open(&path).unwrap();
            store
                .append(json::json!({"runId": run_id, "type": "run.started", "actor": "legion"}))
                .unwrap();
            store
                .append(json::json!({"runId": run_id, "type": "run.progress", "actor": "legion"}))
                .unwrap();
        }
        let reopened = EventStore::open(&path).unwrap();
        assert_eq!(reopened.all().len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn event_store_rejects_missing_actor() {
        let dir = std::env::temp_dir().join(format!("p5d-events-{}", nonce()));
        let path = dir.join("events.jsonl");
        let mut store = EventStore::open(&path).unwrap();
        let error = store
            .append(json::json!({"runId": "run_01ARZ3NDEKTSV4RRFFQ69G5FAV", "type": "run.started"}))
            .unwrap_err();
        assert_eq!(error.code, "INVALID_ARGUMENT");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn event_store_detects_tampered_digest_on_reopen() {
        let dir = std::env::temp_dir().join(format!("p5d-events-{}", nonce()));
        let path = dir.join("events.jsonl");
        {
            let mut store = EventStore::open(&path).unwrap();
            store
                .append(json::json!({"runId": "run_01ARZ3NDEKTSV4RRFFQ69G5FAV", "type": "run.started", "actor": "legion"}))
                .unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let tampered = text.replace("run.started", "run.tampered");
        std::fs::write(&path, tampered).unwrap();
        let error = EventStore::open(&path).unwrap_err();
        assert_eq!(error.code, "EVENT_DIGEST_INVALID");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn artifact_store_round_trips_content() {
        let dir = std::env::temp_dir().join(format!("p5d-artifacts-{}", nonce()));
        let content = b"artifact bytes";
        let digest = digest_content(content);
        let record = json::json!({
            "schemaVersion": 1,
            "kind": "legion-artifact",
            "artifactId": "art_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "artifactKind": "fixture",
            "digest": digest,
            "bytes": content.len(),
            "immutable": true,
            "producerAuthority": "legion",
            "sourceRevision": "abcdef0",
            "sensitivity": "internal",
            "retention": { "policy": "standard" },
            "redaction": { "applied": false, "metadata": [] },
            "createdAt": "2026-01-01T00:00:00Z",
        });
        {
            let mut store = ArtifactStore::open(&dir).unwrap();
            store.put(record.clone(), content).unwrap();
        }
        let reopened = ArtifactStore::open(&dir).unwrap();
        let fetched = reopened.get("art_01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        assert_eq!(fetched["digest"], digest);
        assert_eq!(reopened.get_content("art_01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap(), content);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn artifact_store_rejects_digest_mismatch() {
        let dir = std::env::temp_dir().join(format!("p5d-artifacts-{}", nonce()));
        let content = b"artifact bytes";
        let record = json::json!({
            "schemaVersion": 1,
            "kind": "legion-artifact",
            "artifactId": "art_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000",
            "bytes": content.len(),
            "immutable": true,
        });
        let mut store = ArtifactStore::open(&dir).unwrap();
        let error = store.put(record, content).unwrap_err();
        assert_eq!(error.code, "ARTIFACT_DIGEST_MISMATCH");
        std::fs::remove_dir_all(&dir).ok();
    }
}
