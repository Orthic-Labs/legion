//! Faithful port of `ObservationOutbox` from
//! `src/lib/host/arcane/host-event-ledger.mjs`: durable observation delivery
//! with bounded batches, dead letters, and redrive. Self-contained (no
//! signing dependency), unlike `HostEventLedger` in the same JS file — see
//! `wf_port::w2_047` module docs for why that class is not ported here.

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxEntry {
    #[serde(rename = "eventId")]
    pub event_id: String,
    pub observation: Json,
    pub attempts: u32,
    #[serde(rename = "enqueuedAt")]
    pub enqueued_at: String,
    #[serde(rename = "lastError")]
    pub last_error: Option<String>,
    #[serde(rename = "deliveredAt", skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<String>,
    #[serde(rename = "destinationReceipt", skip_serializing_if = "Option::is_none")]
    pub destination_receipt: Option<Json>,
    #[serde(rename = "deadLetteredAt", skip_serializing_if = "Option::is_none")]
    pub dead_lettered_at: Option<String>,
    #[serde(rename = "redrivenAt", skip_serializing_if = "Option::is_none")]
    pub redriven_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OutboxState {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    pending: Vec<OutboxEntry>,
    delivered: Vec<OutboxEntry>,
    #[serde(rename = "deadLetter")]
    dead_letter: Vec<OutboxEntry>,
}

impl Default for OutboxState {
    fn default() -> Self {
        Self { schema_version: 1, pending: Vec::new(), delivered: Vec::new(), dead_letter: Vec::new() }
    }
}

/// Mirrors `digestValue(observation)` closely enough for outbox
/// deduplication purposes: a stable content id when the caller supplies no
/// explicit `eventId`. Real `digestValue` (canonical.mjs, unowned by this
/// chunk) is a canonical-JSON SHA-256; this uses `sha2` (already a
/// `legion-runtime` dependency) over `serde_json::to_string` of the value,
/// which is stable for a given `Value` but not guaranteed byte-identical to
/// JS's canonicalization for exotic key orderings. Callers that need
/// cross-language-identical ids should pass `event_id` explicitly, exactly
/// as JS callers pass `observation.eventId` when they have one.
fn digest_value(v: &Json) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(v).unwrap_or_default());
    hex::encode(hasher.finalize())
}

#[derive(Debug, thiserror::Error)]
pub enum OutboxError {
    #[error("outbox root is required")]
    MissingRoot,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub struct ObservationOutbox {
    root: PathBuf,
    max_attempts: u32,
    clock: Box<dyn Fn() -> String + Send + Sync>,
}

fn default_clock() -> String {
    // RFC3339-ish millisecond timestamp, matching `new Date().toISOString()`'s
    // shape closely enough for outbox bookkeeping (not asserted byte-for-byte
    // anywhere downstream).
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{}", now.as_millis())
}

impl ObservationOutbox {
    /// Mirrors `new ObservationOutbox({root, clock, maxAttempts})`. Throws
    /// (`TypeError`) when `root` is empty — mirrored as `Err(MissingRoot)`.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, OutboxError> {
        let root = root.as_ref();
        if root.as_os_str().is_empty() {
            return Err(OutboxError::MissingRoot);
        }
        Ok(Self { root: root.to_path_buf(), max_attempts: 3, clock: Box::new(default_clock) })
    }

    pub fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    pub fn with_clock(mut self, clock: impl Fn() -> String + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    fn file(&self) -> PathBuf {
        self.root.join("outbox.json")
    }

    fn read(&self) -> Result<OutboxState, OutboxError> {
        let file = self.file();
        if !file.exists() {
            return Ok(OutboxState::default());
        }
        let raw = fs::read_to_string(file)?;
        Ok(serde_json::from_str(&raw)?)
    }

    fn write(&self, state: &OutboxState) -> Result<(), OutboxError> {
        fs::create_dir_all(&self.root)?;
        let temp = self.root.join(format!(".outbox-{}-{}.tmp", std::process::id(), (self.clock)()));
        fs::write(&temp, serde_json::to_vec(state)?)?;
        fs::rename(&temp, self.file())?;
        Ok(())
    }

    /// Mirrors `enqueue(observation)`. `event_id` mirrors `observation.eventId
    /// ?? digestValue(observation)`.
    pub fn enqueue(&self, observation: Json, event_id: Option<String>) -> Result<(String, bool), OutboxError> {
        let mut state = self.read()?;
        let event_id = event_id.or_else(|| observation.get("eventId").and_then(|v| v.as_str()).map(str::to_string)).unwrap_or_else(|| digest_value(&observation));
        let already = state.pending.iter().chain(state.delivered.iter()).chain(state.dead_letter.iter()).any(|e| e.event_id == event_id);
        if already {
            return Ok((event_id, true));
        }
        state.pending.push(OutboxEntry {
            event_id: event_id.clone(),
            observation,
            attempts: 0,
            enqueued_at: (self.clock)(),
            last_error: None,
            delivered_at: None,
            destination_receipt: None,
            dead_lettered_at: None,
            redriven_at: None,
        });
        self.write(&state)?;
        Ok((event_id, false))
    }

    /// Mirrors `nextBatch({maxCount, maxBytes})`.
    pub fn next_batch(&self, max_count: usize, max_bytes: usize) -> Result<Vec<OutboxEntry>, OutboxError> {
        let state = self.read()?;
        let mut batch = Vec::new();
        let mut bytes = 0usize;
        for entry in state.pending {
            let size = serde_json::to_vec(&entry).map(|v| v.len()).unwrap_or(0);
            if batch.len() >= max_count || bytes + size > max_bytes {
                break;
            }
            batch.push(entry);
            bytes += size;
        }
        Ok(batch)
    }

    /// Mirrors `acknowledge(eventIds, destinationReceipt)`.
    pub fn acknowledge(&self, event_ids: &[String], destination_receipt: Option<Json>) -> Result<usize, OutboxError> {
        let mut state = self.read()?;
        let ids: std::collections::HashSet<&str> = event_ids.iter().map(String::as_str).collect();
        let mut moved = Vec::new();
        let mut remaining = Vec::new();
        for mut entry in state.pending.drain(..) {
            if ids.contains(entry.event_id.as_str()) {
                entry.destination_receipt = destination_receipt.clone();
                entry.delivered_at = Some((self.clock)());
                moved.push(entry);
            } else {
                remaining.push(entry);
            }
        }
        state.pending = remaining;
        let delivered = moved.len();
        state.delivered.extend(moved);
        self.write(&state)?;
        Ok(delivered)
    }

    /// Mirrors `fail(eventIds, error)`. Returns `(retried, dead_lettered)`.
    pub fn fail(&self, event_ids: &[String], error: &str) -> Result<(usize, usize), OutboxError> {
        let mut state = self.read()?;
        let ids: std::collections::HashSet<&str> = event_ids.iter().map(String::as_str).collect();
        let mut dead = Vec::new();
        let mut remaining = Vec::new();
        for mut entry in state.pending.drain(..) {
            if !ids.contains(entry.event_id.as_str()) {
                remaining.push(entry);
                continue;
            }
            entry.attempts += 1;
            entry.last_error = Some(error.to_string());
            if entry.attempts >= self.max_attempts {
                entry.dead_lettered_at = Some((self.clock)());
                dead.push(entry);
            } else {
                remaining.push(entry);
            }
        }
        state.pending = remaining;
        let dead_lettered = dead.len();
        state.dead_letter.extend(dead);
        self.write(&state)?;
        Ok((ids.len().saturating_sub(dead_lettered), dead_lettered))
    }

    /// Mirrors `redrive(eventIds)`.
    pub fn redrive(&self, event_ids: &[String]) -> Result<usize, OutboxError> {
        let mut state = self.read()?;
        let ids: std::collections::HashSet<&str> = event_ids.iter().map(String::as_str).collect();
        let mut redriven = Vec::new();
        let mut remaining = Vec::new();
        for mut entry in state.dead_letter.drain(..) {
            if ids.contains(entry.event_id.as_str()) {
                entry.attempts = 0;
                entry.last_error = None;
                entry.redriven_at = Some((self.clock)());
                redriven.push(entry);
            } else {
                remaining.push(entry);
            }
        }
        state.dead_letter = remaining;
        let count = redriven.len();
        state.pending.extend(redriven);
        self.write(&state)?;
        Ok(count)
    }

    /// Mirrors `inspect()`.
    pub fn inspect(&self) -> Result<(usize, usize, usize), OutboxError> {
        let state = self.read()?;
        Ok((state.pending.len(), state.delivered.len(), state.dead_letter.len()))
    }

    /// Mirrors `aggregateUsage({runId, taskId})`.
    pub fn aggregate_usage(&self, run_id: Option<&str>, task_id: Option<&str>) -> Result<UsageTotals, OutboxError> {
        let state = self.read()?;
        let mut total = UsageTotals::default();
        for entry in state.pending.iter().chain(state.delivered.iter()).chain(state.dead_letter.iter()) {
            let obs = &entry.observation;
            if let Some(rid) = run_id {
                if obs.get("runId").and_then(|v| v.as_str()) != Some(rid) {
                    continue;
                }
            }
            if let Some(tid) = task_id {
                if obs.get("taskId").and_then(|v| v.as_str()) != Some(tid) {
                    continue;
                }
            }
            let usage = obs.get("usage");
            total.calls += usage.and_then(|u| u.get("calls")).and_then(Json::as_i64).unwrap_or(0);
            total.input_tokens += usage.and_then(|u| u.get("inputTokens")).and_then(Json::as_i64).unwrap_or(0);
            total.output_tokens += usage.and_then(|u| u.get("outputTokens")).and_then(Json::as_i64).unwrap_or(0);
            total.cost_micros += usage.and_then(|u| u.get("costMicros")).and_then(Json::as_i64).unwrap_or(0);
            if usage.and_then(|u| u.get("complete")).and_then(Json::as_bool) == Some(false) {
                total.incomplete = true;
            }
        }
        Ok(total)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageTotals {
    pub calls: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cost_micros: i64,
    pub incomplete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Minimal self-cleaning temp dir (no `tempfile`/`tempdir` crate
    /// dependency available in this chunk's Cargo.toml budget).
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("wf_w2_047_outbox_{}_{}_{}", std::process::id(), n, default_clock()));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tmp_outbox() -> (ObservationOutbox, TmpDir) {
        let dir = TmpDir::new();
        let outbox = ObservationOutbox::new(dir.path()).unwrap();
        (outbox, dir)
    }

    #[test]
    fn enqueue_dedupes_by_event_id() {
        let (outbox, _dir) = tmp_outbox();
        let (id1, dup1) = outbox.enqueue(json!({"a": 1}), Some("ev1".to_string())).unwrap();
        let (id2, dup2) = outbox.enqueue(json!({"a": 2}), Some("ev1".to_string())).unwrap();
        assert_eq!(id1, "ev1");
        assert_eq!(id2, "ev1");
        assert!(!dup1);
        assert!(dup2);
        let (pending, delivered, dead) = outbox.inspect().unwrap();
        assert_eq!((pending, delivered, dead), (1, 0, 0));
    }

    #[test]
    fn acknowledge_moves_pending_to_delivered() {
        let (outbox, _dir) = tmp_outbox();
        outbox.enqueue(json!({}), Some("ev1".to_string())).unwrap();
        let delivered = outbox.acknowledge(&["ev1".to_string()], Some(json!({"ok": true}))).unwrap();
        assert_eq!(delivered, 1);
        let (pending, delivered_count, dead) = outbox.inspect().unwrap();
        assert_eq!((pending, delivered_count, dead), (0, 1, 0));
    }

    #[test]
    fn fail_retries_until_max_attempts_then_dead_letters() {
        let (outbox, _dir) = tmp_outbox();
        let outbox = ObservationOutbox::new(outbox.root.clone()).unwrap().with_max_attempts(2);
        outbox.enqueue(json!({}), Some("ev1".to_string())).unwrap();

        let (retried1, dead1) = outbox.fail(&["ev1".to_string()], "boom").unwrap();
        assert_eq!((retried1, dead1), (1, 0));
        let (pending, _, dead) = outbox.inspect().unwrap();
        assert_eq!((pending, dead), (1, 0));

        let (retried2, dead2) = outbox.fail(&["ev1".to_string()], "boom again").unwrap();
        assert_eq!((retried2, dead2), (0, 1));
        let (pending2, _, dead_count) = outbox.inspect().unwrap();
        assert_eq!((pending2, dead_count), (0, 1));
    }

    #[test]
    fn redrive_moves_dead_letter_back_to_pending_and_resets_attempts() {
        let (outbox, _dir) = tmp_outbox();
        let outbox = ObservationOutbox::new(outbox.root.clone()).unwrap().with_max_attempts(1);
        outbox.enqueue(json!({}), Some("ev1".to_string())).unwrap();
        outbox.fail(&["ev1".to_string()], "boom").unwrap();
        let (_, _, dead) = outbox.inspect().unwrap();
        assert_eq!(dead, 1);

        let redriven = outbox.redrive(&["ev1".to_string()]).unwrap();
        assert_eq!(redriven, 1);
        let (pending, _, dead2) = outbox.inspect().unwrap();
        assert_eq!((pending, dead2), (1, 0));
    }

    #[test]
    fn next_batch_respects_max_count_and_bytes() {
        let (outbox, _dir) = tmp_outbox();
        for i in 0..5 {
            outbox.enqueue(json!({"i": i}), Some(format!("ev{i}"))).unwrap();
        }
        let batch = outbox.next_batch(2, usize::MAX).unwrap();
        assert_eq!(batch.len(), 2);
        let tiny = outbox.next_batch(usize::MAX, 1).unwrap();
        assert_eq!(tiny.len(), 0);
    }

    #[test]
    fn aggregate_usage_filters_by_run_and_task_and_sums() {
        let (outbox, _dir) = tmp_outbox();
        outbox
            .enqueue(json!({"runId": "r1", "taskId": "t1", "usage": {"calls": 2, "inputTokens": 10, "outputTokens": 5, "costMicros": 100, "complete": true}}), Some("ev1".to_string()))
            .unwrap();
        outbox
            .enqueue(json!({"runId": "r1", "taskId": "t1", "usage": {"calls": 1, "inputTokens": 3, "outputTokens": 1, "costMicros": 10, "complete": false}}), Some("ev2".to_string()))
            .unwrap();
        outbox.enqueue(json!({"runId": "r2", "taskId": "t2", "usage": {"calls": 99}}), Some("ev3".to_string())).unwrap();

        let totals = outbox.aggregate_usage(Some("r1"), Some("t1")).unwrap();
        assert_eq!(totals.calls, 3);
        assert_eq!(totals.input_tokens, 13);
        assert_eq!(totals.output_tokens, 6);
        assert_eq!(totals.cost_micros, 110);
        assert!(totals.incomplete);
    }

    #[test]
    fn missing_root_errors() {
        let err = ObservationOutbox::new("");
        assert!(matches!(err, Err(OutboxError::MissingRoot)));
    }
}
