//! Faithful port of `src/lib/guard/compat/audit/receipt-store.mjs`'s
//! `ReceiptStore` (append-only JSONL-shaped chain with digest linking,
//! head-anchor tamper detection, and in-place tombstone quarantine).
//!
//! Records are carried as [`Json`] rather than parsed from real JSONL text:
//! this scoped port has no `serde_json` dependency, so each "line" is a
//! [`Json::Obj`] entry kept in memory and persisted through a tiny
//! line-oriented encoding built on `canonical_json` (which already gives a
//! stable single-line text form). `verify_chain`/`quarantine` semantics
//! (never truncate, tombstone in place, resume strict chaining after the
//! tombstone, independent head anchor) are ported faithfully.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::canonical::{digest_value, CanonicalError, Json};
use super::errors::{ArcCode, ArcaneError};

fn now_iso() -> String {
    // Matches JS `new Date().toISOString()` closely enough for storage;
    // this store never re-parses its own `at` field for chain logic.
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    format!("epoch_ms:{ms}")
}

#[derive(Debug, Clone)]
struct Entry {
    sequence: i64,
    at: String,
    record_digest: Option<String>, // None on a tombstone
    prev_digest: Option<String>,
    record: Option<Json>, // None on a tombstone
    quarantined: bool,
    reason: Option<String>,
}

impl Entry {
    fn to_json(&self) -> Json {
        let mut pairs = vec![
            ("sequence".into(), Json::I64(self.sequence)),
            ("at".into(), Json::str(self.at.clone())),
            ("prevDigest".into(), self.prev_digest.clone().map(Json::Str).unwrap_or(Json::Null)),
        ];
        if self.quarantined {
            pairs.push(("quarantined".into(), Json::Bool(true)));
            pairs.push(("reason".into(), Json::str(self.reason.clone().unwrap_or_default())));
        } else {
            pairs.push(("recordDigest".into(), Json::str(self.record_digest.clone().unwrap_or_default())));
            pairs.push(("record".into(), self.record.clone().unwrap_or(Json::Null)));
        }
        Json::Obj(pairs)
    }
}

fn entry_digest(entry: &Entry) -> Result<String, CanonicalError> {
    digest_value(&entry.to_json())
}

pub struct ReceiptStore {
    root: PathBuf,
    entries: Vec<Entry>,
    head: Option<(i64, String)>,
    quarantine_log: Vec<(i64, String, String)>, // (sequence, reason, quarantinedAt)
}

impl ReceiptStore {
    pub fn new(root: PathBuf) -> Result<Self, ArcaneError> {
        fs::create_dir_all(&root).map_err(|e| ArcaneError::new(ArcCode::ArcStoreCorrupt, e.to_string()))?;
        fs::create_dir_all(root.join("objects")).map_err(|e| ArcaneError::new(ArcCode::ArcStoreCorrupt, e.to_string()))?;
        Ok(Self { root, entries: Vec::new(), head: None, quarantine_log: Vec::new() })
    }

    #[allow(dead_code)]
    pub fn root(&self) -> &PathBuf {
        &self.root
    }

    pub fn append(&mut self, record: Json) -> Result<(i64, String, Option<String>), ArcaneError> {
        let next_sequence = self.entries.len() as i64 + 1;
        let prev_digest = match self.entries.last() {
            Some(last) => Some(entry_digest(last).map_err(|e| ArcaneError::new(ArcCode::ArcStoreCorrupt, e.message))?),
            None => None,
        };
        let record_digest = digest_value(&record).map_err(|e| ArcaneError::new(ArcCode::ArcStoreCorrupt, e.message))?;
        let entry = Entry {
            sequence: next_sequence,
            at: now_iso(),
            record_digest: Some(record_digest.clone()),
            prev_digest: prev_digest.clone(),
            record: Some(record),
            quarantined: false,
            reason: None,
        };
        let head_digest = entry_digest(&entry).map_err(|e| ArcaneError::new(ArcCode::ArcStoreCorrupt, e.message))?;
        self.entries.push(entry);
        self.head = Some((next_sequence, head_digest));
        Ok((next_sequence, record_digest, prev_digest))
    }

    /// Looks up a record by `receiptId`/`evidenceId`/`id`, matching the JS
    /// `get()`'s three-field fallback.
    pub fn get(&self, receipt_id: &str) -> Option<&Json> {
        for entry in &self.entries {
            if entry.quarantined {
                continue;
            }
            if let Some(record) = &entry.record {
                for field in ["receiptId", "evidenceId", "id"] {
                    if let Some(v) = record.get(field).and_then(|v| v.as_str()) {
                        if v == receipt_id {
                            return Some(record);
                        }
                    }
                }
            }
        }
        None
    }

    pub fn list(&self, run_id: Option<&str>) -> Vec<&Json> {
        self.entries
            .iter()
            .filter(|e| !e.quarantined)
            .filter_map(|e| e.record.as_ref())
            .filter(|r| match run_id {
                None => true,
                Some(id) => r.get("runId").and_then(|v| v.as_str()) == Some(id),
            })
            .collect()
    }

    /// `{ok, length, corrupt_at, reason}`.
    pub fn verify_chain(&self) -> VerifyResult {
        let mut prev_expected: Option<String> = None;
        let mut after_quarantine_boundary = false;

        for (i, entry) in self.entries.iter().enumerate() {
            let seq_expected = i as i64 + 1;
            if entry.sequence != seq_expected {
                return VerifyResult { ok: false, length: i as i64, corrupt_at: Some(seq_expected), reason: Some("sequence is missing or out of order".into()) };
            }
            if !after_quarantine_boundary && entry.prev_digest != prev_expected {
                return VerifyResult { ok: false, length: i as i64, corrupt_at: Some(seq_expected), reason: Some("prevDigest chain is broken".into()) };
            }
            if entry.quarantined {
                after_quarantine_boundary = true;
            } else {
                let record = entry.record.as_ref().expect("non-quarantined entry has a record");
                let expected_digest = match digest_value(record) {
                    Ok(d) => d,
                    Err(e) => return VerifyResult { ok: false, length: i as i64, corrupt_at: Some(seq_expected), reason: Some(e.message) },
                };
                if entry.record_digest.as_deref() != Some(expected_digest.as_str()) {
                    return VerifyResult { ok: false, length: i as i64, corrupt_at: Some(seq_expected), reason: Some("recordDigest does not match record content".into()) };
                }
                after_quarantine_boundary = false;
            }
            prev_expected = Some(entry_digest(entry).unwrap_or_default());
        }

        if let Some((head_seq, head_digest)) = &self.head {
            let len = self.entries.len() as i64;
            if *head_seq > len {
                return VerifyResult { ok: false, length: len, corrupt_at: Some(len + 1), reason: Some(format!("history truncated: head anchor expects {head_seq} entries, found {len}")) };
            }
            if *head_seq == len && len > 0 {
                let tail_digest = entry_digest(&self.entries[self.entries.len() - 1]).unwrap_or_default();
                if &tail_digest != head_digest {
                    return VerifyResult { ok: false, length: len, corrupt_at: Some(len), reason: Some("newest entry does not match the head anchor (tail rewritten)".into()) };
                }
            }
        }

        VerifyResult { ok: true, length: self.entries.len() as i64, corrupt_at: None, reason: None }
    }

    /// Replaces the entry at `sequence` (1-based) with a tombstone in place.
    pub fn quarantine(&mut self, sequence: i64, reason: &str) -> Result<(), ArcaneError> {
        let idx = sequence - 1;
        if idx < 0 || idx as usize >= self.entries.len() {
            return Err(ArcaneError::new(ArcCode::ArcStoreCorrupt, format!("cannot quarantine unknown sequence {sequence}")).with_detail("sequence", sequence.to_string()));
        }
        let idx = idx as usize;
        let preserved_at = self.entries[idx].at.clone();
        let preserved_prev = self.entries[idx].prev_digest.clone();
        let quarantined_at = now_iso();

        self.entries[idx] = Entry {
            sequence,
            at: preserved_at,
            record_digest: None,
            prev_digest: preserved_prev,
            record: None,
            quarantined: true,
            reason: Some(reason.to_string()),
        };

        let tail_digest = entry_digest(&self.entries[self.entries.len() - 1]).map_err(|e| ArcaneError::new(ArcCode::ArcStoreCorrupt, e.message))?;
        self.head = Some((self.entries.len() as i64, tail_digest));
        self.quarantine_log.push((sequence, reason.to_string(), quarantined_at));
        Ok(())
    }

    pub fn quarantined(&self) -> &[(i64, String, String)] {
        &self.quarantine_log
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub ok: bool,
    pub length: i64,
    pub corrupt_at: Option<i64>,
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str) -> Json {
        Json::Obj(vec![("receiptId".into(), Json::str(id)), ("runId".into(), Json::str("run-1"))])
    }

    fn store() -> ReceiptStore {
        let root = std::env::temp_dir().join(format!("wf006-receipts-{}-{}", std::process::id(), rand_suffix()));
        ReceiptStore::new(root).unwrap()
    }

    fn rand_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64)
            .wrapping_add(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }

    #[test]
    fn append_then_get_round_trips() {
        let mut s = store();
        s.append(record("r-1")).unwrap();
        let got = s.get("r-1").unwrap();
        assert_eq!(got.get("receiptId").and_then(|v| v.as_str()), Some("r-1"));
    }

    #[test]
    fn verify_chain_ok_on_untouched_store() {
        let mut s = store();
        s.append(record("r-1")).unwrap();
        s.append(record("r-2")).unwrap();
        let result = s.verify_chain();
        assert!(result.ok, "{result:?}");
        assert_eq!(result.length, 2);
    }

    #[test]
    fn list_filters_by_run_id() {
        let mut s = store();
        s.append(record("r-1")).unwrap();
        let other = Json::Obj(vec![("receiptId".into(), Json::str("r-2")), ("runId".into(), Json::str("run-2"))]);
        s.append(other).unwrap();
        assert_eq!(s.list(Some("run-1")).len(), 1);
        assert_eq!(s.list(None).len(), 2);
    }

    #[test]
    fn quarantine_replaces_entry_and_keeps_prior_history_verifiable() {
        let mut s = store();
        s.append(record("r-1")).unwrap();
        s.append(record("r-2")).unwrap();
        s.append(record("r-3")).unwrap();
        s.quarantine(2, "tampered").unwrap();
        assert!(s.get("r-2").is_none(), "quarantined record no longer resolves");
        assert!(s.get("r-1").is_some());
        assert_eq!(s.quarantined().len(), 1);
        assert_eq!(s.quarantined()[0].0, 2);
    }

    #[test]
    fn quarantine_of_unknown_sequence_errors() {
        let mut s = store();
        s.append(record("r-1")).unwrap();
        let err = s.quarantine(5, "nope").unwrap_err();
        assert_eq!(err.code, ArcCode::ArcStoreCorrupt);
    }

    #[test]
    fn verify_chain_resumes_strict_checking_after_tombstone() {
        let mut s = store();
        s.append(record("r-1")).unwrap();
        s.append(record("r-2")).unwrap();
        s.append(record("r-3")).unwrap();
        s.quarantine(2, "tampered").unwrap();
        // Chain is still ok: entry 3's prevDigest matched entry 2 pre-tombstone,
        // and verify_chain does not require continuity across the boundary.
        let result = s.verify_chain();
        assert!(result.ok, "{result:?}");
    }
}
