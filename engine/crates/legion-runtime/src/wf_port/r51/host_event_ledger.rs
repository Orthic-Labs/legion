//! Faithful port of `HostEventLedger` from
//! `src/lib/host/arcane/host-event-ledger.mjs`. `ObservationOutbox` from the
//! same source file is already ported at
//! `crate::wf_port::w2_047::observation_outbox`.
//!
//! Signing/verification is an injected [`LedgerSigner`] trait: JS's
//! constructor itself takes `keyRing`/`keyId`/`verificationKeyRing` as
//! external dependencies, so this mirrors that same boundary rather than
//! re-deriving HMAC signing (which lives in `guard/compat/audit/receipt-auth.mjs`,
//! not owned by this file). The digest of a record (`digestValue` in JS)
//! uses `legion_contracts::canonical::canonical_digest`, which already
//! reproduces `contracts/arcane/canonical.mjs` exactly (sorted-key canonical
//! JSON, `sha256:<hex>` output) — no reimplementation needed there.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use legion_contracts::canonical::canonical_digest;
use serde_json::{json, Map, Value as Json};

/// Mirrors JS `HOST_EVENT_LEDGER_FIELDS` — the bound-field list a record is
/// signed over.
pub const HOST_EVENT_LEDGER_FIELDS: &[&str] = &[
    "schemaVersion",
    "kind",
    "eventId",
    "eventSequence",
    "previousDigest",
    "turnCorrelationDigest",
    "stopOrdinal",
    "adapter",
    "eventType",
    "sessionId",
    "runId",
    "taskId",
    "contractId",
    "contractVersion",
    "contractDigest",
    "sourceRevision",
    "observedAuthority",
    "payloadDigest",
    "observedAt",
];

/// Mirrors JS `HEAD_FIELDS`.
const HEAD_FIELDS: &[&str] = &["kind", "eventSequence", "digest"];

/// Mirrors JS `APPEND_LOCK_STALE_MS`.
const APPEND_LOCK_STALE_MS: u128 = 30_000;

fn digest_value(value: &Json) -> String {
    canonical_digest(value).expect("host-event-ledger record must be canonicalizable")
}

/// Mirrors the JS `deny(code, message)` helper's shape (this file only ever
/// denies with `ARC_STORE_CORRUPT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerDecision {
    pub allowed: bool,
    pub code: Option<&'static str>,
    pub message: String,
    pub event_count: usize,
}

impl LedgerDecision {
    fn allow(event_count: usize) -> Self {
        Self { allowed: true, code: None, message: String::new(), event_count }
    }
    fn deny(message: impl Into<String>) -> Self {
        Self { allowed: false, code: Some("ARC_STORE_CORRUPT"), message: message.into(), event_count: 0 }
    }
}

/// Mirrors what `signRecord`/`verifyRecord` (`guard/compat/audit/receipt-auth.mjs`)
/// contribute to `HostEventLedger`. A caller wires this to whichever real
/// receipt-auth port is available (e.g. `legion-arcane::receipt_auth` or
/// `legion-policy::wf_port::wf006::receipt_auth`); JS's own constructor takes
/// the same `keyRing`/`keyId`/`verificationKeyRing` as external dependencies.
pub trait LedgerSigner {
    /// Sign `record` over `bound_fields`, returning the `authentication`
    /// block to attach. Mirrors `signRecord(record, {keyRing, keyId, boundFields})`.
    fn sign(&self, record: &Json, bound_fields: &[&str]) -> Result<Json, String>;
    /// Verify `record`'s `authentication` block over `bound_fields`. Mirrors
    /// `verifyRecord(record, record.authentication, {keyRing: verificationKeyRing, boundFields}).allowed`.
    fn verify(&self, record: &Json, authentication: &Json, bound_fields: &[&str]) -> bool;
}

/// Binding fields a caller supplies to `append` — mirrors the destructured
/// `binding` argument (`binding?.runId`, `binding?.taskId`, `binding?.contractId`).
#[derive(Debug, Clone, Default)]
pub struct AppendBinding {
    pub run_id: Option<String>,
    pub task_id: Option<String>,
    pub contract_id: Option<String>,
    pub contract_version: Option<String>,
    pub contract_digest: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AppendInput<'a> {
    pub event_id: String,
    pub adapter: String,
    pub event_type: String,
    pub session_id: Option<String>,
    pub binding: Option<&'a AppendBinding>,
    pub source_revision: Option<String>,
    pub observed_authority: Option<Json>,
    pub payload: Json,
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("{message}")]
    Denied { code: &'static str, message: String },
    #[error("host event ledger append lock unavailable")]
    LockUnavailable,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Faithful port of JS `class HostEventLedger`.
pub struct HostEventLedger<S: LedgerSigner> {
    root: PathBuf,
    signer: S,
    /// Mirrors JS `clock = () => new Date().toISOString()`.
    clock: Box<dyn Fn() -> String>,
    pid: u32,
}

fn is_record_filename(name: &str) -> bool {
    name.len() == 21 && name.ends_with(".json") && name[..16].bytes().all(|b| b.is_ascii_digit())
}

impl<S: LedgerSigner> HostEventLedger<S> {
    pub fn new(root: impl Into<PathBuf>, signer: S) -> Self {
        Self::with_clock(root, signer, || {
            humantime_iso_now()
        })
    }

    pub fn with_clock(root: impl Into<PathBuf>, signer: S, clock: impl Fn() -> String + 'static) -> Self {
        Self { root: root.into(), signer, clock: Box::new(clock), pid: std::process::id() }
    }

    fn head_path(&self) -> PathBuf {
        self.root.join("head.json")
    }
    fn lock_path(&self) -> PathBuf {
        self.root.join(".append.lock")
    }
    fn lock_owner_path(&self) -> PathBuf {
        self.lock_path().join("owner.json")
    }

    fn owner_is_alive(owner: Option<&Json>) -> bool {
        let Some(owner) = owner else { return false };
        let Some(pid) = owner.get("pid").and_then(Json::as_i64) else { return false };
        if pid <= 0 {
            return false;
        }
        process_alive(pid as u32)
    }

    /// Mirrors `#reclaimStaleLock`. Returns `Ok(true)` when the lock is now
    /// clear (either it never existed, or a stale lock was removed);
    /// `Ok(false)` when a live/live-owner/too-young lock must be respected.
    fn reclaim_stale_lock(&self) -> io::Result<bool> {
        let lock = self.lock_path();
        let meta = match fs::metadata(&lock) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
            Err(e) => return Err(e),
        };
        let age_ms = SystemTime::now()
            .duration_since(meta.modified().unwrap_or(SystemTime::now()))
            .unwrap_or(Duration::ZERO)
            .as_millis();
        let owner: Option<Json> = fs::read(self.lock_owner_path()).ok().and_then(|b| serde_json::from_slice(&b).ok());
        if Self::owner_is_alive(owner.as_ref()) || (owner.is_none() && age_ms < APPEND_LOCK_STALE_MS) {
            return Ok(false);
        }
        let stale = self.root.join(format!(".append.lock.stale-{}-{}", self.pid, now_millis()));
        match fs::rename(&lock, &stale) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
            Err(_) => return Ok(false),
        }
        let _ = fs::remove_dir_all(&stale);
        Ok(true)
    }

    /// Mirrors `#withLock(fn)`: acquire the `mkdir`-based exclusive lock
    /// (retrying once after a stale-lock reclaim), run `fn`, then release.
    fn with_lock<T>(&self, f: impl FnOnce() -> Result<T, LedgerError>) -> Result<T, LedgerError> {
        fs::create_dir_all(&self.root)?;
        let lock = self.lock_path();
        let mut token: Option<String> = None;
        for attempt in 0..2 {
            match fs::create_dir(&lock) {
                Ok(()) => {
                    let tok = format!("{}-{}-{}", self.pid, now_millis(), attempt);
                    let owner = json!({"pid": self.pid, "token": tok});
                    match write_new_file(&self.lock_owner_path(), &serde_json::to_vec(&owner).unwrap()) {
                        Ok(()) => {
                            token = Some(tok);
                            break;
                        }
                        Err(_) => {
                            let _ = fs::remove_dir_all(&lock);
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    if !self.reclaim_stale_lock()? {
                        break;
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        let Some(token) = token else { return Err(LedgerError::LockUnavailable) };
        let result = f();
        // Release: only if we still own it (mirrors JS re-reading owner.json
        // and comparing tokens before removing).
        if let Ok(bytes) = fs::read(self.lock_owner_path()) {
            if let Ok(owner) = serde_json::from_slice::<Json>(&bytes) {
                if owner.get("token").and_then(Json::as_str) == Some(token.as_str()) {
                    let _ = fs::remove_dir_all(&lock);
                }
            }
        }
        result
    }

    /// Mirrors `records()`.
    pub fn records(&self) -> Vec<Json> {
        let Ok(entries) = fs::read_dir(&self.root) else { return Vec::new() };
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| is_record_filename(n))
            .collect();
        names.sort();
        names
            .into_iter()
            .filter_map(|n| fs::read(self.root.join(&n)).ok())
            .filter_map(|b| serde_json::from_slice::<Json>(&b).ok())
            .collect()
    }

    /// Mirrors `#verify()`. Returns the decision and the records it walked
    /// (`append` reuses both, exactly like the JS comment explains).
    fn verify_inner(&self) -> (LedgerDecision, Vec<Json>) {
        let records = self.records();
        let mut prior: Option<&Json> = None;
        for record in &records {
            let auth = record.get("authentication").cloned().unwrap_or(Json::Null);
            let expected_seq = prior.and_then(|p| p.get("eventSequence")).and_then(Json::as_i64).unwrap_or(0) + 1;
            let expected_prev_digest = prior.map(digest_value);
            let seq_ok = record.get("eventSequence").and_then(Json::as_i64) == Some(expected_seq);
            let prev_ok = record.get("previousDigest").cloned().unwrap_or(Json::Null)
                == expected_prev_digest.map(Json::String).unwrap_or(Json::Null);
            if !self.signer.verify(record, &auth, HOST_EVENT_LEDGER_FIELDS) || !seq_ok || !prev_ok {
                return (LedgerDecision::deny("host event ledger continuity is invalid"), records);
            }
            prior = Some(record);
        }
        let head_exists = self.head_path().exists();
        if !records.is_empty() != head_exists {
            return (LedgerDecision::deny("host event ledger head is missing or unanchored"), records);
        }
        if let Some(prior) = prior {
            let Ok(head_bytes) = fs::read(self.head_path()) else {
                return (LedgerDecision::deny("host event ledger head is missing or unanchored"), records);
            };
            let Ok(head) = serde_json::from_slice::<Json>(&head_bytes) else {
                return (LedgerDecision::deny("host event ledger head is missing or unanchored"), records);
            };
            let auth = head.get("authentication").cloned().unwrap_or(Json::Null);
            let seq_ok = head.get("eventSequence") == prior.get("eventSequence");
            let digest_ok = head.get("digest").and_then(Json::as_str) == Some(digest_value(prior).as_str());
            if !self.signer.verify(&head, &auth, HEAD_FIELDS) || !seq_ok || !digest_ok {
                return (LedgerDecision::deny("host event ledger is truncated or forked"), records);
            }
        }
        let n = records.len();
        (LedgerDecision::allow(n), records)
    }

    /// Mirrors `verify()`.
    pub fn verify(&self) -> LedgerDecision {
        self.verify_inner().0
    }

    /// Mirrors `append({eventId, adapter, eventType, sessionId, binding,
    /// sourceRevision, observedAuthority, payload})`.
    pub fn append(&self, input: AppendInput<'_>) -> Result<Json, LedgerError> {
        self.with_lock(|| {
            let (continuity, prior_records) = self.verify_inner();
            if !continuity.allowed {
                return Err(LedgerError::Denied { code: continuity.code.unwrap_or("ARC_STORE_CORRUPT"), message: continuity.message });
            }
            let last = prior_records.last();
            let event_sequence = last.and_then(|r| r.get("eventSequence")).and_then(Json::as_i64).unwrap_or(0) + 1;
            let current_parent = input.session_id.as_deref().and_then(|sid| {
                prior_records.iter().rev().find(|r| r.get("sessionId").and_then(Json::as_str) == Some(sid))
            });
            let turn_correlation_digest = if input.event_type == "UserPromptSubmit" {
                Json::String(digest_value(&json!({
                    "eventId": input.event_id,
                    "sessionId": input.session_id,
                    "eventSequence": event_sequence,
                })))
            } else {
                current_parent.and_then(|p| p.get("turnCorrelationDigest").cloned()).unwrap_or(Json::Null)
            };
            let run_id = input.binding.and_then(|b| b.run_id.clone());
            let stop_ordinal = if input.event_type == "Stop" {
                let count = prior_records
                    .iter()
                    .filter(|r| {
                        r.get("runId").and_then(Json::as_str) == run_id.as_deref()
                            && r.get("eventType").and_then(Json::as_str) == Some("Stop")
                    })
                    .count();
                Json::from(count as i64 + 1)
            } else {
                Json::Null
            };
            let payload_digest = digest_value(&input.payload);
            let mut unsigned = Map::new();
            unsigned.insert("schemaVersion".into(), Json::from(1));
            unsigned.insert("kind".into(), Json::String("arcane-host-event-ledger-record".into()));
            unsigned.insert("eventId".into(), Json::String(input.event_id.clone()));
            unsigned.insert("eventSequence".into(), Json::from(event_sequence));
            unsigned.insert("previousDigest".into(), last.map(digest_value).map(Json::String).unwrap_or(Json::Null));
            unsigned.insert("turnCorrelationDigest".into(), turn_correlation_digest);
            unsigned.insert("stopOrdinal".into(), stop_ordinal);
            unsigned.insert("adapter".into(), Json::String(input.adapter));
            unsigned.insert("eventType".into(), Json::String(input.event_type.clone()));
            unsigned.insert("sessionId".into(), input.session_id.map(Json::String).unwrap_or(Json::Null));
            unsigned.insert("runId".into(), run_id.clone().map(Json::String).unwrap_or(Json::Null));
            unsigned.insert("taskId".into(), input.binding.and_then(|b| b.task_id.clone()).map(Json::String).unwrap_or(Json::Null));
            unsigned.insert("contractId".into(), input.binding.and_then(|b| b.contract_id.clone()).map(Json::String).unwrap_or(Json::Null));
            unsigned.insert("contractVersion".into(), input.binding.and_then(|b| b.contract_version.clone()).map(Json::String).unwrap_or(Json::Null));
            unsigned.insert("contractDigest".into(), input.binding.and_then(|b| b.contract_digest.clone()).map(Json::String).unwrap_or(Json::Null));
            unsigned.insert("sourceRevision".into(), input.source_revision.map(Json::String).unwrap_or(Json::Null));
            unsigned.insert("observedAuthority".into(), input.observed_authority.unwrap_or(Json::Null));
            unsigned.insert("payloadDigest".into(), Json::String(payload_digest));
            unsigned.insert("observedAt".into(), Json::String((self.clock)()));
            let unsigned = Json::Object(unsigned);
            let authentication = self
                .signer
                .sign(&unsigned, HOST_EVENT_LEDGER_FIELDS)
                .map_err(|message| LedgerError::Denied { code: "ARC_AUTH_KEY_UNAVAILABLE", message })?;
            let mut record_map = match unsigned {
                Json::Object(m) => m,
                _ => unreachable!(),
            };
            record_map.insert("authentication".into(), authentication);
            let record = Json::Object(record_map);
            let event_file = self.root.join(format!("{:016}.json", event_sequence));
            write_new_file(&event_file, &serde_json::to_vec(&record)?)?;
            let head = json!({"kind": "arcane-host-event-ledger-head", "eventSequence": event_sequence, "digest": digest_value(&record)});
            let head_auth = self
                .signer
                .sign(&head, HEAD_FIELDS)
                .map_err(|message| LedgerError::Denied { code: "ARC_AUTH_KEY_UNAVAILABLE", message })?;
            let mut head_map = match head {
                Json::Object(m) => m,
                _ => unreachable!(),
            };
            head_map.insert("authentication".into(), head_auth);
            let signed_head = Json::Object(head_map);
            let tmp = self.root.join(format!(".head-{}-{}.tmp", self.pid, event_sequence));
            fs::write(&tmp, serde_json::to_vec(&signed_head)?)?;
            fs::rename(&tmp, self.head_path())?;
            Ok(record)
        })
    }

    /// Mirrors `inspect({sessionId, eventId})`: strips `authentication` down
    /// to `{keyId, alg}` on every returned event, same as JS's
    /// `({authentication, ...r}) => ({...r, authentication: {keyId, alg}})`.
    pub fn inspect(&self, session_id: Option<&str>, event_id: Option<&str>) -> Json {
        let (verified, all) = self.verify_inner();
        let events: Vec<Json> = if verified.allowed {
            all.into_iter()
                .filter(|r| {
                    (session_id.is_none() || r.get("sessionId").and_then(Json::as_str) == session_id)
                        && (event_id.is_none() || r.get("eventId").and_then(Json::as_str) == event_id)
                })
                .map(|r| {
                    let mut m = match r {
                        Json::Object(m) => m,
                        other => return other,
                    };
                    let auth = m.get("authentication").cloned().unwrap_or(Json::Null);
                    let trimmed = json!({"keyId": auth.get("keyId").cloned().unwrap_or(Json::Null), "alg": auth.get("alg").cloned().unwrap_or(Json::Null)});
                    m.insert("authentication".into(), trimmed);
                    Json::Object(m)
                })
                .collect()
        } else {
            Vec::new()
        };
        json!({"allowed": verified.allowed, "code": verified.code, "events": events})
    }
}

/// Creates `path` exclusively (mirrors `writeFileSync(path, data, {flag:'wx'})`).
fn write_new_file(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(data)
}

fn now_millis() -> u128 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or(Duration::ZERO).as_millis()
}

/// Minimal RFC3339 "now" with millisecond precision, matching
/// `new Date().toISOString()`'s shape closely enough for an append-log
/// timestamp (not itself security-relevant — only `observedAt` display).
fn humantime_iso_now() -> String {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let days = secs / 86_400;
    let mut rem = secs % 86_400;
    let hour = rem / 3600;
    rem %= 3600;
    let min = rem / 60;
    let sec = rem % 60;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Howard Hinnant's days-from-epoch civil-date algorithm (public domain).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // Mirrors JS `process.kill(pid, 0)`: ESRCH -> false, EPERM -> true (it
    // exists, just not ours), anything else treated as "does not exist".
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if ret == 0 {
        return true;
    }
    let err = io::Error::last_os_error();
    err.raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn process_alive(pid: u32) -> bool {
    // No Windows-native liveness probe wired here; treat as not-alive so a
    // stale lock is reclaimed rather than wedging forever. Documented gap:
    // JS's `process.kill(pid, 0)` liveness check has no Windows parity path
    // in this port.
    let _ = pid;
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSigner;
    impl LedgerSigner for FakeSigner {
        fn sign(&self, record: &Json, bound_fields: &[&str]) -> Result<Json, String> {
            let projected: Json = Json::Object(
                bound_fields.iter().map(|f| (f.to_string(), record.get(*f).cloned().unwrap_or(Json::Null))).collect(),
            );
            let mac = digest_value(&projected);
            Ok(json!({"alg": "FAKE", "keyId": "k1", "mac": mac}))
        }
        fn verify(&self, record: &Json, authentication: &Json, bound_fields: &[&str]) -> bool {
            let projected: Json = Json::Object(
                bound_fields.iter().map(|f| (f.to_string(), record.get(*f).cloned().unwrap_or(Json::Null))).collect(),
            );
            authentication.get("mac").and_then(Json::as_str) == Some(digest_value(&projected).as_str())
        }
    }

    fn tmp_root(tag: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::env::temp_dir().join(format!("r51-ledger-{}-{}-{}", std::process::id(), tag, n))
    }

    #[test]
    fn empty_ledger_verifies() {
        let root = tmp_root("empty");
        let ledger = HostEventLedger::new(&root, FakeSigner);
        let d = ledger.verify();
        assert!(d.allowed);
        assert_eq!(d.event_count, 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn append_then_verify_chains() {
        let root = tmp_root("chain");
        let ledger = HostEventLedger::new(&root, FakeSigner);
        let r1 = ledger
            .append(AppendInput {
                event_id: "hev_1".into(),
                adapter: "claude-code".into(),
                event_type: "SessionStart".into(),
                session_id: Some("sess1".into()),
                binding: None,
                source_revision: None,
                observed_authority: None,
                payload: json!({"a": 1}),
            })
            .unwrap();
        assert_eq!(r1.get("eventSequence"), Some(&Json::from(1)));
        assert_eq!(r1.get("previousDigest"), Some(&Json::Null));

        let binding = AppendBinding { run_id: Some("run1".into()), ..Default::default() };
        let r2 = ledger
            .append(AppendInput {
                event_id: "hev_2".into(),
                adapter: "claude-code".into(),
                event_type: "Stop".into(),
                session_id: Some("sess1".into()),
                binding: Some(&binding),
                source_revision: None,
                observed_authority: None,
                payload: json!({"b": 2}),
            })
            .unwrap();
        assert_eq!(r2.get("eventSequence"), Some(&Json::from(2)));
        assert_eq!(r2.get("stopOrdinal"), Some(&Json::from(1)));

        let d = ledger.verify();
        assert!(d.allowed, "{:?}", d);
        assert_eq!(d.event_count, 2);

        let inspected = ledger.inspect(None, None);
        assert_eq!(inspected["allowed"], Json::from(true));
        assert_eq!(inspected["events"].as_array().unwrap().len(), 2);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn tampered_record_fails_verification() {
        let root = tmp_root("tamper");
        let ledger = HostEventLedger::new(&root, FakeSigner);
        ledger
            .append(AppendInput {
                event_id: "hev_1".into(),
                adapter: "codex".into(),
                event_type: "SessionStart".into(),
                session_id: Some("sess1".into()),
                binding: None,
                source_revision: None,
                observed_authority: None,
                payload: json!({}),
            })
            .unwrap();
        // Corrupt the sole record file directly.
        let entry = fs::read_dir(&root).unwrap().find_map(|e| {
            let e = e.ok()?;
            let name = e.file_name().into_string().ok()?;
            is_record_filename(&name).then_some(e.path())
        }).unwrap();
        let mut v: Json = serde_json::from_slice(&fs::read(&entry).unwrap()).unwrap();
        v["eventType"] = Json::String("tampered".into());
        fs::write(&entry, serde_json::to_vec(&v).unwrap()).unwrap();

        let d = ledger.verify();
        assert!(!d.allowed);
        assert_eq!(d.code, Some("ARC_STORE_CORRUPT"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn user_prompt_submit_mints_turn_correlation_digest_inherited_by_children() {
        let root = tmp_root("turn-corr");
        let ledger = HostEventLedger::new(&root, FakeSigner);
        let r1 = ledger
            .append(AppendInput {
                event_id: "hev_1".into(),
                adapter: "claude-code".into(),
                event_type: "UserPromptSubmit".into(),
                session_id: Some("sess1".into()),
                binding: None,
                source_revision: None,
                observed_authority: None,
                payload: json!({}),
            })
            .unwrap();
        assert!(r1.get("turnCorrelationDigest").unwrap().is_string());

        let r2 = ledger
            .append(AppendInput {
                event_id: "hev_2".into(),
                adapter: "claude-code".into(),
                event_type: "PreToolUse".into(),
                session_id: Some("sess1".into()),
                binding: None,
                source_revision: None,
                observed_authority: None,
                payload: json!({}),
            })
            .unwrap();
        assert_eq!(r2.get("turnCorrelationDigest"), r1.get("turnCorrelationDigest"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn append_fails_closed_when_signer_has_no_key() {
        struct DenySigner;
        impl LedgerSigner for DenySigner {
            fn sign(&self, _record: &Json, _bound_fields: &[&str]) -> Result<Json, String> {
                Err("key unavailable".into())
            }
            fn verify(&self, _record: &Json, _authentication: &Json, _bound_fields: &[&str]) -> bool {
                false
            }
        }
        let root = tmp_root("deny");
        let ledger = HostEventLedger::new(&root, DenySigner);
        let err = ledger
            .append(AppendInput {
                event_id: "hev_1".into(),
                adapter: "claude-code".into(),
                event_type: "SessionStart".into(),
                session_id: Some("sess1".into()),
                binding: None,
                source_revision: None,
                observed_authority: None,
                payload: json!({}),
            })
            .unwrap_err();
        assert!(matches!(err, LedgerError::Denied { code: "ARC_AUTH_KEY_UNAVAILABLE", .. }));
        let _ = fs::remove_dir_all(&root);
    }
}
