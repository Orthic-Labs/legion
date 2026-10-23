//! Hash-chained, append-only audit event journal (CP section 11).
//!
//! Same semantics as the Legion ledger (`host_runtime::verify_ledger`,
//! `contract.rs` previousDigest/eventSequence): a 1-based dense sequence, each
//! event carries the digest of its predecessor, and a separate head seal
//! anchors the tail so truncation is detectable. The journal is not an
//! authority: it records what the engine did and lets a later reader prove the
//! history was not edited, reordered, forked or cut short. Anything that does
//! not verify is a defect; nothing is repaired silently.
//!
//! Wiring is owned by the execution engine; this module is a pure library.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AuditError;

pub const EVENTS_FILE: &str = "events.jsonl";
pub const HEAD_FILE: &str = "events.head.json";
pub const LOCK_FILE: &str = "events.lock";
pub const EVENT_FORMAT_VERSION: &str = "audit-event/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    PlanFrozen,
    ProviderStarted,
    ProviderFinished,
    ProviderFailed,
    ProviderSkipped,
    RetryScheduled,
    BreakerTripped,
    FallbackUsed,
    AmendmentApplied,
    ReportFinalized,
    RunResumed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditEvent {
    pub sequence: u64,
    pub previous_digest: Option<String>,
    pub digest: String,
    pub plan_digest: String,
    pub kind: EventKind,
    /// Provider id, plan digest (amendment: the superseded plan) or `run`.
    pub subject: String,
    /// Digest of the payload the event vouches for (receipt digest for
    /// `provider_finished`, etc). Never the payload itself: no secrets here.
    pub payload_digest: String,
    /// Caller-supplied epoch milliseconds. Not part of any proof semantics.
    pub at: u64,
}

/// Digest of an event over every field except `digest` itself.
pub fn event_digest(event: &AuditEvent) -> Result<String, AuditError> {
    let mut value = serde_json::to_value(event).map_err(|e| AuditError::Invalid(e.to_string()))?;
    if let Value::Object(map) = &mut value {
        map.remove("digest");
    }
    legion_contracts::canonical_digest(&value).map_err(|e| AuditError::Invalid(e.to_string()))
}

/// Digest used as the payload of the failure event that closes a provider
/// that was started but never finished before a crash and is rerun.
pub fn interrupted_payload_digest(provider: &str) -> String {
    legion_contracts::canonical_digest(&serde_json::json!({"interrupted": provider}))
        .unwrap_or_else(|_| "sha256:invalid".to_owned())
}

/// `sha256:<hex>` over raw bytes.
pub fn bytes_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256:{hex}")
}

const MAC_PREFIX: &str = "hmac-sha256:";

/// Domain-separated HMAC-SHA256 over `bytes`, rendered `hmac-sha256:<hex>`.
pub fn domain_mac(key: &[u8], domain: &[u8], bytes: &[u8]) -> Result<String, AuditError> {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key)
        .map_err(|_| AuditError::Invalid("empty HMAC key".into()))?;
    mac.update(domain);
    mac.update(bytes);
    let hex: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(format!("{MAC_PREFIX}{hex}"))
}

/// Constant-time check of a value produced by [`domain_mac`].
pub fn domain_mac_verify(key: &[u8], domain: &[u8], bytes: &[u8], signature: &str) -> bool {
    use hmac::{Hmac, KeyInit, Mac};
    let Some(hex_part) = signature.strip_prefix(MAC_PREFIX) else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_part) else {
        return false;
    };
    let Ok(mut mac) = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key) else {
        return false;
    };
    mac.update(domain);
    mac.update(bytes);
    mac.verify_slice(&expected).is_ok()
}

pub const ANCHOR_FILE: &str = "journal-anchor.json";
const ANCHOR_FORMAT: &str = "audit-journal-anchor/v1";
const ANCHOR_DOMAIN: &[u8] = b"legion-audit-journal-anchor-v1\0";

/// Signed record of the finalized journal head. The signing key lives in host
/// state (plan key custody), never in the run directory, so a run directory
/// that is rewritten wholesale cannot produce a matching anchor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JournalAnchor {
    pub format: String,
    pub plan_digest: String,
    pub effective_plan_digest: String,
    pub sequence: u64,
    pub digest: String,
    pub signature: String,
}

impl JournalAnchor {
    fn signed_bytes(
        plan_digest: &str,
        effective_plan_digest: &str,
        sequence: u64,
        digest: &str,
    ) -> Result<Vec<u8>, AuditError> {
        legion_contracts::canonical_json_bytes(&serde_json::json!({
            "format": ANCHOR_FORMAT,
            "planDigest": plan_digest,
            "effectivePlanDigest": effective_plan_digest,
            "sequence": sequence,
            "digest": digest,
        }))
        .map_err(|e| AuditError::Invalid(e.to_string()))
    }

    pub fn sign(
        plan_digest: &str,
        effective_plan_digest: &str,
        sequence: u64,
        digest: &str,
        key: &[u8],
    ) -> Result<Self, AuditError> {
        let bytes = Self::signed_bytes(plan_digest, effective_plan_digest, sequence, digest)?;
        Ok(Self {
            format: ANCHOR_FORMAT.to_owned(),
            plan_digest: plan_digest.to_owned(),
            effective_plan_digest: effective_plan_digest.to_owned(),
            sequence,
            digest: digest.to_owned(),
            signature: domain_mac(key, ANCHOR_DOMAIN, &bytes)?,
        })
    }

    pub fn verify(&self, key: &[u8]) -> bool {
        self.format == ANCHOR_FORMAT
            && Self::signed_bytes(
                &self.plan_digest,
                &self.effective_plan_digest,
                self.sequence,
                &self.digest,
            )
            .map(|bytes| domain_mac_verify(key, ANCHOR_DOMAIN, &bytes, &self.signature))
            .unwrap_or(false)
    }

    pub fn write(&self, dir: &Path) -> Result<(), AuditError> {
        let tmp = dir.join(format!("{ANCHOR_FILE}.tmp"));
        let bytes = serde_json::to_vec(self).map_err(|e| AuditError::Invalid(e.to_string()))?;
        let mut file = File::create(&tmp).map_err(|e| io_err("anchor create", e))?;
        file.write_all(&bytes)
            .map_err(|e| io_err("anchor write", e))?;
        file.sync_all().map_err(|e| io_err("anchor fsync", e))?;
        std::fs::rename(&tmp, dir.join(ANCHOR_FILE)).map_err(|e| io_err("anchor rename", e))?;
        sync_dir(dir);
        Ok(())
    }

    /// `Ok(None)` only when the file does not exist; any other problem is an error.
    pub fn read(dir: &Path) -> Result<Option<Self>, AuditError> {
        match std::fs::read(dir.join(ANCHOR_FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| AuditError::Invalid(format!("{ANCHOR_FILE} is invalid: {e}"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_err("anchor read", error)),
        }
    }
}

/// Remove the data files of a previous, finalized run so a fresh run can reuse
/// the directory. Never removes the run lock and refuses an unfinalized or
/// defective journal (it may be resumable evidence).
pub fn clear_finalized_run(dir: &Path) -> Result<(), AuditError> {
    if !dir.join(EVENTS_FILE).exists() {
        return Ok(());
    }
    let bytes = std::fs::read(dir.join(EVENTS_FILE)).map_err(|e| io_err("read", e))?;
    let mut parse_defects = Vec::new();
    let events = parse_lines(&bytes, &mut parse_defects);
    let finalized = parse_defects.is_empty()
        && events
            .last()
            .map(|e| e.kind == EventKind::ReportFinalized)
            .unwrap_or(false);
    if !finalized {
        return Err(AuditError::Invalid(format!(
            "{} holds an unfinalized or unreadable audit journal; resume it with --resume or remove the run directory's journal files explicitly",
            dir.display()
        )));
    }
    for name in [EVENTS_FILE, HEAD_FILE, ANCHOR_FILE, "run-metrics.json"] {
        match std::fs::remove_file(dir.join(name)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(io_err("clear previous run", error))
            }
            _ => {}
        }
    }
    match std::fs::remove_dir_all(dir.join(crate::resume::RECEIPT_DIR)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(io_err("clear previous receipts", error))
        }
        _ => Ok(()),
    }
}

/// Digest used as the payload of the failure event that closes a gap.
pub fn gap_payload_digest(provider: &str) -> String {
    legion_contracts::canonical_digest(&serde_json::json!({"gap": provider}))
        .unwrap_or_else(|_| "sha256:invalid".to_owned())
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Sealed tail of the journal, rewritten (tmp + fsync + rename) after every
/// committed append. `sequence == 0` is an empty journal. Callers that need
/// stronger custody should sign this value or copy it into the final report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedHead {
    pub plan_digest: String,
    pub sequence: u64,
    pub digest: Option<String>,
    pub finalized: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefectCode {
    Unreadable,
    Malformed,
    TornTail,
    SequenceGap,
    ForkOrReorder,
    PreviousDigestMismatch,
    DigestMismatch,
    PlanMismatch,
    FirstEventNotPlanFrozen,
    Ordering,
    AfterFinalized,
    SealMissing,
    SealMismatch,
    Truncated,
    NotFinalized,
    ExpectedHeadMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalDefect {
    pub code: DefectCode,
    pub detail: String,
}

impl std::fmt::Display for JournalDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.detail)
    }
}

fn defect(code: DefectCode, detail: impl Into<String>) -> JournalDefect {
    JournalDefect {
        code,
        detail: detail.into(),
    }
}

/// External expectations a verifier may hold that the journal directory alone
/// cannot prove (for example the head recorded in a finalized report).
#[derive(Clone, Debug, Default)]
pub struct Expectation {
    pub require_finalized: bool,
    pub expected_head: Option<SealedHead>,
    pub final_plan_digest: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct JournalVerification {
    pub events: Vec<AuditEvent>,
    pub defects: Vec<JournalDefect>,
    pub head: Option<SealedHead>,
    /// Committed events past the sealed head (crash between append and seal).
    pub unsealed_tail: u64,
    pub finalized: bool,
    pub effective_plan_digest: Option<String>,
}

impl JournalVerification {
    pub fn is_valid(&self) -> bool {
        self.defects.is_empty()
    }
}

/// Structural verification of an event sequence: chain, digests, plan binding
/// and provider ordering. Returns defects, whether the run is finalized and
/// the effective plan digest after amendments.
pub fn verify_events(
    events: &[AuditEvent],
    plan_digest: &str,
) -> (Vec<JournalDefect>, bool, Option<String>) {
    let mut defects = Vec::new();
    let mut previous: Option<&AuditEvent> = None;
    let mut effective = plan_digest.to_owned();
    let mut open: BTreeSet<&str> = BTreeSet::new();
    let mut done: BTreeSet<&str> = BTreeSet::new();
    let mut finalized = false;
    for (index, event) in events.iter().enumerate() {
        let expected_sequence = previous.map(|p| p.sequence).unwrap_or(0) + 1;
        if event.sequence != expected_sequence {
            let code = if event.sequence < expected_sequence {
                DefectCode::ForkOrReorder
            } else {
                DefectCode::SequenceGap
            };
            defects.push(defect(
                code,
                format!(
                    "event at position {} has sequence {}, expected {}",
                    index + 1,
                    event.sequence,
                    expected_sequence
                ),
            ));
        }
        if event.previous_digest.as_deref() != previous.map(|p| p.digest.as_str()) {
            defects.push(defect(
                DefectCode::PreviousDigestMismatch,
                format!("event {} does not chain to its predecessor", event.sequence),
            ));
        }
        match event_digest(event) {
            Ok(digest) if digest == event.digest => {}
            _ => defects.push(defect(
                DefectCode::DigestMismatch,
                format!("event {} digest does not match its content", event.sequence),
            )),
        }
        if index == 0 {
            if event.kind != EventKind::PlanFrozen || event.plan_digest != plan_digest {
                defects.push(defect(
                    DefectCode::FirstEventNotPlanFrozen,
                    "first event must be plan_frozen bound to the frozen plan digest",
                ));
            }
        } else if event.kind == EventKind::PlanFrozen {
            defects.push(defect(
                DefectCode::Ordering,
                format!("event {} repeats plan_frozen", event.sequence),
            ));
        }
        if finalized {
            defects.push(defect(
                DefectCode::AfterFinalized,
                format!("event {} follows report_finalized", event.sequence),
            ));
        }
        if event.kind == EventKind::AmendmentApplied {
            if event.subject != effective {
                defects.push(defect(
                    DefectCode::PlanMismatch,
                    format!(
                        "amendment event {} supersedes {} but the effective plan is {}",
                        event.sequence, event.subject, effective
                    ),
                ));
            }
            effective = event.plan_digest.clone();
        } else if event.plan_digest != effective {
            defects.push(defect(
                DefectCode::PlanMismatch,
                format!(
                    "event {} is bound to plan {} but the effective plan is {}",
                    event.sequence, event.plan_digest, effective
                ),
            ));
        }
        let subject = event.subject.as_str();
        match event.kind {
            EventKind::ProviderStarted => {
                if done.contains(subject) {
                    defects.push(defect(
                        DefectCode::Ordering,
                        format!("provider {subject} started again after finishing"),
                    ));
                }
                if !open.insert(subject) {
                    defects.push(defect(
                        DefectCode::Ordering,
                        format!("provider {subject} started twice without finishing"),
                    ));
                }
            }
            EventKind::ProviderFinished => {
                if !open.remove(subject) {
                    defects.push(defect(
                        DefectCode::Ordering,
                        format!("provider {subject} finished without a start"),
                    ));
                }
                done.insert(subject);
            }
            EventKind::ProviderFailed => {
                if !open.remove(subject) {
                    defects.push(defect(
                        DefectCode::Ordering,
                        format!("provider {subject} failed without a start"),
                    ));
                }
            }
            EventKind::ProviderSkipped => {
                if open.contains(subject) || done.contains(subject) {
                    defects.push(defect(
                        DefectCode::Ordering,
                        format!("provider {subject} skipped while started or finished"),
                    ));
                }
            }
            EventKind::ReportFinalized => {
                if !open.is_empty() {
                    defects.push(defect(
                        DefectCode::Ordering,
                        "report finalized with providers started but not closed",
                    ));
                }
                finalized = true;
            }
            _ => {}
        }
        previous = Some(event);
    }
    let effective = if events.is_empty() {
        None
    } else {
        Some(effective)
    };
    (defects, finalized, effective)
}

fn parse_lines(bytes: &[u8], defects: &mut Vec<JournalDefect>) -> Vec<AuditEvent> {
    let mut events = Vec::new();
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            defects.push(defect(DefectCode::Malformed, "journal is not valid UTF-8"));
            return events;
        }
    };
    let ends_with_newline = text.is_empty() || text.ends_with('\n');
    let lines: Vec<&str> = text.split('\n').collect();
    // `split` yields a trailing empty piece when the file ends with a newline.
    let count = if ends_with_newline {
        lines.len().saturating_sub(1)
    } else {
        lines.len()
    };
    for (index, line) in lines.iter().take(count).enumerate() {
        match serde_json::from_str::<AuditEvent>(line) {
            Ok(event) => events.push(event),
            Err(error) => {
                let torn = index + 1 == count && !ends_with_newline;
                defects.push(defect(
                    if torn {
                        DefectCode::TornTail
                    } else {
                        DefectCode::Malformed
                    },
                    format!("line {}: {error}", index + 1),
                ));
            }
        }
    }
    events
}

/// Verify the journal directory: chain, plan binding, ordering, head seal and
/// any external expectation. Fails closed on every unreadable or missing piece.
pub fn verify_dir(dir: &Path, plan_digest: &str, expect: &Expectation) -> JournalVerification {
    let mut out = JournalVerification::default();
    let bytes = match std::fs::read(dir.join(EVENTS_FILE)) {
        Ok(bytes) => bytes,
        Err(error) => {
            out.defects.push(defect(
                DefectCode::Unreadable,
                format!("{EVENTS_FILE}: {error}"),
            ));
            return out;
        }
    };
    out.events = parse_lines(&bytes, &mut out.defects);
    let (defects, finalized, effective) = verify_events(&out.events, plan_digest);
    out.defects.extend(defects);
    out.finalized = finalized;
    out.effective_plan_digest = effective;

    match std::fs::read(dir.join(HEAD_FILE)) {
        Err(error) => out.defects.push(defect(
            DefectCode::SealMissing,
            format!("{HEAD_FILE}: {error}"),
        )),
        Ok(raw) => match serde_json::from_slice::<SealedHead>(&raw) {
            Err(error) => out.defects.push(defect(
                DefectCode::SealMismatch,
                format!("{HEAD_FILE} is invalid: {error}"),
            )),
            Ok(seal) => {
                let len = out.events.len() as u64;
                if seal.plan_digest != plan_digest {
                    out.defects.push(defect(
                        DefectCode::SealMismatch,
                        "head seal is bound to a different plan",
                    ));
                }
                if seal.sequence > len {
                    out.defects.push(defect(
                        DefectCode::Truncated,
                        format!(
                            "head seal covers {} events but only {len} remain",
                            seal.sequence
                        ),
                    ));
                } else {
                    let sealed_event = (seal.sequence as usize)
                        .checked_sub(1)
                        .and_then(|i| out.events.get(i));
                    if sealed_event.map(|e| e.digest.clone()) != seal.digest {
                        out.defects.push(defect(
                            DefectCode::SealMismatch,
                            "sealed head digest does not match the journal (fork or edit)",
                        ));
                    }
                    out.unsealed_tail = len - seal.sequence;
                    if seal.finalized && !(out.finalized && out.unsealed_tail == 0) {
                        out.defects.push(defect(
                            DefectCode::Truncated,
                            "head seal records a finalized run but the journal does not end finalized",
                        ));
                    }
                }
                out.head = Some(seal);
            }
        },
    }

    if expect.require_finalized && !out.finalized {
        out.defects.push(defect(
            DefectCode::NotFinalized,
            "journal is not finalized (report_finalized missing or truncated)",
        ));
    }
    if let Some(expected) = &expect.expected_head {
        let sequence = expected.sequence as usize;
        let matches = if expected.sequence == 0 {
            out.events.is_empty()
        } else {
            out.events
                .get(sequence - 1)
                .map(|e| Some(&e.digest) == expected.digest.as_ref())
                .unwrap_or(false)
        };
        if !matches {
            out.defects.push(defect(
                DefectCode::ExpectedHeadMismatch,
                format!(
                    "journal does not contain the expected head at sequence {}",
                    expected.sequence
                ),
            ));
        }
    }
    if let Some(plan) = &expect.final_plan_digest {
        if out.effective_plan_digest.as_ref() != Some(plan) {
            out.defects.push(defect(
                DefectCode::PlanMismatch,
                "effective plan digest does not match the expected final plan",
            ));
        }
    }
    out
}

/// Compare two journals of the same run. Returns the length of the shared
/// prefix and whether they diverge (a fork) rather than one extending the other.
pub fn compare_histories(a: &[AuditEvent], b: &[AuditEvent]) -> (usize, bool) {
    let common = a
        .iter()
        .zip(b.iter())
        .take_while(|(x, y)| x.digest == y.digest)
        .count();
    (common, common < a.len() && common < b.len())
}

struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn sync_dir(dir: &Path) {
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
}

fn io_err(context: &str, error: std::io::Error) -> AuditError {
    AuditError::Invalid(format!("journal {context}: {error}"))
}

fn write_seal(dir: &Path, seal: &SealedHead) -> Result<(), AuditError> {
    let tmp = dir.join(format!("{HEAD_FILE}.tmp"));
    let bytes = serde_json::to_vec(seal).map_err(|e| AuditError::Invalid(e.to_string()))?;
    let mut file = File::create(&tmp).map_err(|e| io_err("seal create", e))?;
    file.write_all(&bytes)
        .map_err(|e| io_err("seal write", e))?;
    file.sync_all().map_err(|e| io_err("seal fsync", e))?;
    std::fs::rename(&tmp, dir.join(HEAD_FILE)).map_err(|e| io_err("seal rename", e))?;
    sync_dir(dir);
    Ok(())
}

fn acquire_lock(dir: &Path) -> Result<LockGuard, AuditError> {
    let path = dir.join(LOCK_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| {
            AuditError::Invalid(format!(
                "journal run lock {} is held or stale ({e}); clear it explicitly with clear_stale_lock after confirming no run is active",
                path.display()
            ))
        })?;
    let _ = writeln!(file, "{}", std::process::id());
    let _ = file.sync_all();
    Ok(LockGuard { path })
}

/// Explicitly remove a lock left by a crashed process. Never called implicitly.
pub fn clear_stale_lock(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join(LOCK_FILE)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// An open, locked, verified journal ready for appends.
pub struct Journal {
    dir: PathBuf,
    plan_digest: String,
    events: Vec<AuditEvent>,
    effective_plan: String,
    file: File,
    byte_len: u64,
    finalized: bool,
    /// Bytes of an uncommitted torn final line removed when opening.
    pub recovered_torn_bytes: u64,
    _lock: LockGuard,
}

impl Journal {
    /// Create a new journal for `plan_digest`, sealing an empty head and
    /// appending `plan_frozen`. Refuses to touch an existing journal.
    pub fn create(dir: &Path, plan_digest: &str, at: u64) -> Result<Self, AuditError> {
        std::fs::create_dir_all(dir).map_err(|e| io_err("create dir", e))?;
        let lock = acquire_lock(dir)?;
        let path = dir.join(EVENTS_FILE);
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| io_err("create (journal exists?)", e))?;
        file.sync_all().map_err(|e| io_err("fsync", e))?;
        sync_dir(dir);
        write_seal(
            dir,
            &SealedHead {
                plan_digest: plan_digest.to_owned(),
                sequence: 0,
                digest: None,
                finalized: false,
            },
        )?;
        let mut journal = Self {
            dir: dir.to_path_buf(),
            plan_digest: plan_digest.to_owned(),
            events: Vec::new(),
            effective_plan: plan_digest.to_owned(),
            file,
            byte_len: 0,
            finalized: false,
            recovered_torn_bytes: 0,
            _lock: lock,
        };
        journal.push(
            EventKind::PlanFrozen,
            plan_digest,
            plan_digest,
            plan_digest,
            at,
        )?;
        Ok(journal)
    }

    /// Lock and verify an existing journal. A torn final line past the sealed
    /// head is an uncommitted write and is truncated; every other defect
    /// refuses the open.
    pub fn open(dir: &Path, plan_digest: &str) -> Result<Self, AuditError> {
        let lock = acquire_lock(dir)?;
        let mut check = verify_dir(dir, plan_digest, &Expectation::default());
        let mut recovered = 0u64;
        let torn_only = !check.defects.is_empty()
            && check.defects.iter().all(|d| d.code == DefectCode::TornTail);
        if torn_only {
            let path = dir.join(EVENTS_FILE);
            let bytes = std::fs::read(&path).map_err(|e| io_err("read", e))?;
            let keep = bytes
                .iter()
                .rposition(|b| *b == b'\n')
                .map(|i| i + 1)
                .unwrap_or(0);
            let handle = OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|e| io_err("open for recovery", e))?;
            handle
                .set_len(keep as u64)
                .map_err(|e| io_err("truncate torn tail", e))?;
            handle.sync_all().map_err(|e| io_err("fsync", e))?;
            recovered = (bytes.len() - keep) as u64;
            check = verify_dir(dir, plan_digest, &Expectation::default());
        }
        if !check.is_valid() {
            return Err(AuditError::Invalid(format!(
                "journal refused: {}",
                check
                    .defects
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            )));
        }
        let path = dir.join(EVENTS_FILE);
        let byte_len = std::fs::metadata(&path)
            .map_err(|e| io_err("stat", e))?
            .len();
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|e| io_err("open", e))?;
        let mut journal = Self {
            dir: dir.to_path_buf(),
            plan_digest: plan_digest.to_owned(),
            effective_plan: check
                .effective_plan_digest
                .clone()
                .unwrap_or_else(|| plan_digest.to_owned()),
            events: check.events,
            file,
            byte_len,
            finalized: check.finalized,
            recovered_torn_bytes: recovered,
            _lock: lock,
        };
        // Re-seal a head that lags by one committed event (crash before seal).
        if check.unsealed_tail > 0 {
            journal.seal()?;
        }
        Ok(journal)
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    pub fn effective_plan_digest(&self) -> &str {
        &self.effective_plan
    }

    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    pub fn head(&self) -> SealedHead {
        SealedHead {
            plan_digest: self.plan_digest.clone(),
            sequence: self.events.len() as u64,
            digest: self.events.last().map(|e| e.digest.clone()),
            finalized: self.finalized,
        }
    }

    /// Append one event bound to the effective plan. `plan_frozen` and
    /// `amendment_applied` have dedicated entry points.
    pub fn append(
        &mut self,
        kind: EventKind,
        subject: &str,
        payload_digest: &str,
        at: u64,
    ) -> Result<AuditEvent, AuditError> {
        if matches!(kind, EventKind::PlanFrozen | EventKind::AmendmentApplied) {
            return Err(AuditError::Invalid(format!(
                "{kind:?} cannot be appended through append()"
            )));
        }
        let plan = self.effective_plan.clone();
        self.push(kind, subject, &plan, payload_digest, at)
    }

    /// Record an applied amendment, moving the effective plan from the current
    /// digest to `new_plan_digest`.
    pub fn append_amendment(
        &mut self,
        new_plan_digest: &str,
        payload_digest: &str,
        at: u64,
    ) -> Result<AuditEvent, AuditError> {
        let prior = self.effective_plan.clone();
        self.push(
            EventKind::AmendmentApplied,
            &prior,
            new_plan_digest,
            payload_digest,
            at,
        )
    }

    fn push(
        &mut self,
        kind: EventKind,
        subject: &str,
        plan_digest: &str,
        payload_digest: &str,
        at: u64,
    ) -> Result<AuditEvent, AuditError> {
        let on_disk = std::fs::metadata(self.dir.join(EVENTS_FILE))
            .map_err(|e| io_err("stat", e))?
            .len();
        if on_disk != self.byte_len {
            return Err(AuditError::Invalid(
                "journal changed on disk outside this writer; refusing to append".to_owned(),
            ));
        }
        let mut event = AuditEvent {
            sequence: self.events.len() as u64 + 1,
            previous_digest: self.events.last().map(|e| e.digest.clone()),
            digest: String::new(),
            plan_digest: plan_digest.to_owned(),
            kind,
            subject: subject.to_owned(),
            payload_digest: payload_digest.to_owned(),
            at,
        };
        event.digest = event_digest(&event)?;
        let mut candidate = self.events.clone();
        candidate.push(event.clone());
        let (defects, finalized, effective) = verify_events(&candidate, &self.plan_digest);
        if !defects.is_empty() {
            return Err(AuditError::Invalid(format!(
                "journal append refused: {}",
                defects
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            )));
        }
        let mut line =
            serde_json::to_string(&event).map_err(|e| AuditError::Invalid(e.to_string()))?;
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .map_err(|e| io_err("write", e))?;
        self.file.sync_all().map_err(|e| io_err("fsync", e))?;
        self.byte_len += line.len() as u64;
        self.events = candidate;
        self.finalized = finalized;
        if let Some(effective) = effective {
            self.effective_plan = effective;
        }
        self.seal()?;
        Ok(event)
    }

    fn seal(&mut self) -> Result<(), AuditError> {
        write_seal(&self.dir, &self.head())
    }
}
