//! Typed source assertions, in-flight reconciliation, and post-cutoff notes.
//!
//! Everything here is a *source assertion*: facts the source chat declares at
//! handoff time (or appends afterwards). They are validated for shape and bound
//! by hash, but they are never merged into transcript evidence and never
//! presented as independently verified. The target must still confirm
//! drift-prone state before relying on it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

pub const SOURCE_BLOCK_SCHEMA: &str = "legion.handoff.source-block.v1";
pub const SOURCE_BLOCK_TRUST: &str = "source_assertion";
pub const RECONCILIATION_SCHEMA: &str = "legion.handoff.reconciliation.v1";
pub const NOTE_SCHEMA: &str = "legion.handoff.note.v1";

const MAX_ITEMS: usize = 200;
const MAX_FIELD: usize = 512;
const MAX_NOTE_CHARS: usize = 2_000;
const MAX_NOTES: usize = 1_000;

fn default_trust() -> String {
    SOURCE_BLOCK_TRUST.into()
}

fn default_repo() -> String {
    ".".into()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoHead {
    #[serde(default = "default_repo")]
    pub repo: String,
    pub sha: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EditState {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UncommittedPath {
    #[serde(default = "default_repo")]
    pub repo: String,
    pub path: String,
    pub owner: String,
    pub state: EditState,
    pub reviewed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipTransfer {
    pub repository: String,
    pub from: String,
    pub to: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InFlightKind {
    Subagent,
    BrokerBuild,
    BackgroundJob,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InFlightState {
    Running,
    Stopped,
    Finished,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InFlightItem {
    pub kind: InFlightKind,
    pub id: String,
    pub state: InFlightState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
    pub owner: String,
}

/// Small typed block the source asserts at handoff. Field order is the
/// canonical serialization order used for hashing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBlock {
    pub schema: String,
    #[serde(default = "default_trust")]
    pub trust: String,
    #[serde(default)]
    pub heads: Vec<RepoHead>,
    #[serde(default)]
    pub uncommitted: Vec<UncommittedPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership_transfer: Option<OwnershipTransfer>,
    #[serde(default)]
    pub in_flight: Vec<InFlightItem>,
    /// Decisions that changed after the baseline named by each entry. Empty
    /// lists are not serialized, so blocks without changes keep their digest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_since: Vec<ChangedSince>,
    /// Where the source chat's auto-memory lives, or why it has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryLocation>,
    /// Process artifacts the work updates, including paths outside the workspace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_roots: Vec<ArtifactRoot>,
}

/// Prior state a change is measured against: a previous continuity/packet
/// receipt digest, a previous transcript cutoff, or both.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeBaseline {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cutoff_bytes: Option<u64>,
}

/// One decision whose value differs from the baseline. `evidence` names the
/// current proof (commit, path:line, command result) of the new value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedSince {
    pub id: String,
    pub decision: String,
    pub old: String,
    pub new: String,
    pub when: String,
    pub since: ChangeBaseline,
    pub evidence: String,
}

/// Exactly one of `dir` (absolute path) or `absent_reason`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryLocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absent_reason: Option<String>,
}

/// A process artifact (register, renderer, form set) the work updates.
/// `rerender` is the command that regenerates it, or `none: <reason>`.
/// A `durable` root must resolve physically and may not sit in temp, cache,
/// or scratch storage when the packet is validated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRoot {
    pub path: String,
    pub owner: String,
    pub rerender: String,
    pub durable: bool,
}

fn field(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{name} must be non-empty"));
    }
    if value.chars().count() > MAX_FIELD || value.chars().any(char::is_control) {
        return Err(format!("{name} is too long or contains control characters"));
    }
    Ok(())
}

/// Repository-relative path: no absolute root, drive letter, backslash, or `..`.
/// `allow_dot` permits the bare repository root `.`.
fn repo_relative(name: &str, value: &str, allow_dot: bool) -> Result<(), String> {
    field(name, value)?;
    if value == "." {
        return if allow_dot {
            Ok(())
        } else {
            Err(format!("{name} must name a path, not the repository root"))
        };
    }
    let bytes = value.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if value.starts_with('/') || value.starts_with('~') || value.contains('\\') || drive {
        return Err(format!("{name} must be repository-relative: {value}"));
    }
    if value
        .split('/')
        .any(|segment| segment.is_empty() || segment == ".." || segment == ".")
    {
        return Err(format!(
            "{name} has an empty, '.', or '..' segment: {value}"
        ));
    }
    Ok(())
}

fn full_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Absolute path (POSIX root or drive letter) with no `..` or `.` segment.
fn absolute_path(name: &str, value: &str) -> Result<(), String> {
    field(name, value)?;
    let bytes = value.as_bytes();
    let drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\');
    if !(value.starts_with('/') || drive) {
        return Err(format!("{name} must be an absolute path: {value}"));
    }
    if value
        .replace('\\', "/")
        .split('/')
        .any(|segment| segment == ".." || segment == ".")
    {
        return Err(format!("{name} has a '.' or '..' segment: {value}"));
    }
    Ok(())
}

/// Free text the block carries into the packet must never hold a secret value.
fn no_secret(name: &str, value: &str) -> Result<(), String> {
    for (label, pattern) in crate::l1b_port::validate::secret_patterns() {
        if pattern.is_match(value) {
            return Err(format!("{name} contains a possible secret ({label})"));
        }
    }
    Ok(())
}

/// Lowercase, whitespace-collapsed form used to compare declared values.
pub fn compare_form(value: &str) -> String {
    value
        .replace(['`', '*'], "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn dated(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() >= 10
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
}

impl ChangedSince {
    fn validate(&self) -> Result<(), String> {
        let id_ok = !self.id.is_empty()
            && self.id.chars().count() <= 32
            && self
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
        if !id_ok {
            return Err(format!(
                "changed_since[].id must be 1-32 characters of [A-Za-z0-9_.-]: {}",
                self.id
            ));
        }
        for (name, value) in [
            ("decision", &self.decision),
            ("old", &self.old),
            ("new", &self.new),
            ("evidence", &self.evidence),
        ] {
            let label = format!("changed_since[{}].{name}", self.id);
            field(&label, value)?;
            no_secret(&label, value)?;
        }
        if !dated(&self.when) || self.when.chars().count() > MAX_FIELD {
            return Err(format!(
                "changed_since[{}].when must start with a YYYY-MM-DD date",
                self.id
            ));
        }
        if compare_form(&self.old) == compare_form(&self.new) {
            return Err(format!(
                "changed_since[{}] lists no change: old and new are the same value",
                self.id
            ));
        }
        let since = &self.since;
        if since.receipt_sha256.is_none() && since.cutoff_bytes.is_none() {
            return Err(format!(
                "changed_since[{}].since must name a prior receipt_sha256 or cutoff_bytes",
                self.id
            ));
        }
        if let Some(receipt) = &since.receipt_sha256 {
            let bare = bare_hex(receipt);
            if bare.len() != 64 || !bare.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!(
                    "changed_since[{}].since.receipt_sha256 must be a 64-hex SHA-256",
                    self.id
                ));
            }
        }
        if since.cutoff_bytes == Some(0) {
            return Err(format!(
                "changed_since[{}].since.cutoff_bytes must be positive",
                self.id
            ));
        }
        Ok(())
    }
}

impl SourceBlock {
    /// Bind every changed-since entry to the frozen prefix this block ships
    /// with: a baseline must be strictly earlier than the current cutoff and
    /// must not be the current prefix itself. Later deltas belong in notes.
    pub fn bind_to_prefix(&self, cutoff_bytes: u64, prefix_sha256: &str) -> Result<(), String> {
        let current = bare_hex(prefix_sha256);
        for change in &self.changed_since {
            if let Some(prior) = change.since.cutoff_bytes {
                if prior >= cutoff_bytes {
                    return Err(format!(
                        "changed_since[{}].since.cutoff_bytes {prior} is not earlier than the frozen cutoff {cutoff_bytes}",
                        change.id
                    ));
                }
            }
            if let Some(receipt) = &change.since.receipt_sha256 {
                if bare_hex(receipt) == current {
                    return Err(format!(
                        "changed_since[{}].since.receipt_sha256 is the current prefix, not a prior receipt",
                        change.id
                    ));
                }
            }
        }
        Ok(())
    }

    /// Extra gate for a block that is about to ship in a handoff: it must
    /// record the source memory directory or an explicit absence.
    pub fn require_handoff_complete(&self) -> Result<(), String> {
        if self.memory.is_none() {
            return Err(
                "source block must record memory: {\"dir\": <absolute path>} or {\"absent_reason\": <why>}"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != SOURCE_BLOCK_SCHEMA {
            return Err(format!("source block schema must be {SOURCE_BLOCK_SCHEMA}"));
        }
        if self.trust != SOURCE_BLOCK_TRUST {
            return Err(format!(
                "source block trust must be {SOURCE_BLOCK_TRUST}; it is never transcript evidence"
            ));
        }
        if self.heads.len() > MAX_ITEMS
            || self.uncommitted.len() > MAX_ITEMS
            || self.in_flight.len() > MAX_ITEMS
            || self.changed_since.len() > MAX_ITEMS
            || self.artifact_roots.len() > MAX_ITEMS
        {
            return Err(format!(
                "source block lists are limited to {MAX_ITEMS} entries"
            ));
        }
        for head in &self.heads {
            repo_relative("heads[].repo", &head.repo, true)?;
            if !full_sha(&head.sha) {
                return Err(format!(
                    "heads[].sha must be a 40-character lowercase hex SHA: {}",
                    head.sha
                ));
            }
        }
        for item in &self.uncommitted {
            repo_relative("uncommitted[].repo", &item.repo, true)?;
            repo_relative("uncommitted[].path", &item.path, false)?;
            field("uncommitted[].owner", &item.owner)?;
            if item.state != EditState::Complete && item.reviewed {
                return Err(format!(
                    "uncommitted path {} is not complete and cannot be marked reviewed",
                    item.path
                ));
            }
        }
        if let Some(transfer) = &self.ownership_transfer {
            repo_relative("ownership_transfer.repository", &transfer.repository, true)?;
            field("ownership_transfer.from", &transfer.from)?;
            field("ownership_transfer.to", &transfer.to)?;
        }
        let mut seen = BTreeSet::new();
        for item in &self.in_flight {
            field("in_flight[].id", &item.id)?;
            field("in_flight[].owner", &item.owner)?;
            if let Some(path) = &item.output_path {
                field("in_flight[].output_path", path)?;
            }
            if !seen.insert((item.kind, item.id.clone())) {
                return Err(format!("duplicate in-flight item: {}", item.id));
            }
        }
        let mut change_ids = BTreeSet::new();
        for change in &self.changed_since {
            change.validate()?;
            if !change_ids.insert(change.id.clone()) {
                return Err(format!("duplicate changed_since id: {}", change.id));
            }
        }
        if let Some(memory) = &self.memory {
            match (&memory.dir, &memory.absent_reason) {
                (Some(dir), None) => {
                    absolute_path("memory.dir", dir)?;
                    no_secret("memory.dir", dir)?;
                }
                (None, Some(reason)) => {
                    field("memory.absent_reason", reason)?;
                    no_secret("memory.absent_reason", reason)?;
                }
                _ => {
                    return Err(
                        "memory must declare exactly one of dir or absent_reason".to_string()
                    )
                }
            }
        }
        let mut roots = BTreeSet::new();
        for root in &self.artifact_roots {
            absolute_path("artifact_roots[].path", &root.path)?;
            field("artifact_roots[].owner", &root.owner)?;
            field("artifact_roots[].rerender", &root.rerender)?;
            for (name, value) in [
                ("artifact_roots[].path", &root.path),
                ("artifact_roots[].rerender", &root.rerender),
            ] {
                no_secret(name, value)?;
            }
            if !roots.insert(root.path.clone()) {
                return Err(format!("duplicate artifact root: {}", root.path));
            }
        }
        Ok(())
    }

    /// Canonical hash over the typed value (independent of file whitespace).
    pub fn digest(&self) -> Result<String, String> {
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }

    /// Parse and validate untrusted JSON text.
    pub fn parse(text: &str) -> Result<Self, String> {
        let block: SourceBlock =
            serde_json::from_str(text).map_err(|e| format!("invalid source block: {e}"))?;
        block.validate()?;
        Ok(block)
    }
}

/// Strip an optional `sha256:` prefix and lowercase.
pub fn bare_hex(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("sha256:")
        .to_ascii_lowercase()
}

// ---------------------------------------------------------------- reconcile

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    StillRunning,
    Stopped,
    Completed,
    Failed,
    Abandoned,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciledItem {
    pub kind: InFlightKind,
    pub id: String,
    pub resolution: Resolution,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reconciliation {
    pub schema: String,
    pub items: Vec<ReconciledItem>,
}

/// Every declared in-flight item needs exactly one reconciliation entry with
/// evidence; entries for undeclared items are rejected.
pub fn check_reconciliation(block: &SourceBlock, rec: &Reconciliation) -> Result<(), String> {
    if rec.schema != RECONCILIATION_SCHEMA {
        return Err(format!(
            "reconciliation schema must be {RECONCILIATION_SCHEMA}"
        ));
    }
    let mut remaining: BTreeSet<(InFlightKind, String)> = block
        .in_flight
        .iter()
        .map(|item| (item.kind, item.id.clone()))
        .collect();
    for entry in &rec.items {
        field("reconciliation.items[].evidence", &entry.evidence)?;
        if !remaining.remove(&(entry.kind, entry.id.clone())) {
            return Err(format!(
                "reconciliation entry {} is undeclared or duplicated",
                entry.id
            ));
        }
    }
    if let Some((_, id)) = remaining.into_iter().next() {
        return Err(format!("in-flight item {id} is not reconciled"));
    }
    Ok(())
}

// -------------------------------------------------------------------- notes

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteKind {
    AgentStopped,
    PeerRequest,
    BuildFinished,
    Other,
}

impl NoteKind {
    pub fn parse(value: &str) -> Result<Self, String> {
        serde_json::from_value(serde_json::Value::String(value.to_string()))
            .map_err(|_| format!("unknown note kind: {value}"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    pub schema: String,
    pub seq: u64,
    pub timestamp: String,
    pub author: String,
    pub kind: NoteKind,
    pub text: String,
    pub prev: String,
    pub hash: String,
}

fn note_hash(note: &Note) -> Result<String, String> {
    let mut clone = note.clone();
    clone.hash.clear();
    let bytes = serde_json::to_vec(&clone).map_err(|e| e.to_string())?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

/// Genesis link: the frozen transcript prefix hash, so a notes file cannot be
/// replayed onto a different handoff.
pub fn notes_genesis(prefix_sha256: &str) -> String {
    format!("sha256:{}", bare_hex(prefix_sha256))
}

#[derive(Debug)]
pub struct NotesSummary {
    pub notes: Vec<Note>,
    pub head: String,
}

/// Read and verify the whole chain. A missing file is an empty chain.
pub fn verify_notes(path: &Path, prefix_sha256: &str) -> Result<NotesSummary, String> {
    let genesis = notes_genesis(prefix_sha256);
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(NotesSummary {
                notes: Vec::new(),
                head: genesis,
            })
        }
        Err(e) => return Err(format!("cannot read notes: {e}")),
    };
    if !text.is_empty() && !text.ends_with('\n') {
        return Err("notes file ends with a partial line".into());
    }
    let mut prev = genesis;
    let mut notes = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let n = (index + 1) as u64;
        let note: Note =
            serde_json::from_str(line).map_err(|e| format!("note {n} is not valid: {e}"))?;
        if note.schema != NOTE_SCHEMA || note.seq != n {
            return Err(format!("note {n} has wrong schema or sequence"));
        }
        if note.prev != prev {
            return Err(format!("note {n} does not chain to the previous note"));
        }
        if note_hash(&note)? != note.hash {
            return Err(format!("note {n} hash mismatch"));
        }
        prev = note.hash.clone();
        notes.push(note);
    }
    Ok(NotesSummary { notes, head: prev })
}

/// Verify the existing chain, then append one redacted note.
pub fn append_note(
    path: &Path,
    prefix_sha256: &str,
    kind: NoteKind,
    author: &str,
    text: &str,
    timestamp: String,
) -> Result<Note, String> {
    field("author", author)?;
    if text.trim().is_empty() {
        return Err("note text must be non-empty".into());
    }
    let summary = verify_notes(path, prefix_sha256)?;
    if summary.notes.len() >= MAX_NOTES {
        return Err(format!("notes are limited to {MAX_NOTES} entries"));
    }
    let mut body: String = super::continuity::redact_text(text)
        .chars()
        .take(MAX_NOTE_CHARS)
        .collect();
    body = body.trim().to_string();
    let mut note = Note {
        schema: NOTE_SCHEMA.into(),
        seq: summary.notes.len() as u64 + 1,
        timestamp,
        author: author.into(),
        kind,
        text: body,
        prev: summary.head,
        hash: String::new(),
    };
    note.hash = note_hash(&note)?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let line = serde_json::to_string(&note).map_err(|e| e.to_string())? + "\n";
    file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    Ok(note)
}
