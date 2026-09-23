//! Port of `tools/audit/audit_store.py` — the typed `AuditFindingV1` JSONL
//! store rooted at `<repo>/.audit/audit/findings.jsonl`.
//!
//! This module is storage-only: stable finding-id derivation, record
//! construction, and the upsert/supersede/set-status mutation paths. It does
//! not depend on the Membrane planner adapter (`tools/audit/audit_provider.py`,
//! which this chunk drops — see `wf065::mod` docs) and is reusable on its own.
//!
//! Field names are kept in the source's camelCase (`repositoryId`,
//! `evidenceLoci`, ...) via `#[serde(rename = ...)]` so a JSONL line written
//! by this port round-trips byte-identically with one written by the Python
//! original (`serde_json::Value::Object` is a `BTreeMap` here — no
//! `preserve_order` feature — so `sort_keys=True` parity holds automatically
//! once each record is passed through a canonical `Value`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: u32 = 1;
pub const ID_KIND_PREFIX: &str = "audit:rule:";

pub fn active_statuses() -> &'static [&'static str] {
    &["open"]
}

pub fn terminal_statuses() -> &'static [&'static str] {
    &["resolved", "dismissed", "superseded"]
}

fn is_active_status(status: &str) -> bool {
    active_statuses().contains(&status)
}

fn is_terminal_status(status: &str) -> bool {
    terminal_statuses().contains(&status)
}

fn is_valid_status(status: &str) -> bool {
    is_active_status(status) || is_terminal_status(status)
}

pub const PROVENANCE_KINDS: &[&str] = &["deterministic_scanner", "reasoning_lens", "manual"];

#[derive(Debug, thiserror::Error)]
pub enum AuditStoreError {
    #[error("{0}")]
    Invalid(String),
    #[error("unknown finding: {0}")]
    UnknownFinding(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupt JSONL at {path}:{line}: {source}")]
    Corrupt {
        path: String,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
}

pub type Result<T> = std::result::Result<T, AuditStoreError>;

fn err(msg: impl Into<String>) -> AuditStoreError {
    AuditStoreError::Invalid(msg.into())
}

/// UTC "YYYY-MM-DDTHH:MM:SSZ" without a chrono dependency — matches
/// `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")`. Callers that
/// need a real wall-clock value pass one in via `now`; the store never
/// synthesizes one when a deterministic caller-supplied value is available.
pub fn utc_now_from_unix(seconds: u64) -> String {
    // Civil-from-days algorithm (Howard Hinnant's `civil_from_days`), pure
    // integer arithmetic, valid for any Gregorian date — no external crate.
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn locus_content_hash(path: &str, start_line: i64, end_line: i64) -> String {
    let norm = path.replace('\\', "/");
    let norm = norm.trim_start_matches('/');
    let key = format!("{norm}:{start_line}-{end_line}");
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Derive a stable finding ID from repository + rule + the first evidence
/// locus. Mirrors `audit_store.derive_finding_id` field-for-field, including
/// the 7-char repo/locus digest truncation.
pub fn derive_finding_id(
    repository_id: &str,
    rule_id: &str,
    evidence_loci: &[EvidenceLocusInput],
) -> Result<String> {
    let norm_repo = repository_id.trim();
    if norm_repo.is_empty() {
        return Err(err("repositoryId is required for stable finding ID"));
    }
    let norm_rule = rule_id.trim();
    if norm_rule.is_empty() {
        return Err(err("ruleId is required for stable finding ID"));
    }
    let first = evidence_loci
        .first()
        .ok_or_else(|| err("at least one evidence locus is required for stable finding ID"))?;
    let locus_hash = locus_content_hash(&first.path, first.start_line, first.end_line);
    let norm_path = first.path.replace('\\', "/");
    let norm_path = norm_path.trim_start_matches('/');
    let mut repo_hasher = Sha256::new();
    repo_hasher.update(norm_repo.as_bytes());
    let repo_digest = &hex::encode(repo_hasher.finalize())[..7];
    let locus_digest = &locus_hash.rsplit(':').next().unwrap_or("")[..7.min(locus_hash.len())];
    Ok(format!(
        "{ID_KIND_PREFIX}{repo_digest}-{norm_rule}:{norm_path}:{locus_digest}"
    ))
}

#[derive(Debug, Clone)]
pub struct EvidenceLocusInput {
    pub path: String,
    pub start_line: i64,
    pub end_line: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceLocus {
    pub path: String,
    #[serde(rename = "startLine")]
    pub start_line: i64,
    #[serde(rename = "endLine")]
    pub end_line: i64,
    #[serde(rename = "contentSha256")]
    pub content_sha256: String,
}

fn coerce_locus(input: &EvidenceLocusInput) -> Result<EvidenceLocus> {
    if input.path.is_empty() {
        return Err(err("evidence locus requires non-empty path"));
    }
    if input.start_line < 1 {
        return Err(err("evidence locus requires positive integer startLine"));
    }
    if input.end_line < input.start_line {
        return Err(err("evidence locus requires endLine >= startLine >= 1"));
    }
    Ok(EvidenceLocus {
        path: input.path.clone(),
        start_line: input.start_line,
        end_line: input.end_line,
        content_sha256: locus_content_hash(&input.path, input.start_line, input.end_line),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub kind: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "ruleId")]
    pub rule_id: String,
}

fn default_provenance(rule_id: &str, kind: &str, version: &str) -> Result<Provenance> {
    if !PROVENANCE_KINDS.contains(&kind) {
        return Err(err(format!("invalid provenance kind: {kind:?}")));
    }
    Ok(Provenance {
        kind: kind.to_string(),
        name: rule_id.to_string(),
        version: version.to_string(),
        rule_id: rule_id.to_string(),
    })
}

/// In-memory draft used to construct an `AuditFindingV1` record. Mirrors
/// `audit_store.FindingDraft`.
#[derive(Debug, Clone)]
pub struct FindingDraft {
    pub repository_id: String,
    pub scope_id: String,
    pub rule_id: String,
    pub category: String,
    pub title: String,
    pub evidence_loci: Vec<EvidenceLocusInput>,
    pub severity: String,
    pub confidence: f64,
    pub provenance: Option<Provenance>,
    pub audit_generation: String,
    pub linked_graph_generation: Option<String>,
    pub provenance_kind: String,
    pub provenance_version: String,
}

impl Default for FindingDraft {
    fn default() -> Self {
        Self {
            repository_id: String::new(),
            scope_id: String::new(),
            rule_id: String::new(),
            category: String::new(),
            title: String::new(),
            evidence_loci: Vec::new(),
            severity: "medium".to_string(),
            confidence: 1.0,
            provenance: None,
            audit_generation: String::new(),
            linked_graph_generation: None,
            provenance_kind: "deterministic_scanner".to_string(),
            provenance_version: "1".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub id: String,
    #[serde(rename = "repositoryId")]
    pub repository_id: String,
    #[serde(rename = "scopeId")]
    pub scope_id: String,
    #[serde(rename = "auditGeneration")]
    pub audit_generation: String,
    #[serde(rename = "linkedGraphGeneration")]
    pub linked_graph_generation: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    #[serde(rename = "evidenceLoci")]
    pub evidence_loci: Vec<EvidenceLocus>,
    pub confidence: f64,
    pub status: String,
    pub supersedes: Vec<String>,
    #[serde(rename = "supersededBy")]
    pub superseded_by: Option<String>,
    #[serde(rename = "firstSeenGeneration")]
    pub first_seen_generation: String,
    #[serde(rename = "lastSeenGeneration")]
    pub last_seen_generation: String,
    #[serde(rename = "firstSeenAt")]
    pub first_seen_at: String,
    #[serde(rename = "lastSeenAt")]
    pub last_seen_at: String,
    #[serde(rename = "resolvedGeneration")]
    pub resolved_generation: Option<String>,
    #[serde(rename = "resolvedAt")]
    pub resolved_at: Option<String>,
    pub provenance: Provenance,
}

/// Construct a fully-typed `AuditFindingV1` record from a draft. `now` is an
/// explicit override hook for deterministic tests, mirroring the Python
/// `now: str | None` parameter.
pub fn make_finding(
    draft: &FindingDraft,
    audit_generation: Option<&str>,
    linked_graph_generation: Option<&str>,
    status: &str,
    now: &str,
) -> Result<Finding> {
    if !is_valid_status(status) {
        return Err(err(format!("invalid status: {status:?}")));
    }
    if draft.evidence_loci.is_empty() {
        return Err(err("finding requires at least one evidence locus"));
    }
    let loci = draft
        .evidence_loci
        .iter()
        .map(coerce_locus)
        .collect::<Result<Vec<_>>>()?;
    let fid = derive_finding_id(&draft.repository_id, &draft.rule_id, &draft.evidence_loci)?;
    let gen = audit_generation
        .filter(|s| !s.is_empty())
        .unwrap_or(&draft.audit_generation)
        .to_string();
    let linked = linked_graph_generation
        .map(str::to_string)
        .or_else(|| draft.linked_graph_generation.clone())
        .unwrap_or_default();
    let provenance = match &draft.provenance {
        Some(p) => p.clone(),
        None => default_provenance(&draft.rule_id, &draft.provenance_kind, &draft.provenance_version)?,
    };
    Ok(Finding {
        schema_version: SCHEMA_VERSION,
        id: fid,
        repository_id: draft.repository_id.clone(),
        scope_id: draft.scope_id.clone(),
        audit_generation: gen.clone(),
        linked_graph_generation: linked,
        severity: draft.severity.clone(),
        category: draft.category.clone(),
        title: draft.title.clone(),
        evidence_loci: loci,
        confidence: draft.confidence,
        status: status.to_string(),
        supersedes: Vec::new(),
        superseded_by: None,
        first_seen_generation: gen.clone(),
        last_seen_generation: gen,
        first_seen_at: now.to_string(),
        last_seen_at: now.to_string(),
        resolved_generation: None,
        resolved_at: None,
        provenance,
    })
}

fn validate(record: &Finding) -> Result<()> {
    if record.schema_version != SCHEMA_VERSION {
        return Err(err(format!(
            "unexpected schemaVersion: {}",
            record.schema_version
        )));
    }
    if !is_valid_status(&record.status) {
        return Err(err(format!("invalid status: {:?}", record.status)));
    }
    if record.evidence_loci.is_empty() {
        return Err(err("evidenceLoci must be a non-empty list"));
    }
    Ok(())
}

/// JSONL-backed typed `AuditFindingV1` store. Every write goes through
/// `upsert` / `supersede` / `set_status`, each of which rewrites the whole
/// file (temp-file-then-rename, matching the Python `_flush`).
pub struct AuditStore {
    repo: PathBuf,
    store_path: PathBuf,
    cache: BTreeMap<String, Finding>,
    loaded: bool,
}

impl AuditStore {
    pub fn new(repo: impl AsRef<Path>) -> Self {
        let repo = repo.as_ref().to_path_buf();
        let store_path = repo.join(".audit").join("audit").join("findings.jsonl");
        Self {
            repo,
            store_path,
            cache: BTreeMap::new(),
            loaded: false,
        }
    }

    pub fn store_path(&self) -> &Path {
        &self.store_path
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }

    fn ensure_loaded(&mut self) -> Result<()> {
        if self.loaded {
            return Ok(());
        }
        self.loaded = true;
        self.cache.clear();
        if !self.store_path.is_file() {
            return Ok(());
        }
        let text = fs::read_to_string(&self.store_path)?;
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let record: Finding =
                serde_json::from_str(line).map_err(|source| AuditStoreError::Corrupt {
                    path: self.store_path.display().to_string(),
                    line: lineno + 1,
                    source,
                })?;
            validate(&record)?;
            self.cache.insert(record.id.clone(), record);
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        if let Some(parent) = self.store_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.store_path.with_extension("jsonl.tmp");
        let mut body = String::new();
        // BTreeMap iteration is key-sorted (finding id), which is a superset
        // of the Python dict-insertion-order guarantee needed for byte
        // stability across identical inputs; content itself is unaffected.
        for record in self.cache.values() {
            let canonical: serde_json::Value = serde_json::to_value(record)
                .map_err(|e| err(format!("finding record is not serializable: {e}")))?;
            body.push_str(&serde_json::to_string(&canonical).unwrap());
            body.push('\n');
        }
        fs::write(&tmp, body)?;
        fs::rename(&tmp, &self.store_path)?;
        Ok(())
    }

    pub fn load(&mut self) -> Result<Vec<Finding>> {
        self.ensure_loaded()?;
        Ok(self.cache.values().cloned().collect())
    }

    pub fn len(&mut self) -> Result<usize> {
        self.ensure_loaded()?;
        Ok(self.cache.len())
    }

    pub fn is_empty(&mut self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    pub fn get(&mut self, finding_id: &str) -> Result<Option<Finding>> {
        self.ensure_loaded()?;
        Ok(self.cache.get(finding_id).cloned())
    }

    /// `status == "open"` records, optionally filtered by repository.
    pub fn active(&mut self, repository_id: Option<&str>) -> Result<Vec<Finding>> {
        self.ensure_loaded()?;
        Ok(self
            .cache
            .values()
            .filter(|rec| is_active_status(&rec.status))
            .filter(|rec| repository_id.is_none_or(|rid| rec.repository_id == rid))
            .cloned()
            .collect())
    }

    /// Insert or refresh a record, preserving `firstSeen*` and identity.
    /// `now` provides the wall clock for tests; callers that omit it must
    /// supply one deterministically (the Python original defaults to
    /// `datetime.now`, which this port does not reproduce implicitly).
    pub fn upsert(&mut self, mut record: Finding, now: &str) -> Result<Finding> {
        validate(&record)?;
        self.ensure_loaded()?;
        let fid = record.id.clone();
        match self.cache.get(&fid) {
            None => {
                if record.first_seen_generation.is_empty() {
                    record.first_seen_generation = record.audit_generation.clone();
                }
                record.last_seen_generation = record.audit_generation.clone();
                if record.first_seen_at.is_empty() {
                    record.first_seen_at = now.to_string();
                }
                if record.last_seen_at.is_empty() {
                    record.last_seen_at = now.to_string();
                }
                self.cache.insert(fid.clone(), record.clone());
                self.flush()?;
                Ok(record)
            }
            Some(prior) => {
                let mut merged = prior.clone();
                let incoming = record.clone();
                merged.repository_id = incoming.repository_id;
                merged.scope_id = incoming.scope_id;
                merged.audit_generation = incoming.audit_generation.clone();
                merged.linked_graph_generation = incoming.linked_graph_generation;
                merged.severity = incoming.severity;
                merged.category = incoming.category;
                merged.title = incoming.title;
                merged.evidence_loci = incoming.evidence_loci;
                merged.confidence = incoming.confidence;
                merged.status = incoming.status;
                merged.provenance = incoming.provenance;
                merged.id = fid.clone();
                merged.first_seen_generation = prior.first_seen_generation.clone();
                merged.first_seen_at = prior.first_seen_at.clone();
                merged.last_seen_generation = if incoming.audit_generation.is_empty() {
                    prior.last_seen_generation.clone()
                } else {
                    incoming.audit_generation.clone()
                };
                merged.last_seen_at = if incoming.last_seen_at.is_empty() {
                    now.to_string()
                } else {
                    incoming.last_seen_at.clone()
                };
                merged.superseded_by = incoming.superseded_by.or_else(|| prior.superseded_by.clone());
                merged.supersedes = if incoming.supersedes.is_empty() {
                    prior.supersedes.clone()
                } else {
                    incoming.supersedes.clone()
                };
                if incoming.resolved_generation.is_none() {
                    merged.resolved_generation = prior.resolved_generation.clone().or(merged.resolved_generation);
                } else {
                    merged.resolved_generation = incoming.resolved_generation;
                }
                if incoming.resolved_at.is_none() {
                    merged.resolved_at = prior.resolved_at.clone().or(merged.resolved_at);
                } else {
                    merged.resolved_at = incoming.resolved_at;
                }
                self.cache.insert(fid, merged.clone());
                self.flush()?;
                Ok(merged)
            }
        }
    }

    /// Mark `old_id` as `superseded`, linked to `new_record`'s id, then
    /// upsert the successor with an appended `supersedes` chain.
    pub fn supersede(&mut self, old_id: &str, mut new_record: Finding, now: &str) -> Result<Finding> {
        validate(&new_record)?;
        self.ensure_loaded()?;
        let mut old = self
            .cache
            .get(old_id)
            .cloned()
            .ok_or_else(|| AuditStoreError::UnknownFinding(old_id.to_string()))?;
        old.status = "superseded".to_string();
        old.superseded_by = Some(new_record.id.clone());
        old.resolved_generation = Some(if new_record.audit_generation.is_empty() {
            old.last_seen_generation.clone()
        } else {
            new_record.audit_generation.clone()
        });
        old.resolved_at = Some(now.to_string());
        old.last_seen_at = now.to_string();
        self.cache.insert(old_id.to_string(), old);

        if !new_record.supersedes.iter().any(|s| s == old_id) {
            new_record.supersedes.push(old_id.to_string());
        }
        if new_record.first_seen_generation.is_empty() {
            new_record.first_seen_generation = new_record.audit_generation.clone();
        }
        new_record.last_seen_generation = new_record.audit_generation.clone();
        if new_record.first_seen_at.is_empty() {
            new_record.first_seen_at = now.to_string();
        }
        new_record.last_seen_at = now.to_string();
        self.cache.insert(new_record.id.clone(), new_record.clone());
        self.flush()?;
        Ok(new_record)
    }

    /// Set status (`resolved` / `dismissed` / `open`). `superseded` is not a
    /// valid direct target — use `supersede`.
    pub fn set_status(
        &mut self,
        finding_id: &str,
        status: &str,
        generation: Option<&str>,
        now: &str,
    ) -> Result<Finding> {
        if !is_valid_status(status) || status == "superseded" {
            return Err(err(
                "use store.supersede() to retire by supersession; set_status accepts resolved/dismissed/open",
            ));
        }
        self.ensure_loaded()?;
        let mut rec = self
            .cache
            .get(finding_id)
            .cloned()
            .ok_or_else(|| AuditStoreError::UnknownFinding(finding_id.to_string()))?;
        rec.status = status.to_string();
        if is_terminal_status(status) {
            let gen = generation
                .map(str::to_string)
                .filter(|s| !s.is_empty())
                .or_else(|| Some(rec.audit_generation.clone()).filter(|s| !s.is_empty()))
                .unwrap_or_else(|| rec.last_seen_generation.clone());
            rec.resolved_generation = Some(gen);
            rec.resolved_at = Some(now.to_string());
        } else {
            rec.resolved_generation = None;
            rec.resolved_at = None;
        }
        rec.last_seen_at = now.to_string();
        self.cache.insert(finding_id.to_string(), rec.clone());
        self.flush()?;
        Ok(rec)
    }
}
