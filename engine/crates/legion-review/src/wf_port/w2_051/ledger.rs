//! Port of `src/lib/review/ledger.py` — jury revision ledger, per-artifact
//! blocker disposition log.
//!
//! Schema (locked 2026-07-14), `<artifact>.verdict.ledger.json`:
//! ```json
//! {
//!   "schema_version": 1,
//!   "artifact": "out/shot3.mp4",
//!   "rounds": [ { "round": 1, "ts": "...", "verdict_path": "...", "blockers": [...] } ]
//! }
//! ```
//! `disposition` in {null, "fixed", "rebutted", "waived_by_operator"}; null == "pending".
//!
//! File I/O (`load_ledger`/`save_ledger`) and the CLI's argv parsing are
//! ported as pure functions taking/returning paths and strings so they are
//! unit-testable without a process boundary; the binary entry point
//! (`main`) is intentionally not ported here — wiring a bin is out of this
//! module's owned paths.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde::{Deserialize, Serialize};

pub const VALID_DISPOSITIONS: [&str; 3] = ["fixed", "rebutted", "waived_by_operator"];
pub const TIER_VALUES: [&str; 3] = ["P0", "P1", "P2"];

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("invalid disposition: {0:?}; must be one of [\"fixed\", \"rebutted\", \"waived_by_operator\"]")]
    InvalidDisposition(String),
    #[error("invalid blocker id: {0:?}; expected b<digits>")]
    InvalidBlockerId(String),
    #[error("--dispose expects id=disposition[:evidence], got {0:?}")]
    BadDisposeArg(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockerEntry {
    pub id: String,
    pub tier: String,
    pub text: String,
    #[serde(default)]
    pub from_juror: String,
    #[serde(default)]
    pub disposition: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub disposed_at: Option<String>,
}

impl BlockerEntry {
    /// Mirrors `BlockerEntry.from_dict`: tolerant tier coercion, defaulting
    /// an unrecognised or missing tier to "P1".
    pub fn from_loose(
        id: impl Into<String>,
        tier: Option<&str>,
        text: impl Into<String>,
        from_juror: impl Into<String>,
        disposition: Option<String>,
        evidence: Option<String>,
        disposed_at: Option<String>,
    ) -> Self {
        let tier = normalize_tier(tier);
        Self {
            id: id.into(),
            tier,
            text: text.into().trim().to_string(),
            from_juror: from_juror.into().trim().to_string(),
            disposition,
            evidence,
            disposed_at,
        }
    }
}

fn normalize_tier(tier: Option<&str>) -> String {
    let upper = tier.unwrap_or("P1").to_uppercase();
    if TIER_VALUES.contains(&upper.as_str()) {
        upper
    } else {
        "P1".to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Round {
    pub round: i64,
    pub ts: String,
    pub verdict_path: String,
    #[serde(default)]
    pub blockers: Vec<BlockerEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ledger {
    pub schema_version: i64,
    pub artifact: String,
    #[serde(default)]
    pub rounds: Vec<Round>,
}

impl Ledger {
    pub fn new(artifact: impl Into<String>) -> Self {
        Self {
            schema_version: 1,
            artifact: artifact.into(),
            rounds: Vec::new(),
        }
    }

    pub fn latest_round(&self) -> Option<&Round> {
        self.rounds.iter().max_by_key(|r| r.round)
    }

    pub fn latest_round_mut(&mut self) -> Option<&mut Round> {
        let max_round = self.rounds.iter().map(|r| r.round).max()?;
        self.rounds.iter_mut().find(|r| r.round == max_round)
    }

    /// Pending blockers from the latest round only.
    pub fn pending_blockers(&self) -> Vec<&BlockerEntry> {
        match self.latest_round() {
            None => Vec::new(),
            Some(r) => r.blockers.iter().filter(|b| b.disposition.is_none()).collect(),
        }
    }

    /// True iff the latest round has no pending blockers.
    pub fn is_clean(&self) -> bool {
        self.pending_blockers().is_empty()
    }
}

// ---------- File helpers ----------

/// `<basename>.verdict.ledger.json` next to `<basename>.verdict.json`.
pub fn ledger_path_for(artifact: &Path) -> PathBuf {
    let parent = artifact.parent().unwrap_or_else(|| Path::new(""));
    let stem = artifact
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    parent.join(format!("{stem}.verdict.ledger.json"))
}

pub fn load_ledger(path: &Path) -> Option<Ledger> {
    if !path.is_file() {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn save_ledger(ledger: &Ledger, path: Option<&Path>) -> Result<PathBuf, LedgerError> {
    let owned;
    let p: &Path = match path {
        Some(p) => p,
        None => {
            owned = ledger_path_for(Path::new(&ledger.artifact));
            &owned
        }
    };
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(ledger)?;
    std::fs::write(p, json)?;
    Ok(p.to_path_buf())
}

// ---------- Adding a new round from a verdict ----------

/// One blocker as submitted for a new round: either free text (legacy,
/// optionally prefixed `[P0] ...`) or an already-structured tier+text pair.
#[derive(Debug, Clone)]
pub enum RawBlocker {
    Text(String),
    Structured { tier: Option<String>, text: String },
}

fn tier_prefix_re() -> Regex {
    Regex::new(r"^\[(P0|P1|P2)\]").expect("static regex")
}

/// Same normalizer the Python synthesizer uses: returns (tier, text).
pub fn normalize_blocker(b: &RawBlocker) -> (String, String) {
    match b {
        RawBlocker::Structured { tier, text } => {
            (normalize_tier(tier.as_deref()), text.trim().to_string())
        }
        RawBlocker::Text(raw) => {
            let text = raw.trim();
            let re = tier_prefix_re();
            if let Some(caps) = re.captures(text) {
                let tier = caps.get(1).unwrap().as_str().to_string();
                let rest = re.replace(text, "").trim().to_string();
                (tier, rest)
            } else {
                ("P1".to_string(), text.to_string())
            }
        }
    }
}

/// Deterministic UTC RFC3339 timestamp (no external time crate available
/// to this crate). Second precision, matching the Python
/// `datetime.now(timezone.utc).isoformat()` shape closely enough for the
/// ledger's own consumers, which only compare/display it.
pub fn now_iso_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_unix_utc(secs)
}

fn format_unix_utc(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}+00:00")
}

/// Howard Hinnant's civil_from_days algorithm (proleptic Gregorian, days
/// since 1970-01-01).
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
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Append a new round to the ledger from a verdict's per-juror blockers.
///
/// `juror_blockers` maps juror id -> blockers raised this round. The round
/// number is `previous_max + 1` (or 1 if empty). Existing blocker ids from
/// earlier rounds are NOT carried over (each round starts fresh); a
/// recurring blocker (matched by lower-cased text) inherits its prior
/// disposition onto the new id.
pub fn register_verdict_round(
    ledger: &mut Ledger,
    verdict_path: &str,
    juror_blockers: &BTreeMap<String, Vec<RawBlocker>>,
) {
    let next_round = ledger.rounds.iter().map(|r| r.round).max().unwrap_or(0) + 1;
    let ts = now_iso_utc();

    let mut prior_dispositions: BTreeMap<String, (String, Option<String>)> = BTreeMap::new();
    for r in &ledger.rounds {
        for b in &r.blockers {
            if let Some(disp) = &b.disposition {
                prior_dispositions.insert(b.text.to_lowercase(), (disp.clone(), b.evidence.clone()));
            }
        }
    }

    let mut new_blockers = Vec::new();
    let mut counter = 1u64;
    // juror_blockers is a BTreeMap so iteration is already juror-alphabetical.
    for (juror, blockers) in juror_blockers {
        for blocker in blockers {
            let (tier, text) = normalize_blocker(blocker);
            if text.is_empty() {
                continue;
            }
            let block_id = format!("b{counter}");
            counter += 1;
            let prior = prior_dispositions.get(&text.to_lowercase());
            new_blockers.push(BlockerEntry {
                id: block_id,
                tier,
                text,
                from_juror: juror.clone(),
                disposition: prior.map(|(d, _)| d.clone()),
                evidence: prior.and_then(|(_, e)| e.clone()),
                disposed_at: if prior.is_some() { Some(now_iso_utc()) } else { None },
            });
        }
    }

    ledger.rounds.push(Round {
        round: next_round,
        ts,
        verdict_path: verdict_path.to_string(),
        blockers: new_blockers,
    });
}

// ---------- Disposing a blocker ----------

fn blocker_id_re() -> Regex {
    Regex::new(r"^b\d+$").expect("static regex")
}

/// Set the disposition on one blocker in the latest round. Returns
/// `Ok(true)` if a blocker was updated, `Ok(false)` if the id wasn't found
/// (caller should treat that as an error, per the Python CLI's warning).
pub fn dispose_blocker(
    ledger: &mut Ledger,
    blocker_id: &str,
    disposition: &str,
    evidence: Option<String>,
) -> Result<bool, LedgerError> {
    if !VALID_DISPOSITIONS.contains(&disposition) {
        return Err(LedgerError::InvalidDisposition(disposition.to_string()));
    }
    if !blocker_id_re().is_match(blocker_id) {
        return Err(LedgerError::InvalidBlockerId(blocker_id.to_string()));
    }
    let ts = now_iso_utc();
    let Some(round) = ledger.latest_round_mut() else {
        return Ok(false);
    };
    for b in &mut round.blockers {
        if b.id == blocker_id {
            b.disposition = Some(disposition.to_string());
            b.evidence = evidence;
            b.disposed_at = Some(ts);
            return Ok(true);
        }
    }
    Ok(false)
}

// ---------- CLI arg parsing ----------

/// Parse `b1=fixed:src/foo.rs:42` -> ("b1", "fixed", Some("src/foo.rs:42")).
pub fn parse_dispose_arg(arg: &str) -> Result<(String, String, Option<String>), LedgerError> {
    let Some((bid, rest)) = arg.split_once('=') else {
        return Err(LedgerError::BadDisposeArg(arg.to_string()));
    };
    let bid = bid.trim().to_string();
    if let Some((disposition, evidence)) = rest.split_once(':') {
        Ok((bid, disposition.trim().to_string(), Some(evidence.trim().to_string())))
    } else {
        Ok((bid, rest.trim().to_string(), None))
    }
}

/// JSON status payload, matching the CLI's `--json`/`--status` output shape.
#[derive(Debug, Serialize)]
pub struct StatusPayload {
    pub ledger_path: String,
    pub artifact: String,
    pub rounds: usize,
    pub latest_round: Option<i64>,
    pub pending_count: usize,
    pub is_clean: bool,
    pub pending_blockers: Vec<BlockerEntry>,
}

pub fn status_payload(ledger: &Ledger, ledger_path: &Path) -> StatusPayload {
    let pending: Vec<BlockerEntry> = ledger.pending_blockers().into_iter().cloned().collect();
    StatusPayload {
        ledger_path: ledger_path.to_string_lossy().to_string(),
        artifact: ledger.artifact.clone(),
        rounds: ledger.rounds.len(),
        latest_round: ledger.latest_round().map(|r| r.round),
        pending_count: pending.len(),
        is_clean: ledger.is_clean(),
        pending_blockers: pending,
    }
}
