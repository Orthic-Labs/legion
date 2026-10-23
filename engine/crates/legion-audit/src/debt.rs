//! Debt ledger harvest (A15): TODO-style markers and suppressions.
//!
//! Debt is advisory evidence. A marker's age is reported only from a recorded
//! date and labelled by its basis: a history-derived date (for example from
//! version control, supplied by the caller) is distinct from the date Audit
//! first observed the marker. Unknown stays unknown. Age alone never blocks;
//! only an explicit product policy deadline or an explicit expiry on an
//! accepted suppression does. A marker disappearing is `Removed`, never a
//! verified fix.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const DEBT_SCHEMA_VERSION: u32 = 1;

const MARKERS: [&str; 4] = ["TODO", "FIXME", "HACK", "XXX"];
/// Suppression tokens recognised in comments or attributes.
const SUPPRESSIONS: [&str; 12] = [
    "eslint-disable",
    "@ts-ignore",
    "@ts-expect-error",
    "nosec",
    "NOSONAR",
    "noqa",
    "#[allow(",
    "@SuppressWarnings",
    "swiftlint:disable",
    "#pragma warning disable",
    "@Suppress(",
    "pylint: disable",
];
const ACCEPT_TAG: &str = "audit-accept:";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DebtKind {
    Marker,
    Suppression,
}

/// Where a first-seen date came from. Never merged into one field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "basis")]
pub enum FirstSeen {
    /// From repository history supplied by the caller (RFC 3339 date/time).
    History {
        at: String,
    },
    /// First time an Audit run observed it (run date), not authorship date.
    Observed {
        at: String,
        run_digest: String,
    },
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebtRecord {
    /// Stable across line moves: path + kind + token + text digest.
    pub id: String,
    pub kind: DebtKind,
    pub path: String,
    pub line: u32,
    pub token: String,
    pub text_digest: String,
    pub owner: Option<String>,
    pub reason: Option<String>,
    /// `YYYY-MM-DD` explicit expiry from an `audit-accept:` annotation.
    pub expiry: Option<String>,
    /// True only for a suppression carrying owner, reason and expiry.
    pub accepted: bool,
    pub first_seen: FirstSeen,
}

fn digest_hex(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

fn attr<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("{key}=");
    let start = text.find(&marker)? + marker.len();
    let rest = &text[start..];
    if let Some(quoted) = rest.strip_prefix('"') {
        return quoted.split('"').next().filter(|v| !v.trim().is_empty());
    }
    rest.split_whitespace()
        .next()
        .filter(|v| !v.trim().is_empty())
}

fn valid_date(date: &str) -> bool {
    parse_date(date).is_some()
}

/// Days since 1970-01-01 for `YYYY-MM-DD` (first ten bytes of RFC 3339).
fn parse_date(value: &str) -> Option<i64> {
    let head = value.get(..10)?;
    let mut parts = head.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Harvests markers and suppressions from one file's text. `path` is
/// recorded verbatim (normalised to `/`). Line numbers are 1-based.
pub fn harvest(path: &str, content: &str) -> Vec<DebtRecord> {
    let path = path.replace('\\', "/");
    let mut out = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let line_no = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let trimmed = line.trim();
        if let Some((token, at)) = MARKERS
            .iter()
            .find_map(|m| marker_at(trimmed, m).map(|at| (m, at)))
        {
            let after = &trimmed[at + token.len()..];
            let (owner, rest) = match after.strip_prefix('(').and_then(|r| r.split_once(')')) {
                Some((who, rest)) if !who.trim().is_empty() && !who.contains(' ') => {
                    (Some(who.trim().to_owned()), rest)
                }
                _ => (None, after),
            };
            let reason = rest.trim_start_matches(':').trim().to_owned();
            out.push(record(
                &path,
                line_no,
                DebtKind::Marker,
                token,
                trimmed,
                owner,
                (!reason.is_empty()).then_some(reason),
                None,
            ));
        }
        if let Some(token) = SUPPRESSIONS.iter().find(|s| trimmed.contains(**s)) {
            let tag = trimmed
                .find(ACCEPT_TAG)
                .map(|i| &trimmed[i + ACCEPT_TAG.len()..]);
            let owner = tag.and_then(|t| attr(t, "owner")).map(str::to_owned);
            let reason = tag.and_then(|t| attr(t, "reason")).map(str::to_owned);
            let expiry = tag
                .and_then(|t| attr(t, "expires"))
                .filter(|d| valid_date(d))
                .map(str::to_owned);
            out.push(record(
                &path,
                line_no,
                DebtKind::Suppression,
                token,
                trimmed,
                owner,
                reason,
                expiry,
            ));
        }
    }
    out
}

/// Byte offset of `marker` as a whole word inside a comment-like line.
fn marker_at(line: &str, marker: &str) -> Option<usize> {
    let comment = ["//", "#", "/*", "*", "--", "<!--", ";"]
        .iter()
        .any(|c| line.contains(c));
    if !comment {
        return None;
    }
    line.match_indices(marker).map(|(at, _)| at).find(|at| {
        let before = line[..*at].chars().next_back();
        let after = line[*at + marker.len()..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
            && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

#[allow(clippy::too_many_arguments)]
fn record(
    path: &str,
    line: u32,
    kind: DebtKind,
    token: &str,
    text: &str,
    owner: Option<String>,
    reason: Option<String>,
    expiry: Option<String>,
) -> DebtRecord {
    let kind_label = match kind {
        DebtKind::Marker => "marker",
        DebtKind::Suppression => "suppression",
    };
    let text_digest = digest_hex(&[text]);
    let accepted =
        kind == DebtKind::Suppression && owner.is_some() && reason.is_some() && expiry.is_some();
    DebtRecord {
        id: format!(
            "debt:{}",
            &digest_hex(&[path, kind_label, token, &text_digest])[..16]
        ),
        kind,
        path: path.to_owned(),
        line,
        token: token.to_owned(),
        text_digest,
        owner,
        reason,
        expiry,
        accepted,
        first_seen: FirstSeen::Unknown,
    }
}

/// Explicit product policy; absent means debt age is advisory only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DebtPolicy {
    /// Maximum marker age in days, when the product declares one.
    pub marker_deadline_days: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgeBasis {
    History,
    Observed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DebtAssessment {
    pub id: String,
    /// `None` when no first-seen date is known; never defaulted.
    pub age_days: Option<i64>,
    pub age_basis: Option<AgeBasis>,
    /// Advisory flags: `no-owner`, `no-reason`, `age-unknown`.
    pub advisories: Vec<String>,
    /// Blocking only through explicit expiry or explicit policy deadline.
    pub expired: bool,
    pub deadline_exceeded: bool,
    pub invalid_acceptance: Option<String>,
}

/// Assesses one record at `now` (RFC 3339 or `YYYY-MM-DD`). An unparsable
/// `now` yields unknown ages and no expiry judgement.
pub fn assess(record: &DebtRecord, now: &str, policy: DebtPolicy) -> DebtAssessment {
    let today = parse_date(now);
    let (first, basis) = match &record.first_seen {
        FirstSeen::History { at } => (parse_date(at), Some(AgeBasis::History)),
        FirstSeen::Observed { at, .. } => (parse_date(at), Some(AgeBasis::Observed)),
        FirstSeen::Unknown => (None, None),
    };
    let age_days = match (today, first) {
        (Some(t), Some(f)) if t >= f => Some(t - f),
        _ => None,
    };
    let mut advisories = Vec::new();
    if record.owner.is_none() {
        advisories.push("no-owner".to_owned());
    }
    if record.reason.is_none() {
        advisories.push("no-reason".to_owned());
    }
    if age_days.is_none() {
        advisories.push("age-unknown".to_owned());
    }
    let expired = match (today, record.expiry.as_deref().and_then(parse_date)) {
        (Some(t), Some(e)) => t > e,
        _ => false,
    };
    let invalid_acceptance = (record.kind == DebtKind::Suppression
        && !record.accepted
        && record.owner.is_some() | record.reason.is_some() | record.expiry.is_some())
    .then(|| "audit-accept requires owner, reason and a valid expires date".to_owned());
    let deadline_exceeded = record.kind == DebtKind::Marker
        && matches!((policy.marker_deadline_days, age_days), (Some(limit), Some(age)) if age > i64::from(limit));
    DebtAssessment {
        id: record.id.clone(),
        age_days,
        age_basis: age_days.and(basis),
        advisories,
        expired,
        deadline_exceeded,
        invalid_acceptance,
    }
}

/// Carries first-seen evidence from the prior ledger onto freshly harvested
/// records. A record keeps the earliest known date; a history date replaces
/// an observed one (it is the stronger evidence) but never the reverse.
/// `history_dates` maps id -> history-derived RFC 3339 date.
pub fn merge_first_seen(
    prior: &[DebtRecord],
    mut current: Vec<DebtRecord>,
    history_dates: &BTreeMap<String, String>,
    run_at: &str,
    run_digest: &str,
) -> Vec<DebtRecord> {
    let prior: BTreeMap<&str, &FirstSeen> = prior
        .iter()
        .map(|r| (r.id.as_str(), &r.first_seen))
        .collect();
    for record in &mut current {
        record.first_seen = match (history_dates.get(&record.id), prior.get(record.id.as_str())) {
            (Some(at), _) => FirstSeen::History { at: at.clone() },
            (None, Some(FirstSeen::Unknown)) | (None, None) => FirstSeen::Observed {
                at: run_at.to_owned(),
                run_digest: run_digest.to_owned(),
            },
            (None, Some(existing)) => (*existing).clone(),
        };
    }
    current
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DebtDiff {
    pub added: Vec<String>,
    /// Gone from source. Removal is not proof the debt was repaired.
    pub removed: Vec<String>,
    pub unchanged: Vec<String>,
}

/// Compares ledgers by stable id. `removed` carries no repair claim.
pub fn diff(prior: &[DebtRecord], current: &[DebtRecord]) -> DebtDiff {
    let before: std::collections::BTreeSet<&str> = prior.iter().map(|r| r.id.as_str()).collect();
    let after: std::collections::BTreeSet<&str> = current.iter().map(|r| r.id.as_str()).collect();
    let owned = |set: Vec<&&str>| set.into_iter().map(|s| (**s).to_owned()).collect();
    DebtDiff {
        added: owned(after.difference(&before).collect()),
        removed: owned(before.difference(&after).collect()),
        unchanged: owned(after.intersection(&before).collect()),
    }
}
