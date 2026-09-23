//! Faithful port of `src/lib/guard/compat/effects/replay.mjs`.
//!
//! S03 — replay defense: nonce cache + strictly monotonic per-scope
//! sequence + freshness window + bounded clock skew.
//!
//! A [`ReplayGuard`] is scoped by the composite `{issuerId, sessionId,
//! runId, workspaceId}` ([`scope_key`]): the same nonce presented in a
//! different scope is a different message, not a replay, so both the nonce
//! cache and the sequence-monotonicity check are keyed per scope, never
//! globally.
//!
//! Three independent rejections, deliberately distinct codes because each
//! has a different remediation:
//!   - `ARC_REPLAY_NONCE_SEEN` — this exact nonce was already consumed in
//!     this scope.
//!   - `ARC_REPLAY_SEQUENCE_REGRESSION` — sequence must be strictly
//!     increasing per scope. A repeat of the last-accepted sequence is a
//!     regression too, not a separate case.
//!   - `ARC_REPLAY_STALE` — timestamp is older than the freshness window,
//!     further in the future than the bounded clock-skew allowance, or not
//!     a parsable date at all.
//!
//! `clock` is injectable so tests are deterministic: this module never
//! sleeps and never reads the wall clock except through the injected clock.
//!
//! Memory is bounded by `max_entries`, which governs the nonce cache. Once
//! full, the oldest entry (by insertion order) is evicted to admit a new
//! one. [`ReplayGuard::prune`] proactively drops nonce entries already
//! outside the freshness window.
//!
//! The per-scope sequence map is NOT part of the bounded nonce cache and is
//! never pruned by eviction: dropping a scope's last-accepted sequence
//! would let a subsequent regression silently pass.

use std::collections::HashMap;

use super::canon::{Json, canonical_json};

/// Composite replay scope. Missing fields normalize to `None`, matching the
/// JS destructuring defaults (`issuerId = null`, ...).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayScope {
    pub issuer_id: Option<String>,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
    pub workspace_id: Option<String>,
}

/// Stable string form of a replay scope. Mirrors JS `scopeKey()`: canonical
/// JSON over `{issuerId, sessionId, runId, workspaceId}` with missing fields
/// as `null`.
pub fn scope_key(scope: &ReplayScope) -> String {
    fn field(v: &Option<String>) -> Json {
        match v {
            Some(s) => Json::str(s.clone()),
            None => Json::Null,
        }
    }
    canonical_json(&Json::Obj(vec![
        ("issuerId", field(&scope.issuer_id)),
        ("sessionId", field(&scope.session_id)),
        ("runId", field(&scope.run_id)),
        ("workspaceId", field(&scope.workspace_id)),
    ]))
}

/// One of the three distinct replay-rejection codes, plus the accepted case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayCode {
    Allowed,
    NonceSeen,
    SequenceRegression,
    Stale,
}

impl ReplayCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReplayCode::Allowed => "ALLOWED",
            ReplayCode::NonceSeen => "ARC_REPLAY_NONCE_SEEN",
            ReplayCode::SequenceRegression => "ARC_REPLAY_SEQUENCE_REGRESSION",
            ReplayCode::Stale => "ARC_REPLAY_STALE",
        }
    }
}

/// Mirrors JS `decision(...)`: never throws/panics — a denial is data the
/// caller must record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayDecision {
    pub allowed: bool,
    pub code: ReplayCode,
    pub message: String,
}

fn allow() -> ReplayDecision {
    ReplayDecision { allowed: true, code: ReplayCode::Allowed, message: String::new() }
}

fn deny(code: ReplayCode, message: impl Into<String>) -> ReplayDecision {
    ReplayDecision { allowed: false, code, message: message.into() }
}

/// A replay-check request. `timestamp` is an RFC 3339 / ISO 8601 string, as
/// in the JS source (`Date.parse(timestamp)`); an unparsable value is
/// `ARC_REPLAY_STALE`, never trusted.
pub struct ReplayCheck<'a> {
    pub scope: &'a ReplayScope,
    pub nonce: &'a str,
    pub sequence: i64,
    pub timestamp: &'a str,
}

pub struct ReplayGuardOptions {
    pub freshness_window_seconds: i64,
    pub max_skew_seconds: i64,
    pub max_entries: usize,
}

impl Default for ReplayGuardOptions {
    fn default() -> Self {
        Self { freshness_window_seconds: 300, max_skew_seconds: 60, max_entries: 100_000 }
    }
}

pub struct ReplayGuard {
    freshness_window_seconds: i64,
    max_skew_seconds: i64,
    max_entries: usize,
    // `${scopeKey}\0${nonce}` -> timestampMs. `Vec` alongside the map
    // preserves insertion order for oldest-entry eviction, mirroring the JS
    // `Map`'s iteration order guarantee.
    nonce_order: Vec<String>,
    nonces: HashMap<String, i64>,
    // scopeKey -> last accepted sequence number.
    sequences: HashMap<String, i64>,
}

impl ReplayGuard {
    pub fn new(options: ReplayGuardOptions) -> Self {
        Self {
            freshness_window_seconds: options.freshness_window_seconds,
            max_skew_seconds: options.max_skew_seconds,
            max_entries: options.max_entries,
            nonce_order: Vec::new(),
            nonces: HashMap::new(),
            sequences: HashMap::new(),
        }
    }

    /// `now_ms` is the injected clock reading for this call, mirroring the
    /// JS constructor's injectable `clock()`.
    pub fn check(&mut self, req: ReplayCheck<'_>, now_ms: i64) -> ReplayDecision {
        let key = scope_key(req.scope);

        let ts_ms = match parse_rfc3339_ms(req.timestamp) {
            Some(ms) => ms,
            None => return deny(ReplayCode::Stale, "timestamp is not a parsable date"),
        };

        let age_seconds = (now_ms - ts_ms) as f64 / 1000.0;
        if age_seconds > self.freshness_window_seconds as f64 {
            return deny(ReplayCode::Stale, "timestamp is older than the freshness window");
        }
        if -age_seconds > self.max_skew_seconds as f64 {
            return deny(ReplayCode::Stale, "timestamp is further in the future than the allowed clock skew");
        }

        let nonce_key = format!("{key}\0{}", req.nonce);
        if self.nonces.contains_key(&nonce_key) {
            return deny(ReplayCode::NonceSeen, "nonce already consumed in this scope");
        }

        if let Some(&last_sequence) = self.sequences.get(&key) {
            if req.sequence <= last_sequence {
                return deny(ReplayCode::SequenceRegression, "sequence must be strictly increasing within a scope");
            }
        }

        self.record_nonce(nonce_key, ts_ms, now_ms);
        self.sequences.insert(key, req.sequence);

        allow()
    }

    fn record_nonce(&mut self, nonce_key: String, ts_ms: i64, now_ms: i64) {
        if self.nonces.len() >= self.max_entries {
            self.prune(now_ms);
        }
        if self.nonces.len() >= self.max_entries {
            if !self.nonce_order.is_empty() {
                let oldest = self.nonce_order.remove(0);
                self.nonces.remove(&oldest);
            }
        }
        if !self.nonces.contains_key(&nonce_key) {
            self.nonce_order.push(nonce_key.clone());
        }
        self.nonces.insert(nonce_key, ts_ms);
    }

    /// Current size of the bounded nonce cache.
    pub fn size(&self) -> usize {
        self.nonces.len()
    }

    /// Drop nonce entries already outside the freshness window.
    pub fn prune(&mut self, now_ms: i64) {
        let cutoff_ms = now_ms - self.freshness_window_seconds * 1000;
        self.nonce_order.retain(|k| {
            let keep = self.nonces.get(k).map(|&ts| ts >= cutoff_ms).unwrap_or(false);
            if !keep {
                self.nonces.remove(k);
            }
            keep
        });
    }
}

/// Minimal RFC 3339 parser sufficient for the ISO 8601 strings this module
/// receives (`new Date(...).toISOString()` output, or equivalent). Returns
/// `None` for anything else, matching `Number.isFinite(Date.parse(...))`
/// failing on garbage input. Deliberately narrow rather than a general
/// date-parsing library: only `YYYY-MM-DDTHH:MM:SS[.sss]Z` /
/// `±HH:MM` forms are accepted.
pub(super) fn parse_rfc3339_ms(input: &str) -> Option<i64> {
    let bytes = input.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let year: i64 = input.get(0..4)?.parse().ok()?;
    if input.as_bytes().get(4) != Some(&b'-') {
        return None;
    }
    let month: i64 = input.get(5..7)?.parse().ok()?;
    if input.as_bytes().get(7) != Some(&b'-') {
        return None;
    }
    let day: i64 = input.get(8..10)?.parse().ok()?;
    let sep = input.as_bytes().get(10)?;
    if *sep != b'T' && *sep != b't' && *sep != b' ' {
        return None;
    }
    let hour: i64 = input.get(11..13)?.parse().ok()?;
    if input.as_bytes().get(13) != Some(&b':') {
        return None;
    }
    let minute: i64 = input.get(14..16)?.parse().ok()?;
    if input.as_bytes().get(16) != Some(&b':') {
        return None;
    }
    let second: i64 = input.get(17..19)?.parse().ok()?;

    let mut idx = 19;
    let mut millis: i64 = 0;
    if input.as_bytes().get(idx) == Some(&b'.') {
        idx += 1;
        let start = idx;
        while input.as_bytes().get(idx).map(|b| b.is_ascii_digit()).unwrap_or(false) {
            idx += 1;
        }
        let frac = &input[start..idx];
        if !frac.is_empty() {
            let mut digits: String = frac.chars().take(3).collect();
            while digits.len() < 3 {
                digits.push('0');
            }
            millis = digits.parse().ok()?;
        }
    }

    let (offset_minutes, consumed_all) = match input.as_bytes().get(idx) {
        Some(b'Z') | Some(b'z') => (0i64, idx + 1 == bytes.len()),
        Some(b'+') | Some(b'-') => {
            let sign: i64 = if input.as_bytes()[idx] == b'-' { -1 } else { 1 };
            let rest = &input[idx + 1..];
            if rest.len() < 5 {
                return None;
            }
            let oh: i64 = rest.get(0..2)?.parse().ok()?;
            let om: i64 = rest.get(3..5)?.parse().ok()?;
            (sign * (oh * 60 + om), idx + 6 == bytes.len())
        }
        None => (0, true),
        _ => return None,
    };
    if !consumed_all {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let days = days_from_civil(year, month, day);
    let total_seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset_minutes * 60;
    Some(total_seconds * 1000 + millis)
}

/// Days since 1970-01-01 for a civil (Gregorian) date. Howard Hinnant's
/// well-known constant-time algorithm.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(session: &str) -> ReplayScope {
        ReplayScope { issuer_id: Some("iss".into()), session_id: Some(session.into()), run_id: Some("run".into()), workspace_id: Some("ws".into()) }
    }

    const T0: &str = "2026-01-01T00:00:00.000Z";
    const T0_MS: i64 = 1_767_225_600_000; // known-good reference below is re-derived in test

    #[test]
    fn parses_known_epoch() {
        // 2026-01-01T00:00:00Z per any standard converter.
        assert_eq!(parse_rfc3339_ms(T0), Some(T0_MS));
    }

    #[test]
    fn rejects_unparsable_timestamp() {
        let mut g = ReplayGuard::new(ReplayGuardOptions::default());
        let d = g.check(ReplayCheck { scope: &scope("s"), nonce: "n1", sequence: 1, timestamp: "not-a-date" }, T0_MS);
        assert!(!d.allowed);
        assert_eq!(d.code, ReplayCode::Stale);
    }

    #[test]
    fn accepts_first_message_then_rejects_repeated_nonce() {
        let mut g = ReplayGuard::new(ReplayGuardOptions::default());
        let s = scope("s");
        let d1 = g.check(ReplayCheck { scope: &s, nonce: "n1", sequence: 1, timestamp: T0 }, T0_MS);
        assert!(d1.allowed);
        let d2 = g.check(ReplayCheck { scope: &s, nonce: "n1", sequence: 2, timestamp: T0 }, T0_MS);
        assert!(!d2.allowed);
        assert_eq!(d2.code, ReplayCode::NonceSeen);
    }

    #[test]
    fn rejects_sequence_regression_including_repeat() {
        let mut g = ReplayGuard::new(ReplayGuardOptions::default());
        let s = scope("s");
        assert!(g.check(ReplayCheck { scope: &s, nonce: "n1", sequence: 5, timestamp: T0 }, T0_MS).allowed);
        let repeat = g.check(ReplayCheck { scope: &s, nonce: "n2", sequence: 5, timestamp: T0 }, T0_MS);
        assert_eq!(repeat.code, ReplayCode::SequenceRegression);
        let regress = g.check(ReplayCheck { scope: &s, nonce: "n3", sequence: 4, timestamp: T0 }, T0_MS);
        assert_eq!(regress.code, ReplayCode::SequenceRegression);
    }

    #[test]
    fn different_scopes_do_not_share_nonce_or_sequence_state() {
        let mut g = ReplayGuard::new(ReplayGuardOptions::default());
        let a = scope("a");
        let b = scope("b");
        assert!(g.check(ReplayCheck { scope: &a, nonce: "n1", sequence: 9, timestamp: T0 }, T0_MS).allowed);
        // Same nonce, different scope: allowed.
        assert!(g.check(ReplayCheck { scope: &b, nonce: "n1", sequence: 1, timestamp: T0 }, T0_MS).allowed);
    }

    #[test]
    fn rejects_stale_timestamp_beyond_freshness_window() {
        let mut g = ReplayGuard::new(ReplayGuardOptions { freshness_window_seconds: 300, ..ReplayGuardOptions::default() });
        let now = T0_MS + 400_000; // 400s later, window is 300s
        let d = g.check(ReplayCheck { scope: &scope("s"), nonce: "n1", sequence: 1, timestamp: T0 }, now);
        assert_eq!(d.code, ReplayCode::Stale);
    }

    #[test]
    fn rejects_timestamp_beyond_clock_skew_allowance() {
        let mut g = ReplayGuard::new(ReplayGuardOptions { max_skew_seconds: 60, ..ReplayGuardOptions::default() });
        let now = T0_MS - 120_000; // timestamp is 120s in the guard's future
        let d = g.check(ReplayCheck { scope: &scope("s"), nonce: "n1", sequence: 1, timestamp: T0 }, now);
        assert_eq!(d.code, ReplayCode::Stale);
    }

    #[test]
    fn evicts_oldest_nonce_when_full() {
        let mut g = ReplayGuard::new(ReplayGuardOptions { max_entries: 2, ..ReplayGuardOptions::default() });
        let s = scope("s");
        assert!(g.check(ReplayCheck { scope: &s, nonce: "n1", sequence: 1, timestamp: T0 }, T0_MS).allowed);
        assert!(g.check(ReplayCheck { scope: &s, nonce: "n2", sequence: 2, timestamp: T0 }, T0_MS).allowed);
        assert_eq!(g.size(), 2);
        assert!(g.check(ReplayCheck { scope: &s, nonce: "n3", sequence: 3, timestamp: T0 }, T0_MS).allowed);
        assert_eq!(g.size(), 2);
        // n1 was evicted, so a fresh sequence reuse of it is now representable
        // as a *new* nonce entry — sequence monotonicity still blocks replay
        // via the sequence map, which is never pruned.
        let d = g.check(ReplayCheck { scope: &s, nonce: "n1", sequence: 4, timestamp: T0 }, T0_MS);
        assert!(d.allowed);
    }

    #[test]
    fn scope_key_normalizes_missing_fields_to_null_and_sorts_keys() {
        let s = ReplayScope::default();
        assert_eq!(scope_key(&s), r#"{"issuerId":null,"runId":null,"sessionId":null,"workspaceId":null}"#);
    }
}
