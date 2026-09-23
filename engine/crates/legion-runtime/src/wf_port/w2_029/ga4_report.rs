//! Port of `skills/seo/scripts/ga4_report.py`.
//!
//! The GA4 `BetaAnalyticsDataClient` calls are not ported — this crate has
//! no GA4/OAuth dependency and stays at the pure-transform edge. What is
//! ported, faithfully: `_resolve_property`, the
//! `datetime.now() - timedelta(days=...)` date-range computation (as pure
//! civil-calendar arithmetic, since this crate carries no date/time
//! crate), and the totals/slimming logic in `organic_traffic_report`'s
//! totals block and `top_pages_report`.

use serde::Serialize;
use serde_json::Value;

/// Mirrors Python `_resolve_property(property_id)`.
pub fn resolve_property(property_id: &str) -> String {
    if property_id.is_empty() {
        return String::new();
    }
    if property_id.starts_with("properties/") {
        property_id.to_string()
    } else {
        format!("properties/{property_id}")
    }
}

/// A civil (proleptic Gregorian) calendar date, used only for the pure
/// `days` arithmetic `ga4_report.py` does via `datetime`/`timedelta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CivilDate {
    pub year: i64,
    pub month: u32,
    pub day: u32,
}

impl CivilDate {
    pub fn new(year: i64, month: u32, day: u32) -> Self {
        Self { year, month, day }
    }

    /// Days since the civil epoch (0000-03-01), per Howard Hinnant's
    /// `days_from_civil` algorithm — used only to implement `- N days`.
    fn to_days(self) -> i64 {
        let y = if self.month <= 2 {
            self.year - 1
        } else {
            self.year
        };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = (y - era * 400) as i64; // [0, 399]
        let mp = (self.month as i64 + 9) % 12; // [0, 11]
        let doy = (153 * mp + 2) / 5 + self.day as i64 - 1; // [0, 365]
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
        era * 146097 + doe - 719468
    }

    fn from_days(z: i64) -> Self {
        let z = z + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = z - era * 146097; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
        let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
        let year = if month <= 2 { y + 1 } else { y };
        CivilDate { year, month, day }
    }

    /// Mirrors `date - timedelta(days=n)`.
    pub fn minus_days(self, n: i64) -> Self {
        Self::from_days(self.to_days() - n)
    }

    /// Mirrors `date.strftime("%Y-%m-%d")`.
    pub fn to_iso(self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DateRange {
    pub start: String,
    pub end: String,
}

/// Mirrors the date-range computation shared by `organic_traffic_report`,
/// `device_breakdown`, and `country_breakdown`:
/// `start = today - timedelta(days=days)`, `end = today - timedelta(days=1)`,
/// both formatted `%Y-%m-%d`. `today` is caller-supplied (this crate does
/// not read the system clock).
pub fn date_range(today: CivilDate, days: i64) -> DateRange {
    DateRange {
        start: today.minus_days(days).to_iso(),
        end: today.minus_days(1).to_iso(),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct Totals {
    pub sessions: i64,
    pub users: i64,
    pub pageviews: i64,
    pub avg_daily_sessions: f64,
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// Mirrors the totals block at the end of `organic_traffic_report`:
/// summed from each daily row's `sessions`/`users`/`pageviews`, with
/// `avg_daily_sessions = round(total_sessions / len(daily_data), 1)`.
/// Returns `None` when `daily_data` is empty, matching Python's
/// `if result["daily_data"]:` guard (an empty `{}` totals object).
pub fn compute_totals(daily_sessions: &[i64], daily_users: &[i64], daily_pageviews: &[i64]) -> Option<Totals> {
    if daily_sessions.is_empty() {
        return None;
    }
    let total_sessions: i64 = daily_sessions.iter().sum();
    let total_users: i64 = daily_users.iter().sum();
    let total_pageviews: i64 = daily_pageviews.iter().sum();
    Some(Totals {
        sessions: total_sessions,
        users: total_users,
        pageviews: total_pageviews,
        avg_daily_sessions: round1(total_sessions as f64 / daily_sessions.len() as f64),
    })
}

/// Mirrors `top_pages_report()`'s slimming of an already-built
/// `organic_traffic_report()` result down to just the pages view. `report`
/// is the JSON object `organic_traffic_report` would have returned;
/// `property_id` is passed through as-is (Python re-uses its own
/// argument, not the report's `property` field).
pub fn slim_to_top_pages(property_id: &str, report: &Value) -> Value {
    let total_organic_sessions = report
        .get("totals")
        .and_then(|t| t.get("sessions"))
        .cloned()
        .unwrap_or(Value::from(0));
    serde_json::json!({
        "property": property_id,
        "report": "top_organic_pages",
        "date_range": report.get("date_range").cloned().unwrap_or(Value::Null),
        "pages": report.get("top_pages").cloned().unwrap_or_else(|| Value::Array(vec![])),
        "total_organic_sessions": total_organic_sessions,
        "quota_tokens_used": report.get("quota_tokens_used").cloned().unwrap_or(Value::Null),
        "error": report.get("error").cloned().unwrap_or(Value::Null),
    })
}
