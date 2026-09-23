//! Minimal ISO-8601 calendar-date helpers used by the wf025 port
//! (`gap_critic.py`'s `_iso_age_days`, and `ledger.py`/`manifest.py`'s date
//! validation). No date/time crate is in this crate's `Cargo.lock`, so this
//! is a small, dependency-free proleptic-Gregorian day-count implementation
//! (Howard Hinnant's `days_from_civil`), plus a `SystemTime`-derived "today".

use std::time::{SystemTime, UNIX_EPOCH};

/// Parses a strict `YYYY-MM-DD` string into (year, month, day), rejecting
/// anything Python's `datetime.date.fromisoformat` would reject: wrong
/// shape, non-numeric fields, month out of 1..=12, or day out of range for
/// that month/year (leap years included).
pub fn parse_iso_date(value: &str) -> Option<(i64, u32, u32)> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year: i64 = value.get(0..4)?.parse().ok()?;
    let month: u32 = value.get(5..7)?.parse().ok()?;
    let day: u32 = value.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    let max_day = days_in_month(year, month)?;
    if day < 1 || day > max_day {
        return None;
    }
    Some((year, month, day))
}

/// `true` when `value` is a valid ISO calendar date (mirrors `ledger.py`'s
/// `_date()` and `gap_critic.py`'s try/except around `date.fromisoformat`).
pub fn is_valid_iso_date(value: &str) -> bool {
    parse_iso_date(value).is_some()
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: u32) -> Option<u32> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => return None,
    })
}

/// Days since the epoch (1970-01-01 = 0) for a proleptic-Gregorian civil
/// date, via Howard Hinnant's `days_from_civil` algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64; // [0, 399]
    let mp = (m as i64 + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Today's epoch day, derived from the system clock (UTC). Mirrors Python's
/// `datetime.date.today()` closely enough for age-in-days comparisons; it
/// is not meant to be timezone-exact.
pub fn today_epoch_day() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    secs.div_euclid(86_400)
}

/// `(today - value).days`, or `None` when `value` is not a valid ISO date
/// (mirrors `gap_critic.py`'s `_iso_age_days`).
pub fn iso_age_days(value: &str) -> Option<i64> {
    let (y, m, d) = parse_iso_date(value)?;
    Some(today_epoch_day() - days_from_civil(y, m, d))
}

/// Inverse of `days_from_civil`: the proleptic-Gregorian (y, m, d) for a
/// given epoch day (Howard Hinnant's `civil_from_days`).
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Today's date as an ISO `YYYY-MM-DD` string (mirrors Python's
/// `datetime.date.today().isoformat()`).
pub fn today_iso_date() -> String {
    let (y, m, d) = civil_from_days(today_epoch_day());
    format!("{y:04}-{m:02}-{d:02}")
}

/// The proleptic-Gregorian (y, m, d) for a Unix epoch timestamp in seconds
/// (UTC), used by `manifest.rs`'s `utc_now()`.
pub(crate) fn civil_from_epoch_secs(secs: i64) -> (i64, u32, u32) {
    civil_from_days(secs.div_euclid(86_400))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_calendar_dates() {
        assert!(is_valid_iso_date("2024-02-29")); // leap year
        assert!(!is_valid_iso_date("2023-02-29")); // not a leap year
        assert!(!is_valid_iso_date("2024-13-01"));
        assert!(!is_valid_iso_date("2024-00-01"));
        assert!(!is_valid_iso_date("not-a-date"));
        assert!(!is_valid_iso_date("2024-1-1"));
    }

    #[test]
    fn epoch_day_matches_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
    }

    #[test]
    fn age_days_is_none_for_invalid_dates() {
        assert_eq!(iso_age_days("garbage"), None);
    }

    #[test]
    fn age_days_is_zero_or_positive_for_today_or_past() {
        assert!(iso_age_days("1970-01-02").unwrap() > 0);
    }

    #[test]
    fn civil_from_days_round_trips_through_days_from_civil() {
        for (y, m, d) in [(1970, 1, 1), (2000, 3, 1), (2024, 2, 29), (1999, 12, 31)] {
            let day = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(day), (y, m, d));
        }
    }

    #[test]
    fn today_iso_date_is_well_formed() {
        let today = today_iso_date();
        assert!(is_valid_iso_date(&today), "{today}");
    }
}
