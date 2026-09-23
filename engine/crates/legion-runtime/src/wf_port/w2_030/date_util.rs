//! Dependency-free Gregorian calendar arithmetic used to port `datetime.now() -
//! timedelta(days=N)` from `gsc_query.py` / `gsc_query_v2.py` without adding a date/time crate
//! dependency (none is in `legion-runtime`'s `Cargo.toml`; see the report's dependency-patch
//! note). Uses Howard Hinnant's well-known `days_from_civil` / `civil_from_days` algorithms,
//! which are exact for the proleptic Gregorian calendar.

/// Days since the Unix epoch (1970-01-01) for a Gregorian (y, m, d) date. `m` is 1-12, `d` is
/// 1-31.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64; // [0, 399]
    let mp = (m + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`]: converts a day count since the Unix epoch back to (year,
/// month, day).
pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Formats (y, m, d) as `YYYY-MM-DD`, matching python's `strftime("%Y-%m-%d")`.
pub fn format_ymd(y: i64, m: i64, d: i64) -> String {
    format!("{y:04}-{m:02}-{d:02}")
}

/// `(now - timedelta(days=n))` formatted as `YYYY-MM-DD`.
pub fn days_before(now: (i64, i64, i64), n: i64) -> String {
    let (y, m, d) = now;
    let epoch_day = days_from_civil(y, m, d) - n;
    let (y2, m2, d2) = civil_from_days(epoch_day);
    format_ymd(y2, m2, d2)
}

/// Port of the shared `end`/`start` default-date-range computation used by `gsc_query.py`'s
/// `main()` and `gsc_query_v2.py`'s `main()`: `end = end_date or now-3d`, `start = start_date or
/// now-days`.
pub fn default_date_range(
    now: (i64, i64, i64),
    days: i64,
    start_date: Option<&str>,
    end_date: Option<&str>,
) -> (String, String) {
    let end = end_date.map(str::to_string).unwrap_or_else(|| days_before(now, 3));
    let start = start_date.map(str::to_string).unwrap_or_else(|| days_before(now, days));
    (start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_civil_days() {
        for (y, m, d) in [(2026, 1, 1), (2026, 8, 28), (2000, 2, 29), (1970, 1, 1), (2026, 12, 31)] {
            let epoch = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(epoch), (y, m, d));
        }
    }

    #[test]
    fn days_before_crosses_month_boundary() {
        // 2026-08-02 minus 3 days = 2026-07-30
        assert_eq!(days_before((2026, 8, 2), 3), "2026-07-30");
    }

    #[test]
    fn days_before_crosses_year_boundary() {
        assert_eq!(days_before((2026, 1, 2), 5), "2025-12-28");
    }

    #[test]
    fn default_date_range_matches_python_defaults() {
        let (start, end) = default_date_range((2026, 8, 31), 28, None, None);
        assert_eq!(end, "2026-08-28");
        assert_eq!(start, "2026-08-03");
    }

    #[test]
    fn default_date_range_honors_explicit_overrides() {
        let (start, end) = default_date_range((2026, 8, 31), 28, Some("2026-01-01"), Some("2026-01-31"));
        assert_eq!(start, "2026-01-01");
        assert_eq!(end, "2026-01-31");
    }
}
