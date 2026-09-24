//! Minimal dependency-free ISO-8601 UTC millisecond timestamp helpers,
//! matching the pattern already used at
//! `crate::wf_port::wf006::capability_store::{parse_iso_millis, stamp}`
//! (Howard Hinnant's civil_from_days/days_from_civil algorithm). Shared by
//! `current_user_risk_acceptance` for the TTL/freshness checks ported from
//! `src/lib/verification/arcane/current-user-risk-acceptance.mjs`
//! (`Date.parse`/`new Date(...).toISOString()`).

/// Howard Hinnant's civil_from_days algorithm.
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

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = ((if m > 2 { m - 3 } else { m + 9 }) as u64) % 12;
    let doy = (153 * mp + 2) / 5 + (d - 1) as u64;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Mirrors JS `new Date(ms).toISOString()`.
pub fn stamp(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = day_secs / 3600;
    let mm = (day_secs % 3600) / 60;
    let ss = day_secs % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

/// Mirrors JS `Date.parse(s)` for the `YYYY-MM-DDTHH:MM:SS[.mmm]Z` shape
/// this module always produces/consumes. Returns `None` (mirroring
/// `Number.isFinite(NaN) === false`) on anything else.
pub fn parse_iso_millis(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut date_parts = date.split('-');
    let y: i64 = date_parts.next()?.parse().ok()?;
    let m: i64 = date_parts.next()?.parse().ok()?;
    let d: i64 = date_parts.next()?.parse().ok()?;
    let (time, millis) = match time.split_once('.') {
        Some((t, ms)) => (t, ms.parse::<i64>().ok()?),
        None => (time, 0),
    };
    let mut time_parts = time.split(':');
    let hh: i64 = time_parts.next()?.parse().ok()?;
    let mm: i64 = time_parts.next()?.parse().ok()?;
    let ss: i64 = time_parts.next()?.parse().ok()?;
    let days = days_from_civil(y, m, d);
    Some(((days * 86_400 + hh * 3600 + mm * 60 + ss) * 1000) + millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let ms = 1_735_689_600_123; // arbitrary
        let s = stamp(ms);
        assert_eq!(parse_iso_millis(&s), Some(ms));
    }
}
