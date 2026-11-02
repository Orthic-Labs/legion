//! UTC date and time helpers for `legion daily` (no chrono dependency).
use std::time::{SystemTime, UNIX_EPOCH};

pub const DAY_SECONDS: i64 = 86_400;

pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Days since 1970-01-01 for a proleptic Gregorian civil date.
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Civil date (year, month, day) for a count of days since 1970-01-01.
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Epoch seconds for `YYYY-MM-DDTHH:MM:SS[.fraction][Z|+hh:mm|-hh:mm]`.
pub fn parse_rfc3339(text: &str) -> Option<i64> {
    let bytes = text.trim().as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let number = |from: usize, to: usize| -> Option<i64> {
        std::str::from_utf8(bytes.get(from..to)?)
            .ok()?
            .parse::<i64>()
            .ok()
    };
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || !(bytes[10] == b'T' || bytes[10] == b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let mut epoch =
        days_from_civil(year, month, day) * DAY_SECONDS + hour * 3600 + minute * 60 + second;
    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        while bytes.get(index).is_some_and(|byte| byte.is_ascii_digit()) {
            index += 1;
        }
    }
    match bytes.get(index) {
        None | Some(b'Z') | Some(b'z') => {}
        Some(&sign) if sign == b'+' || sign == b'-' => {
            let offset_hours = number(index + 1, index + 3)?;
            let offset_minutes = number(index + 4, index + 6).unwrap_or(0);
            let offset = offset_hours * 3600 + offset_minutes * 60;
            if sign == b'+' {
                epoch -= offset;
            } else {
                epoch += offset;
            }
        }
        _ => return None,
    }
    Some(epoch)
}

/// `YYYY-MM-DDTHH:MM:SSZ` for epoch seconds.
pub fn rfc3339(epoch: i64) -> String {
    let days = epoch.div_euclid(DAY_SECONDS);
    let seconds = epoch.rem_euclid(DAY_SECONDS);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

/// `YYYY-MM-DD` (UTC) for epoch seconds.
pub fn date_of(epoch: i64) -> String {
    let (year, month, day) = civil_from_days(epoch.div_euclid(DAY_SECONDS));
    format!("{year:04}-{month:02}-{day:02}")
}

/// `HH:MMZ` (UTC) for epoch seconds.
pub fn clock_of(epoch: i64) -> String {
    let seconds = epoch.rem_euclid(DAY_SECONDS);
    format!("{:02}:{:02}Z", seconds / 3600, (seconds % 3600) / 60)
}

fn days_of_date(date: &str) -> Option<i64> {
    let mut parts = date.split('-');
    let year = parts.next()?.parse::<i64>().ok()?;
    let month = parts.next()?.parse::<i64>().ok()?;
    let day = parts.next()?.parse::<i64>().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

/// The date `days` after (or before, when negative) `date`.
pub fn shift_date(date: &str, days: i64) -> Option<String> {
    let (year, month, day) = civil_from_days(days_of_date(date)? + days);
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

/// Seconds for `90s`, `45m`, `24h`, `2d` or `1w`.
pub fn parse_duration(text: &str) -> Option<i64> {
    let trimmed = text.trim();
    let unit = trimmed.chars().last()?;
    let digits = &trimmed[..trimmed.len() - unit.len_utf8()];
    let value = digits.parse::<i64>().ok()?;
    if value <= 0 {
        return None;
    }
    let factor = match unit.to_ascii_lowercase() {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => DAY_SECONDS,
        'w' => 7 * DAY_SECONDS,
        _ => return None,
    };
    value.checked_mul(factor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_known_instants() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-11-02T14:06:34Z"), Some(1_793_628_394));
        assert_eq!(
            parse_rfc3339("2026-11-02T14:06:34.681Z"),
            Some(1_793_628_394)
        );
        assert_eq!(
            parse_rfc3339("2026-11-02T13:04:21.8236972Z"),
            Some(1_793_624_661)
        );
        assert_eq!(parse_rfc3339("2024-02-29T23:59:59Z"), Some(1_709_251_199));
        assert_eq!(
            parse_rfc3339("2026-11-02T14:06:34+05:30"),
            Some(1_793_608_594)
        );
        assert_eq!(rfc3339(1_793_628_394), "2026-11-02T14:06:34Z");
        assert_eq!(date_of(1_793_577_600), "2026-11-02");
        assert_eq!(date_of(1_793_577_599), "2026-11-01");
        assert_eq!(clock_of(1_793_628_394), "14:06Z");
    }

    #[test]
    fn rejects_malformed_timestamps() {
        assert_eq!(parse_rfc3339(""), None);
        assert_eq!(parse_rfc3339("2026-11-02"), None);
        assert_eq!(parse_rfc3339("2026-13-02T00:00:00Z"), None);
        assert_eq!(parse_rfc3339("2026-11-02T25:00:00Z"), None);
        assert_eq!(parse_rfc3339("2026-11-02T00:00:00Q"), None);
    }

    #[test]
    fn shifts_and_measures_dates() {
        assert_eq!(shift_date("2026-11-02", -2).as_deref(), Some("2026-10-31"));
        assert_eq!(shift_date("2026-02-28", 1).as_deref(), Some("2026-03-01"));
        assert_eq!(shift_date("nope", 1), None);
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("24h"), Some(86_400));
        assert_eq!(parse_duration("2d"), Some(172_800));
        assert_eq!(parse_duration("90m"), Some(5_400));
        assert_eq!(parse_duration("1w"), Some(604_800));
        assert_eq!(parse_duration("0h"), None);
        assert_eq!(parse_duration("24"), None);
        assert_eq!(parse_duration("h"), None);
        assert_eq!(parse_duration(""), None);
    }
}
