//! UTC helpers (no chrono). Offsets are not applied: every source writes `Z` times.
use std::time::{SystemTime, UNIX_EPOCH};

pub const DAY: i64 = 86_400;

fn secs(at: SystemTime) -> i64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

pub fn now() -> i64 {
    secs(SystemTime::now())
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let (era, doy) = (
        y.div_euclid(400),
        (153 * ((month + 9) % 12) + 2) / 5 + day - 1,
    );
    let yoe = y - era * 400;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, doy - (153 * mp + 2) / 5 + 1)
}

/// A file's modification time in epoch seconds (0 when unknown).
pub fn modified(meta: &std::fs::Metadata) -> i64 {
    meta.modified().map_or(0, secs)
}

/// Epoch seconds for `YYYY-MM-DDTHH:MM:SS[...]`.
pub fn parse(text: &str) -> Option<i64> {
    let n = |from: usize, to: usize| -> Option<i64> { text.get(from..to)?.parse().ok() };
    let days = days_from_civil(n(0, 4)?, n(5, 7)?, n(8, 10)?);
    Some(days * DAY + n(11, 13)? * 3600 + n(14, 16)? * 60 + n(17, 19)?)
}

/// `YYYY-MM-DD`.
pub fn date(epoch: i64) -> String {
    let (year, month, day) = civil_from_days(epoch.div_euclid(DAY));
    format!("{year:04}-{month:02}-{day:02}")
}

/// `YYYY-MM-DD HH:MMZ`.
pub fn stamp(epoch: i64) -> String {
    let minutes = epoch.rem_euclid(DAY) / 60;
    format!("{} {:02}:{:02}Z", date(epoch), minutes / 60, minutes % 60)
}

/// Seconds for `90m`, `24h`, `2d` or `1w`.
pub fn duration(text: &str) -> Option<i64> {
    let unit = text.trim().chars().last()?;
    let value: i64 = text.trim().strip_suffix(unit)?.parse().ok()?;
    let factor = match unit {
        'm' => 60,
        'h' => 3600,
        'd' => DAY,
        'w' => 7 * DAY,
        _ => return None,
    };
    (value > 0).then_some(value * factor)
}
