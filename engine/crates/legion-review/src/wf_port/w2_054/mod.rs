//! Chunk w2_054 — Rust port of `src/lib/review/{render_debate,
//! review_evidence, room_protocol, synthesizer, test_input}.py`.
//!
//! `test_input.py` is not ported: it is a fixture ("Sample code change for
//! council smoke test") used as sample input for other review-pipeline
//! smoke tests, not review logic. There is no behaviour to port.
//!
//! `synthesizer`, `render_debate`, `review_evidence`, and `room_protocol`
//! are faithful ports of the corresponding Python modules' pure/typed logic.
//! See each module's doc comment for exact scope and any gap.

pub mod render_debate;
pub mod review_evidence;
pub mod room_protocol;
pub mod synthesizer;

/// RFC 3339 / ISO-8601 UTC timestamp with second precision, e.g.
/// `2026-09-23T12:34:56+00:00` — matches Python's
/// `datetime.now(timezone.utc).isoformat()` output shape (offset form,
/// not a trailing `Z`).
///
/// Implemented from `std::time::SystemTime` with no new crate dependency,
/// using Howard Hinnant's `civil_from_days` algorithm for the calendar
/// conversion.
pub(crate) fn now_iso() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00"
    )
}

/// Days-since-epoch (1970-01-01) to (year, month, day). Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn civil_from_days_known_date() {
        // 2026-09-23 is 20,719 days after epoch.
        let days = 20_719;
        assert_eq!(civil_from_days(days), (2026, 9, 23));
    }

    #[test]
    fn now_iso_shape() {
        let ts = now_iso();
        assert_eq!(ts.len(), 25);
        assert!(ts.contains('T'));
        assert!(ts.ends_with("+00:00"));
    }
}
