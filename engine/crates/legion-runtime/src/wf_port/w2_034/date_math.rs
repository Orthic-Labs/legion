//! Minimal, dependency-free civil-date arithmetic used by the `source_freshness` port.
//!
//! No `chrono`/`time` crate is a dependency of this crate, and this crate is read-only
//! for `Cargo.toml`, so date handling here uses Howard Hinnant's well-known
//! `days_from_civil` / `civil_from_days` algorithms (proleptic Gregorian, valid across
//! the full range Python's `datetime.date` supports for realistic years).

/// A plain calendar date (year-month-day), Gregorian, no timezone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub year: i64,
    pub month: u32,
    pub day: u32,
}

/// Error returned when a date string does not match `YYYY-MM-DD` or names an
/// impossible calendar date, mirroring Python's `datetime.strptime(...).date()`
/// raising `ValueError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid date: {0}")]
pub struct DateParseError(pub String);

impl Date {
    /// Days since the epoch 1970-01-01, using Hinnant's `days_from_civil`.
    fn to_days(self) -> i64 {
        let y = if self.month <= 2 {
            self.year - 1
        } else {
            self.year
        };
        let era = (if y >= 0 { y } else { y - 399 }) / 400;
        let yoe = y - era * 400; // [0, 399]
        let mp = (self.month as i64 + 9) % 12; // [0, 11]
        let doy = (153 * mp + 2) / 5 + self.day as i64 - 1; // [0, 365]
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
        era * 146097 + doe - 719468
    }

    /// Inverse of `to_days`.
    fn from_days(days: i64) -> Date {
        let z = days + 719468;
        let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
        let doe = z - era * 146097; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
        let year = if month <= 2 { y + 1 } else { y };
        Date { year, month, day }
    }

    /// Parses `YYYY-MM-DD`, matching `datetime.strptime(s, '%Y-%m-%d').date()`.
    pub fn parse(s: &str) -> Result<Date, DateParseError> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 3 {
            return Err(DateParseError(s.to_string()));
        }
        let year: i64 = parts[0].parse().map_err(|_| DateParseError(s.to_string()))?;
        let month: u32 = parts[1].parse().map_err(|_| DateParseError(s.to_string()))?;
        let day: u32 = parts[2].parse().map_err(|_| DateParseError(s.to_string()))?;
        if !(1..=12).contains(&month) || day == 0 {
            return Err(DateParseError(s.to_string()));
        }
        let candidate = Date { year, month, day };
        // Round-trip through the day-count conversion to reject e.g. day 31 of April.
        if Date::from_days(candidate.to_days()) != candidate {
            return Err(DateParseError(s.to_string()));
        }
        Ok(candidate)
    }

    /// Adds `days` (may be negative) to this date.
    pub fn add_days(self, days: i64) -> Date {
        Date::from_days(self.to_days() + days)
    }

    /// `YYYY-MM-DD`, matching Python's `date.isoformat()`.
    pub fn isoformat(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.isoformat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_round_trip() {
        let d = Date::parse("2026-09-23").unwrap();
        assert_eq!(d, Date { year: 2026, month: 9, day: 23 });
        assert_eq!(d.isoformat(), "2026-09-23");
    }

    #[test]
    fn rejects_impossible_date() {
        assert!(Date::parse("2026-04-31").is_err());
        assert!(Date::parse("2026-13-01").is_err());
        assert!(Date::parse("not-a-date").is_err());
    }

    #[test]
    fn add_days_crosses_month_and_year_boundaries() {
        let d = Date::parse("2026-01-20").unwrap();
        assert_eq!(d.add_days(15).isoformat(), "2026-02-04");
        let d2 = Date::parse("2026-12-20").unwrap();
        assert_eq!(d2.add_days(15).isoformat(), "2027-01-04");
    }

    #[test]
    fn ordering_matches_calendar_order() {
        let a = Date::parse("2026-01-01").unwrap();
        let b = Date::parse("2026-01-02").unwrap();
        assert!(a < b);
        assert!(b > a);
    }
}
