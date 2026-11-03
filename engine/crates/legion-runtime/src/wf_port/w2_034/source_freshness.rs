//! Port of `skills/seo/scripts/source_freshness.py`.
//!
//! Fully ported: `assess()` is a pure function of the parsed `official-sources.json`
//! register and an as-of date — it fails closed when any registered source is overdue
//! for review or has an invalid `checked_at`/`review_interval_days`. Reading
//! `config/official-sources.json` from disk is left to the caller (host IO); this module
//! takes the already-parsed JSON `Value` register, matching the Python `load()` output.

use serde::Serialize;
use serde_json::Value;

use super::date_math::Date;

/// One row in the `due` or `current` lists, matching the Python dict shape built in
/// `assess()`: `{id, authority, url, checked_at, next_review, applies_to}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SourceRow {
    pub id: String,
    pub authority: Value,
    pub url: Value,
    pub checked_at: String,
    pub next_review: String,
    pub applies_to: Vec<Value>,
}

/// One row in the `invalid` list, matching `{'id': src.get('id'), 'error': str(exc)}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InvalidRow {
    pub id: Option<String>,
    pub error: String,
}

/// The full `assess()` result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FreshnessReport {
    pub status: &'static str,
    pub as_of: String,
    pub due: Vec<SourceRow>,
    pub invalid: Vec<InvalidRow>,
    pub current_count: usize,
    pub trigger_rule: Value,
}

/// Reads `src["id"]` as a string when present, matching Python's `src.get('id')` used in
/// the invalid-row error dict (which can hold `None`).
fn opt_id(src: &Value) -> Option<String> {
    src.get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Port of `assess(as_of=None)`. `as_of` mirrors the Python default of "today" — the
/// caller supplies it explicitly since this crate has no calendar/clock dependency.
/// `register` is the parsed `official-sources.json` document (the Python `load()` return
/// value); `register["sources"]` is iterated exactly like `load().get('sources', [])`,
/// and `register["trigger_rule"]` is copied through exactly like `load().get('trigger_rule')`.
pub fn assess(register: &Value, as_of: Date) -> FreshnessReport {
    let sources = register
        .get("sources")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut due = Vec::new();
    let mut current = Vec::new();
    let mut invalid = Vec::new();

    for src in &sources {
        let checked_at_str = src.get("checked_at").and_then(|v| v.as_str());
        let interval = src.get("review_interval_days").and_then(value_as_i64);

        let (checked_at_str, interval) = match (checked_at_str, interval) {
            (Some(c), Some(i)) => (c, i),
            _ => {
                invalid.push(InvalidRow {
                    id: opt_id(src),
                    error: "missing or invalid 'checked_at'/'review_interval_days'".to_string(),
                });
                continue;
            }
        };

        let checked = match Date::parse(checked_at_str) {
            Ok(d) => d,
            Err(e) => {
                invalid.push(InvalidRow {
                    id: opt_id(src),
                    error: e.to_string(),
                });
                continue;
            }
        };

        // Fields the Python code accesses with `src['id']`/`src['authority']`/`src['url']`
        // (a `KeyError` there would be an unhandled Python exception, not caught by the
        // `except Exception` around the date/interval parse); a missing/absent key here
        // is treated the same way — as an invalid row — rather than panicking.
        let (Some(id), Some(authority), Some(url)) = (
            src.get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            src.get("authority").cloned(),
            src.get("url").cloned(),
        ) else {
            invalid.push(InvalidRow {
                id: opt_id(src),
                error: "missing required field: id/authority/url".to_string(),
            });
            continue;
        };

        let next_review = checked.add_days(interval);
        let row = SourceRow {
            id,
            authority,
            url,
            checked_at: checked_at_str.to_string(),
            next_review: next_review.isoformat(),
            applies_to: src
                .get("applies_to")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default(),
        };

        if as_of > next_review {
            due.push(row);
        } else {
            current.push(row);
        }
    }

    let status = if !due.is_empty() || !invalid.is_empty() {
        "fail"
    } else {
        "pass"
    };

    FreshnessReport {
        status,
        as_of: as_of.isoformat(),
        due,
        invalid,
        current_count: current.len(),
        trigger_rule: register.get("trigger_rule").cloned().unwrap_or(Value::Null),
    }
}

fn value_as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse::<i64>().ok(),
        _ => None,
    }
}

/// Exit-code mapping matching `main()`: `0` when `status == "pass"`, else `1`.
pub fn exit_code(report: &FreshnessReport) -> i32 {
    if report.status == "pass" {
        0
    } else {
        1
    }
}
