//! Port of `src/lib/research-core/effect_audit.py`.
//!
//! Reconciles hook-metered effect receipts (a JSON-lines event stream)
//! with the frozen run manifest's recorded usage and budget.

use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};

/// Port of `read_events`: returns `[]` for a missing file, otherwise parses
/// each non-blank line as JSON.
pub fn read_events(path: &Path) -> Result<Vec<Value>, ReadEventsError> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(ReadEventsError::from))
        .collect()
}

#[derive(Debug)]
pub enum ReadEventsError {
    Io(std::io::Error),
    Json(serde_json::Error),
}
impl std::fmt::Display for ReadEventsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadEventsError::Io(e) => write!(f, "{e}"),
            ReadEventsError::Json(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for ReadEventsError {}
impl From<std::io::Error> for ReadEventsError {
    fn from(e: std::io::Error) -> Self {
        ReadEventsError::Io(e)
    }
}
impl From<serde_json::Error> for ReadEventsError {
    fn from(e: serde_json::Error) -> Self {
        ReadEventsError::Json(e)
    }
}

fn str_field<'a>(obj: &'a Value, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Value::as_str)
}

/// Python's `event.get('units', 1)` then `isinstance(units, int)` check.
/// JSON has no distinct int type; we require the value to be an integer
/// (no fractional part) the way `serde_json::Number::as_i64` does, and a
/// JSON `true`/`false` never satisfies Python's `isinstance(x, int)` check
/// here because the events are produced as plain numbers, not booleans, so
/// we simply reject non-numeric or fractional `units`.
fn units_field(event: &Value) -> Option<i64> {
    match event.get("units") {
        None => Some(1),
        Some(Value::Number(n)) => n.as_i64(),
        _ => None,
    }
}

fn usize_from_manifest(usage: &Value, key: &str) -> Option<i64> {
    usage.get(key).and_then(Value::as_i64)
}

/// Faithful port of `audit(manifest_doc, events)`.
pub fn audit(manifest_doc: &Value, events: &[Value]) -> Value {
    let mut external: i64 = 0;
    let mut workers_started: i64 = 0;
    let mut workers_active: i64 = 0;
    let mut refusals: i64 = 0;
    let mut malformed: Vec<String> = Vec::new();

    for (index, event) in events.iter().enumerate() {
        let event_type = str_field(event, "type");
        if event_type == Some("budget.refused") {
            refusals += 1;
            continue;
        }
        if event_type != Some("budget.consumed") {
            continue;
        }
        let effect = str_field(event, "effect");
        let units = match units_field(event) {
            Some(u) if u > 0 => u,
            _ => {
                malformed.push(format!("event {index}: invalid units"));
                continue;
            }
        };
        match effect {
            Some("external_request") => external += units,
            Some("worker") => {
                let worker_event = str_field(event, "worker_event");
                match worker_event {
                    Some("start") => {
                        workers_started += units;
                        workers_active += units;
                    }
                    Some("finish") => {
                        workers_active -= units;
                        if workers_active < 0 {
                            malformed.push(format!(
                                "event {index}: worker finish without active worker"
                            ));
                        }
                    }
                    _ => {
                        malformed.push(format!("event {index}: invalid worker_event"));
                    }
                }
            }
            other => {
                malformed.push(format!(
                    "event {index}: unknown metered effect {}",
                    python_repr_opt_str(other)
                ));
            }
        }
    }

    let usage = manifest_doc
        .get("usage")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let expected = json!({
        "external_requests": external,
        "workers_started": workers_started,
        "workers_active": workers_active,
    });

    let mut mismatches = Map::new();
    for key in ["external_requests", "workers_started", "workers_active"] {
        let manifest_value = usage.get(key).cloned().unwrap_or(Value::Null);
        let event_value = expected.get(key).cloned().unwrap_or(Value::Null);
        if manifest_value != event_value {
            mismatches.insert(
                key.to_string(),
                json!({"manifest": manifest_value, "events": event_value}),
            );
        }
    }

    let budget = manifest_doc
        .get("budget")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let budget_external = usize_from_manifest(&budget, "external_requests").unwrap_or(0);
    let budget_workers = usize_from_manifest(&budget, "workers").unwrap_or(0);
    let over_external = external > budget_external;
    let over_workers_active = workers_active > budget_workers;
    let over_budget = json!({
        "external_requests": over_external,
        "workers_active": over_workers_active,
    });

    let ok = malformed.is_empty() && mismatches.is_empty() && !over_external && !over_workers_active;

    json!({
        "ok": ok,
        "reason": if ok { "ok" } else { "meter receipts do not reconcile with manifest usage" },
        "event_usage": expected,
        "manifest_usage": usage,
        "mismatches": Value::Object(mismatches),
        "over_budget": over_budget,
        "refusals": refusals,
        "malformed": malformed,
    })
}

/// Python `repr()` of a string uses single quotes (`'mystery'`), unlike
/// Rust's `{:?}` which uses double quotes; `effect!r` on a missing `effect`
/// key (`None`) reprs as the bare word `None`. This reproduces both.
fn python_repr_opt_str(value: Option<&str>) -> String {
    match value {
        Some(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
        None => "None".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_events_reconcile_with_zero_usage() {
        let manifest = json!({
            "usage": {"external_requests": 0, "workers_started": 0, "workers_active": 0},
            "budget": {"external_requests": 5, "workers": 2}
        });
        let result = audit(&manifest, &[]);
        assert_eq!(result["ok"], json!(true));
        assert_eq!(result["reason"], json!("ok"));
        assert_eq!(result["refusals"], json!(0));
        assert_eq!(result["malformed"], json!([]));
    }

    #[test]
    fn counts_external_requests_and_worker_lifecycle() {
        let events = vec![
            json!({"type": "budget.consumed", "effect": "external_request", "units": 2}),
            json!({"type": "budget.consumed", "effect": "worker", "worker_event": "start", "units": 1}),
            json!({"type": "budget.consumed", "effect": "worker", "worker_event": "finish", "units": 1}),
            json!({"type": "budget.refused"}),
        ];
        let manifest = json!({
            "usage": {"external_requests": 2, "workers_started": 1, "workers_active": 0},
            "budget": {"external_requests": 5, "workers": 2}
        });
        let result = audit(&manifest, &events);
        assert_eq!(result["ok"], json!(true));
        assert_eq!(result["refusals"], json!(1));
        assert_eq!(
            result["event_usage"],
            json!({"external_requests": 2, "workers_started": 1, "workers_active": 0})
        );
    }

    #[test]
    fn mismatch_between_manifest_and_events_fails() {
        let events = vec![json!({
            "type": "budget.consumed", "effect": "external_request", "units": 3
        })];
        let manifest = json!({
            "usage": {"external_requests": 1, "workers_started": 0, "workers_active": 0},
            "budget": {"external_requests": 10, "workers": 2}
        });
        let result = audit(&manifest, &events);
        assert_eq!(result["ok"], json!(false));
        assert_eq!(
            result["mismatches"]["external_requests"],
            json!({"manifest": 1, "events": 3})
        );
    }

    #[test]
    fn over_budget_external_requests_fails() {
        let events = vec![json!({
            "type": "budget.consumed", "effect": "external_request", "units": 6
        })];
        let manifest = json!({
            "usage": {"external_requests": 6, "workers_started": 0, "workers_active": 0},
            "budget": {"external_requests": 5, "workers": 2}
        });
        let result = audit(&manifest, &events);
        assert_eq!(result["ok"], json!(false));
        assert_eq!(result["over_budget"]["external_requests"], json!(true));
    }

    #[test]
    fn worker_finish_without_start_is_malformed() {
        let events = vec![json!({
            "type": "budget.consumed", "effect": "worker", "worker_event": "finish", "units": 1
        })];
        let manifest = json!({
            "usage": {"external_requests": 0, "workers_started": 0, "workers_active": -1},
            "budget": {}
        });
        let result = audit(&manifest, &events);
        assert_eq!(result["ok"], json!(false));
        assert_eq!(
            result["malformed"],
            json!(["event 0: worker finish without active worker"])
        );
    }

    #[test]
    fn invalid_units_is_malformed_and_skipped() {
        let events = vec![json!({
            "type": "budget.consumed", "effect": "external_request", "units": 0
        })];
        let manifest = json!({"usage": {}, "budget": {}});
        let result = audit(&manifest, &events);
        assert_eq!(result["malformed"], json!(["event 0: invalid units"]));
        assert_eq!(result["event_usage"]["external_requests"], json!(0));
    }

    #[test]
    fn unknown_effect_is_malformed() {
        let events = vec![json!({
            "type": "budget.consumed", "effect": "mystery", "units": 1
        })];
        let manifest = json!({"usage": {}, "budget": {}});
        let result = audit(&manifest, &events);
        assert_eq!(
            result["malformed"],
            json!(["event 0: unknown metered effect 'mystery'"])
        );
    }

    #[test]
    fn ignores_events_of_other_types() {
        let events = vec![json!({"type": "something.else"})];
        // effect_audit.py lines 47-58 build `mismatches` from
        // `usage.get(key) != value`: an absent manifest key compares as
        // `None != 0`, which counts as a mismatch. The manifest usage must
        // carry the expected zeros for `ok` to come back true here.
        let manifest = json!({
            "usage": {"external_requests": 0, "workers_started": 0, "workers_active": 0},
            "budget": {}
        });
        let result = audit(&manifest, &events);
        assert_eq!(result["ok"], json!(true));
    }

    #[test]
    fn read_events_returns_empty_for_missing_file() {
        let missing = std::path::Path::new("/nonexistent/legion-wf024-effect-audit.jsonl");
        let events = read_events(missing).unwrap();
        assert!(events.is_empty());
    }
}
