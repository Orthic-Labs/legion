//! Port of `src/lib/research-core/meter.py`.
//!
//! Research-internal meter for external requests & worker lifecycles. The
//! Python original loads `manifest.py` (a sibling script this port does not
//! own) to mutate a run's `manifest.json` under a file lock and append
//! `events.jsonl` records. `manifest.py`'s durable-run infrastructure is out
//! of this packet's owned scope, so this port implements the same minimal,
//! self-contained manifest read/mutate/write + event-append behaviour that
//! `consume()` actually exercises, against the identical on-disk
//! `manifest.json` / `events.jsonl` schema (see any file under
//! `src/lib/research-core/runs/*/manifest.json` for the shape). It does not
//! reimplement run creation, locking, or the other `manifest.py` verbs those
//! are a different file's scope.
//!
//! Behaviour kept identical to the Python `consume()`:
//! - `effect == "external_request"`: `usage.external_requests += units`,
//!   refused (without mutating usage) if it would exceed
//!   `budget.external_requests`.
//! - `effect == "worker"` with `worker_event == "start"`:
//!   `usage.workers_active += units` (refused, without mutating usage, if it
//!   would exceed `budget.workers`) and unconditionally
//!   `usage.workers_started += units`.
//! - `effect == "worker"` with `worker_event == "finish"`:
//!   `usage.workers_active = max(0, usage.workers_active - units)`.
//! - `effect == "worker"` with no `worker_event`: error (not a budget
//!   refusal - the Python raises `ValueError`, which is never caught by the
//!   `try/except RuntimeError` around `mutate_run`, so it propagates as a
//!   hard failure rather than an `{"ok": false, ...}` result).
//! - any other `effect`: error, same propagation as above (`ValueError`).
//! - On budget refusal (the `RuntimeError` path only): the run's `acquire`
//!   stage is set to `blocked` with `detail: "budget"`, a `budget.refused`
//!   event is appended, and `{"ok": false, "reason": ...}` is returned
//!   *without* raising.
//! - On success: a `budget.consumed` event is appended and
//!   `{"ok": true, "usage": ..., "budget": ...}` is returned.

use serde_json::{json, Value};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// Mirrors the Python script raising `ValueError` for a malformed call
/// (unknown effect, or a `worker` effect with no `worker_event`). The
/// Python `main()` lets this propagate as an uncaught exception (nonzero
/// exit, traceback) rather than the structured `{"ok": false}` JSON that a
/// budget refusal produces.
#[derive(Debug)]
pub struct MeterCallError(pub String);

impl fmt::Display for MeterCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for MeterCallError {}

/// I/O or malformed-manifest failure reading/writing the run's files.
/// The Python original would raise `FileNotFoundError`/`json.JSONDecodeError`
/// etc. uncaught, same as `MeterCallError`.
#[derive(Debug)]
pub struct ManifestIoError(pub String);

impl fmt::Display for ManifestIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ManifestIoError {}

#[derive(Debug)]
pub enum MeterError {
    Call(MeterCallError),
    Io(ManifestIoError),
}

impl fmt::Display for MeterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MeterError::Call(e) => e.fmt(f),
            MeterError::Io(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for MeterError {}

fn manifest_path(run_dir: &Path) -> PathBuf {
    run_dir.join("manifest.json")
}

fn events_path(run_dir: &Path) -> PathBuf {
    run_dir.join("events.jsonl")
}

fn read_manifest(run_dir: &Path) -> Result<Value, MeterError> {
    let text = fs::read_to_string(manifest_path(run_dir))
        .map_err(|e| MeterError::Io(ManifestIoError(format!("cannot read manifest.json: {e}"))))?;
    serde_json::from_str(&text)
        .map_err(|e| MeterError::Io(ManifestIoError(format!("invalid manifest.json: {e}"))))
}

fn write_manifest(run_dir: &Path, manifest: &Value) -> Result<(), MeterError> {
    let text = serde_json::to_string_pretty(manifest)
        .map_err(|e| MeterError::Io(ManifestIoError(e.to_string())))?;
    fs::write(manifest_path(run_dir), text + "\n")
        .map_err(|e| MeterError::Io(ManifestIoError(format!("cannot write manifest.json: {e}"))))
}

fn append_event(run_dir: &Path, event: &Value) -> Result<(), MeterError> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(events_path(run_dir))
        .map_err(|e| MeterError::Io(ManifestIoError(format!("cannot open events.jsonl: {e}"))))?;
    let line = serde_json::to_string(event).map_err(|e| MeterError::Io(ManifestIoError(e.to_string())))?;
    writeln!(file, "{line}")
        .map_err(|e| MeterError::Io(ManifestIoError(format!("cannot append events.jsonl: {e}"))))
}

fn get_i64(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

/// Applies the metered effect to `usage`/`budget` in place. Returns `Ok(())`
/// on success, `Err(reason)` for a budget-exceeded refusal (the Python
/// `RuntimeError` path, caught by `consume()`), or `Err(MeterCallError)` for
/// a malformed call (the Python `ValueError` path, left uncaught).
fn apply_effect(
    manifest: &mut Value,
    effect: &str,
    units: i64,
    worker_event: Option<&str>,
) -> Result<Result<(), String>, MeterCallError> {
    if manifest.get("usage").is_none() {
        return Err(MeterCallError("manifest missing usage".into()));
    }
    match effect {
        "external_request" => {
            let current = get_i64(manifest.get("usage").unwrap(), "external_requests");
            let proposed = current + units;
            let budget_limit = get_i64(manifest.get("budget").unwrap_or(&Value::Null), "external_requests");
            if proposed > budget_limit {
                return Ok(Err(format!(
                    "research budget exceeded: external_requests {proposed} > {budget_limit}"
                )));
            }
            manifest["usage"]["external_requests"] = json!(proposed);
            Ok(Ok(()))
        }
        "worker" => match worker_event {
            Some("start") => {
                let current = get_i64(manifest.get("usage").unwrap(), "workers_active");
                let proposed = current + units;
                let budget_limit = get_i64(manifest.get("budget").unwrap_or(&Value::Null), "workers");
                if proposed > budget_limit {
                    return Ok(Err(format!(
                        "research budget exceeded: workers_active {proposed} > {budget_limit}"
                    )));
                }
                manifest["usage"]["workers_active"] = json!(proposed);
                let started = get_i64(manifest.get("usage").unwrap(), "workers_started") + units;
                manifest["usage"]["workers_started"] = json!(started);
                Ok(Ok(()))
            }
            Some("finish") => {
                let current = get_i64(manifest.get("usage").unwrap(), "workers_active");
                manifest["usage"]["workers_active"] = json!((current - units).max(0));
                Ok(Ok(()))
            }
            _ => Err(MeterCallError(
                "worker effect requires worker_event=start|finish".into(),
            )),
        },
        other => Err(MeterCallError(format!("unknown metered effect: {other}"))),
    }
}

/// Faithful port of `meter.consume()`. `run_dir` is the already-resolved run
/// directory (`<root>/<run_id>` in the Python original); this port takes it
/// directly rather than re-deriving it from `manifest.py`'s
/// `default_run_root()`/`run_dir()`, which live outside this packet's owned
/// files.
pub fn consume(
    run_dir: &Path,
    effect: &str,
    units: i64,
    worker_event: Option<&str>,
) -> Result<Value, MeterError> {
    let mut manifest = read_manifest(run_dir)?;
    let outcome = apply_effect(&mut manifest, effect, units, worker_event).map_err(MeterError::Call)?;
    match outcome {
        Ok(()) => {
            write_manifest(run_dir, &manifest)?;
            append_event(
                run_dir,
                &json!({
                    "type": "budget.consumed",
                    "effect": effect,
                    "units": units,
                    "worker_event": worker_event,
                }),
            )?;
            Ok(json!({
                "ok": true,
                "usage": manifest["usage"].clone(),
                "budget": manifest["budget"].clone(),
            }))
        }
        Err(reason) => {
            if let Some(stages) = manifest.get_mut("stages") {
                stages["acquire"] = json!({"status": "blocked", "detail": "budget"});
            }
            write_manifest(run_dir, &manifest)?;
            append_event(
                run_dir,
                &json!({
                    "type": "budget.refused",
                    "effect": effect,
                    "units": units,
                    "reason": reason,
                }),
            )?;
            Ok(json!({"ok": false, "reason": reason}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture_manifest(external_requests_budget: i64, workers_budget: i64) -> Value {
        json!({
            "manifest_version": 2,
            "run_id": "run-test",
            "budget": {
                "external_requests": external_requests_budget,
                "workers": workers_budget,
            },
            "usage": {
                "external_requests": 0,
                "workers_started": 0,
                "workers_active": 0,
            },
            "stages": {
                "acquire": {"status": "pending"},
            },
        })
    }

    fn write_fixture(dir: &Path, manifest: &Value) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            manifest_path(dir),
            serde_json::to_string_pretty(manifest).unwrap(),
        )
        .unwrap();
    }

    fn tmp_run_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("legion-wf026-meter-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn external_request_under_budget_increments_usage_and_reports_ok() {
        let dir = tmp_run_dir("ext-ok");
        write_fixture(&dir, &fixture_manifest(12, 1));

        let result = consume(&dir, "external_request", 1, None).unwrap();
        assert_eq!(result["ok"], json!(true));
        assert_eq!(result["usage"]["external_requests"], json!(1));

        let on_disk = read_manifest(&dir).unwrap();
        assert_eq!(on_disk["usage"]["external_requests"], json!(1));
    }

    #[test]
    fn external_request_over_budget_is_refused_without_mutating_usage() {
        let dir = tmp_run_dir("ext-refused");
        let mut manifest = fixture_manifest(1, 1);
        manifest["usage"]["external_requests"] = json!(1);
        write_fixture(&dir, &manifest);

        let result = consume(&dir, "external_request", 1, None).unwrap();
        assert_eq!(result["ok"], json!(false));
        assert_eq!(
            result["reason"],
            json!("research budget exceeded: external_requests 2 > 1")
        );

        let on_disk = read_manifest(&dir).unwrap();
        assert_eq!(on_disk["usage"]["external_requests"], json!(1));
        assert_eq!(on_disk["stages"]["acquire"]["status"], json!("blocked"));
        assert_eq!(on_disk["stages"]["acquire"]["detail"], json!("budget"));
    }

    #[test]
    fn worker_start_under_budget_increments_active_and_started() {
        let dir = tmp_run_dir("worker-start-ok");
        write_fixture(&dir, &fixture_manifest(12, 2));

        let result = consume(&dir, "worker", 1, Some("start")).unwrap();
        assert_eq!(result["ok"], json!(true));
        assert_eq!(result["usage"]["workers_active"], json!(1));
        assert_eq!(result["usage"]["workers_started"], json!(1));
    }

    #[test]
    fn worker_start_over_budget_is_refused_and_leaves_started_untouched() {
        let dir = tmp_run_dir("worker-start-refused");
        let mut manifest = fixture_manifest(12, 1);
        manifest["usage"]["workers_active"] = json!(1);
        write_fixture(&dir, &manifest);

        let result = consume(&dir, "worker", 1, Some("start")).unwrap();
        assert_eq!(result["ok"], json!(false));
        assert_eq!(
            result["reason"],
            json!("research budget exceeded: workers_active 2 > 1")
        );

        let on_disk = read_manifest(&dir).unwrap();
        assert_eq!(on_disk["usage"]["workers_active"], json!(1));
        assert_eq!(on_disk["usage"]["workers_started"], json!(0));
    }

    #[test]
    fn worker_finish_decrements_active_and_floors_at_zero() {
        let dir = tmp_run_dir("worker-finish-floor");
        let mut manifest = fixture_manifest(12, 2);
        manifest["usage"]["workers_active"] = json!(0);
        write_fixture(&dir, &manifest);

        let result = consume(&dir, "worker", 5, Some("finish")).unwrap();
        assert_eq!(result["ok"], json!(true));
        assert_eq!(result["usage"]["workers_active"], json!(0));
    }

    #[test]
    fn worker_without_event_is_a_call_error_not_a_refusal() {
        let dir = tmp_run_dir("worker-no-event");
        write_fixture(&dir, &fixture_manifest(12, 1));

        let err = consume(&dir, "worker", 1, None).unwrap_err();
        assert!(matches!(err, MeterError::Call(_)));
        assert_eq!(
            err.to_string(),
            "worker effect requires worker_event=start|finish"
        );
    }

    #[test]
    fn unknown_effect_is_a_call_error() {
        let dir = tmp_run_dir("unknown-effect");
        write_fixture(&dir, &fixture_manifest(12, 1));

        let err = consume(&dir, "bogus", 1, None).unwrap_err();
        assert!(matches!(err, MeterError::Call(_)));
        assert_eq!(err.to_string(), "unknown metered effect: bogus");
    }

    #[test]
    fn success_appends_budget_consumed_event() {
        let dir = tmp_run_dir("event-consumed");
        write_fixture(&dir, &fixture_manifest(12, 1));

        consume(&dir, "external_request", 1, None).unwrap();
        let events = fs::read_to_string(events_path(&dir)).unwrap();
        assert!(events.contains("\"type\":\"budget.consumed\""));
        assert!(events.contains("\"effect\":\"external_request\""));
    }

    #[test]
    fn refusal_appends_budget_refused_event() {
        let dir = tmp_run_dir("event-refused");
        let mut manifest = fixture_manifest(0, 1);
        manifest["usage"]["external_requests"] = json!(0);
        write_fixture(&dir, &manifest);

        consume(&dir, "external_request", 1, None).unwrap();
        let events = fs::read_to_string(events_path(&dir)).unwrap();
        assert!(events.contains("\"type\":\"budget.refused\""));
    }
}
