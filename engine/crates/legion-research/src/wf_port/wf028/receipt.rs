//! Port of `src/lib/research-core/receipt.py`, whose entire body is
//! `from manifest import finalize`. `manifest.py`'s durable run state
//! machine (`create_run`/`load_run`/`save_run`/`mutate_run`/`set_stage`/...)
//! is a different, larger surface this packet does not own; only
//! `finalize()` -- the function `receipt.py` actually re-exports -- is
//! ported here, self-contained against the identical `manifest.json`/
//! `events.jsonl`/`receipt.json` on-disk shapes, the same boundary choice
//! `super::wf026::meter` and `super::resource_guard` make.

use serde_json::{json, Value};
use std::fmt;
use std::path::Path;
use std::time::Duration;

use super::support::{self, IoError};

#[derive(Debug)]
pub enum FinalizeError {
    /// Port of `raise ValueError('verdict must be ship, block, or degraded')`.
    InvalidVerdict(String),
    Io(IoError),
}
impl fmt::Display for FinalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FinalizeError::InvalidVerdict(v) => write!(f, "verdict must be ship, block, or degraded: {v:?}"),
            FinalizeError::Io(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for FinalizeError {}
impl From<IoError> for FinalizeError {
    fn from(e: IoError) -> Self {
        FinalizeError::Io(e)
    }
}

/// Port of `manifest.finalize()`. `run_dir` is the already-resolved run
/// directory (`<root>/<run_id>` in the Python original); see the module
/// doc for why this port takes it directly rather than re-deriving it.
pub fn finalize(run_dir: &Path, run_id: &str, verdict: &str, checks: &Value) -> Result<Value, FinalizeError> {
    if !matches!(verdict, "ship" | "block" | "degraded") {
        return Err(FinalizeError::InvalidVerdict(verdict.to_string()));
    }
    let manifest_path = run_dir.join("manifest.json");
    let events_path = run_dir.join("events.jsonl");
    let receipt_path = run_dir.join("receipt.json");

    let receipt = {
        let _lock = support::FileLock::acquire(&manifest_path, Duration::from_secs(10))?;
        let mut manifest = support::read_json(&manifest_path)?;

        let status = if matches!(verdict, "ship" | "degraded") { "done" } else { "blocked" };
        manifest["status"] = json!(status);
        manifest["updated_at"] = json!(support::utc_now());
        if verdict == "block" {
            let mut blocked_on: Vec<Value> = manifest
                .get("blocked_on")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if !blocked_on.iter().any(|v| v == "ship-gate") {
                blocked_on.push(json!("ship-gate"));
            }
            manifest["blocked_on"] = Value::Array(blocked_on);
        }
        support::atomic_write_json(&manifest_path, &manifest)?;

        let receipt = json!({
            "receipt_version": 1,
            "run_id": run_id,
            "query_sha256": manifest.get("query_sha256").cloned().unwrap_or(Value::Null),
            "route_sha256": manifest.get("route_sha256").cloned().unwrap_or(Value::Null),
            "verdict": verdict,
            "checks": checks,
            "usage": manifest.get("usage").cloned().unwrap_or(Value::Null),
            "budget": manifest.get("budget").cloned().unwrap_or(Value::Null),
            "approvals": manifest.get("approvals").cloned().unwrap_or(Value::Null),
            "artifacts": manifest.get("artifacts").cloned().unwrap_or(Value::Null),
            "events_path": events_path.to_string_lossy().to_string(),
            "issued_at": support::utc_now(),
        });
        support::atomic_write_json(&receipt_path, &receipt)?;
        receipt
    };

    record_event(run_dir, run_id, "run.finalized", &json!({"verdict": verdict}))?;
    Ok(receipt)
}

/// Port of `manifest.record_event()`, self-contained the same way
/// `super::resource_guard::record_event` is.
fn record_event(run_dir: &Path, run_id: &str, event_type: &str, payload: &Value) -> Result<(), IoError> {
    let events_path = run_dir.join("events.jsonl");
    let _lock = support::FileLock::acquire(&events_path, Duration::from_secs(10))?;
    let mut event = json!({"at": support::utc_now(), "type": event_type, "run_id": run_id});
    if let (Value::Object(base), Value::Object(extra)) = (&mut event, payload) {
        for (k, v) in extra {
            base.insert(k.clone(), v.clone());
        }
    }
    support::append_jsonl(&events_path, &event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmp_run_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("legion-wf028-receipt-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_manifest(dir: &Path) {
        let manifest = json!({
            "manifest_version": 2,
            "run_id": "run-1",
            "query_sha256": "qsha",
            "route_sha256": "rsha",
            "status": "running",
            "blocked_on": [],
            "usage": {"external_requests": 3},
            "budget": {"external_requests": 12},
            "approvals": {},
            "artifacts": {},
        });
        support::atomic_write_json(&dir.join("manifest.json"), &manifest).unwrap();
    }

    #[test]
    fn invalid_verdict_is_rejected() {
        let dir = tmp_run_dir("invalid-verdict");
        write_manifest(&dir);
        let err = finalize(&dir, "run-1", "bogus", &json!({})).unwrap_err();
        assert!(matches!(err, FinalizeError::InvalidVerdict(_)));
    }

    #[test]
    fn ship_marks_manifest_done_and_writes_receipt() {
        let dir = tmp_run_dir("ship");
        write_manifest(&dir);
        let receipt = finalize(&dir, "run-1", "ship", &json!({"citecheck": "ok"})).unwrap();
        assert_eq!(receipt["verdict"], json!("ship"));
        assert_eq!(receipt["run_id"], json!("run-1"));

        let manifest = support::read_json(&dir.join("manifest.json")).unwrap();
        assert_eq!(manifest["status"], json!("done"));

        let on_disk_receipt = support::read_json(&dir.join("receipt.json")).unwrap();
        assert_eq!(on_disk_receipt["verdict"], json!("ship"));

        let events = fs::read_to_string(dir.join("events.jsonl")).unwrap();
        assert!(events.contains("run.finalized"));
    }

    #[test]
    fn block_marks_manifest_blocked_and_appends_ship_gate() {
        let dir = tmp_run_dir("block");
        write_manifest(&dir);
        finalize(&dir, "run-1", "block", &json!({})).unwrap();
        let manifest = support::read_json(&dir.join("manifest.json")).unwrap();
        assert_eq!(manifest["status"], json!("blocked"));
        assert_eq!(manifest["blocked_on"], json!(["ship-gate"]));
    }

    #[test]
    fn block_does_not_duplicate_ship_gate() {
        let dir = tmp_run_dir("block-dup");
        let manifest = json!({
            "run_id": "run-1",
            "status": "running",
            "blocked_on": ["ship-gate"],
        });
        support::atomic_write_json(&dir.join("manifest.json"), &manifest).unwrap();
        finalize(&dir, "run-1", "block", &json!({})).unwrap();
        let on_disk = support::read_json(&dir.join("manifest.json")).unwrap();
        assert_eq!(on_disk["blocked_on"], json!(["ship-gate"]));
    }

    #[test]
    fn degraded_marks_manifest_done() {
        let dir = tmp_run_dir("degraded");
        write_manifest(&dir);
        let receipt = finalize(&dir, "run-1", "degraded", &json!({})).unwrap();
        assert_eq!(receipt["verdict"], json!("degraded"));
        let manifest = support::read_json(&dir.join("manifest.json")).unwrap();
        assert_eq!(manifest["status"], json!("done"));
    }
}
