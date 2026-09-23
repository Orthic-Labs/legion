//! Minimal faithful port of the stateful slice of `run.py` (backed by
//! `manifest.py`'s on-disk shapes) that
//! `test_research_route_effect_boundaries.py` exercises: `init_run`,
//! `grant`, `record_evidence`, and `acquire`'s frozen-route provider
//! check. See `super`'s module doc for what is and is not covered.
//!
//! Manifest shape mirrors `manifest.create_run`/`manifest.load_run`
//! exactly for the fields this slice reads or writes
//! (`run_id`/`route`/`route_sha256`/`status`); fields this slice never
//! touches (`stages`, `usage`, `budget`, `approvals`, `artifacts`,
//! `failures`, ...) are carried through unread/unwritten rather than
//! reimplemented, since nothing ported here depends on them.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::wf_port::wf025::ledger;
use crate::wf_port::wf029::route_resolve::{self, Context};
use crate::wf_port::wf029::run as run_decisions;

const MANIFEST_VERSION: u64 = 2;

#[derive(Debug)]
pub enum RunStateError {
    /// Mirrors a Python `ValueError`/`RuntimeError` message.
    Message(String),
    Io(String),
}

impl std::fmt::Display for RunStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunStateError::Message(m) => write!(f, "{m}"),
            RunStateError::Io(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for RunStateError {}

fn msg(s: impl Into<String>) -> RunStateError {
    RunStateError::Message(s.into())
}

/// Port of `common.sha256_text`.
fn sha256_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

/// Canonical-JSON sha256 matching Python's
/// `json.dumps(value, sort_keys=True, separators=(',', ':'))`.
fn sha256_canonical_json(value: &Value) -> String {
    sha256_text(&canonical_json(value))
}

fn canonical_json(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for k in keys {
                    out.insert(k.clone(), sorted(&map[k]));
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    // serde_json's compact `to_string` already omits whitespace, matching
    // `separators=(',', ':')`.
    serde_json::to_string(&sorted(value)).unwrap_or_default()
}

/// Port of `common.utc_now`: RFC3339 UTC seconds with a `Z` suffix.
fn utc_now() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let days = (now.as_secs() / 86_400) as i64;
    let secs_of_day = now.as_secs() % 86_400;
    let (h, m, s) = (secs_of_day / 3600, (secs_of_day % 3600) / 60, secs_of_day % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

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

static RUN_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Port of `manifest.new_run_id`. Python uses `secrets.token_hex(3)` for
/// the trailing random suffix; this port substitutes a process-local
/// monotonic counter mixed with the current time, since the run id here is
/// only a filesystem directory name with no security role (uniqueness,
/// not unguessability, is what callers depend on) and no CSPRNG crate is
/// already in `Cargo.lock` for this crate.
fn new_run_id(query: &str) -> String {
    let date = &utc_now()[..10];
    let short = &sha256_text(query)[..8];
    let counter = RUN_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut hasher = DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    counter.hash(&mut hasher);
    let suffix = format!("{:012x}", hasher.finish());
    format!("run-{date}-{short}-{}", &suffix[..6])
}

/// Port of `manifest.default_run_root`: honors `RESEARCH_RUN_ROOT` exactly
/// like the Python original (the only path this ported slice's tests use).
fn default_run_root() -> PathBuf {
    match std::env::var("RESEARCH_RUN_ROOT") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => std::env::temp_dir().join("legion-research-runs"),
    }
}

/// Port of `manifest.run_dir`.
fn run_dir(run_id: &str, root: Option<&Path>) -> Result<PathBuf, RunStateError> {
    if run_id.is_empty() || run_id.contains('/') || run_id.contains('\\') || run_id.starts_with('.') {
        return Err(msg(format!("invalid run id: {run_id:?}")));
    }
    let base = root.map(Path::to_path_buf).unwrap_or_else(default_run_root);
    Ok(base.join(run_id))
}

fn manifest_path(run_id: &str, root: Option<&Path>) -> Result<PathBuf, RunStateError> {
    Ok(run_dir(run_id, root)?.join("manifest.json"))
}

fn read_json(path: &Path) -> Result<Value, RunStateError> {
    let text = std::fs::read_to_string(path).map_err(|e| RunStateError::Io(format!("cannot read {}: {e}", path.display())))?;
    serde_json::from_str(&text).map_err(|e| RunStateError::Io(format!("invalid JSON in {}: {e}", path.display())))
}

fn atomic_write_json(path: &Path, value: &Value) -> Result<(), RunStateError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| RunStateError::Io(e.to_string()))?;
    }
    let text = serde_json::to_string_pretty(value).map_err(|e| RunStateError::Io(e.to_string()))? + "\n";
    std::fs::write(path, text).map_err(|e| RunStateError::Io(format!("cannot write {}: {e}", path.display())))
}

/// Port of `manifest.load_run`.
pub fn load_run(run_id: &str, root: Option<&Path>) -> Result<Value, RunStateError> {
    let path = manifest_path(run_id, root)?;
    let manifest = read_json(&path)?;
    if manifest.get("manifest_version").and_then(Value::as_u64) != Some(MANIFEST_VERSION) {
        return Err(msg(format!(
            "unsupported manifest version: {:?}",
            manifest.get("manifest_version")
        )));
    }
    Ok(manifest)
}

fn save_run(manifest: &mut Value, root: Option<&Path>) -> Result<(), RunStateError> {
    let run_id = manifest
        .get("run_id")
        .and_then(Value::as_str)
        .ok_or_else(|| msg("manifest missing run_id"))?
        .to_string();
    manifest["updated_at"] = json!(utc_now());
    atomic_write_json(&manifest_path(&run_id, root)?, manifest)
}

/// Result of [`init_run`], mirroring `run.init_run`'s returned dict shape
/// (`{'run', 'route', 'gate_verdicts'}`).
pub struct InitRunResult {
    pub run: Value,
    pub route: Value,
    pub gate_verdicts: Vec<Value>,
}

/// Port of `run.init_run`'s route resolution, budget selection, and
/// manifest creation. `query_contract.persist` (writing the wrapper
/// contract alongside the run) is not ported: it is orthogonal plumbing
/// this test does not exercise and touches no state `grant`/`acquire`/
/// `record_evidence` read back.
pub fn init_run(intent: &str, context: &Context, root: Option<&Path>) -> Result<InitRunResult, RunStateError> {
    let route = route_resolve::resolve(intent, context).map_err(msg)?;
    let scale = route.get("scale").and_then(Value::as_str).unwrap_or("");
    let context_budget = context.get("budget");
    let budget = run_decisions::scale_budget(scale, context_budget).map_err(msg)?;

    let run_id = new_run_id(intent);
    let directory = run_dir(&run_id, root)?;
    if directory.exists() {
        return Err(RunStateError::Io(format!("run directory already exists: {}", directory.display())));
    }
    std::fs::create_dir_all(&directory).map_err(|e| RunStateError::Io(e.to_string()))?;
    let query_text = format!("{}\n", intent.trim_end());
    std::fs::write(directory.join("query.md"), &query_text).map_err(|e| RunStateError::Io(e.to_string()))?;

    let now = utc_now();
    let query_sha256 = sha256_text(&query_text);
    let route_sha256 = sha256_canonical_json(&route);
    let external_requests = budget.get("external_requests").and_then(Value::as_i64).unwrap_or(12);
    let workers = budget.get("workers").and_then(Value::as_i64).unwrap_or(1);
    let manifest = json!({
        "manifest_version": MANIFEST_VERSION,
        "run_id": run_id,
        "query_sha256": query_sha256,
        "route": route,
        "route_sha256": route_sha256,
        "status": "running",
        "blocked_on": [],
        "created_at": now,
        "updated_at": now,
        "budget": {"external_requests": external_requests, "workers": workers},
        "usage": {"external_requests": 0, "workers_started": 0, "workers_active": 0},
        "approvals": {},
        "stages": {
            "route": {"status": "done", "started_at": now, "finished_at": now},
        },
        "artifacts": {},
        "failures": [],
    });
    atomic_write_json(&manifest_path(&run_id, root)?, &manifest)?;
    std::fs::write(
        directory.join("route.json"),
        serde_json::to_string_pretty(&route).map_err(|e| RunStateError::Io(e.to_string()))? + "\n",
    )
    .map_err(|e| RunStateError::Io(e.to_string()))?;

    let gate_verdicts = route_resolve::gate_verdicts(&route, None);
    Ok(InitRunResult { run: manifest, route, gate_verdicts })
}

/// Result of [`grant`], mirroring `run.grant`'s returned dict.
pub struct GrantResult {
    pub ready: bool,
    pub route: Value,
    pub gate_verdicts: Vec<Value>,
    pub pending: Vec<String>,
}

/// Port of `run.grant`.
pub fn grant(run_id: &str, root: Option<&Path>) -> Result<GrantResult, RunStateError> {
    let mut manifest = load_run(run_id, root)?;
    let route = manifest.get("route").cloned().unwrap_or(Value::Null);
    let approvals = manifest.get("approvals").and_then(Value::as_object).cloned();
    let (granted, verdicts) = route_resolve::grant_effects(&route, approvals.as_ref()).map_err(msg)?;

    let allowed_empty = granted
        .get("allowed_effects")
        .and_then(Value::as_array)
        .map(|a| a.is_empty())
        .unwrap_or(true);
    if allowed_empty {
        let pending: Vec<String> = verdicts
            .iter()
            .filter(|v| v.get("verdict").and_then(Value::as_str) != Some("ok"))
            .filter_map(|v| v.get("gate").and_then(Value::as_str).map(str::to_string))
            .collect();
        return Ok(GrantResult { ready: false, route: granted, gate_verdicts: verdicts, pending });
    }

    manifest["route"] = granted.clone();
    manifest["route_sha256"] = json!(sha256_canonical_json(&granted));
    if let Some(stages) = manifest.get_mut("stages").and_then(Value::as_object_mut) {
        let entry = stages.entry("route").or_insert_with(|| json!({}));
        if let Some(entry) = entry.as_object_mut() {
            entry.insert("status".into(), json!("done"));
        }
    }
    manifest["blocked_on"] = json!([]);
    manifest["status"] = json!("running");
    save_run(&mut manifest, root)?;
    let route_path = run_dir(run_id, root)?.join("route.json");
    std::fs::write(
        &route_path,
        serde_json::to_string_pretty(&granted).map_err(|e| RunStateError::Io(e.to_string()))? + "\n",
    )
    .map_err(|e| RunStateError::Io(e.to_string()))?;

    Ok(GrantResult { ready: true, route: granted, gate_verdicts: verdicts, pending: Vec::new() })
}

/// Port of `run._require_granted`.
fn require_granted(run_id: &str, effects: &[&str], root: Option<&Path>) -> Result<Value, RunStateError> {
    let run = load_run(run_id, root)?;
    let route = run.get("route").cloned().unwrap_or(Value::Null);
    let allowed_present = route
        .get("allowed_effects")
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if !allowed_present {
        return Err(msg("route effects have not been granted"));
    }
    run_decisions::check_effects(&route, effects).map_err(msg)?;
    Ok(run)
}

/// Port of `run.record_evidence`. Evidence is admitted only through
/// [`ledger::validate_evidence`] (already ported at `wf_port::wf025`); the
/// on-disk `evidence.jsonl` append and duplicate-id check this test does
/// not exercise are not ported here.
pub fn record_evidence(run_id: &str, row: &Value, root: Option<&Path>) -> Result<Value, RunStateError> {
    require_granted(run_id, &["extract"], root)?;
    let verdict = ledger::validate_evidence(std::slice::from_ref(row))
        .into_iter()
        .next()
        .expect("validate_evidence returns one verdict per input row");
    if verdict.blocked {
        return Err(msg(format!("evidence record blocked: {:?}", verdict.reasons)));
    }
    Ok(row.clone())
}

/// Result of [`acquire`]'s provider-resolution stage, mirroring the
/// `provider` field of `run.acquire`'s returned dict. The rest of
/// `acquire` (meter, provider `search`/`open`/`find` calls, the
/// `acquisition.json` artifact write) needs `providers/search_open_find.py`
/// (not ported anywhere under `legion-research`) and is out of scope here.
pub fn acquire_resolve_provider(
    run_id: &str,
    provider_name: Option<&str>,
    root: Option<&Path>,
) -> Result<String, RunStateError> {
    let run = require_granted(run_id, &["search", "extract"], root)?;
    let route = run.get("route").cloned().unwrap_or(Value::Null);
    run_decisions::resolve_acquire_provider(&route, provider_name).map_err(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;
    use std::sync::atomic::{AtomicU64 as TestCounter, Ordering as TestOrdering};

    static TMP_COUNTER: TestCounter = TestCounter::new(0);

    fn tmp_root(name: &str) -> PathBuf {
        let n = TMP_COUNTER.fetch_add(1, TestOrdering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "legion-wf031-run-state-{name}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn valid_evidence() -> Value {
        json!({
            "id": "ev1",
            "url": "file:///tmp/source.md",
            "title": "Source",
            "publisher": "local-corpus",
            "retrieved_at": "2026-08-05",
            "locator": "chars:0-42",
            "quote_or_paraphrase": "Vendor X costs $29 per month.",
            "suggested_by": "seed:query:1",
            "seed_chain": ["seed:query:1"],
            "is_primary": true,
            "authority_role": "vendor-official",
            "instructionPolicy": "data_only",
        })
    }

    // Ported from research-core/tests/test_research_route_effect_boundaries.py
    // (the stateful `run.py` half: `init_run`/`grant`/`acquire`/
    // `record_evidence` are frozen-route bound).
    #[test]
    fn route_effects_and_evidence_admission_are_frozen_route_bound() {
        let root = tmp_root("effect-boundaries");
        let mut context = Map::new();
        context.insert("provider".into(), json!("local-corpus"));
        let init = init_run("Verify Vendor X pricing", &context, Some(&root)).unwrap();
        let run_id = init.run["run_id"].as_str().unwrap().to_string();

        let err = record_evidence(&run_id, &valid_evidence(), Some(&root)).unwrap_err();
        assert!(
            err.to_string().contains("route effects have not been granted"),
            "{err}"
        );

        let granted = grant(&run_id, Some(&root)).unwrap();
        assert!(granted.ready);

        let err = acquire_resolve_provider(&run_id, Some("browser"), Some(&root)).unwrap_err();
        assert!(
            err.to_string().contains("not authorized by frozen route provider"),
            "{err}"
        );

        // Now that effects are granted, evidence admission itself is
        // ledger-validated (a duplicate of `ledger`'s own coverage, kept
        // here to prove this slice's `record_evidence` wiring end to end).
        let ok = record_evidence(&run_id, &valid_evidence(), Some(&root)).unwrap();
        assert_eq!(ok["id"], json!("ev1"));

        let mut missing_policy = valid_evidence();
        missing_policy.as_object_mut().unwrap().remove("instructionPolicy");
        let err = record_evidence(&run_id, &missing_policy, Some(&root)).unwrap_err();
        assert!(err.to_string().contains("evidence record blocked"), "{err}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn init_run_persists_a_reloadable_manifest_and_route() {
        let root = tmp_root("init-run");
        let context = Map::new();
        let init = init_run("What is the price of Vendor X?", &context, Some(&root)).unwrap();
        let run_id = init.run["run_id"].as_str().unwrap().to_string();
        let reloaded = load_run(&run_id, Some(&root)).unwrap();
        assert_eq!(reloaded["route_sha256"], init.run["route_sha256"]);
        assert_eq!(reloaded["status"], json!("running"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
