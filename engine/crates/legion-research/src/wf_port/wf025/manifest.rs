//! Faithful Rust port of `src/lib/research-core/manifest.py` (plus the
//! shared helpers it uses from `common.py`): durable Research run state,
//! exact resume, approvals, events, and receipts, persisted as JSON/JSONL
//! files on disk. `events.py` is a one-function re-export of
//! `manifest.record_event`, ported here as [`record_event`] directly.

use std::collections::HashSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const MANIFEST_VERSION: u64 = 2;
const DEFAULT_STAGES: &[&str] = &[
    "route",
    "acquire",
    "normalize",
    "challenge",
    "synthesize",
    "citecheck",
    "retraction",
    "patch",
    "ship",
];
const STAGE_STATUSES: &[&str] = &["pending", "running", "done", "skipped", "blocked", "failed"];

#[derive(Debug)]
pub enum ManifestError {
    Io(String),
    Json(String),
    Invalid(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::Io(m) | ManifestError::Json(m) | ManifestError::Invalid(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<std::io::Error> for ManifestError {
    fn from(e: std::io::Error) -> Self {
        ManifestError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for ManifestError {
    fn from(e: serde_json::Error) -> Self {
        ManifestError::Json(e.to_string())
    }
}

type Result<T> = std::result::Result<T, ManifestError>;

/// `utc_now()`: an RFC3339-ish UTC timestamp with second precision and a
/// trailing `Z`, matching `common.py`'s `utc_now()`.
pub fn utc_now() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() as i64;
    let (y, m, d) = super::iso_date::civil_from_epoch_secs(secs);
    let time_of_day = secs.rem_euclid(86_400);
    let (h, mi, s) = (time_of_day / 3600, (time_of_day / 60) % 60, time_of_day % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

pub fn sha256_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

fn read_json(path: &Path) -> Result<Value> {
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn atomic_write_text(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or("json"),
        std::process::id()
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn atomic_write_json(path: &Path, value: &Value) -> Result<()> {
    let text = serde_json::to_string_pretty(value)? + "\n";
    atomic_write_text(path, &text)
}

fn append_jsonl(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(value)? + "\n";
    f.write_all(line.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// A simple cross-process advisory lock via exclusive file creation,
/// mirroring `common.py`'s `file_lock`: a stale lock older than 5 minutes
/// is reclaimed, and acquisition retries until `timeout`.
struct FileLock {
    lock_path: PathBuf,
}

impl FileLock {
    fn acquire(path: &Path, timeout: std::time::Duration) -> Result<Self> {
        let lock_path = {
            let mut p = path.as_os_str().to_owned();
            p.push(".lock");
            PathBuf::from(p)
        };
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match fs::OpenOptions::new().create_new(true).write(true).open(&lock_path) {
                Ok(mut f) => {
                    let _ = write!(f, "{} {}\n", std::process::id(), utc_now());
                    return Ok(FileLock { lock_path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if let Ok(meta) = fs::metadata(&lock_path) {
                        if let Ok(modified) = meta.modified() {
                            if modified.elapsed().unwrap_or_default() > std::time::Duration::from_secs(300) {
                                let _ = fs::remove_file(&lock_path);
                                continue;
                            }
                        }
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(ManifestError::Io(format!(
                            "timed out acquiring lock: {}",
                            lock_path.display()
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

/// `default_run_root()`: `$RESEARCH_RUN_ROOT`, or `<crate>/runs` when unset.
/// The Python default was relative to the script file; callers of this
/// port should generally pass an explicit `root` instead of relying on the
/// process's current directory.
pub fn default_run_root() -> PathBuf {
    match std::env::var("RESEARCH_RUN_ROOT") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => PathBuf::from("runs"),
    }
}

fn pseudo_random_hex(len_bytes: usize) -> String {
    // No `rand` dependency is declared for this crate; mirrors
    // `secrets.token_hex()`'s uniqueness requirement (not its CSPRNG
    // guarantee) using a monotonically-advancing counter plus wall-clock
    // nanoseconds, hashed for even hex-digit distribution.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!("{nanos}-{counter}-{:?}", std::process::id());
    let digest = sha256_text(&seed);
    digest[..len_bytes * 2].to_string()
}

/// Ports `new_run_id()`.
pub fn new_run_id(query: &str) -> String {
    let today = &utc_now()[..10];
    format!("run-{today}-{}-{}", &sha256_text(query)[..8], pseudo_random_hex(3))
}

/// Ports `run_dir()`, including its path-traversal guard.
pub fn run_dir(run_id: &str, root: Option<&Path>) -> Result<PathBuf> {
    if run_id.is_empty() || run_id.contains('/') || run_id.contains('\\') || run_id.starts_with('.') {
        return Err(ManifestError::Invalid(format!("invalid run id: {run_id:?}")));
    }
    let base = root.map(Path::to_path_buf).unwrap_or_else(default_run_root);
    Ok(base.join(run_id))
}

fn paths(run_id: &str, root: Option<&Path>) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let dir = run_dir(run_id, root)?;
    Ok((dir.join("manifest.json"), dir.join("events.jsonl"), dir.join("receipt.json")))
}

fn obj_mut(v: &mut Value) -> &mut Map<String, Value> {
    v.as_object_mut().expect("manifest value must be an object")
}

/// Ports `create_run()`.
pub fn create_run(query: &str, route: &Value, budget: &Value, root: Option<&Path>) -> Result<Value> {
    let rid = new_run_id(query);
    let (mpath, epath, _) = paths(&rid, root)?;
    let dir = mpath.parent().expect("manifest path has a parent").to_path_buf();
    fs::create_dir_all(&dir)?;
    let query_text = format!("{}\n", query.trim_end());
    fs::write(dir.join("query.md"), query_text.as_bytes())?;
    let now = utc_now();
    let route_sha = sha256_text(&serde_json::to_string(route)?);
    let query_sha = sha256_text(&query_text);

    let external_requests = budget
        .get("external_requests")
        .and_then(Value::as_i64)
        .unwrap_or(12);
    let workers = budget.get("workers").and_then(Value::as_i64).unwrap_or(1);

    let mut stages = Map::new();
    for name in DEFAULT_STAGES {
        stages.insert(
            (*name).to_string(),
            serde_json::json!({"status": "pending"}),
        );
    }
    stages.insert(
        "route".to_string(),
        serde_json::json!({"status": "done", "started_at": now, "finished_at": now}),
    );

    let manifest = serde_json::json!({
        "manifest_version": MANIFEST_VERSION,
        "run_id": rid,
        "query_sha256": query_sha,
        "route": route,
        "route_sha256": route_sha,
        "status": "running",
        "blocked_on": [],
        "created_at": now,
        "updated_at": now,
        "budget": {"external_requests": external_requests, "workers": workers},
        "usage": {"external_requests": 0, "workers_started": 0, "workers_active": 0},
        "approvals": {},
        "stages": Value::Object(stages),
        "artifacts": {},
        "failures": [],
    });
    atomic_write_json(&mpath, &manifest)?;
    append_jsonl(
        &epath,
        &serde_json::json!({"at": now, "type": "run.created", "run_id": rid, "query_sha256": query_sha}),
    )?;
    Ok(manifest)
}

/// Ports `load_run()`.
pub fn load_run(run_id: &str, root: Option<&Path>) -> Result<Value> {
    let (mpath, _, _) = paths(run_id, root)?;
    let manifest = read_json(&mpath)?;
    let version = manifest.get("manifest_version").and_then(Value::as_u64);
    if version != Some(MANIFEST_VERSION) {
        return Err(ManifestError::Invalid(format!(
            "unsupported manifest version: {version:?}"
        )));
    }
    Ok(manifest)
}

/// Ports `save_run()`.
pub fn save_run(manifest: &mut Value, root: Option<&Path>) -> Result<()> {
    let rid = manifest
        .get("run_id")
        .and_then(Value::as_str)
        .ok_or_else(|| ManifestError::Invalid("manifest missing run_id".to_string()))?
        .to_string();
    let (mpath, _, _) = paths(&rid, root)?;
    obj_mut(manifest).insert("updated_at".to_string(), Value::String(utc_now()));
    atomic_write_json(&mpath, manifest)
}

/// Ports `mutate_run()`: loads under lock, applies `f`, saves, returns the
/// updated manifest.
pub fn mutate_run(run_id: &str, root: Option<&Path>, f: impl FnOnce(&mut Value)) -> Result<Value> {
    let (mpath, _, _) = paths(run_id, root)?;
    let _lock = FileLock::acquire(&mpath, std::time::Duration::from_secs(10))?;
    let mut manifest = load_run(run_id, root)?;
    f(&mut manifest);
    save_run(&mut manifest, root)?;
    Ok(manifest)
}

/// Ports `record_event()` (and is `events.py`'s sole re-export).
pub fn record_event(run_id: &str, event_type: &str, payload: Option<&Value>, root: Option<&Path>) -> Result<()> {
    let (_, epath, _) = paths(run_id, root)?;
    let _lock = FileLock::acquire(&epath, std::time::Duration::from_secs(10))?;
    let mut event = Map::new();
    event.insert("at".to_string(), Value::String(utc_now()));
    event.insert("type".to_string(), Value::String(event_type.to_string()));
    event.insert("run_id".to_string(), Value::String(run_id.to_string()));
    if let Some(Value::Object(extra)) = payload {
        for (k, v) in extra {
            event.insert(k.clone(), v.clone());
        }
    }
    append_jsonl(&epath, &Value::Object(event))
}

/// Ports `approve()`.
pub fn approve(run_id: &str, gate: &str, approval_text: &str, actor: &str, root: Option<&Path>) -> Result<Value> {
    if gate.is_empty() || approval_text.trim().is_empty() {
        return Err(ManifestError::Invalid(
            "gate and non-empty approval text are required".to_string(),
        ));
    }
    let text = approval_text.trim().to_string();
    let out = mutate_run(run_id, root, |m| {
        let now = utc_now();
        let obj = obj_mut(m);
        let approvals = obj
            .entry("approvals".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        obj_mut(approvals).insert(
            gate.to_string(),
            serde_json::json!({"actor": actor, "text": text, "approved_at": now}),
        );
        let blocked_on: Vec<Value> = obj
            .get("blocked_on")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|v| v.as_str() != Some(gate))
            .collect();
        let still_blocked = !blocked_on.is_empty();
        obj.insert("blocked_on".to_string(), Value::Array(blocked_on));
        if obj.get("status").and_then(Value::as_str) == Some("blocked") && !still_blocked {
            obj.insert("status".to_string(), Value::String("running".to_string()));
        }
    })?;
    record_event(run_id, "gate.approved", Some(&serde_json::json!({"gate": gate, "actor": actor})), root)?;
    Ok(out)
}

/// Ports `set_stage()`.
pub fn set_stage(run_id: &str, stage: &str, status: &str, detail: Option<&str>, root: Option<&Path>) -> Result<Value> {
    if !STAGE_STATUSES.contains(&status) {
        return Err(ManifestError::Invalid(format!("invalid stage status: {status}")));
    }
    let out = mutate_run(run_id, root, |m| {
        let now = utc_now();
        let obj = obj_mut(m);
        let stages = obj
            .entry("stages".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        let stages_obj = obj_mut(stages);
        let entry = stages_obj
            .entry(stage.to_string())
            .or_insert_with(|| serde_json::json!({"status": "pending"}));
        let entry_obj = obj_mut(entry);
        entry_obj.insert("status".to_string(), Value::String(status.to_string()));
        if status == "running" && !entry_obj.contains_key("started_at") {
            entry_obj.insert("started_at".to_string(), Value::String(now.clone()));
        }
        if matches!(status, "done" | "skipped" | "blocked" | "failed") {
            entry_obj.insert("finished_at".to_string(), Value::String(now.clone()));
        }
        if let Some(d) = detail {
            entry_obj.insert("detail".to_string(), Value::String(d.to_string()));
        }
        if status == "blocked" {
            obj.insert("status".to_string(), Value::String("blocked".to_string()));
            let blocked_on = obj
                .entry("blocked_on".to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Value::Array(arr) = blocked_on {
                if let Some(d) = detail {
                    if !arr.iter().any(|v| v.as_str() == Some(d)) {
                        arr.push(Value::String(d.to_string()));
                    }
                }
            }
        } else if status == "failed" {
            obj.insert("status".to_string(), Value::String("failed".to_string()));
            let failures = obj
                .entry("failures".to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Value::Array(arr) = failures {
                arr.push(serde_json::json!({
                    "stage": stage,
                    "detail": detail.unwrap_or("failed"),
                    "at": now,
                }));
            }
        }
    })?;
    record_event(
        run_id,
        "stage.changed",
        Some(&serde_json::json!({"stage": stage, "status": status, "detail": detail})),
        root,
    )?;
    Ok(out)
}

/// Ports `attach_artifact()`.
pub fn attach_artifact(
    run_id: &str,
    name: &str,
    path: &str,
    sha256: Option<&str>,
    root: Option<&Path>,
) -> Result<Value> {
    let out = mutate_run(run_id, root, |m| {
        let now = utc_now();
        let obj = obj_mut(m);
        let artifacts = obj
            .entry("artifacts".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        obj_mut(artifacts).insert(
            name.to_string(),
            serde_json::json!({"path": path, "sha256": sha256, "recorded_at": now}),
        );
    })?;
    record_event(
        run_id,
        "artifact.recorded",
        Some(&serde_json::json!({"name": name, "path": path, "sha256": sha256})),
        root,
    )?;
    Ok(out)
}

/// Ports `resume_position()`.
pub fn resume_position(manifest: &Value) -> Value {
    let stages = manifest.get("stages").and_then(Value::as_object).cloned().unwrap_or_default();
    let mut ordered: Vec<String> = DEFAULT_STAGES.iter().map(|s| s.to_string()).collect();
    let known: HashSet<&str> = DEFAULT_STAGES.iter().copied().collect();
    for key in stages.keys() {
        if !known.contains(key.as_str()) {
            ordered.push(key.clone());
        }
    }
    let remaining: Vec<Value> = ordered
        .into_iter()
        .filter(|s| {
            let status = stages
                .get(s)
                .and_then(|v| v.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("pending");
            status != "done" && status != "skipped"
        })
        .map(Value::String)
        .collect();
    let next_stage = remaining.first().cloned().unwrap_or(Value::Null);
    let blocked_on = manifest
        .get("blocked_on")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    serde_json::json!({
        "next_stage": next_stage,
        "remaining": remaining,
        "blocked_on": blocked_on,
    })
}

/// Ports `finalize()`.
pub fn finalize(run_id: &str, verdict: &str, checks: &Value, root: Option<&Path>) -> Result<Value> {
    if !matches!(verdict, "ship" | "block" | "degraded") {
        return Err(ManifestError::Invalid("verdict must be ship, block, or degraded".to_string()));
    }
    let (mpath, epath, rpath) = paths(run_id, root)?;
    let receipt = {
        let _lock = FileLock::acquire(&mpath, std::time::Duration::from_secs(10))?;
        let mut manifest = load_run(run_id, root)?;
        {
            let obj = obj_mut(&mut manifest);
            obj.insert(
                "status".to_string(),
                Value::String(if matches!(verdict, "ship" | "degraded") { "done" } else { "blocked" }.to_string()),
            );
            obj.insert("updated_at".to_string(), Value::String(utc_now()));
            if verdict == "block" {
                let blocked_on = obj
                    .entry("blocked_on".to_string())
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(arr) = blocked_on {
                    if !arr.iter().any(|v| v.as_str() == Some("ship-gate")) {
                        arr.push(Value::String("ship-gate".to_string()));
                    }
                }
            }
        }
        atomic_write_json(&mpath, &manifest)?;
        let receipt = serde_json::json!({
            "receipt_version": 1,
            "run_id": run_id,
            "query_sha256": manifest.get("query_sha256"),
            "route_sha256": manifest.get("route_sha256"),
            "verdict": verdict,
            "checks": checks,
            "usage": manifest.get("usage"),
            "budget": manifest.get("budget"),
            "approvals": manifest.get("approvals"),
            "artifacts": manifest.get("artifacts"),
            "events_path": epath.to_string_lossy(),
            "issued_at": utc_now(),
        });
        atomic_write_json(&rpath, &receipt)?;
        receipt
    };
    record_event(run_id, "run.finalized", Some(&serde_json::json!({"verdict": verdict})), root)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "legion-wf025-manifest-{name}-{}-{}",
            std::process::id(),
            pseudo_random_hex(4)
        ));
        dir
    }

    #[test]
    fn run_dir_rejects_traversal() {
        assert!(run_dir("../escape", None).is_err());
        assert!(run_dir("a/b", None).is_err());
        assert!(run_dir(".hidden", None).is_err());
        assert!(run_dir("", None).is_err());
    }

    #[test]
    fn create_load_and_resume_round_trip() {
        let root = tmp_root("roundtrip");
        let route = serde_json::json!({"kind": "test"});
        let budget = serde_json::json!({"external_requests": 5, "workers": 2});
        let manifest = create_run("what is the sky color?", &route, &budget, Some(&root)).unwrap();
        let run_id = manifest["run_id"].as_str().unwrap().to_string();

        let loaded = load_run(&run_id, Some(&root)).unwrap();
        assert_eq!(loaded["status"], "running");
        assert_eq!(loaded["stages"]["route"]["status"], "done");

        let resume = resume_position(&loaded);
        assert_eq!(resume["next_stage"], "acquire");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn approve_clears_blocked_on_and_unblocks() {
        let root = tmp_root("approve");
        let route = serde_json::json!({});
        let budget = serde_json::json!({});
        let manifest = create_run("q", &route, &budget, Some(&root)).unwrap();
        let run_id = manifest["run_id"].as_str().unwrap().to_string();

        set_stage(&run_id, "acquire", "blocked", Some("needs-approval"), Some(&root)).unwrap();
        let blocked = load_run(&run_id, Some(&root)).unwrap();
        assert_eq!(blocked["status"], "blocked");
        assert_eq!(blocked["blocked_on"][0], "needs-approval");

        let approved = approve(&run_id, "needs-approval", "looks good", "user", Some(&root)).unwrap();
        assert_eq!(approved["status"], "running");
        assert!(approved["blocked_on"].as_array().unwrap().is_empty());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn finalize_writes_receipt_and_blocks_on_block_verdict() {
        let root = tmp_root("finalize");
        let route = serde_json::json!({});
        let budget = serde_json::json!({});
        let manifest = create_run("q", &route, &budget, Some(&root)).unwrap();
        let run_id = manifest["run_id"].as_str().unwrap().to_string();

        let receipt = finalize(&run_id, "block", &serde_json::json!({"ok": false}), Some(&root)).unwrap();
        assert_eq!(receipt["verdict"], "block");
        let final_manifest = load_run(&run_id, Some(&root)).unwrap();
        assert_eq!(final_manifest["status"], "blocked");
        assert_eq!(final_manifest["blocked_on"][0], "ship-gate");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn record_event_appends_jsonl() {
        let root = tmp_root("events");
        let route = serde_json::json!({});
        let budget = serde_json::json!({});
        let manifest = create_run("q", &route, &budget, Some(&root)).unwrap();
        let run_id = manifest["run_id"].as_str().unwrap().to_string();

        record_event(&run_id, "custom.event", Some(&serde_json::json!({"x": 1})), Some(&root)).unwrap();
        let (_, epath, _) = paths(&run_id, Some(&root)).unwrap();
        let contents = fs::read_to_string(&epath).unwrap();
        assert!(contents.lines().count() >= 2);
        assert!(contents.contains("custom.event"));

        let _ = fs::remove_dir_all(&root);
    }
}
