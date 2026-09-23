//! Port of `skills/designer/engine/scripts/live/session-store.mjs`.
//!
//! `resolveProjectRoot`'s project-root-walk (`../context.mjs`, outside this
//! chunk) is not reimplemented: callers pass the resolved project root
//! directly as `cwd`. The CLI/JS `getLegacyLiveSessionsDir`/`getLiveSessionsDir`
//! helpers (`../lib/impeccable-paths.mjs`) are replicated inline as
//! `live_sessions_dir`/`legacy_live_sessions_dir` since only their path-join
//! logic (not the project-root walk) is needed here.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::manual_edits_buffer::now_iso;

const COMPLETED_PHASES: [&str; 2] = ["completed", "discarded"];

pub fn live_sessions_dir(cwd: &Path) -> PathBuf {
    cwd.join(".impeccable").join("live").join("sessions")
}

pub fn legacy_live_sessions_dir(cwd: &Path) -> PathBuf {
    cwd.join(".impeccable-live").join("sessions")
}

fn safe_session_id(id: &str) -> Result<&str, String> {
    let valid = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if valid {
        Ok(id)
    } else {
        Err(format!("invalid session id: {id}"))
    }
}

fn journal_path(root_dir: &Path, id: &str) -> Result<PathBuf, String> {
    Ok(root_dir.join(format!("{}.jsonl", safe_session_id(id)?)))
}

fn snapshot_path(root_dir: &Path, id: &str) -> Result<PathBuf, String> {
    Ok(root_dir.join(format!("{}.snapshot.json", safe_session_id(id)?)))
}

fn base_snapshot(id: &str) -> Value {
    json!({
        "id": id,
        "phase": "new",
        "pageUrl": null,
        "sourceFile": null,
        "previewFile": null,
        "previewMode": null,
        "expectedVariants": 0,
        "arrivedVariants": 0,
        "visibleVariant": null,
        "paramValues": {},
        "pendingEventSeq": null,
        "pendingEvent": null,
        "deliveryLease": null,
        "checkpointRevision": 0,
        "activeOwner": null,
        "sourceMarkers": {},
        "fallbackMode": null,
        "annotationArtifacts": [],
        "diagnostics": [],
        "updatedAt": null,
    })
}

struct Rebuilt {
    snapshot: Value,
    next_seq: i64,
}

fn rebuild_snapshot_from_journal(journal_path: &Path, id: &str) -> Rebuilt {
    let mut snapshot = base_snapshot(id);
    let mut diagnostics: Vec<Value> = Vec::new();
    let mut next_seq: i64 = 1;
    let contents = match fs::read_to_string(journal_path) {
        Ok(c) => c,
        Err(_) => {
            return Rebuilt {
                snapshot,
                next_seq,
            }
        }
    };
    for (i, line) in contents.split('\n').enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(entry) if entry.is_object() => {
                if let Some(seq) = entry.get("seq").and_then(Value::as_i64) {
                    next_seq = next_seq.max(seq + 1);
                }
                snapshot = apply_event(&snapshot, &entry, &[]);
            }
            Ok(_) => diagnostics.push(json!({
                "error": "journal_parse_failed",
                "line": i + 1,
                "message": "entry is not object",
            })),
            Err(err) => diagnostics.push(json!({
                "error": "journal_parse_failed",
                "line": i + 1,
                "message": err.to_string(),
            })),
        }
    }
    if let Some(arr) = snapshot.get_mut("diagnostics").and_then(Value::as_array_mut) {
        arr.extend(diagnostics);
    }
    Rebuilt { snapshot, next_seq }
}

fn to_pending_event(event: &Value) -> Value {
    let mut pending = event.clone();
    if let Some(obj) = pending.as_object_mut() {
        obj.remove("token");
    }
    pending
}

fn upsert_artifact(artifacts: &mut Vec<Value>, artifact: Value) {
    let dup = artifacts.iter().any(|existing| {
        existing.get("path") == artifact.get("path") && existing.get("type") == artifact.get("type")
    });
    if !dup {
        artifacts.push(artifact);
    }
}

/// Port of `applyEvent`. `entry` is `{ seq, id, type, ts, event }`; `event` is
/// looked up as `entry.event` falling back to `entry` itself (mirrors
/// `const event = entry.event || entry;`).
fn apply_event(snapshot: &Value, entry: &Value, inherited_diagnostics: &[Value]) -> Value {
    let event = entry.get("event").cloned().unwrap_or_else(|| entry.clone());
    let mut next = snapshot.clone();
    let obj = next.as_object_mut().expect("snapshot must be object");

    let param_values = snapshot
        .get("paramValues")
        .cloned()
        .unwrap_or_else(|| json!({}));
    obj.insert("paramValues".into(), param_values);
    let source_markers = snapshot
        .get("sourceMarkers")
        .cloned()
        .unwrap_or_else(|| json!({}));
    obj.insert("sourceMarkers".into(), source_markers);
    let mut annotation_artifacts: Vec<Value> = snapshot
        .get("annotationArtifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut diagnostics: Vec<Value> = snapshot
        .get("diagnostics")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let updated_at = entry
        .get("ts")
        .cloned()
        .unwrap_or_else(|| Value::String(now_iso()));
    obj.insert("updatedAt".into(), updated_at);

    if !inherited_diagnostics.is_empty() && diagnostics.is_empty() {
        diagnostics = inherited_diagnostics.to_vec();
    }

    let ev_type = event.get("type").and_then(Value::as_str).unwrap_or("");
    let phase_is_completed = |phase: &Value| {
        phase
            .as_str()
            .map(|p| COMPLETED_PHASES.contains(&p))
            .unwrap_or(false)
    };

    macro_rules! set_or_keep {
        ($key:expr, $val:expr) => {
            if let Some(v) = $val {
                obj.insert($key.into(), v.clone());
            }
        };
    }

    match ev_type {
        "generate" => {
            obj.insert("phase".into(), json!("generate_requested"));
            set_or_keep!("pageUrl", event.get("pageUrl"));
            set_or_keep!("expectedVariants", event.get("count"));
            set_or_keep!("pendingEventSeq", entry.get("seq"));
            obj.insert("pendingEvent".into(), to_pending_event(&event));
            if let Some(sp) = event.get("screenshotPath").and_then(Value::as_str) {
                upsert_artifact(
                    &mut annotation_artifacts,
                    json!({ "type": "screenshot", "path": sp }),
                );
            }
        }
        "variants_ready" | "agent_done" => {
            let carbonize = event.get("carbonize") == Some(&Value::Bool(true));
            obj.insert(
                "phase".into(),
                json!(if carbonize { "carbonize_required" } else { "variants_ready" }),
            );
            let source_file = event
                .get("sourceFile")
                .or_else(|| event.get("file"))
                .cloned();
            set_or_keep!("sourceFile", source_file.as_ref());
            set_or_keep!("previewFile", event.get("previewFile"));
            set_or_keep!("previewMode", event.get("previewMode"));
            // JS: event.arrivedVariants ?? (next.expectedVariants || next.arrivedVariants || 0)
            let is_truthy_num = |v: &Value| v.as_i64().map(|n| n != 0).unwrap_or(false);
            let arrived = match event.get("arrivedVariants") {
                Some(v) if !v.is_null() => v.clone(),
                _ => {
                    let exp = obj.get("expectedVariants").cloned().unwrap_or(Value::Null);
                    if is_truthy_num(&exp) {
                        exp
                    } else {
                        let cur = obj.get("arrivedVariants").cloned().unwrap_or(Value::Null);
                        if is_truthy_num(&cur) {
                            cur
                        } else {
                            json!(0)
                        }
                    }
                }
            };
            obj.insert("arrivedVariants".into(), arrived);
            obj.insert("pendingEventSeq".into(), Value::Null);
            obj.insert("pendingEvent".into(), Value::Null);
            if carbonize {
                diagnostics.push(json!({
                    "error": "carbonize_cleanup_required",
                    "file": event.get("file").cloned().unwrap_or(Value::Null),
                    "message": "Accepted variant still has carbonize markers that must be folded into source CSS.",
                }));
            }
        }
        "checkpoint" => {
            if phase_is_completed(obj.get("phase").unwrap_or(&Value::Null)) {
                diagnostics.push(json!({
                    "error": "checkpoint_after_terminal_ignored",
                    "phase": event.get("phase").cloned().unwrap_or(Value::Null),
                    "revision": event.get("revision").cloned().unwrap_or(Value::Null),
                }));
            } else {
                let event_rev = event.get("revision").and_then(Value::as_i64).unwrap_or(0);
                let cur_rev = obj
                    .get("checkpointRevision")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                if event_rev >= cur_rev {
                    set_or_keep!("phase", event.get("phase"));
                    set_or_keep!("checkpointRevision", event.get("revision"));
                    set_or_keep!("activeOwner", event.get("owner"));
                    set_or_keep!("arrivedVariants", event.get("arrivedVariants"));
                    set_or_keep!("visibleVariant", event.get("visibleVariant"));
                    set_or_keep!("sourceFile", event.get("sourceFile"));
                    set_or_keep!("previewFile", event.get("previewFile"));
                    set_or_keep!("previewMode", event.get("previewMode"));
                    if let Some(pv) = event.get("paramValues") {
                        obj.insert("paramValues".into(), pv.clone());
                    }
                } else {
                    diagnostics.push(json!({
                        "error": "stale_checkpoint_ignored",
                        "revision": event.get("revision").cloned().unwrap_or(Value::Null),
                    }));
                }
            }
        }
        "accept" | "accept_intent" => {
            obj.insert("phase".into(), json!("accept_requested"));
            let raw_variant = match event.get("variantId") {
                Some(v) if !v.is_null() => v.clone(),
                _ => obj.get("visibleVariant").cloned().unwrap_or(Value::Null),
            };
            // JS `Number(...)`: numeric strings/numbers convert; anything
            // else (including null) becomes NaN, encoded here as JSON null
            // since serde_json has no NaN.
            let variant_id = match &raw_variant {
                Value::Number(_) => raw_variant.clone(),
                Value::String(s) => s
                    .trim()
                    .parse::<f64>()
                    .map(|n| json!(n))
                    .unwrap_or(Value::Null),
                Value::Null => Value::Null,
                _ => Value::Null,
            };
            obj.insert("visibleVariant".into(), variant_id);
            if let Some(pv) = event.get("paramValues") {
                obj.insert("paramValues".into(), pv.clone());
            }
            set_or_keep!("pendingEventSeq", entry.get("seq"));
            obj.insert("pendingEvent".into(), to_pending_event(&event));
        }
        "manual_edit_apply" => {
            obj.insert("phase".into(), json!("manual_edit_apply_requested"));
            set_or_keep!("pageUrl", event.get("pageUrl"));
            set_or_keep!("pendingEventSeq", entry.get("seq"));
            obj.insert("pendingEvent".into(), to_pending_event(&event));
        }
        "steer" => {
            obj.insert("phase".into(), json!("steer_requested"));
            set_or_keep!("pageUrl", event.get("pageUrl"));
            set_or_keep!("pendingEventSeq", entry.get("seq"));
            obj.insert("pendingEvent".into(), to_pending_event(&event));
        }
        "steer_done" => {
            obj.insert("phase".into(), json!("steer_done"));
            let source_file = event
                .get("sourceFile")
                .or_else(|| event.get("file"))
                .cloned();
            set_or_keep!("sourceFile", source_file.as_ref());
            set_or_keep!("previewFile", event.get("previewFile"));
            set_or_keep!("previewMode", event.get("previewMode"));
            set_or_keep!("message", event.get("message"));
            obj.insert("pendingEventSeq".into(), Value::Null);
            obj.insert("pendingEvent".into(), Value::Null);
        }
        "discard" => {
            obj.insert("phase".into(), json!("discard_requested"));
            set_or_keep!("pendingEventSeq", entry.get("seq"));
            obj.insert("pendingEvent".into(), to_pending_event(&event));
        }
        "discarded" => {
            obj.insert("phase".into(), json!("discarded"));
            obj.insert("pendingEventSeq".into(), Value::Null);
            obj.insert("pendingEvent".into(), Value::Null);
        }
        "complete" => {
            obj.insert("phase".into(), json!("completed"));
            let source_file = event
                .get("sourceFile")
                .or_else(|| event.get("file"))
                .cloned();
            set_or_keep!("sourceFile", source_file.as_ref());
            set_or_keep!("previewFile", event.get("previewFile"));
            set_or_keep!("previewMode", event.get("previewMode"));
            obj.insert("pendingEventSeq".into(), Value::Null);
            obj.insert("pendingEvent".into(), Value::Null);
        }
        "agent_error" => {
            obj.insert("phase".into(), json!("agent_error"));
            obj.insert("pendingEventSeq".into(), Value::Null);
            obj.insert("pendingEvent".into(), Value::Null);
            diagnostics.push(json!({
                "error": "agent_error",
                "message": event.get("message").and_then(Value::as_str).unwrap_or("unknown agent error"),
            }));
        }
        other => {
            diagnostics.push(json!({ "error": "unknown_event_type", "type": other }));
        }
    }

    obj.insert("annotationArtifacts".into(), Value::Array(annotation_artifacts));
    obj.insert("diagnostics".into(), Value::Array(diagnostics));
    next
}

fn write_snapshot(path: &Path, snapshot: &Value) -> std::io::Result<()> {
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(snapshot).unwrap()),
    )
}

/// Faithful port of `createLiveSessionStore`. Owns its own in-memory
/// snapshot cache, matching the JS closure's `Map`.
pub struct LiveSessionStore {
    pub root_dir: PathBuf,
    pub legacy_root_dir: PathBuf,
    session_id: Option<String>,
    snapshot_cache: HashMap<String, (Value, i64)>,
}

impl LiveSessionStore {
    pub fn new(cwd: &Path, session_id: Option<String>) -> std::io::Result<Self> {
        let root_dir = live_sessions_dir(cwd);
        let legacy_root_dir = legacy_live_sessions_dir(cwd);
        fs::create_dir_all(&root_dir)?;
        Ok(Self {
            root_dir,
            legacy_root_dir,
            session_id,
            snapshot_cache: HashMap::new(),
        })
    }

    fn readable_journal_path(&self, id: &str) -> Result<PathBuf, String> {
        let primary = journal_path(&self.root_dir, id)?;
        if primary.exists() {
            return Ok(primary);
        }
        let legacy = journal_path(&self.legacy_root_dir, id)?;
        if legacy.exists() {
            return Ok(legacy);
        }
        Ok(primary)
    }

    fn load_cached_or_rebuild(&mut self, id: &str) -> Result<(Value, i64), String> {
        if let Some(cached) = self.snapshot_cache.get(id) {
            return Ok(cached.clone());
        }
        let journal_path = self.readable_journal_path(id)?;
        let rebuilt = rebuild_snapshot_from_journal(&journal_path, id);
        let out = (rebuilt.snapshot, rebuilt.next_seq);
        self.snapshot_cache.insert(id.to_string(), out.clone());
        Ok(out)
    }

    /// Normalizes `event`, appends it to the journal, applies it, writes the
    /// refreshed snapshot, and returns the new snapshot.
    pub fn append_event(&mut self, mut event: Value, fallback_id: Option<&str>) -> Result<Value, String> {
        if !event.is_object() {
            return Err("event object required".into());
        }
        let id = event
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| fallback_id.map(str::to_string))
            .ok_or_else(|| "event id required".to_string())?;
        if event.get("type").and_then(Value::as_str).is_none() {
            return Err("event type required".into());
        }
        event
            .as_object_mut()
            .unwrap()
            .insert("id".into(), json!(id));

        let journal_path = journal_path(&self.root_dir, &id)?;
        let snapshot_path = snapshot_path(&self.root_dir, &id)?;
        let legacy_journal_path = journal_path_unchecked(&self.legacy_root_dir, &id);
        if !journal_path.exists() && legacy_journal_path.exists() {
            let _ = fs::copy(&legacy_journal_path, &journal_path);
        }
        let (prior_snapshot, seq) = self.load_cached_or_rebuild(&id)?;
        let prior_diagnostics: Vec<Value> = prior_snapshot
            .get("diagnostics")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let ts = Value::String(now_iso());
        let entry = json!({
            "seq": seq,
            "id": id,
            "type": event.get("type"),
            "ts": ts,
            "event": event,
        });
        if let Some(parent) = journal_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&journal_path)
                .map_err(|e| e.to_string())?;
            writeln!(f, "{}", serde_json::to_string(&entry).unwrap()).map_err(|e| e.to_string())?;
        }
        let next = apply_event(&prior_snapshot, &entry, &prior_diagnostics);
        self.snapshot_cache
            .insert(id.clone(), (next.clone(), seq + 1));
        let _ = write_snapshot(&snapshot_path, &next);
        Ok(next)
    }

    /// Returns `None` when the session is completed/discarded and
    /// `include_completed` is false, matching `getSnapshot`.
    pub fn get_snapshot(&mut self, id: Option<&str>, include_completed: bool) -> Result<Option<Value>, String> {
        let id = id
            .map(str::to_string)
            .or_else(|| self.session_id.clone())
            .ok_or_else(|| "session id required".to_string())?;
        let journal_path = self.readable_journal_path(&id)?;
        let snapshot_path = snapshot_path(&self.root_dir, &id)?;
        let rebuilt = rebuild_snapshot_from_journal(&journal_path, &id);
        self.snapshot_cache
            .insert(id.clone(), (rebuilt.snapshot.clone(), rebuilt.next_seq));
        let _ = write_snapshot(&snapshot_path, &rebuilt.snapshot);
        let phase = rebuilt
            .snapshot
            .get("phase")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !include_completed && COMPLETED_PHASES.contains(&phase) {
            return Ok(None);
        }
        Ok(Some(rebuilt.snapshot))
    }

    pub fn list_active_sessions(&mut self) -> Vec<Value> {
        let mut ids: HashSet<String> = HashSet::new();
        for dir in [self.legacy_root_dir.clone(), self.root_dir.clone()] {
            if !dir.exists() {
                continue;
            }
            if let Ok(read_dir) = fs::read_dir(&dir) {
                for entry in read_dir.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if let Some(id) = name.strip_suffix(".jsonl") {
                            ids.insert(id.to_string());
                        }
                    }
                }
            }
        }
        let mut sorted: Vec<String> = ids.into_iter().collect();
        sorted.sort();
        sorted
            .into_iter()
            .filter_map(|id| self.get_snapshot(Some(&id), false).ok().flatten())
            .collect()
    }
}

fn journal_path_unchecked(root_dir: &Path, id: &str) -> PathBuf {
    root_dir.join(format!("{id}.jsonl"))
}
