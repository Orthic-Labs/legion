//! Port of `src/lib/review/agent_room_driver.py`.
//!
//! Resumable production driver for phase-gated Council Room reviews.
//!
//! `review_evidence` (`RUNS_ROOT`, `persist_finding_ledger`, `pin_run_evidence`,
//! `start_room_fallback`, `verify_run_evidence`, `verify_terminal_finding_ledger`)
//! is a *different* Python module, outside this chunk's owned scope
//! (`src/lib/review/agent_room_driver.py` only). This port keeps every
//! self-contained function faithful and fully tested, and expresses the
//! `review_evidence` dependency as the `RunsEvidence` trait so
//! `run_room_advisory` stays wired exactly like the Python (same call sites,
//! same order, same state-machine branches) without inventing behavior for a
//! module this task does not own. The integrator wires a concrete
//! `RunsEvidence` impl once `review_evidence` is ported.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

pub const ROOM_SEATS: [&str; 3] = ["claude", "codex", "minimax"];
pub const READINESS_TIMEOUT_SECS: u64 = 60;

#[derive(Debug)]
pub struct RoomDriverError(pub String);

impl std::fmt::Display for RoomDriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for RoomDriverError {}

impl From<io::Error> for RoomDriverError {
    fn from(e: io::Error) -> Self {
        RoomDriverError(e.to_string())
    }
}
impl From<serde_json::Error> for RoomDriverError {
    fn from(e: serde_json::Error) -> Self {
        RoomDriverError(e.to_string())
    }
}

fn read_json(path: &Path) -> Result<Value, RoomDriverError> {
    let raw = fs::read_to_string(path)
        .map_err(|e| RoomDriverError(format!("{}: {e}", path.display())))?;
    Ok(serde_json::from_str(&raw)?)
}

fn write_json(path: &Path, value: &Value) -> Result<(), RoomDriverError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp_path = path.with_file_name(tmp_name);
    let serialized = serde_json::to_string_pretty(value)?;
    fs::write(&tmp_path, serialized)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, RoomDriverError> {
    let bytes = fs::read(path).map_err(|e| RoomDriverError(format!("{}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_str(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

/// RFC3339 UTC timestamp with no external time crate, matching
/// `datetime.now(timezone.utc).isoformat()`'s `+00:00` offset style closely
/// enough for evidence/logging purposes (second precision).
pub fn now_iso() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let (y, m, d, hh, mm, ss) = civil_from_unix_secs(secs as i64);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}+00:00")
}

/// Howard Hinnant's `civil_from_days` algorithm, extended with time-of-day.
fn civil_from_unix_secs(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let hh = (time_of_day / 3600) as u32;
    let mm = ((time_of_day % 3600) / 60) as u32;
    let ss = (time_of_day % 60) as u32;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as i64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, hh, mm, ss)
}

/// Result of `discover_passed_value_gate`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PassedValueGate {
    pub path: String,
    pub sha256: String,
    pub denominator: Value,
    pub material_change_count: Value,
}

/// Verifier for a candidate value-gate result directory. Corresponds to
/// `review_evidence.verify_run_evidence`.
pub trait RunsEvidence {
    fn verify_run_evidence(&self, run_dir: &Path, runs_root: &Path) -> Result<bool, RoomDriverError>;
    fn persist_finding_ledger(
        &self,
        output: &Path,
        ledger: &Value,
        lane: &str,
        transcript_path: &str,
    ) -> Result<(), RoomDriverError>;
    fn verify_terminal_finding_ledger(&self, output: &Path) -> Result<(), RoomDriverError>;
    fn start_room_fallback(
        &self,
        state_path: &Path,
        pinned_packet_path: &str,
        pinned_packet_digest: &str,
        partial_ledger_path: &str,
        partial_ledger_digest: &str,
    ) -> Result<Value, RoomDriverError>;
    fn pin_run_evidence(&self, output: &Path, runs_root: &Path) -> Result<(), RoomDriverError>;
}

/// Port of `discover_passed_value_gate`. Scans `<runs_root>/value-gate-final-*/value-gate.result.json`
/// newest-first (lexicographic descending, matching Python's `sorted(..., reverse=True)`
/// over glob-returned paths), returning the first entry whose result is
/// `passed: true` and whose evidence verifies.
pub fn discover_passed_value_gate(
    runs_root: &Path,
    evidence: &dyn RunsEvidence,
) -> Result<PassedValueGate, RoomDriverError> {
    let root = runs_root
        .canonicalize()
        .unwrap_or_else(|_| runs_root.to_path_buf());
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = fs::read_dir(&root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() && name.starts_with("value-gate-final-") {
                let result_path = path.join("value-gate.result.json");
                if result_path.is_file() {
                    candidates.push(result_path);
                }
            }
        }
    }
    candidates.sort();
    candidates.reverse();

    for result_path in candidates {
        let result = match read_json(&result_path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let run_dir = result_path.parent().unwrap_or(&root);
        let verified = evidence.verify_run_evidence(run_dir, &root)?;
        let passed = result.get("passed").and_then(Value::as_bool).unwrap_or(false);
        if passed && verified {
            return Ok(PassedValueGate {
                path: result_path.to_string_lossy().into_owned(),
                sha256: sha256_file(&result_path)?,
                denominator: result.get("denominator").cloned().unwrap_or(Value::Null),
                material_change_count: result
                    .get("material_change_count")
                    .cloned()
                    .unwrap_or(Value::Null),
            });
        }
    }
    Err(RoomDriverError(
        "Agent Room frozen value gate is missing, failed, or digest-invalid".to_string(),
    ))
}

/// Port of `resolve_room_binary`. Checks, in order: an explicit override, the
/// `AGENT_ROOM_BIN` env var, `room` on `PATH`, then the two conventional
/// debug-build locations relative to this source tree's `rightkit` sibling.
pub fn resolve_room_binary(
    explicit: Option<&Path>,
    engine_dir: &Path,
) -> Result<PathBuf, RoomDriverError> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = explicit {
        candidates.push(p.to_path_buf());
    }
    if let Ok(env) = std::env::var("AGENT_ROOM_BIN") {
        if !env.is_empty() {
            candidates.push(PathBuf::from(env));
        }
    }
    if let Some(found) = which_room() {
        candidates.push(found);
    }
    candidates.push(engine_dir.join("rightkit").join("target").join("debug").join("room.exe"));
    candidates.push(engine_dir.join("rightkit").join("target").join("debug").join("room"));

    for candidate in candidates {
        if candidate.is_file() {
            return candidate
                .canonicalize()
                .or_else(|_| Ok::<PathBuf, RoomDriverError>(candidate));
        }
    }
    Err(RoomDriverError(
        "Agent Room CLI binary is unavailable; build agent-room-core first".to_string(),
    ))
}

/// Minimal `shutil.which("room")` equivalent: scan `PATH` for an executable
/// named `room` (or `room.exe` on Windows).
fn which_room() -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let exe_name = if cfg!(windows) { "room.exe" } else { "room" };
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(exe_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Port of `_room_id`: lowercase alnum-safe slug of the run directory's
/// basename, non-alnum runs collapsed to single `-`, trimmed of leading and
/// trailing `-`, prefixed `council-`.
pub fn room_id(out_dir: &Path) -> String {
    let name = out_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    let trimmed = safe.trim_matches('-');
    format!("council-{trimmed}")
}

/// Port of `_pending_link_delivery`.
pub fn pending_link_delivery(watch_url: &str) -> Value {
    json!({
        "required": true,
        "status": "pending",
        "created_at": now_iso(),
        "watch_url_sha256": sha256_str(watch_url),
    })
}

/// Port of `_active_result`.
pub fn active_result(state: &Value) -> Value {
    let room = state.get("room").cloned().unwrap_or(json!({}));
    let delivery = room.get("link_delivery").cloned().unwrap_or(json!({}));
    let pending = delivery.get("status").and_then(Value::as_str) != Some("acknowledged");
    let watch_url = room.get("watch_url").and_then(Value::as_str).unwrap_or("");
    let notification = json!({
        "required": pending,
        "status": if pending { "pending" } else { "acknowledged" },
        "message": format!("Council Room is live: {watch_url}"),
        "next_action": if pending { "send_to_user_then_acknowledge" } else { "wait_for_room_completion" },
    });
    json!({
        "schema_version": 1,
        "panel": "council",
        "lane": "room",
        "status": "room_active",
        "watch_url": watch_url,
        "user_notification": notification,
        "room": room,
        "jurors": [],
        "synthesis": {"majority_verdict": "PENDING_ROOM"},
    })
}

/// Port of `_fallback_result`.
pub fn fallback_result(state: &Value, diagnostic: &Value) -> Value {
    json!({
        "schema_version": 1,
        "panel": "council",
        "lane": "room-fallback",
        "status": "fallback_required",
        "room": state.get("room").cloned().unwrap_or(json!({})),
        "fallback": state.get("fallback").cloned().unwrap_or(Value::Null),
        "seat_failures": diagnostic.get("seat_failures").cloned().unwrap_or(json!([])),
        "jurors": [],
        "synthesis": {"majority_verdict": "FALLBACK_REQUIRED"},
    })
}

/// Port of `_safe_diagnostic`.
pub fn safe_diagnostic(room_dir: &Path, returncode: i32) -> Value {
    let path = room_dir.join("launch.failure.json");
    if path.is_file() {
        if let Ok(value) = read_json(&path) {
            if value.is_object() {
                return value;
            }
        }
    }
    let detail = if returncode != 0 {
        "Agent Room launcher exited before publishing launch.failure.json"
    } else {
        "Agent Room launcher did not publish durable readiness evidence"
    };
    let code = if returncode != 0 { "launch_failed" } else { "readiness_evidence_missing" };
    json!({
        "schema_version": 1,
        "status": "aborted",
        "stage": "launcher",
        "returncode": returncode,
        "seat_failures": [{
            "seat": "launcher",
            "code": code,
            "detail": detail,
        }],
    })
}

/// Port of `_readiness_complete`.
pub fn readiness_complete(room_dir: &Path) -> bool {
    let path = room_dir.join("seat-readiness.json");
    if !path.is_file() {
        return false;
    }
    let readiness = match read_json(&path) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut ready: BTreeSet<String> = BTreeSet::new();
    if let Some(seats) = readiness.get("seats").and_then(Value::as_array) {
        for seat in seats {
            let status_ready = seat.get("status").and_then(Value::as_str) == Some("ready");
            let has_seq = seat.get("ready_event_seq").map(Value::is_i64).unwrap_or(false)
                || seat.get("ready_event_seq").map(Value::is_u64).unwrap_or(false);
            if status_ready && has_seq {
                let seat_id = seat.get("seat_id").and_then(Value::as_str).unwrap_or("");
                let stripped = seat_id.strip_prefix("seat-").unwrap_or(seat_id);
                ready.insert(stripped.to_ascii_lowercase());
            }
        }
    }
    let status_ready = readiness.get("status").and_then(Value::as_str) == Some("ready");
    let expected: BTreeSet<String> = ROOM_SEATS.iter().map(|s| s.to_string()).collect();
    status_ready && ready == expected
}

/// Executes a room-binary subprocess. Abstracted so tests can substitute a
/// fake runner, matching the Python `Runner` callable parameter.
pub trait CommandRunner {
    fn run(&self, args: &[String]) -> io::Result<Output>;
}

/// Default runner: shells out via `std::process::Command`.
pub struct SystemRunner;
impl CommandRunner for SystemRunner {
    fn run(&self, args: &[String]) -> io::Result<Output> {
        Command::new(&args[0]).args(&args[1..]).output()
    }
}

fn run_ok(runner: &dyn CommandRunner, args: Vec<String>) -> i32 {
    match runner.run(&args) {
        Ok(out) => out.status.code().unwrap_or(-1),
        Err(_) => -1,
    }
}

/// Port of `run_room_advisory`.
///
/// `evidence` stands in for the `review_evidence` module (out of this
/// chunk's owned scope — see the module doc comment); `runner` stands in for
/// the Python `Runner` callable parameter (default `subprocess.run`).
#[allow(clippy::too_many_arguments)]
pub fn run_room_advisory(
    skill: &str,
    input_text: &str,
    out_dir: &Path,
    runs_root: &Path,
    workspace_root: &Path,
    room_binary: Option<&Path>,
    engine_dir: &Path,
    runner: &dyn CommandRunner,
    evidence: &dyn RunsEvidence,
    acknowledge_link_delivery: bool,
) -> Result<Value, RoomDriverError> {
    let output = out_dir
        .canonicalize()
        .unwrap_or_else(|_| out_dir.to_path_buf());
    let root = runs_root
        .canonicalize()
        .unwrap_or_else(|_| runs_root.to_path_buf());
    if output.parent() != Some(root.as_path()) {
        return Err(RoomDriverError(format!(
            "room review must be an immediate child of canonical runs root: {}",
            root.display()
        )));
    }
    fs::create_dir_all(&output)?;
    let workspace = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    if output.strip_prefix(&workspace).is_err() {
        return Err(RoomDriverError(
            "room review directory must be inside the scoped workspace".to_string(),
        ));
    }

    let gate = discover_passed_value_gate(&root, evidence)?;
    let packet_path = output.join("packet.md");
    fs::write(&packet_path, input_text)?;
    let packet_digest = sha256_file(&packet_path)?;
    let state_path = output.join("review.state.json");
    let mut state: Value = if state_path.is_file() {
        read_json(&state_path)?
    } else {
        json!({"schema_version": 1})
    };
    let room_dir = output.join("room");
    let binary = resolve_room_binary(room_binary, engine_dir)?;

    let lane = state.get("lane").and_then(Value::as_str).unwrap_or("");
    let input_hash = state.get("input_hash").and_then(Value::as_str).unwrap_or("");

    if lane == "room-fallback" && input_hash == packet_digest {
        let partial = state
            .get("fallback")
            .and_then(|f| f.get("partial_ledger"))
            .and_then(|p| p.get("path"))
            .and_then(Value::as_str);
        let mut diagnostic = json!({});
        if let Some(partial) = partial {
            let partial_path = output.join(partial);
            if partial_path.is_file() {
                diagnostic = read_json(&partial_path)?
                    .get("diagnostic")
                    .cloned()
                    .unwrap_or(json!({}));
            }
        }
        return Ok(fallback_result(&state, &diagnostic));
    }

    let resuming_active_room = lane == "room"
        && state.get("status").and_then(Value::as_str) == Some("room_active")
        && input_hash == packet_digest;
    if resuming_active_room {
        let delivery = state["room"].get("link_delivery").cloned();
        if !matches!(delivery, Some(Value::Object(_))) {
            let watch_url = state["room"]["watch_url"].as_str().unwrap_or("").to_string();
            state["room"]["link_delivery"] = pending_link_delivery(&watch_url);
            write_json(&state_path, &state)?;
            return Ok(active_result(&state));
        }
        let mut delivery = delivery.unwrap();
        if delivery.get("status").and_then(Value::as_str) != Some("acknowledged") {
            if !acknowledge_link_delivery {
                return Ok(active_result(&state));
            }
            delivery["status"] = json!("acknowledged");
            delivery["acknowledged_at"] = json!(now_iso());
            state["room"]["link_delivery"] = delivery;
            write_json(&state_path, &state)?;
        }
    }

    let lane = state.get("lane").and_then(Value::as_str).unwrap_or("");
    let input_hash = state.get("input_hash").and_then(Value::as_str).unwrap_or("");
    if lane != "room" || input_hash != packet_digest {
        if room_dir.exists() {
            return Err(RoomDriverError(
                "room run directory already exists for a different packet".to_string(),
            ));
        }
        let relative_packet = packet_path
            .strip_prefix(&workspace)
            .map_err(|_| RoomDriverError("packet path must be inside workspace".to_string()))?
            .to_string_lossy()
            .replace('\\', "/");
        let rid = room_id(&output);
        let command: Vec<String> = vec![
            binary.to_string_lossy().into_owned(),
            "spawn".to_string(),
            "--run-dir".to_string(),
            room_dir.to_string_lossy().into_owned(),
            "--room-id".to_string(),
            rid.clone(),
            "--workspace".to_string(),
            workspace.to_string_lossy().into_owned(),
            "--seats".to_string(),
            "claude,codex,minimax".to_string(),
            "--mode".to_string(),
            "debate".to_string(),
            "--scope-ref".to_string(),
            relative_packet,
            "--readiness-timeout-secs".to_string(),
            READINESS_TIMEOUT_SECS.to_string(),
            "--no-open".to_string(),
        ];
        let launching_state = json!({
            "schema_version": 1,
            "skill": skill,
            "status": "room_launching",
            "lane": "room",
            "input_hash": packet_digest,
            "rebuttal": false,
            "dissent_policy": "advocate",
            "peer_phase": "PeerDebate",
            "value_gate": {
                "path": gate.path.clone(),
                "sha256": gate.sha256.clone(),
                "denominator": gate.denominator.clone(),
                "material_change_count": gate.material_change_count.clone(),
            },
            "room": {
                "room_id": rid.clone(),
                "run_dir": "room",
                "transcript_path": "room/transcript.jsonl",
                "finding_ledger_path": "room/finding-ledger.json",
                "readiness_path": "room/seat-readiness.json",
                "session_path": "room/seat-sessions.json",
            },
            "auto_memory": true,
        });
        write_json(&state_path, &launching_state)?;

        let completed = runner.run(&command)?;
        let returncode = completed.status.code().unwrap_or(-1);
        if returncode != 0 || !readiness_complete(&room_dir) {
            if returncode == 0 {
                let _ = runner.run(&[
                    binary.to_string_lossy().into_owned(),
                    "abort".to_string(),
                    "--run-dir".to_string(),
                    room_dir.to_string_lossy().into_owned(),
                ]);
            }
            let diagnostic = safe_diagnostic(&room_dir, returncode);
            return enter_room_fallback(&room_dir, &state_path, &packet_digest, &diagnostic, evidence);
        }
        let runtime_path = room_dir.join("runtime.json");
        if !runtime_path.is_file() {
            let _ = runner.run(&[
                binary.to_string_lossy().into_owned(),
                "abort".to_string(),
                "--run-dir".to_string(),
                room_dir.to_string_lossy().into_owned(),
            ]);
            let diagnostic = safe_diagnostic(&room_dir, 0);
            return enter_room_fallback(&room_dir, &state_path, &packet_digest, &diagnostic, evidence);
        }
        let runtime = read_json(&runtime_path)?;
        let base_url = runtime.get("base_url").and_then(Value::as_str).unwrap_or("");
        let pairing_code = runtime.get("pairing_code").and_then(Value::as_str).unwrap_or("");
        let watch_url = format!("{base_url}/join/{pairing_code}");
        let active_room_id = runtime.get("room_id").cloned().unwrap_or(json!(rid));
        let active_state = json!({
            "schema_version": 1,
            "skill": skill,
            "status": "room_active",
            "lane": "room",
            "input_hash": packet_digest,
            "rebuttal": false,
            "dissent_policy": "advocate",
            "peer_phase": "PeerDebate",
            "value_gate": {
                "path": gate.path,
                "sha256": gate.sha256,
                "denominator": gate.denominator,
                "material_change_count": gate.material_change_count,
            },
            "room": {
                "room_id": active_room_id,
                "run_dir": "room",
                "watch_url": watch_url,
                "link_delivery": pending_link_delivery(&watch_url),
                "transcript_path": "room/transcript.jsonl",
                "finding_ledger_path": "room/finding-ledger.json",
                "readiness_path": "room/seat-readiness.json",
                "session_path": "room/seat-sessions.json",
            },
            "auto_memory": true,
        });
        write_json(&state_path, &active_state)?;
        return Ok(active_result(&active_state));
    }

    let ledger_path = room_dir.join("finding-ledger.json");
    if !ledger_path.is_file() {
        let returncode = run_ok(
            runner,
            vec![
                binary.to_string_lossy().into_owned(),
                "export".to_string(),
                "--run-dir".to_string(),
                room_dir.to_string_lossy().into_owned(),
            ],
        );
        if returncode != 0 {
            return Ok(active_result(&state));
        }
    }
    let transcript_path = room_dir.join("transcript.jsonl");
    if !ledger_path.is_file() || !transcript_path.is_file() {
        return Ok(active_result(&state));
    }

    let ledger = read_json(&ledger_path)?;
    evidence.persist_finding_ledger(&output, &ledger, "room", "room/transcript.jsonl")?;
    evidence.verify_terminal_finding_ledger(&output)?;
    let mut state = read_json(&state_path)?;
    state["skill"] = json!(skill);
    state["status"] = json!("awaiting_revision");
    state["input_hash"] = json!(packet_digest);
    state["room"] = state.get("room").cloned().unwrap_or(json!({}));
    state["auto_memory"] = json!(true);
    write_json(&state_path, &state)?;
    let advisory = json!({
        "schema_version": 1,
        "panel": "council",
        "lane": "room",
        "status": "complete",
        "room": state["room"],
        "findings": ledger.get("findings").cloned().unwrap_or(json!([])),
        "dispositions": ledger.get("dispositions").cloned().unwrap_or(json!([])),
        "receipts": ledger.get("receipts").cloned().unwrap_or(json!([])),
        "jurors": [],
        "synthesis": {
            "majority_verdict": "ADVISORY_COMPLETE",
            "finding_count": ledger.get("findings").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
        },
    });
    write_json(&output.join("council.advisory.json"), &advisory)?;
    evidence.pin_run_evidence(&output, &root)?;
    Ok(advisory)
}

fn enter_room_fallback(
    room_dir: &Path,
    state_path: &Path,
    packet_digest: &str,
    diagnostic: &Value,
    evidence: &dyn RunsEvidence,
) -> Result<Value, RoomDriverError> {
    fs::create_dir_all(room_dir)?;
    let mut artifacts = Vec::new();
    let mut entries: Vec<PathBuf> = fs::read_dir(room_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_file() && path.file_name().and_then(|n| n.to_str()) != Some("partial-room.json") {
            artifacts.push(json!({
                "path": format!("room/{}", path.file_name().unwrap().to_string_lossy()),
                "sha256": sha256_file(&path)?,
                "bytes": fs::metadata(&path)?.len(),
            }));
        }
    }
    let partial_path = room_dir.join("partial-room.json");
    let partial_value = json!({
        "schema_version": 1,
        "status": "aborted",
        "merge_forbidden": true,
        "diagnostic": diagnostic,
        "artifacts": artifacts,
    });
    write_json(&partial_path, &partial_value)?;
    let partial_digest = sha256_file(&partial_path)?;
    let state = evidence.start_room_fallback(
        state_path,
        "packet.md",
        packet_digest,
        "room/partial-room.json",
        &partial_digest,
    )?;
    Ok(fallback_result(&state, diagnostic))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_dir(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "legion-review-wf_w2_050-room-{label}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn room_id_slugifies_and_trims() {
        assert_eq!(room_id(Path::new("/tmp/My Run!!2024")), "council-my-run-2024");
        assert_eq!(room_id(Path::new("---weird---")), "council-weird");
        assert_eq!(room_id(Path::new("plain")), "council-plain");
    }

    #[test]
    fn pending_link_delivery_hashes_watch_url() {
        let v = pending_link_delivery("https://example/join/abc");
        assert_eq!(v["required"], json!(true));
        assert_eq!(v["status"], json!("pending"));
        assert_eq!(v["watch_url_sha256"], json!(sha256_str("https://example/join/abc")));
    }

    #[test]
    fn active_result_pending_when_delivery_unacknowledged() {
        let state = json!({
            "room": {
                "watch_url": "https://example/join/xyz",
                "link_delivery": {"status": "pending"},
            }
        });
        let result = active_result(&state);
        assert_eq!(result["status"], json!("room_active"));
        assert_eq!(result["user_notification"]["required"], json!(true));
        assert_eq!(
            result["user_notification"]["next_action"],
            json!("send_to_user_then_acknowledge")
        );
    }

    #[test]
    fn active_result_acknowledged_when_delivery_done() {
        let state = json!({
            "room": {
                "watch_url": "https://example/join/xyz",
                "link_delivery": {"status": "acknowledged"},
            }
        });
        let result = active_result(&state);
        assert_eq!(result["user_notification"]["required"], json!(false));
        assert_eq!(
            result["user_notification"]["next_action"],
            json!("wait_for_room_completion")
        );
    }

    #[test]
    fn fallback_result_carries_seat_failures() {
        let state = json!({"room": {"room_id": "council-x"}, "fallback": {"a": 1}});
        let diagnostic = json!({"seat_failures": [{"seat": "codex", "code": "quota"}]});
        let result = fallback_result(&state, &diagnostic);
        assert_eq!(result["status"], json!("fallback_required"));
        assert_eq!(result["seat_failures"][0]["seat"], json!("codex"));
        assert_eq!(result["room"]["room_id"], json!("council-x"));
    }

    #[test]
    fn safe_diagnostic_reads_launch_failure_file_when_present() {
        let dir = tmp_dir("diag-present");
        let payload = json!({"schema_version": 1, "status": "custom"});
        fs::write(dir.join("launch.failure.json"), payload.to_string()).unwrap();
        let got = safe_diagnostic(&dir, 1);
        assert_eq!(got, payload);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn safe_diagnostic_synthesizes_when_missing_nonzero_returncode() {
        let dir = tmp_dir("diag-missing-nonzero");
        let got = safe_diagnostic(&dir, 7);
        assert_eq!(got["returncode"], json!(7));
        assert_eq!(got["seat_failures"][0]["code"], json!("launch_failed"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn safe_diagnostic_synthesizes_when_missing_zero_returncode() {
        let dir = tmp_dir("diag-missing-zero");
        let got = safe_diagnostic(&dir, 0);
        assert_eq!(got["seat_failures"][0]["code"], json!("readiness_evidence_missing"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn readiness_complete_requires_all_seats_ready_with_seq() {
        let dir = tmp_dir("readiness-complete");
        let readiness = json!({
            "status": "ready",
            "seats": [
                {"seat_id": "seat-claude", "status": "ready", "ready_event_seq": 1},
                {"seat_id": "seat-codex", "status": "ready", "ready_event_seq": 2},
                {"seat_id": "seat-minimax", "status": "ready", "ready_event_seq": 3},
            ]
        });
        fs::write(dir.join("seat-readiness.json"), readiness.to_string()).unwrap();
        assert!(readiness_complete(&dir));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn readiness_complete_false_when_seat_missing() {
        let dir = tmp_dir("readiness-partial");
        let readiness = json!({
            "status": "ready",
            "seats": [
                {"seat_id": "seat-claude", "status": "ready", "ready_event_seq": 1},
                {"seat_id": "seat-codex", "status": "ready", "ready_event_seq": 2},
            ]
        });
        fs::write(dir.join("seat-readiness.json"), readiness.to_string()).unwrap();
        assert!(!readiness_complete(&dir));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn readiness_complete_false_when_file_absent() {
        let dir = tmp_dir("readiness-absent");
        assert!(!readiness_complete(&dir));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn readiness_complete_false_when_seq_not_int() {
        let dir = tmp_dir("readiness-badseq");
        let readiness = json!({
            "status": "ready",
            "seats": [
                {"seat_id": "seat-claude", "status": "ready", "ready_event_seq": "one"},
                {"seat_id": "seat-codex", "status": "ready", "ready_event_seq": 2},
                {"seat_id": "seat-minimax", "status": "ready", "ready_event_seq": 3},
            ]
        });
        fs::write(dir.join("seat-readiness.json"), readiness.to_string()).unwrap();
        assert!(!readiness_complete(&dir));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_room_binary_finds_explicit_path() {
        let dir = tmp_dir("resolve-explicit");
        let bin = dir.join("room");
        fs::write(&bin, b"stub").unwrap();
        let resolved = resolve_room_binary(Some(&bin), &dir).unwrap();
        assert!(resolved.ends_with("room"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_room_binary_errors_when_nothing_found() {
        let dir = tmp_dir("resolve-missing");
        let err = resolve_room_binary(None, &dir.join("nowhere")).unwrap_err();
        assert!(err.0.contains("Agent Room CLI binary is unavailable"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn now_iso_matches_rfc3339_utc_shape() {
        let s = now_iso();
        // e.g. 2026-09-23T12:34:56+00:00
        assert_eq!(s.len(), 25);
        assert!(s.ends_with("+00:00"));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], "T");
    }

    #[test]
    fn civil_from_unix_secs_known_epoch() {
        // 2000-01-01T00:00:00Z = 946684800
        assert_eq!(civil_from_unix_secs(946_684_800), (2000, 1, 1, 0, 0, 0));
        // Unix epoch itself.
        assert_eq!(civil_from_unix_secs(0), (1970, 1, 1, 0, 0, 0));
    }

    struct NoopEvidence {
        verified: bool,
    }
    impl RunsEvidence for NoopEvidence {
        fn verify_run_evidence(&self, _run_dir: &Path, _runs_root: &Path) -> Result<bool, RoomDriverError> {
            Ok(self.verified)
        }
        fn persist_finding_ledger(
            &self,
            _output: &Path,
            _ledger: &Value,
            _lane: &str,
            _transcript_path: &str,
        ) -> Result<(), RoomDriverError> {
            Ok(())
        }
        fn verify_terminal_finding_ledger(&self, _output: &Path) -> Result<(), RoomDriverError> {
            Ok(())
        }
        fn start_room_fallback(
            &self,
            _state_path: &Path,
            _pinned_packet_path: &str,
            _pinned_packet_digest: &str,
            _partial_ledger_path: &str,
            _partial_ledger_digest: &str,
        ) -> Result<Value, RoomDriverError> {
            Ok(json!({}))
        }
        fn pin_run_evidence(&self, _output: &Path, _runs_root: &Path) -> Result<(), RoomDriverError> {
            Ok(())
        }
    }

    #[test]
    fn discover_passed_value_gate_picks_newest_passing_verified() {
        let root = tmp_dir("gate-root");
        for (name, passed) in [
            ("value-gate-final-0001", true),
            ("value-gate-final-0002", true),
            ("value-gate-final-0003", false),
        ] {
            let dir = root.join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("value-gate.result.json"),
                json!({"passed": passed, "denominator": 10, "material_change_count": 2}).to_string(),
            )
            .unwrap();
        }
        let evidence = NoopEvidence { verified: true };
        let gate = discover_passed_value_gate(&root, &evidence).unwrap();
        assert!(gate.path.contains("value-gate-final-0002"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn discover_passed_value_gate_errors_when_none_pass() {
        let root = tmp_dir("gate-root-none");
        fs::create_dir_all(root.join("value-gate-final-0001")).unwrap();
        fs::write(
            root.join("value-gate-final-0001").join("value-gate.result.json"),
            json!({"passed": false}).to_string(),
        )
        .unwrap();
        let evidence = NoopEvidence { verified: true };
        let err = discover_passed_value_gate(&root, &evidence).unwrap_err();
        assert!(err.0.contains("missing, failed, or digest-invalid"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn discover_passed_value_gate_errors_when_verification_fails() {
        let root = tmp_dir("gate-root-unverified");
        fs::create_dir_all(root.join("value-gate-final-0001")).unwrap();
        fs::write(
            root.join("value-gate-final-0001").join("value-gate.result.json"),
            json!({"passed": true}).to_string(),
        )
        .unwrap();
        let evidence = NoopEvidence { verified: false };
        let err = discover_passed_value_gate(&root, &evidence).unwrap_err();
        assert!(err.0.contains("missing, failed, or digest-invalid"));
        fs::remove_dir_all(&root).ok();
    }
}
