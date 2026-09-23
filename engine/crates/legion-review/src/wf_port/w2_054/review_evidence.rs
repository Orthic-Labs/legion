//! Port of `src/lib/review/review_evidence.py` — canonical P-1 evidence
//! receipts and the frozen Agent Room value gate.
//!
//! GAP: the Python CLI (`main`, argv parsing/subcommands) is not ported;
//! every function below is the pure/typed core Python's subcommands call
//! into, taking explicit paths instead of computing a module-relative
//! `RUNS_ROOT`. `RUNS_ROOT`/`MANIFEST_NAME`/`STATE_NAME`/`SAMPLE_NAME` are
//! kept as the same string constants; callers own where `.council-runs`
//! actually lives (Python derived it from `__file__`, which has no direct
//! Rust equivalent and is an integration/wiring concern outside this
//! module's owned paths).
//!
//! GAP: `archive_verified_room_memory`'s external `crypt put` call is
//! ported with the same injectable-runner shape Python already uses
//! (`runner=subprocess.run`), so the side effect stays unit-testable; the
//! default "real" runner (`real_command_runner`) shells out via
//! `std::process::Command`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::now_iso;

pub const MANIFEST_NAME: &str = "evidence.manifest.json";
pub const STATE_NAME: &str = "review.state.json";
pub const SAMPLE_NAME: &str = "value-gate.sample.json";

/// Mirrors Python's `ValueError` raised throughout this module: a fail-closed
/// rejection with a human-readable message, no separate machine code (the
/// Python source never keyed on a code for these, only the message text).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct EvidenceError(pub String);

impl EvidenceError {
    fn new(msg: impl Into<String>) -> Self {
        EvidenceError(msg.into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IoOrEvidenceError {
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, IoOrEvidenceError>;

fn read_json(path: &Path) -> Result<Value> {
    let text = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("value")
    ));
    fs::write(&temp, serde_json::to_string_pretty(value)?)?;
    fs::rename(&temp, path)?;
    Ok(())
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// `run` must be an immediate child of `runs_root`. Mirrors `_canonical_run_dir`.
fn canonical_run_dir(run_dir: &Path, runs_root: &Path) -> std::result::Result<PathBuf, EvidenceError> {
    let run = run_dir
        .canonicalize()
        .map_err(|e| EvidenceError::new(format!("cannot resolve run dir: {e}")))?;
    let root = runs_root
        .canonicalize()
        .map_err(|e| EvidenceError::new(format!("cannot resolve runs root: {e}")))?;
    if run.parent() != Some(root.as_path()) {
        return Err(EvidenceError::new(format!(
            "run must be an immediate child of canonical runs root: {}",
            root.display()
        )));
    }
    Ok(run)
}

const EXCLUDED_NAMES: &[&str] = &[
    "runtime.json",
    ".serve-config.json",
    "claude-mcp.json",
    "minimax-mcp.json",
    "service.stdout.log",
    "service.stderr.log",
    "room.sqlite3",
    "room.sqlite3-wal",
    "room.sqlite3-shm",
];

/// All substantive run artifacts under `run_dir`, sorted by POSIX-style
/// relative path. Mirrors `_artifact_paths`.
fn artifact_paths(run_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let excluded: HashSet<PathBuf> = [run_dir.join(MANIFEST_NAME), run_dir.join(STATE_NAME)]
        .into_iter()
        .collect();
    let mut out = Vec::new();
    fn walk(dir: &Path, run_dir: &Path, excluded: &HashSet<PathBuf>, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                walk(&path, run_dir, excluded, out)?;
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if excluded.contains(&path) {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if EXCLUDED_NAMES.contains(&name)
                || name.ends_with(".credentials.json")
                || name.ends_with(".tmp")
            {
                continue;
            }
            out.push(path);
        }
        Ok(())
    }
    walk(run_dir, run_dir, &excluded, &mut out)?;
    out.sort_by_key(|p| relative_posix(run_dir, p));
    Ok(out)
}

fn relative_posix(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Hash every run artifact and record the receipt in state + manifest.
/// Mirrors `pin_run_evidence`.
pub fn pin_run_evidence(run_dir: &Path, runs_root: &Path) -> Result<Value> {
    fs::create_dir_all(run_dir)?;
    let run = canonical_run_dir(run_dir, runs_root)?;
    let state_path = run.join(STATE_NAME);
    let mut state: Value = if state_path.is_file() {
        read_json(&state_path)?
    } else {
        json!({"schema_version": 1})
    };
    let mut artifacts = Vec::new();
    for path in artifact_paths(&run)? {
        let sha256 = sha256_file(&path)?;
        let bytes = fs::metadata(&path)?.len();
        artifacts.push(json!({
            "path": relative_posix(&run, &path),
            "sha256": sha256,
            "bytes": bytes,
        }));
    }
    let run_name = run
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    let now = now_iso();
    let evidence = json!({
        "schema_version": 1,
        "run_id": run_name.clone(),
        "artifact_root": run.to_string_lossy(),
        "artifacts": artifacts,
        "pinned_at": now.clone(),
    });
    state["run_id"] = json!(run_name);
    state["evidence"] = evidence.clone();
    state["updated_at"] = json!(now);
    write_json(&state_path, &state)?;
    let mut manifest = evidence;
    manifest["state_path"] = json!(STATE_NAME);
    write_json(&run.join(MANIFEST_NAME), &manifest)?;
    Ok(manifest)
}

/// Mirrors `verify_run_evidence`.
pub fn verify_run_evidence(run_dir: &Path, runs_root: &Path) -> Result<Value> {
    let run = canonical_run_dir(run_dir, runs_root)?;
    let state_path = run.join(STATE_NAME);
    let manifest_path = run.join(MANIFEST_NAME);
    if !state_path.is_file() || !manifest_path.is_file() {
        return Ok(json!({
            "ok": false,
            "mismatches": [{"path": STATE_NAME, "reason": "pin_missing"}],
        }));
    }
    let state = read_json(&state_path)?;
    let manifest = read_json(&manifest_path)?;
    let state_evidence = state.get("evidence").cloned().unwrap_or(Value::Null);
    let run_name = run.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let mut mismatches: Vec<Value> = Vec::new();
    if state_evidence.get("run_id").and_then(Value::as_str) != Some(run_name)
        || manifest.get("run_id").and_then(Value::as_str) != Some(run_name)
    {
        mismatches.push(json!({"path": STATE_NAME, "reason": "run_id_mismatch"}));
    }
    if state_evidence.get("artifacts") != manifest.get("artifacts") {
        mismatches.push(json!({"path": MANIFEST_NAME, "reason": "state_manifest_mismatch"}));
    }

    let manifest_artifacts: Vec<Value> = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let expected: BTreeMap<String, &Value> = manifest_artifacts
        .iter()
        .filter_map(|item| item.get("path").and_then(Value::as_str).map(|p| (p.to_string(), item)))
        .collect();
    let actual_paths_vec = artifact_paths(&run)?;
    let actual_paths: HashMap<String, PathBuf> = actual_paths_vec
        .into_iter()
        .map(|p| (relative_posix(&run, &p), p))
        .collect();
    for (relative, item) in &expected {
        match actual_paths.get(relative) {
            None => mismatches.push(json!({"path": relative, "reason": "missing"})),
            Some(path) => {
                let actual_sha = sha256_file(path)?;
                let actual_bytes = fs::metadata(path)?.len();
                let expected_sha = item.get("sha256").and_then(Value::as_str).unwrap_or("");
                let expected_bytes = item.get("bytes").and_then(Value::as_u64);
                if actual_sha != expected_sha || Some(actual_bytes) != expected_bytes {
                    mismatches.push(json!({"path": relative, "reason": "digest_mismatch"}));
                }
            }
        }
    }
    let actual_keys: BTreeSet<&String> = actual_paths.keys().collect();
    let expected_keys: BTreeSet<&String> = expected.keys().collect();
    for relative in actual_keys.difference(&expected_keys) {
        mismatches.push(json!({"path": relative, "reason": "unpinned"}));
    }
    let ok = mismatches.is_empty();
    Ok(json!({
        "ok": ok,
        "run_id": run_name,
        "mismatches": mismatches,
        "artifacts": manifest_artifacts,
    }))
}

/// Mirrors `schedule_finding`.
#[allow(clippy::too_many_arguments)]
pub fn schedule_finding(
    state_path: &Path,
    finding_id: &str,
    source_phase: &str,
    owner_phase: &str,
    claim: &str,
    missing_evidence: &str,
    source_ledger_digest: &str,
) -> Result<Value> {
    if source_phase.is_empty() || owner_phase.is_empty() {
        return Err(EvidenceError::new(
            "scheduled finding requires named source and owner phases",
        )
        .into());
    }
    if source_ledger_digest.len() != 64 {
        return Err(EvidenceError::new(
            "scheduled finding requires a SHA-256 source ledger digest",
        )
        .into());
    }
    let mut state: Value = if state_path.is_file() {
        read_json(state_path)?
    } else {
        json!({"schema_version": 1})
    };
    if state.get("scheduled_findings").is_none() {
        state["scheduled_findings"] = json!([]);
    }
    let scheduled = state["scheduled_findings"].as_array().cloned().unwrap_or_default();
    if let Some(prior) = scheduled
        .iter()
        .find(|item| item.get("finding_id").and_then(Value::as_str) == Some(finding_id))
    {
        if prior.get("status").and_then(Value::as_str) == Some("Open") {
            return Err(EvidenceError::new("open finding cannot be rescheduled").into());
        }
        return Err(EvidenceError::new(format!(
            "scheduled finding already exists: {finding_id}"
        ))
        .into());
    }
    let record = json!({
        "finding_id": finding_id,
        "source_phase": source_phase,
        "owner_phase": owner_phase,
        "claim": claim,
        "missing_evidence": missing_evidence,
        "source_ledger_digest": source_ledger_digest,
        "status": "Scheduled",
    });
    state["scheduled_findings"]
        .as_array_mut()
        .expect("scheduled_findings is an array")
        .push(record.clone());
    state["updated_at"] = json!(now_iso());
    write_json(state_path, &state)?;
    Ok(record)
}

/// Mirrors `reconcile_scheduled_findings`.
pub fn reconcile_scheduled_findings(
    state_path: &Path,
    current_phase: &str,
    phase_order: &[String],
) -> Result<Value> {
    let mut state = read_json(state_path)?;
    let current_index = phase_order.iter().position(|p| p == current_phase);
    if state.get("escalation_queue").is_none() {
        state["escalation_queue"] = json!([]);
    }
    let findings = state
        .get("scheduled_findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut updated_findings = Vec::with_capacity(findings.len());
    let mut escalations: Vec<Value> = state["escalation_queue"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for mut finding in findings {
        if finding.get("status").and_then(Value::as_str) != Some("Scheduled") {
            updated_findings.push(finding);
            continue;
        }
        let owner = finding
            .get("owner_phase")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let owner_index = phase_order.iter().position(|p| p == &owner);
        let finding_id = finding.get("finding_id").cloned().unwrap_or(Value::Null);
        if owner_index.is_none() {
            finding["status"] = json!("Escalated");
            if !escalations.contains(&finding_id) {
                escalations.push(finding_id);
            }
        } else {
            let owner_index = owner_index.unwrap();
            if current_phase == owner {
                finding["status"] = json!("Open");
                finding["reentered_at_phase"] = json!(current_phase);
            } else if let Some(ci) = current_index {
                if ci > owner_index {
                    finding["status"] = json!("Escalated");
                    if !escalations.contains(&finding_id) {
                        escalations.push(finding_id);
                    }
                }
            }
        }
        updated_findings.push(finding);
    }
    state["scheduled_findings"] = json!(updated_findings);
    state["escalation_queue"] = json!(escalations);
    state["updated_at"] = json!(now_iso());
    write_json(state_path, &state)?;
    Ok(state)
}

/// Persist a typed room ledger and bind its digest into `review.state.json`.
/// Mirrors `persist_finding_ledger`.
pub fn persist_finding_ledger(
    out_dir: &Path,
    ledger: &Value,
    lane: &str,
    transcript_path: Option<&str>,
) -> Result<Value> {
    if !matches!(lane, "room" | "room-fallback") {
        return Err(EvidenceError::new(format!("invalid room lane: {lane}")).into());
    }
    if ledger.get("schema_version").and_then(Value::as_i64) != Some(1) {
        return Err(EvidenceError::new("finding ledger schema_version must be 1").into());
    }
    if !ledger.get("findings").is_some_and(Value::is_array) {
        return Err(EvidenceError::new("finding ledger requires findings: []").into());
    }
    if !ledger.get("dispositions").is_some_and(Value::is_array) {
        return Err(EvidenceError::new("finding ledger requires dispositions: []").into());
    }
    fs::create_dir_all(out_dir)?;
    let ledger_path = out_dir.join("finding-ledger.json");
    write_json(&ledger_path, ledger)?;
    let digest = sha256_file(&ledger_path)?;
    let terminal = ["Folded", "Refuted"];
    let open_ids: Vec<Value> = ledger["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| {
            !terminal.contains(&f.get("status").and_then(Value::as_str).unwrap_or(""))
        })
        .map(|f| json!(f.get("finding_id").map(value_to_str_lossy).unwrap_or_default()))
        .collect();
    let state_path = out_dir.join(STATE_NAME);
    let mut state: Value = if state_path.is_file() {
        read_json(&state_path)?
    } else {
        json!({"schema_version": 1})
    };
    state["lane"] = json!(lane);
    state["finding_ledger"] = json!({"path": "finding-ledger.json", "sha256": digest});
    state["open_finding_count"] = json!(open_ids.len());
    state["open_finding_ids"] = json!(open_ids);
    state["updated_at"] = json!(now_iso());
    if let Some(t) = transcript_path {
        state["transcript_path"] = json!(t);
    }
    write_json(&state_path, &state)?;
    Ok(state)
}

fn value_to_str_lossy(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// Fail closed unless the room ledger is digest-valid and every exit
/// accepted. Mirrors `verify_terminal_finding_ledger`.
pub fn verify_terminal_finding_ledger(out_dir: &Path) -> Result<Value> {
    let state_path = out_dir.join(STATE_NAME);
    if !state_path.is_file() {
        return Err(EvidenceError::new("room finding ledger state is missing").into());
    }
    let state = read_json(&state_path)?;
    let descriptor = state.get("finding_ledger").cloned().unwrap_or(Value::Null);
    let relative = descriptor.get("path").and_then(Value::as_str);
    let expected_digest = descriptor.get("sha256").and_then(Value::as_str);
    let (relative, expected_digest) = match (relative, expected_digest) {
        (Some(r), Some(d)) if !r.is_empty() && !d.is_empty() => (r, d),
        _ => {
            return Err(EvidenceError::new("room finding ledger receipt is missing").into());
        }
    };
    let out_dir_resolved = out_dir
        .canonicalize()
        .map_err(|e| EvidenceError::new(format!("cannot resolve review directory: {e}")))?;
    let ledger_path = out_dir_resolved.join(relative);
    let ledger_path_resolved = if ledger_path.exists() {
        ledger_path
            .canonicalize()
            .map_err(|e| EvidenceError::new(format!("cannot resolve ledger path: {e}")))?
    } else {
        ledger_path.clone()
    };
    if ledger_path_resolved.strip_prefix(&out_dir_resolved).is_err() {
        return Err(EvidenceError::new("room finding ledger is outside the review directory").into());
    }
    if !ledger_path_resolved.is_file() || sha256_file(&ledger_path_resolved)? != expected_digest {
        return Err(EvidenceError::new("room finding ledger digest is invalid").into());
    }
    let ledger = read_json(&ledger_path_resolved)?;
    if ledger.get("schema_version").and_then(Value::as_i64) != Some(1) {
        return Err(EvidenceError::new("room finding ledger schema is invalid").into());
    }
    let findings = ledger.get("findings").and_then(Value::as_array);
    let dispositions = ledger.get("dispositions").and_then(Value::as_array);
    let receipts = ledger.get("receipts").and_then(Value::as_array);
    let (findings, dispositions, receipts) = match (findings, dispositions, receipts) {
        (Some(f), Some(d), Some(r)) => (f, d, r),
        _ => return Err(EvidenceError::new("room finding ledger structure is invalid").into()),
    };
    let mut receipt_index: HashMap<String, &Value> = HashMap::new();
    for receipt in receipts {
        if !receipt.is_object() {
            return Err(EvidenceError::new("room finding ledger receipt shape is invalid").into());
        }
        let receipt_id = receipt.get("receipt_id").and_then(Value::as_str);
        let receipt_id = match receipt_id {
            Some(id) if !id.is_empty() && !receipt_index.contains_key(id) => id,
            _ => return Err(EvidenceError::new("room finding ledger receipt id is invalid").into()),
        };
        let kind = receipt.get("kind").and_then(Value::as_str).unwrap_or("");
        if !matches!(kind, "file" | "artifact" | "measurement" | "web" | "scope_motion") {
            return Err(EvidenceError::new(format!(
                "room finding ledger receipt kind is invalid: {receipt_id}"
            ))
            .into());
        }
        if receipt.get("locator").and_then(Value::as_str).unwrap_or("").is_empty() {
            return Err(EvidenceError::new(format!(
                "room finding ledger receipt locator is missing: {receipt_id}"
            ))
            .into());
        }
        receipt_index.insert(receipt_id.to_string(), receipt);
    }
    let open_ids: Vec<String> = findings
        .iter()
        .filter(|f| {
            !matches!(f.get("status").and_then(Value::as_str), Some("Folded") | Some("Refuted"))
        })
        .map(|f| value_to_str_lossy(f.get("finding_id").unwrap_or(&Value::Null)))
        .collect();
    let open_finding_count = state.get("open_finding_count").and_then(Value::as_i64);
    if !open_ids.is_empty() || open_finding_count != Some(0) {
        return Err(EvidenceError::new(format!(
            "room finding ledger has open findings: {}",
            open_ids.join(",")
        ))
        .into());
    }
    let dispositions_by_finding: HashMap<String, &Value> = dispositions
        .iter()
        .map(|d| (value_to_str_lossy(d.get("finding_id").unwrap_or(&Value::Null)), d))
        .collect();
    for finding in findings {
        let finding_id = value_to_str_lossy(finding.get("finding_id").unwrap_or(&Value::Null));
        let disposition = dispositions_by_finding.get(&finding_id).ok_or_else(|| {
            EvidenceError::new(format!("room finding ledger lacks disposition: {finding_id}"))
        })?;
        let status = disposition.get("status").and_then(Value::as_str).unwrap_or("");
        if !matches!(status, "Accepted" | "Ruled") {
            return Err(EvidenceError::new(format!(
                "room finding ledger exit is not accepted: {finding_id}"
            ))
            .into());
        }
        let receipt_refs: Vec<String> = disposition
            .get("final_receipt_refs")
            .or_else(|| disposition.get("receipt_refs"))
            .and_then(Value::as_array)
            .map(|a| a.iter().map(value_to_str_lossy).collect())
            .unwrap_or_default();
        if receipt_refs.is_empty() {
            return Err(EvidenceError::new(format!(
                "room finding ledger exit lacks receipt: {finding_id}"
            ))
            .into());
        }
        let unknown: Vec<&String> = receipt_refs
            .iter()
            .filter(|r| !receipt_index.contains_key(r.as_str()))
            .collect();
        if !unknown.is_empty() {
            return Err(EvidenceError::new(format!(
                "room finding ledger exit has unknown receipt: {finding_id}"
            ))
            .into());
        }
        if finding.get("status").and_then(Value::as_str) == Some("Folded")
            && !receipt_refs.iter().any(|r| {
                receipt_index
                    .get(r.as_str())
                    .and_then(|rec| rec.get("kind"))
                    .and_then(Value::as_str)
                    == Some("artifact")
            })
        {
            return Err(EvidenceError::new(format!(
                "room finding ledger fold lacks artifact receipt: {finding_id}"
            ))
            .into());
        }
    }
    Ok(ledger)
}

/// Injectable command runner, mirroring Python's `runner=subprocess.run`
/// testability seam.
pub trait CommandRunner {
    fn run(&self, command: &[String]) -> std::io::Result<std::process::Output>;
}

/// The "real" runner: shells out via `std::process::Command`.
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, command: &[String]) -> std::io::Result<std::process::Output> {
        Command::new(&command[0]).args(&command[1..]).output()
    }
}

fn verify_relative_artifact(directory: &Path, relative: &str, expected_digest: &str) -> Result<PathBuf> {
    let path = directory.join(relative);
    let resolved = if path.exists() {
        path.canonicalize()
            .map_err(|e| EvidenceError::new(format!("cannot resolve artifact: {e}")))?
    } else {
        path.clone()
    };
    let dir_resolved = directory
        .canonicalize()
        .map_err(|e| EvidenceError::new(format!("cannot resolve directory: {e}")))?;
    if resolved.strip_prefix(&dir_resolved).is_err() {
        return Err(EvidenceError::new(format!(
            "fallback artifact is outside review directory: {relative}"
        ))
        .into());
    }
    if !resolved.is_file() || sha256_file(&resolved)? != expected_digest {
        return Err(EvidenceError::new(format!("fallback artifact digest is invalid: {relative}")).into());
    }
    Ok(resolved)
}

/// Archive verdict rationale only after the typed room ledger verifies
/// terminal. Mirrors `archive_verified_room_memory`.
pub fn archive_verified_room_memory(
    out_dir: &Path,
    scope: Option<&str>,
    crypt: &str,
    runner: &dyn CommandRunner,
) -> Result<Value> {
    let directory = out_dir
        .canonicalize()
        .map_err(|e| EvidenceError::new(format!("cannot resolve out_dir: {e}")))?;
    let ledger = verify_terminal_finding_ledger(&directory)?;
    let state_path = directory.join(STATE_NAME);
    let mut state = read_json(&state_path)?;
    let ledger_digest = state
        .get("finding_ledger")
        .and_then(|fl| fl.get("sha256"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let prior = state.get("memory").cloned().unwrap_or(Value::Null);
    if prior.get("status").and_then(Value::as_str) == Some("stored")
        && prior.get("ledger_sha256").and_then(Value::as_str) == ledger_digest.as_deref()
    {
        return Ok(prior);
    }

    let jury_path = directory.join("jury.verdict.json");
    let jury: Value = if jury_path.is_file() {
        read_json(&jury_path)?
    } else {
        json!({})
    };
    let transcript_relative = state.get("transcript_path").and_then(Value::as_str).map(str::to_string);
    let mut transcript_digest: Option<String> = None;
    if let Some(rel) = &transcript_relative {
        let transcript = directory.join(rel);
        let resolved = if transcript.exists() {
            transcript
                .canonicalize()
                .map_err(|e| EvidenceError::new(format!("cannot resolve transcript: {e}")))?
        } else {
            transcript.clone()
        };
        if resolved.strip_prefix(&directory).is_err() {
            return Err(EvidenceError::new("room transcript is outside the review directory").into());
        }
        if resolved.is_file() {
            transcript_digest = Some(sha256_file(&resolved)?);
        }
    }

    let memory_path = directory.join("room-memory.md");
    let dispositions_by_finding: HashMap<String, Value> = ledger["dispositions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|d| (value_to_str_lossy(d.get("finding_id").unwrap_or(&Value::Null)), d))
        .collect();
    let findings_all: Vec<Value> = ledger["findings"].as_array().cloned().unwrap_or_default();
    let mut findings_lines = Vec::new();
    for finding in &findings_all {
        let finding_id = value_to_str_lossy(finding.get("finding_id").unwrap_or(&Value::Null));
        let disposition = dispositions_by_finding.get(&finding_id);
        let claim = finding
            .get("claim")
            .and_then(Value::as_str)
            .unwrap_or(&finding_id);
        let status = finding.get("status").and_then(Value::as_str).unwrap_or("");
        let disp_status = disposition
            .and_then(|d| d.get("status"))
            .and_then(Value::as_str)
            .unwrap_or("");
        findings_lines.push(format!("- {claim}: {status} ({disp_status})"));
    }
    let synthesis = jury.get("synthesis").cloned().unwrap_or(json!({}));
    let majority = synthesis
        .get("majority_verdict")
        .and_then(Value::as_str)
        .unwrap_or("not-yet-recorded");
    let mut content_lines = vec![
        "---".to_string(),
        "source: agent-room".to_string(),
        format!("ledger_sha256: {}", ledger_digest.clone().unwrap_or_default()),
        format!(
            "transcript_sha256: {}",
            transcript_digest.clone().unwrap_or_else(|| "unavailable".to_string())
        ),
        "verified_terminal_ledger: true".to_string(),
        "---".to_string(),
        format!(
            "# Agent Room verdict — {}",
            directory.file_name().and_then(|n| n.to_str()).unwrap_or("")
        ),
        String::new(),
        format!("Jury verdict: {majority}"),
        String::new(),
        "## Finding exits".to_string(),
        String::new(),
    ];
    content_lines.extend(findings_lines);
    content_lines.push(String::new());
    fs::write(&memory_path, content_lines.join("\n"))?;

    let resolved_scope = scope.map(str::to_string).unwrap_or_else(|| {
        let cwd = std::env::current_dir().unwrap_or_default();
        let s = cwd
            .to_string_lossy()
            .replace(':', "-")
            .replace('\\', "-")
            .replace('/', "-");
        let trimmed = s.trim_matches('-').to_string();
        if trimmed.is_empty() {
            "global".to_string()
        } else {
            trimmed
        }
    });
    let run_name = directory.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let command: Vec<String> = vec![
        crypt.to_string(),
        "put".to_string(),
        format!("agent-room-{run_name}"),
        "--scope".to_string(),
        resolved_scope.clone(),
        "--file".to_string(),
        memory_path.to_string_lossy().to_string(),
        "--artifact-family".to_string(),
        "skill_output".to_string(),
        "--producer".to_string(),
        "agent_room".to_string(),
        "--record-type".to_string(),
        "review_verdict".to_string(),
    ];
    let completed = runner.run(&command);
    let mut record = json!({
        "ledger_sha256": ledger_digest,
        "transcript_sha256": transcript_digest,
        "path": "room-memory.md",
        "scope": resolved_scope,
    });
    match completed {
        Ok(output) if output.status.success() => {
            record["status"] = json!("stored");
        }
        Ok(output) => {
            record["status"] = json!("failed");
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            record["error"] = json!(if stderr.is_empty() {
                "crypt put failed".to_string()
            } else {
                stderr
            });
        }
        Err(e) => {
            record["status"] = json!("failed");
            record["error"] = json!(e.to_string());
        }
    }
    state["memory"] = record.clone();
    state["updated_at"] = json!(now_iso());
    write_json(&state_path, &state)?;
    Ok(record)
}

/// Seal an aborted room and enter the mandatory two-pass fallback lane.
/// Mirrors `start_room_fallback`.
pub fn start_room_fallback(
    state_path: &Path,
    pinned_packet_path: &str,
    pinned_packet_digest: &str,
    partial_ledger_path: &str,
    partial_ledger_digest: &str,
) -> Result<Value> {
    let directory = state_path.parent().unwrap_or(Path::new("."));
    let mut state = read_json(state_path)?;
    let lane = state.get("lane").and_then(Value::as_str).unwrap_or("");
    if !matches!(lane, "room" | "room-fallback") {
        return Err(EvidenceError::new("room fallback requires a room lane").into());
    }
    verify_relative_artifact(directory, pinned_packet_path, pinned_packet_digest)?;
    verify_relative_artifact(directory, partial_ledger_path, partial_ledger_digest)?;
    state["lane"] = json!("room-fallback");
    state["status"] = json!("fallback_required");
    state["fallback"] = json!({
        "status": "finding_pass_required",
        "pinned_packet": {"path": pinned_packet_path, "sha256": pinned_packet_digest},
        "partial_ledger": {"path": partial_ledger_path, "sha256": partial_ledger_digest},
        "partial_room_sealed": true,
        "merge_forbidden": true,
        "passes": [],
    });
    state["updated_at"] = json!(now_iso());
    write_json(state_path, &state)?;
    Ok(state)
}

/// Mirrors `advance_room_fallback`.
pub fn advance_room_fallback(
    state_path: &Path,
    completed_pass: &str,
    artifact_path: &str,
    artifact_digest: &str,
    author_acceptance_complete: Option<bool>,
) -> Result<Value> {
    let directory = state_path.parent().unwrap_or(Path::new("."));
    let mut state = read_json(state_path)?;
    let fallback = state.get("fallback").cloned().unwrap_or(json!({}));
    let merge_forbidden = fallback.get("merge_forbidden").and_then(Value::as_bool).unwrap_or(false);
    if state.get("lane").and_then(Value::as_str) != Some("room-fallback") || !merge_forbidden {
        return Err(EvidenceError::new("room fallback state is invalid").into());
    }
    verify_relative_artifact(directory, artifact_path, artifact_digest)?;
    let status = fallback.get("status").and_then(Value::as_str).unwrap_or("");
    let next_status = if completed_pass == "finding" && status == "finding_pass_required" {
        "disposition_check_required".to_string()
    } else if completed_pass == "disposition_check" && status == "disposition_check_required" {
        if author_acceptance_complete != Some(true) {
            return Err(EvidenceError::new(
                "fallback disposition check requires author acceptance",
            )
            .into());
        }
        "ready_for_verdict".to_string()
    } else {
        return Err(EvidenceError::new(format!(
            "invalid fallback pass transition: {status}->{completed_pass}"
        ))
        .into());
    };
    let mut fallback = fallback;
    let passes = fallback
        .get_mut("passes")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .unwrap_or_default();
    let mut passes = passes;
    passes.push(json!({
        "pass": completed_pass,
        "artifact": {"path": artifact_path, "sha256": artifact_digest},
        "author_acceptance_complete": author_acceptance_complete,
    }));
    fallback["passes"] = json!(passes);
    fallback["status"] = json!(next_status.clone());
    state["fallback"] = fallback;
    state["status"] = json!(next_status);
    state["updated_at"] = json!(now_iso());
    write_json(state_path, &state)?;
    Ok(state)
}

const FROZEN_MAX_BLOCKER_INFLATION: f64 = 1.1;
const FROZEN_MAX_ESCALATION_RATE_EXCLUSIVE: f64 = 0.5;
const FROZEN_DENOMINATOR: usize = 3;
const FROZEN_REQUIRED_LOOP: i64 = 2;
const FROZEN_ADJUDICATOR: &str = "the operator";

pub fn frozen_value_gate() -> Value {
    json!({
        "schema_version": 1,
        "denominator": FROZEN_DENOMINATOR,
        "exclude_self_referential": true,
        "required_loop": FROZEN_REQUIRED_LOOP,
        "material_change": [
            "disposition_action_flip",
            "jury_verdict_tier_change",
            "jury_blocker_add_remove",
        ],
        "max_blocker_inflation": FROZEN_MAX_BLOCKER_INFLATION,
        "correct_minority_erasure_allowed": false,
        "max_escalation_rate_exclusive": FROZEN_MAX_ESCALATION_RATE_EXCLUSIVE,
        "adjudicator": FROZEN_ADJUDICATOR,
    })
}

/// Mirrors `_material_changes`.
fn material_changes(sample: &Value) -> Vec<&'static str> {
    let blind = &sample["blind"];
    let debate = &sample["peer_debate"];
    let mut changes = Vec::new();
    let empty = json!({});
    let blind_d = blind.get("dispositions").unwrap_or(&empty).as_object();
    let debate_d = debate.get("dispositions").unwrap_or(&empty).as_object();
    let accepted_rejected: BTreeSet<&str> = ["accepted", "rejected"].into_iter().collect();
    let fold_actions: BTreeSet<&str> = ["folded", "fold"].into_iter().collect();
    let refute_actions: BTreeSet<&str> = ["refuted", "refute"].into_iter().collect();
    let mut disposition_flipped = false;
    if let (Some(bd), Some(dd)) = (blind_d, debate_d) {
        let common: BTreeSet<&String> = bd.keys().collect::<BTreeSet<_>>().intersection(&dd.keys().collect()).cloned().collect();
        for finding_id in common {
            let bv = value_to_str_lossy(&bd[finding_id]).to_lowercase();
            let dv = value_to_str_lossy(&dd[finding_id]).to_lowercase();
            let pair: BTreeSet<&str> = [bv.as_str(), dv.as_str()].into_iter().collect();
            if pair == accepted_rejected
                || (fold_actions.contains(bv.as_str()) && refute_actions.contains(dv.as_str()))
                || (refute_actions.contains(bv.as_str()) && fold_actions.contains(dv.as_str()))
            {
                disposition_flipped = true;
                break;
            }
        }
    }
    if disposition_flipped {
        changes.push("disposition_action_flip");
    }
    if blind.get("jury_verdict_tier") != debate.get("jury_verdict_tier") {
        changes.push("jury_verdict_tier_change");
    }
    let blind_blockers: BTreeSet<String> = blind
        .get("blockers")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(value_to_str_lossy).collect())
        .unwrap_or_default();
    let debate_blockers: BTreeSet<String> = debate
        .get("blockers")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(value_to_str_lossy).collect())
        .unwrap_or_default();
    if blind_blockers != debate_blockers {
        changes.push("jury_blocker_add_remove");
    }
    changes
}

/// Mirrors `_inflation_ratio`.
fn inflation_ratio(blind_count: usize, debate_count: usize) -> f64 {
    if blind_count == 0 {
        if debate_count == 0 {
            1.0
        } else {
            f64::INFINITY
        }
    } else {
        debate_count as f64 / blind_count as f64
    }
}

/// Mirrors `_branch_outcome`.
fn branch_outcome(run_dir: &Path) -> Result<Value> {
    let disposition_path = run_dir.join("review.disposition.json");
    let jury_path = run_dir.join("jury.verdict.json");
    if !disposition_path.is_file() || !jury_path.is_file() {
        return Err(EvidenceError::new(format!(
            "branch lacks disposition or Jury artifact: {}",
            run_dir.display()
        ))
        .into());
    }
    let disposition = read_json(&disposition_path)?;
    let mut actions: BTreeMap<String, String> = BTreeMap::new();
    for (index, item) in disposition
        .get("advisory_dispositions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let finding_id = item
            .get("finding_id")
            .or_else(|| item.get("finding"))
            .cloned();
        let action = item.get("action").cloned();
        let (finding_id, action) = match (finding_id, action) {
            (Some(f), Some(a)) if !f.is_null() && !a.is_null() => (f, a),
            _ => {
                return Err(EvidenceError::new(format!(
                    "disposition {index} lacks finding_id/finding or action: {}",
                    run_dir.display()
                ))
                .into())
            }
        };
        let key = value_to_str_lossy(&finding_id);
        let value = value_to_str_lossy(&action).to_lowercase();
        if let Some(existing) = actions.get(&key) {
            if existing != &value {
                return Err(EvidenceError::new(format!(
                    "conflicting disposition for {key}: {}",
                    run_dir.display()
                ))
                .into());
            }
        }
        actions.insert(key, value);
    }

    let jury = read_json(&jury_path)?;
    let tier = jury
        .get("synthesis")
        .and_then(|s| s.get("majority_verdict"))
        .and_then(Value::as_str);
    let tier = tier.ok_or_else(|| {
        EvidenceError::new(format!("Jury artifact lacks majority verdict: {}", run_dir.display()))
    })?;
    let mut blockers: BTreeSet<String> = BTreeSet::new();
    for juror in jury.get("jurors").and_then(Value::as_array).unwrap_or(&vec![]).to_owned() {
        if !juror.get("parsed_ok").map(|v| v.as_bool().unwrap_or(true)).unwrap_or(true) {
            continue;
        }
        for blocker in juror.get("blockers").and_then(Value::as_array).cloned().unwrap_or_default() {
            let normalized = match &blocker {
                Value::String(s) => s.trim().to_string(),
                Value::Object(m) if m.get("finding_id").is_some() => {
                    value_to_str_lossy(&m["finding_id"])
                }
                other => serde_json::to_string(other).unwrap_or_default(),
            };
            if !normalized.is_empty() {
                blockers.insert(normalized);
            }
        }
    }
    Ok(json!({
        "dispositions": actions,
        "jury_verdict_tier": tier,
        "blockers": blockers.into_iter().collect::<Vec<_>>(),
    }))
}

/// Mirrors `_peer_round_accounting`.
fn peer_round_accounting(run_dir: &Path) -> Result<Value> {
    let mut calls: i64 = 0;
    let mut tokens: i64 = 0;
    let mut complete = true;
    for name in ["council.rebuttal.json", "council.response.json"] {
        let path = run_dir.join(name);
        if !path.is_file() {
            return Err(EvidenceError::new(format!(
                "peer-debate branch lacks {name}: {}",
                run_dir.display()
            ))
            .into());
        }
        let doc = read_json(&path)?;
        let accounting = doc.get("accounting").cloned().unwrap_or(json!({}));
        let call_count = accounting.get("calls");
        let total_tokens = accounting.get("usage").and_then(|u| u.get("total_tokens"));
        let call_count_ok = call_count.and_then(Value::as_i64).is_some_and(|c| c >= 0)
            && !matches!(call_count, Some(Value::Bool(_)));
        let tokens_ok = total_tokens.and_then(Value::as_i64).is_some_and(|t| t >= 0)
            && !matches!(total_tokens, Some(Value::Bool(_)));
        if !call_count_ok || !tokens_ok {
            return Err(EvidenceError::new(format!(
                "invalid peer-round accounting: {}",
                path.display()
            ))
            .into());
        }
        calls += call_count.and_then(Value::as_i64).unwrap_or(0);
        tokens += total_tokens.and_then(Value::as_i64).unwrap_or(0);
        complete = complete && accounting.get("usage_complete").and_then(Value::as_bool) == Some(true);
    }
    let response = read_json(&run_dir.join("council.response.json"))?;
    let audit = response.get("resolution_audit").cloned().unwrap_or(json!({}));
    let resolutions = audit.get("resolutions").and_then(Value::as_array);
    let resolutions = match resolutions {
        Some(r) if !r.is_empty() => r,
        _ => {
            return Err(EvidenceError::new(format!(
                "peer response lacks artifact-derived escalation audit: {}",
                run_dir.display()
            ))
            .into())
        }
    };
    let escalation_count = resolutions
        .iter()
        .filter(|r| r.get("outcome").and_then(Value::as_str) == Some("unanswered"))
        .count();
    if audit.get("unanswered_count").and_then(Value::as_i64) != Some(escalation_count as i64) {
        return Err(EvidenceError::new(format!(
            "peer response escalation audit is inconsistent: {}",
            run_dir.display()
        ))
        .into());
    }
    Ok(json!({
        "calls": calls,
        "tokens": tokens,
        "usage_source": "provider",
        "usage_complete": complete,
        "escalation_count": escalation_count,
        "escalation_eligible": resolutions.len(),
        "escalation_rate": escalation_count as f64 / resolutions.len() as f64,
    }))
}

/// Mirrors `_validate_experiment_pair`.
fn validate_experiment_pair(blind: &Path, debate: &Path, review_kind: &str) -> Result<()> {
    let required = ["packet.md", STATE_NAME];
    for directory in [blind, debate] {
        for name in required {
            if !directory.join(name).is_file() {
                return Err(EvidenceError::new(format!(
                    "branch lacks pinned input identity artifact: {}",
                    directory.join(name).display()
                ))
                .into());
            }
        }
    }
    let blind_state = read_json(&blind.join(STATE_NAME))?;
    let debate_state = read_json(&debate.join(STATE_NAME))?;
    let same_packet = sha256_file(&blind.join("packet.md"))? == sha256_file(&debate.join("packet.md"))?;
    let blind_hash = blind_state.get("input_hash").and_then(Value::as_str).filter(|s| !s.is_empty());
    let same_input_hash = blind_hash.is_some() && blind_hash == debate_state.get("input_hash").and_then(Value::as_str);
    if !same_packet || !same_input_hash {
        return Err(EvidenceError::new("gate branches must use the same pinned input packet").into());
    }
    if blind_state.get("skill").and_then(Value::as_str) != Some(review_kind)
        || debate_state.get("skill").and_then(Value::as_str) != Some(review_kind)
    {
        return Err(EvidenceError::new("gate branch review kind does not match").into());
    }
    let blind_rebuttal = blind_state.get("rebuttal").cloned().unwrap_or(Value::Null);
    if !matches!(blind_rebuttal, Value::Null) && blind_rebuttal != Value::Bool(false) {
        return Err(EvidenceError::new("blind branch must not enable peer debate").into());
    }
    if debate_state.get("rebuttal") != Some(&Value::Bool(true))
        || debate_state.get("dissent_policy").and_then(Value::as_str) != Some("required_contest")
        || debate_state.get("peer_phase").and_then(Value::as_str) != Some("PeerDebate")
    {
        return Err(EvidenceError::new(
            "peer branch lacks predeclared required_contest/PeerDebate condition",
        )
        .into());
    }
    Ok(())
}

/// Build one immutable gate sample by copying and pinning both branches.
/// Mirrors `build_value_gate_sample`.
#[allow(clippy::too_many_arguments)]
pub fn build_value_gate_sample(
    run_id: &str,
    blind_run_dir: &Path,
    peer_debate_run_dir: &Path,
    review_kind: &str,
    self_referential: bool,
    operator_adjudication: &Value,
    runs_root: &Path,
) -> Result<Value> {
    if run_id.is_empty() || Path::new(run_id).file_name().and_then(|n| n.to_str()) != Some(run_id) {
        return Err(EvidenceError::new("run_id must be one path-safe segment").into());
    }
    if operator_adjudication.get("adjudicated_by").and_then(Value::as_str) != Some(FROZEN_ADJUDICATOR) {
        return Err(EvidenceError::new("value sample requires the operator adjudication").into());
    }

    let blind_source = blind_run_dir
        .canonicalize()
        .map_err(|e| EvidenceError::new(format!("cannot resolve blind run: {e}")))?;
    let debate_source = peer_debate_run_dir
        .canonicalize()
        .map_err(|e| EvidenceError::new(format!("cannot resolve peer debate run: {e}")))?;
    validate_experiment_pair(&blind_source, &debate_source, review_kind)?;
    let blind = branch_outcome(&blind_source)?;
    let debate = branch_outcome(&debate_source)?;
    let accounting = peer_round_accounting(&debate_source)?;
    let output = runs_root
        .canonicalize()
        .map_err(|e| EvidenceError::new(format!("cannot resolve runs root: {e}")))?
        .join(run_id);
    if output.exists() {
        return Err(EvidenceError::new(format!("value-gate run already exists: {}", output.display())).into());
    }

    let blind_names = ["packet.md", STATE_NAME, "review.disposition.json", "jury.verdict.json"];
    let debate_names = [
        "packet.md",
        STATE_NAME,
        "review.disposition.json",
        "jury.verdict.json",
        "council.advisory.json",
        "council.rebuttal.json",
        "council.response.json",
    ];
    for name in blind_names {
        if !blind_source.join(name).is_file() {
            return Err(EvidenceError::new(format!(
                "missing gate source artifact: {}",
                blind_source.join(name).display()
            ))
            .into());
        }
    }
    for name in debate_names {
        if !debate_source.join(name).is_file() {
            return Err(EvidenceError::new(format!(
                "missing gate source artifact: {}",
                debate_source.join(name).display()
            ))
            .into());
        }
    }

    fs::create_dir_all(&output)?;
    let blind_target = output.join("blind");
    fs::create_dir(&blind_target)?;
    for name in blind_names {
        fs::copy(blind_source.join(name), blind_target.join(name))?;
    }
    let debate_target = output.join("peer_debate");
    fs::create_dir(&debate_target)?;
    for name in debate_names {
        fs::copy(debate_source.join(name), debate_target.join(name))?;
    }

    let sample = json!({
        "schema_version": 1,
        "run_id": run_id,
        "review_kind": review_kind,
        "self_referential": self_referential,
        "loop": 2,
        "real_review": true,
        "blind": blind,
        "peer_debate": debate,
        "room": accounting,
        "operator_adjudication": operator_adjudication,
    });
    write_json(&output.join(SAMPLE_NAME), &sample)?;
    write_json(
        &output.join(STATE_NAME),
        &json!({
            "schema_version": 1,
            "run_id": run_id,
            "lane": "p-1-value-gate",
            "status": "complete",
            "updated_at": now_iso(),
        }),
    )?;
    pin_run_evidence(&output, runs_root)?;
    Ok(sample)
}

/// Mirrors `evaluate_frozen_value_gate`.
pub fn evaluate_frozen_value_gate(run_dirs: &[PathBuf], runs_root: &Path) -> Result<Value> {
    let mut runs = Vec::new();
    for p in run_dirs {
        runs.push(
            p.canonicalize()
                .map_err(|e| EvidenceError::new(format!("cannot resolve run dir: {e}")))?,
        );
    }
    if runs.len() != FROZEN_DENOMINATOR {
        return Err(EvidenceError::new("frozen value gate requires exactly 3 samples").into());
    }
    let names: BTreeSet<&std::ffi::OsStr> = runs.iter().filter_map(|r| r.file_name()).collect();
    if names.len() != runs.len() {
        return Err(EvidenceError::new("frozen value gate requires 3 distinct run ids").into());
    }

    let mut rows = Vec::new();
    let mut failures: BTreeSet<&'static str> = BTreeSet::new();
    for run in &runs {
        let run_name = run.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let verification = verify_run_evidence(run, runs_root)?;
        if !verification.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            return Err(EvidenceError::new(format!("run evidence is not pinned or digest-valid: {run_name}")).into());
        }
        let sample_path = run.join(SAMPLE_NAME);
        if !sample_path.is_file() {
            return Err(EvidenceError::new(format!("missing {SAMPLE_NAME}: {run_name}")).into());
        }
        let sample = read_json(&sample_path)?;
        if sample.get("run_id").and_then(Value::as_str) != Some(run_name) {
            return Err(EvidenceError::new(format!("sample run_id mismatch: {run_name}")).into());
        }
        if sample.get("self_referential").and_then(Value::as_bool).unwrap_or(false) {
            return Err(EvidenceError::new(
                "self-referential jury-plan packets are excluded from the gate",
            )
            .into());
        }
        if sample.get("loop").and_then(Value::as_i64) != Some(FROZEN_REQUIRED_LOOP)
            || sample.get("real_review").and_then(Value::as_bool) != Some(true)
        {
            return Err(EvidenceError::new(format!("sample is not a real Loop-2 review: {run_name}")).into());
        }
        let adjudication = sample.get("operator_adjudication").cloned().unwrap_or(json!({}));
        if adjudication.get("adjudicated_by").and_then(Value::as_str) != Some(FROZEN_ADJUDICATOR) {
            return Err(EvidenceError::new(format!("missing the operator adjudication: {run_name}")).into());
        }
        let room_metrics = sample.get("room").cloned().unwrap_or(json!({}));
        let calls = room_metrics.get("calls");
        let tokens = room_metrics.get("tokens");
        let calls_ok = calls.and_then(Value::as_i64).is_some_and(|c| c >= 0) && !matches!(calls, Some(Value::Bool(_)));
        let tokens_ok = tokens.and_then(Value::as_i64).is_some_and(|t| t >= 0) && !matches!(tokens, Some(Value::Bool(_)));
        if !calls_ok || !tokens_ok {
            return Err(EvidenceError::new(format!("room calls/tokens accounting is required: {run_name}")).into());
        }
        let usage_source = room_metrics.get("usage_source").and_then(Value::as_str).unwrap_or("");
        if room_metrics.get("usage_complete").and_then(Value::as_bool) != Some(true)
            || !matches!(usage_source, "provider" | "cli_self_report")
        {
            return Err(EvidenceError::new(format!(
                "room usage must be a complete provider or CLI self-report: {run_name}"
            ))
            .into());
        }

        let changes = material_changes(&sample);
        let blind_blockers = sample["blind"].get("blockers").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
        let debate_blockers = sample["peer_debate"].get("blockers").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
        let inflation = inflation_ratio(blind_blockers, debate_blockers);
        let minority_erased = adjudication.get("correct_minority_erased").and_then(Value::as_bool).unwrap_or(false);
        let escalation_rate = room_metrics.get("escalation_rate").and_then(Value::as_f64).unwrap_or(1.0);
        if inflation > FROZEN_MAX_BLOCKER_INFLATION {
            failures.insert("blocker_inflation");
        }
        if minority_erased {
            failures.insert("correct_minority_erased");
        }
        if escalation_rate >= FROZEN_MAX_ESCALATION_RATE_EXCLUSIVE {
            failures.insert("majority_escalation");
        }
        rows.push(json!({
            "run_id": run_name,
            "material_changes": changes,
            "blocker_inflation": inflation,
            "correct_minority_erased": minority_erased,
            "escalation_rate": escalation_rate,
            "calls": calls,
            "tokens": tokens,
            "usage_source": usage_source,
        }));
    }

    let material_count = rows
        .iter()
        .filter(|r| r["material_changes"].as_array().is_some_and(|a| !a.is_empty()))
        .count();
    if material_count == 0 {
        failures.insert("no_material_change");
    }
    Ok(json!({
        "schema_version": 1,
        "definition": frozen_value_gate(),
        "denominator": rows.len(),
        "material_change_count": material_count,
        "samples": rows,
        "passed": failures.is_empty(),
        "failures": failures.into_iter().collect::<Vec<_>>(),
        "evaluated_at": now_iso(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "legion-review-evidence-test-{}-{}",
            std::process::id(),
            now_iso().replace([':', '+', '.'], "-")
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn inflation_ratio_both_zero_is_one() {
        assert_eq!(inflation_ratio(0, 0), 1.0);
    }

    #[test]
    fn inflation_ratio_zero_blind_nonzero_debate_is_infinite() {
        assert!(inflation_ratio(0, 3).is_infinite());
    }

    #[test]
    fn inflation_ratio_normal() {
        assert_eq!(inflation_ratio(4, 8), 2.0);
    }

    #[test]
    fn pin_and_verify_round_trip() {
        let root = tempdir();
        let run = root.join("run-1");
        fs::create_dir_all(&run).unwrap();
        fs::write(run.join("packet.md"), b"hello").unwrap();
        let manifest = pin_run_evidence(&run, &root).unwrap();
        assert_eq!(manifest["run_id"], json!("run-1"));
        let verification = verify_run_evidence(&run, &root).unwrap();
        assert_eq!(verification["ok"], json!(true));
    }

    #[test]
    fn verify_reports_digest_mismatch_after_tamper() {
        let root = tempdir();
        let run = root.join("run-2");
        fs::create_dir_all(&run).unwrap();
        fs::write(run.join("packet.md"), b"hello").unwrap();
        pin_run_evidence(&run, &root).unwrap();
        fs::write(run.join("packet.md"), b"tampered").unwrap();
        let verification = verify_run_evidence(&run, &root).unwrap();
        assert_eq!(verification["ok"], json!(false));
        let mismatches = verification["mismatches"].as_array().unwrap();
        assert!(mismatches.iter().any(|m| m["reason"] == "digest_mismatch"));
    }

    #[test]
    fn verify_missing_pin_reports_pin_missing() {
        let root = tempdir();
        let run = root.join("run-3");
        fs::create_dir_all(&run).unwrap();
        let verification = verify_run_evidence(&run, &root).unwrap();
        assert_eq!(verification["ok"], json!(false));
        assert_eq!(verification["mismatches"][0]["reason"], json!("pin_missing"));
    }

    #[test]
    fn schedule_finding_rejects_short_digest() {
        let root = tempdir();
        let state_path = root.join(STATE_NAME);
        let err = schedule_finding(&state_path, "f1", "phase-a", "phase-b", "claim", "missing", "short").unwrap_err();
        assert!(err.to_string().contains("SHA-256"));
    }

    #[test]
    fn schedule_finding_then_reschedule_open_fails() {
        let root = tempdir();
        let state_path = root.join(STATE_NAME);
        let digest = "a".repeat(64);
        schedule_finding(&state_path, "f1", "phase-a", "phase-b", "claim", "missing", &digest).unwrap();
        let err = schedule_finding(&state_path, "f1", "phase-a", "phase-b", "claim", "missing", &digest).unwrap_err();
        assert!(err.to_string().contains("cannot be rescheduled"));
    }

    #[test]
    fn reconcile_moves_scheduled_to_open_at_owner_phase() {
        let root = tempdir();
        let state_path = root.join(STATE_NAME);
        let digest = "a".repeat(64);
        schedule_finding(&state_path, "f1", "phase-a", "phase-b", "claim", "missing", &digest).unwrap();
        let phases = vec!["phase-a".to_string(), "phase-b".to_string(), "phase-c".to_string()];
        let state = reconcile_scheduled_findings(&state_path, "phase-b", &phases).unwrap();
        assert_eq!(state["scheduled_findings"][0]["status"], json!("Open"));
    }

    #[test]
    fn reconcile_escalates_when_phase_passed_owner() {
        let root = tempdir();
        let state_path = root.join(STATE_NAME);
        let digest = "a".repeat(64);
        schedule_finding(&state_path, "f1", "phase-a", "phase-b", "claim", "missing", &digest).unwrap();
        let phases = vec!["phase-a".to_string(), "phase-b".to_string(), "phase-c".to_string()];
        let state = reconcile_scheduled_findings(&state_path, "phase-c", &phases).unwrap();
        assert_eq!(state["scheduled_findings"][0]["status"], json!("Escalated"));
        assert!(state["escalation_queue"]
            .as_array()
            .unwrap()
            .contains(&json!("f1")));
    }

    #[test]
    fn persist_and_verify_terminal_finding_ledger() {
        let root = tempdir();
        let ledger = json!({
            "schema_version": 1,
            "findings": [{"finding_id": "f1", "status": "Folded"}],
            "dispositions": [{"finding_id": "f1", "status": "Accepted", "final_receipt_refs": ["r1"]}],
            "receipts": [{"receipt_id": "r1", "kind": "artifact", "locator": "out.txt"}],
        });
        let state = persist_finding_ledger(&root, &ledger, "room", None).unwrap();
        assert_eq!(state["open_finding_count"], json!(0));
        let verified = verify_terminal_finding_ledger(&root).unwrap();
        assert_eq!(verified["schema_version"], json!(1));
    }

    #[test]
    fn verify_terminal_rejects_open_findings() {
        let root = tempdir();
        let ledger = json!({
            "schema_version": 1,
            "findings": [{"finding_id": "f1", "status": "Open"}],
            "dispositions": [],
            "receipts": [],
        });
        persist_finding_ledger(&root, &ledger, "room", None).unwrap();
        let err = verify_terminal_finding_ledger(&root).unwrap_err();
        assert!(err.to_string().contains("open findings"));
    }

    #[test]
    fn material_changes_detects_disposition_flip() {
        let sample = json!({
            "blind": {"dispositions": {"f1": "accepted"}, "jury_verdict_tier": "P1", "blockers": ["a"]},
            "peer_debate": {"dispositions": {"f1": "rejected"}, "jury_verdict_tier": "P1", "blockers": ["a"]},
        });
        let changes = material_changes(&sample);
        assert!(changes.contains(&"disposition_action_flip"));
        assert!(!changes.contains(&"jury_verdict_tier_change"));
    }

    #[test]
    fn frozen_value_gate_matches_locked_constants() {
        let gate = frozen_value_gate();
        assert_eq!(gate["denominator"], json!(3));
        assert_eq!(gate["max_blocker_inflation"], json!(1.1));
        assert_eq!(gate["adjudicator"], json!("the operator"));
    }
}
