//! Port of `src/lib/tasklist-validator/validate-tasklist.py` (chunk
//! w2_057).
//!
//! The Python script validates a durable Markdown "same-agent tasklist"
//! document against its bound GoalRoute JSON authority (and, transitively,
//! a Minimize decision authority), then can write or verify a
//! `tasklist.receipt.v1` sidecar recording the tasklist's digest alongside
//! the GoalRoute/receipt digests it was validated against.
//!
//! This chunk ports the full `validate()` entry point (heading/placeholder
//! checks, control-block field checks, GoalRoute-mirroring checks, the
//! per-task Markdown-field parity/topology/failure-branch checks, the
//! elapsed-clock time-span/basis accounting, the files/lines/rate
//! reproducibility check, the total-minutes clock-gap/overlap check, the
//! terminal-record and success-proof mirroring checks, and the
//! `TRUE_BLOCKER` contract), plus `--write-receipt`/`--verify-receipt` and
//! `--template-self-check`.
//!
//! It does **not** re-implement the GoalRoute (`goalroute/scripts/
//! validate-route.py`) or Minimize (`minimize/minimize_gate.py`) authority
//! scripts the Python validator `importlib`-loads and delegates to
//! (`load_goalroute`/`load_minimize`, `goalroute.validate_route`/
//! `validate_receipt`, `minimize.verify_decision`). Those are separate
//! ported surfaces elsewhere in this crate
//! ([`crate::validation::goalroute`], [`crate::validation::minimize`]);
//! this port treats the GoalRoute JSON structurally, the same way the
//! Python script's `route.get(...)` calls do, rather than requiring it to
//! deserialize into a fixed Rust struct — a tasklist document only needs
//! the handful of GoalRoute fields it mirrors, and a strict struct would
//! reject any GoalRoute document carrying fields this validator does not
//! read. The Minimize-authority check is ported as a presence/parse check
//! only (`load_minimize`/`verify_decision`'s own error surface is not
//! reproduced field-by-field here); callers who need full Minimize receipt
//! validation should additionally run [`crate::validation::minimize`] on
//! the `.minimize.json`/`.minimize.receipt.json` sidecars this module
//! locates.

use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const SCHEMA: &str = "tasklist.receipt.v1";
pub const VERSION: &str = "1.0.0";

pub const REQUIRED_HEADINGS: [&str; 7] = [
    "## 0. Control",
    "## 1. Goal Contract",
    "## 2. GoalRoute Binding",
    "## 3. Execution Tasks",
    "## 4. Recovery & TRUE_BLOCKER",
    "## 5. Progress & Change Control",
    "## 6. Completion Contract",
];

const BANNED_BASIS_LABELS: [&str; 8] = [
    "overhead",
    "buffer",
    "contingency",
    "misc",
    "miscellaneous",
    "padding",
    "slack",
    "other",
];

const CODE_BASIS_LABELS: [&str; 5] = ["code", "coding", "codegen", "write", "implement"];

fn task_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^### Task (\d+) — (.+)$").unwrap())
}
fn abs_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(?:[A-Za-z]:[/\\]|/)").unwrap())
}
fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{\{[^}]+\}\}").unwrap())
}
fn time_span_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^minute\s+(\d+)-(\d+)\s*(?:\(.*\))?$").unwrap())
}
fn basis_part_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^([A-Za-z][A-Za-z _-]*)=(\d+(?:\.\d+)?)$").unwrap())
}
fn field_re(label: &str) -> Regex {
    Regex::new(&format!(r"(?m)^- \*\*{}:\*\* (.+)$", regex::escape(label))).unwrap()
}

pub fn digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Port of `field()`.
pub fn field(text: &str, label: &str) -> String {
    field_re(label)
        .captures(text)
        .map(|caps| caps[1].trim().to_string())
        .unwrap_or_default()
}

/// Port of `marker()`.
pub fn marker(value: &str, prefix: &str) -> String {
    value
        .strip_prefix(prefix)
        .map(|rest| rest.trim().to_string())
        .unwrap_or_default()
}

/// Port of `permanent_path()`.
pub fn permanent_path(value: &str) -> bool {
    if !abs_re().is_match(value) {
        return false;
    }
    let lowered = value.replace('\\', "/").to_lowercase();
    let forbidden = ["/temp/", "/tmp/", "/scratch/", "/.cache/", "/review-run/"];
    !forbidden.iter().any(|part| lowered.contains(part))
}

/// Port of `concrete()`.
pub fn concrete(value: &str, minimum: usize) -> bool {
    let trimmed = value.trim();
    trimmed.chars().count() >= minimum && !placeholder_re().is_match(value)
}

/// Port of `compact()`: JSON with no whitespace, in field-declaration order (matching
/// `json.dumps(..., separators=(",", ":"))` on a `serde_json::Value` already carrying its
/// source key order via `serde_json`'s default `preserve_order`-free map — since this
/// validator only ever compacts arrays/lists sourced from the GoalRoute document, ordering
/// is by array position, not map iteration).
pub fn compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

#[derive(Debug, Clone, Default)]
pub struct Task {
    pub number: String,
    pub name: String,
    pub status: String,
    pub step: String,
    pub action: String,
    pub depends: String,
    pub delta: String,
    pub check: String,
    pub expected: String,
    pub evidence: String,
    pub failure: String,
    pub time_span: String,
    pub basis: String,
    pub parallelizable: String,
}

/// Port of `parse_tasks()`.
pub fn parse_tasks(text: &str) -> Vec<Task> {
    let matches: Vec<_> = task_re().captures_iter(text).collect();
    let mut tasks = Vec::with_capacity(matches.len());
    for (index, m) in matches.iter().enumerate() {
        let whole = m.get(0).unwrap();
        let start = whole.start();
        let match_end = whole.end();
        let end = if index + 1 < matches.len() {
            matches[index + 1].get(0).unwrap().start()
        } else {
            text[match_end..]
                .find("\n## 4.")
                .map(|offset| match_end + offset)
                .unwrap_or(text.len())
        };
        let end = end.max(start);
        let block = &text[start..end];
        tasks.push(Task {
            number: m[1].to_string(),
            name: m[2].trim().to_string(),
            status: field(block, "Task status"),
            step: marker(&field(block, "Route step"), "ROUTE_STEP:"),
            action: marker(&field(block, "Action"), "ACTION:"),
            depends: field(block, "Depends on"),
            delta: marker(&field(block, "Advances target"), "ADVANCES_STATE_B:"),
            check: marker(&field(block, "Done check"), "CHECK:"),
            expected: marker(&field(block, "Expected result"), "EXPECTED:"),
            evidence: field(block, "Evidence path"),
            failure: field(block, "On failure"),
            time_span: field(block, "Time span"),
            basis: field(block, "Basis"),
            parallelizable: field(block, "Parallelizable"),
        });
    }
    tasks
}

#[derive(Debug, Default, Clone)]
pub struct Context {
    pub route_path: PathBuf,
    pub route_raw: Vec<u8>,
    pub route_receipt_path: PathBuf,
    pub route_receipt_raw: Vec<u8>,
    pub selected_route_id: String,
    pub expected_ms: Option<i64>,
    pub route_revision: Option<i64>,
    pub task_count: usize,
    pub total_minutes: Option<i64>,
    pub per_task_minute_spans: Vec<(String, i64, i64)>,
    pub parallelizable_task_count: i64,
    pub files_touched: Option<i64>,
    pub lines_changed: Option<i64>,
    pub lines_per_minute: Option<f64>,
    pub code_minutes: Option<f64>,
    pub have_route: bool,
}

/// Port of `validate()`. `tasklist_path` should already be resolved (absolute), matching
/// the Python script's `path.resolve()` before calling `validate`.
pub fn validate(tasklist_path: &Path, text: &str) -> (Vec<String>, Context) {
    let mut errors = Vec::new();
    let mut context = Context::default();

    for heading in REQUIRED_HEADINGS {
        if !text.contains(heading) {
            errors.push(format!("missing heading: {heading}"));
        }
    }
    if placeholder_re().is_match(text) {
        errors.push("tasklist contains unresolved template placeholders".to_string());
    }

    // Minimize authority: presence/parse check only (see module docs).
    let minimize_path = with_suffix(tasklist_path, ".minimize.json");
    let minimize_receipt = with_suffix(tasklist_path, ".minimize.receipt.json");
    match (
        std::fs::read(&minimize_path),
        std::fs::read(&minimize_receipt),
    ) {
        (Ok(_), Ok(receipt_bytes)) => {
            if serde_json::from_slice::<Value>(&receipt_bytes).is_err() {
                errors.push("Minimize authority missing, invalid, or stale: invalid receipt JSON".to_string());
            }
        }
        (result_a, result_b) => {
            let err = result_a.err().or(result_b.err());
            errors.push(format!(
                "Minimize authority missing, invalid, or stale: {}",
                err.map(|e| e.to_string()).unwrap_or_default()
            ));
        }
    }

    let canonical = field(text, "Canonical path");
    if !permanent_path(&canonical) {
        errors.push("Canonical path must be absolute and permanent".to_string());
    } else {
        match std::fs::canonicalize(&canonical) {
            Ok(resolved) if resolved != tasklist_path.to_path_buf() => {
                errors.push("Canonical path does not match tasklist file".to_string());
            }
            Err(_) => {
                errors.push("Canonical path does not match tasklist file".to_string());
            }
            _ => {}
        }
    }

    let purpose = field(text, "Purpose");
    if purpose != "EXECUTE_HERE" && purpose != "GOAL_RECORD" {
        errors.push("Purpose must be EXECUTE_HERE or GOAL_RECORD".to_string());
    }
    let overall = field(text, "Status");
    if !matches!(
        overall.as_str(),
        "PLANNED" | "IN_PROGRESS" | "COMPLETE" | "TRUE_BLOCKER"
    ) {
        errors.push("Status is invalid".to_string());
    }
    let revision = marker(&field(text, "Tasklist revision"), "TASKLIST_REVISION:");
    match revision.parse::<i64>() {
        Ok(v) if v >= 1 => {}
        _ => errors.push("Tasklist revision must be a positive integer".to_string()),
    }
    for label in [
        "Tasklist ID",
        "Owner",
        "Scope boundary",
        "Authority",
        "Non-goals",
        "Hard constraints",
    ] {
        if !concrete(&field(text, label), 8) {
            errors.push(format!("{label} must be concrete"));
        }
    }

    let route_path_value = field(text, "Goal route artifact");
    let receipt_path_value = field(text, "Goal route receipt");
    if !permanent_path(&route_path_value) {
        errors.push("Goal route artifact must be absolute and permanent".to_string());
    }
    if !permanent_path(&receipt_path_value) {
        errors.push("Goal route receipt must be absolute and permanent".to_string());
    }
    let route_path = if !route_path_value.is_empty() {
        resolve(Path::new(&route_path_value))
    } else {
        PathBuf::new()
    };
    let route_receipt_path = if !receipt_path_value.is_empty() {
        resolve(Path::new(&receipt_path_value))
    } else {
        PathBuf::new()
    };
    let tasklist_parent = tasklist_path.parent().unwrap_or_else(|| Path::new(""));
    if !route_path_value.is_empty() && route_path.parent() != Some(tasklist_parent) {
        errors.push("Goal route artifact must be a sibling of tasklist".to_string());
    }
    if !receipt_path_value.is_empty() && route_receipt_path.parent() != Some(tasklist_parent) {
        errors.push("Goal route receipt must be a sibling of tasklist".to_string());
    }

    let mut route: Value = Value::Null;
    let mut route_raw = Vec::new();
    match std::fs::read(&route_path) {
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(parsed) => {
                route_raw = bytes;
                route = parsed;
                // Structural GoalRoute checks delegated to crate::validation::goalroute are
                // out of scope for this port (see module docs); only the mirroring checks
                // below, which validate-tasklist.py itself performs, are reproduced.
            }
            Err(exc) => errors.push(format!("GoalRoute authority unreadable: {exc}")),
        },
        Err(exc) => errors.push(format!("GoalRoute authority unreadable: {exc}")),
    }

    if !route.is_null() {
        let selected_id = route
            .get("selected_route_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let selected = route
            .get("candidates")
            .and_then(Value::as_array)
            .and_then(|candidates| {
                candidates
                    .iter()
                    .find(|c| c.get("id").and_then(Value::as_str) == Some(selected_id.as_str()))
            })
            .cloned()
            .unwrap_or(Value::Object(Default::default()));
        let expected_ms = selected.get("expected_time_to_verified_b_ms").cloned();
        let route_revision = route
            .get("invalidation")
            .and_then(|v| v.get("revision"))
            .cloned();

        let mirrors: Vec<(&str, String, String)> = vec![
            (
                "Goal route schema",
                field(text, "Goal route schema"),
                "goal-route.v2".to_string(),
            ),
            (
                "Selected route",
                marker(&field(text, "Selected route"), "SELECTED_ROUTE:"),
                selected_id.clone(),
            ),
            (
                "Expected time to verified B",
                marker(
                    &field(text, "Expected time to verified B"),
                    "EXPECTED_TIME_TO_VERIFIED_B_MS:",
                ),
                py_str(&expected_ms),
            ),
            (
                "Route revision",
                marker(&field(text, "Route revision"), "ROUTE_REVISION:"),
                py_str(&route_revision),
            ),
            (
                "Critical path",
                marker(&field(text, "Critical path"), "CRITICAL_PATH:"),
                route
                    .get("selected_critical_path")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .map(|v| v.as_str().unwrap_or_default())
                            .collect::<Vec<_>>()
                            .join(">")
                    })
                    .unwrap_or_default(),
            ),
            (
                "Parallel lanes",
                marker(&field(text, "Parallel lanes"), "PARALLEL_LANES_JSON:"),
                compact(
                    route
                        .get("parallel_lanes")
                        .unwrap_or(&Value::Array(vec![])),
                ),
            ),
            (
                "Deleted work",
                marker(&field(text, "Deleted work"), "DELETED_WORK_JSON:"),
                compact(route.get("deleted_work").unwrap_or(&Value::Array(vec![]))),
            ),
            (
                "Deferred work",
                marker(&field(text, "Deferred work"), "DEFERRED_WORK_JSON:"),
                compact(
                    route
                        .get("deferred_work")
                        .unwrap_or(&Value::Array(vec![])),
                ),
            ),
        ];
        for (label, actual, expected) in &mirrors {
            if actual != expected {
                errors.push(format!("{label} does not mirror GoalRoute"));
            }
        }

        let state_a = marker(&field(text, "State A"), "STATE_A:");
        let state_b = marker(&field(text, "State B"), "STATE_B:");
        if Some(state_a.as_str())
            != route
                .get("state_a")
                .and_then(|v| v.get("description"))
                .and_then(Value::as_str)
        {
            errors.push("State A does not mirror GoalRoute".to_string());
        }
        if Some(state_b.as_str())
            != route
                .get("state_b")
                .and_then(|v| v.get("description"))
                .and_then(Value::as_str)
        {
            errors.push("State B does not mirror GoalRoute".to_string());
        }

        let tasks = parse_tasks(text);
        let steps = selected
            .get("steps")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let expected_numbers: Vec<String> = (1..=tasks.len()).map(|n| n.to_string()).collect();
        let actual_numbers: Vec<String> = tasks.iter().map(|t| t.number.clone()).collect();
        if actual_numbers != expected_numbers {
            errors.push("Task numbers must be contiguous from 1".to_string());
        }
        if tasks.len() != steps.len() {
            errors.push("task count must equal selected route step count".to_string());
        }
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut per_task_spans: Vec<(String, i64, i64)> = Vec::new();
        let mut span_by_step: BTreeMap<String, (i64, i64)> = BTreeMap::new();
        let mut parallel_by_step: BTreeMap<String, bool> = BTreeMap::new();
        let mut parallelizable_count: i64 = 0;
        let mut code_basis_minutes: f64 = 0.0;

        for (index, step) in steps.iter().enumerate() {
            let Some(task) = tasks.get(index) else {
                break;
            };
            let step_id = py_str(&step.get("id").cloned());
            if task.step != step_id {
                errors.push(format!("Task {} route step mismatch", index + 1));
            }
            if Some(task.action.as_str()) != step.get("operation").and_then(Value::as_str) {
                errors.push(format!(
                    "Task {} action does not match route operation",
                    index + 1
                ));
            }
            if Some(task.delta.as_str()) != step.get("b_state_delta").and_then(Value::as_str) {
                errors.push(format!(
                    "Task {} target delta does not match route",
                    index + 1
                ));
            }
            let dependencies: Vec<String> = step
                .get("depends_on")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .map(|v| v.as_str().unwrap_or_default().to_string())
                        .collect()
                })
                .unwrap_or_default();
            let expected_depends = if dependencies.is_empty() {
                "START".to_string()
            } else {
                format!("AFTER:{}", dependencies.join(","))
            };
            if task.depends != expected_depends {
                errors.push(format!(
                    "Task {} dependency contract mismatch",
                    index + 1
                ));
            }
            if dependencies.iter().any(|dep| !seen.contains(dep)) {
                errors.push(format!("Task {} is not topologically ordered", index + 1));
            }
            seen.insert(step_id.clone());
            if !matches!(
                task.status.as_str(),
                "TODO" | "IN_PROGRESS" | "DONE" | "TRUE_BLOCKER"
            ) {
                errors.push(format!("Task {} status invalid", index + 1));
            }
            if !concrete(&task.check, 8) || !concrete(&task.expected, 8) {
                errors.push(format!(
                    "Task {} needs exact check and expected result",
                    index + 1
                ));
            }
            if !permanent_path(&task.evidence) {
                errors.push(format!(
                    "Task {} evidence path must be absolute and permanent",
                    index + 1
                ));
            }
            let failure = &task.failure;
            if !["TRY:", "FALLBACK:", "RECOMPILE_IF:"]
                .iter()
                .all(|token| failure.contains(token))
            {
                errors.push(format!("Task {} failure branch is incomplete", index + 1));
            }

            let trimmed_span = task.time_span.trim();
            match time_span_re().captures(trimmed_span) {
                None => errors.push(format!(
                    "Task {} time span must be an elapsed-clock span from minute 0, formatted as \"minute START-END\" (not a duration, not a low/high range)",
                    index + 1
                )),
                Some(caps) => {
                    let span_start: i64 = caps[1].parse().unwrap_or(0);
                    let span_end: i64 = caps[2].parse().unwrap_or(0);
                    if span_end <= span_start {
                        errors.push(format!("Task {} time span must end after it starts", index + 1));
                    }
                    per_task_spans.push((task.number.clone(), span_start, span_end));
                    span_by_step.insert(step_id.clone(), (span_start, span_end));
                }
            }

            let basis_parts: Vec<&str> = task
                .basis
                .split(',')
                .map(|part| part.trim())
                .filter(|part| !part.is_empty())
                .collect();
            if basis_parts.is_empty() {
                errors.push(format!(
                    "Task {} must name what its minutes are spent on",
                    index + 1
                ));
            }
            let mut basis_total: f64 = 0.0;
            for part in &basis_parts {
                match basis_part_re().captures(part) {
                    None => errors.push(format!(
                        "Task {} basis part {part:?} must be formatted as label=minutes",
                        index + 1
                    )),
                    Some(caps) => {
                        let label = caps[1].trim().to_lowercase();
                        let minutes: f64 = caps[2].parse().unwrap_or(0.0);
                        if BANNED_BASIS_LABELS.contains(&label.as_str()) {
                            errors.push(format!(
                                "Task {} basis label {label:?} is a generic bucket; name the actual activity (inspect, compile, test, deploy, smoke, report)",
                                index + 1
                            ));
                        }
                        basis_total += minutes;
                        if CODE_BASIS_LABELS.contains(&label.as_str()) {
                            code_basis_minutes += minutes;
                        }
                    }
                }
            }
            if let (Some(caps), false) = (
                time_span_re().captures(trimmed_span),
                basis_parts.is_empty(),
            ) {
                let span_length: i64 =
                    caps[2].parse::<i64>().unwrap_or(0) - caps[1].parse::<i64>().unwrap_or(0);
                if (basis_total - span_length as f64).abs() > 0.5 {
                    errors.push(format!(
                        "Task {} named minutes sum to {} but its span is {} minutes long",
                        index + 1,
                        fmt_g(basis_total),
                        span_length
                    ));
                }
            }

            let parallel_flag = task.parallelizable.trim().to_lowercase();
            if parallel_flag != "yes" && parallel_flag != "no" {
                errors.push(format!(
                    "Task {} parallelizable must be yes or no",
                    index + 1
                ));
            } else {
                let is_parallel = parallel_flag == "yes";
                parallel_by_step.insert(step_id.clone(), is_parallel);
                if is_parallel {
                    parallelizable_count += 1;
                }
            }
        }

        let statuses: Vec<&str> = tasks.iter().map(|t| t.status.as_str()).collect();
        if overall == "PLANNED" && statuses.iter().any(|s| *s != "TODO") {
            errors.push("PLANNED requires every task TODO".to_string());
        }
        if overall == "COMPLETE" && statuses.iter().any(|s| *s != "DONE") {
            errors.push("COMPLETE requires every task DONE".to_string());
        }
        if overall == "TRUE_BLOCKER" && !statuses.contains(&"TRUE_BLOCKER") {
            errors.push("TRUE_BLOCKER status requires blocked task".to_string());
        }

        let terminal = field(text, "Terminal record");
        let done_count = statuses.iter().filter(|s| **s == "DONE").count();
        let expected_next = tasks
            .iter()
            .find(|t| t.status != "DONE")
            .map(|t| t.step.clone())
            .unwrap_or_else(|| "NONE".to_string());
        let expected_terminal = format!(
            "STATUS={overall}; DONE={done_count}/{}; NEXT={expected_next}",
            tasks.len()
        );
        if terminal != expected_terminal {
            errors.push("Terminal record does not match task states".to_string());
        }

        let empty_proof_list = vec![Value::Object(Default::default())];
        let proof = route
            .get("state_b")
            .and_then(|v| v.get("proof"))
            .and_then(Value::as_array)
            .unwrap_or(&empty_proof_list)
            .first()
            .cloned()
            .unwrap_or(Value::Object(Default::default()));
        let success = field(text, "Success proof");
        let success_re = Regex::new(r"^PROOF_COMMAND:(.*); EXPECTED:(.*); EVIDENCE:(.*)$").unwrap();
        match success_re.captures(&success) {
            None => errors.push("Success proof format invalid".to_string()),
            Some(caps) => {
                let actual = (
                    caps[1].trim().to_string(),
                    caps[2].trim().to_string(),
                    caps[3].trim().to_string(),
                );
                let expected = (
                    proof
                        .get("command")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    proof
                        .get("expected")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    proof
                        .get("evidence_path")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                );
                if actual != expected {
                    errors.push("Success proof does not mirror GoalRoute".to_string());
                }
            }
        }

        let files_touched_raw = marker(&field(text, "Files touched"), "FILES_TOUCHED:");
        let lines_changed_raw = marker(&field(text, "Lines changed"), "LINES_CHANGED:");
        let rate_raw = marker(&field(text, "Rate"), "LINES_PER_MINUTE:");

        let files_touched_ok = files_touched_raw
            .parse::<i64>()
            .map(|v| v >= 1)
            .unwrap_or(false);
        if !files_touched_ok {
            errors.push("Files touched must be a positive integer".to_string());
        }
        let lines_changed_ok = lines_changed_raw
            .parse::<i64>()
            .map(|v| v >= 1)
            .unwrap_or(false);
        if !lines_changed_ok {
            errors.push("Lines changed must be a positive integer".to_string());
        }
        let rate: f64 = rate_raw.parse().unwrap_or(0.0);
        if rate <= 0.0 {
            errors.push("Lines per minute must be a positive number".to_string());
        } else if rate < 10.0 {
            errors.push(format!(
                "Lines per minute ({}) is implausibly slow for code generation; bill inspection, compile, and test time as named parts instead",
                fmt_rate(rate)
            ));
        }
        if let (Ok(lines_changed), true) = (lines_changed_raw.parse::<i64>(), rate > 0.0) {
            let expected_code_minutes = lines_changed as f64 / rate;
            if code_basis_minutes > 0.0
                && (code_basis_minutes - expected_code_minutes).abs()
                    > (2.0_f64).max(0.5 * expected_code_minutes)
            {
                errors.push(format!(
                    "Declared code minutes ({}) do not follow from {} lines / {} per minute (~{:.0})",
                    fmt_g(code_basis_minutes),
                    lines_changed_raw,
                    fmt_rate(rate),
                    expected_code_minutes
                ));
            }
        }

        let total_minutes_raw = marker(&field(text, "Total minutes"), "TOTAL_MINUTES:");
        let total_minutes_parsed = total_minutes_raw.parse::<i64>().ok();
        if total_minutes_parsed.map(|v| v < 1).unwrap_or(true) {
            errors.push("Total minutes must be a positive integer".to_string());
        } else if let Some(total_minutes) = total_minutes_parsed {
            let mut spans: Vec<(i64, i64)> = span_by_step.values().copied().collect();
            spans.sort();
            if !spans.is_empty() {
                if spans[0].0 != 0 {
                    errors.push(format!(
                        "First step must start at minute 0, found {}",
                        spans[0].0
                    ));
                }
                let finish = spans.iter().map(|(_, end)| *end).max().unwrap_or(0);
                if total_minutes != finish {
                    errors.push(format!(
                        "Total minutes ({total_minutes}) must equal the last minute any step is still running ({finish})"
                    ));
                }
                let mut covered_to = 0;
                for (start, end) in &spans {
                    if *start > covered_to {
                        errors.push(format!(
                            "Clock gap: nothing runs between minute {covered_to} and {start}"
                        ));
                        break;
                    }
                    covered_to = covered_to.max(*end);
                }
                for (step_id, (start, end)) in &span_by_step {
                    let overlaps = span_by_step.iter().any(|(other_id, (other_start, other_end))| {
                        other_id != step_id && start < other_end && other_start < end
                    });
                    if parallel_by_step.get(step_id) == Some(&true) && !overlaps {
                        errors.push(format!(
                            "Step {step_id} is flagged parallelizable but its span overlaps no other step"
                        ));
                    }
                    if parallel_by_step.get(step_id) == Some(&false) && overlaps {
                        errors.push(format!(
                            "Step {step_id} is flagged serial but its span overlaps another step"
                        ));
                    }
                }
            }
        }

        context = Context {
            route_path,
            route_raw,
            route_receipt_path,
            route_receipt_raw: Vec::new(),
            selected_route_id: selected_id,
            expected_ms: expected_ms.and_then(|v| v.as_i64()),
            route_revision: route_revision.and_then(|v| v.as_i64()),
            task_count: tasks.len(),
            total_minutes: total_minutes_parsed,
            per_task_minute_spans: per_task_spans,
            parallelizable_task_count: parallelizable_count,
            files_touched: files_touched_raw.parse().ok(),
            lines_changed: lines_changed_raw.parse().ok(),
            lines_per_minute: if rate > 0.0 { Some(rate) } else { None },
            code_minutes: if code_basis_minutes > 0.0 {
                Some(code_basis_minutes)
            } else {
                None
            },
            have_route: true,
        };
    }

    if overall == "TRUE_BLOCKER" {
        let blocked = field(text, "Blocked artifact path");
        if !permanent_path(&blocked) || !Path::new(&blocked).exists() {
            errors.push("TRUE_BLOCKER requires existing permanent blocked artifact".to_string());
        }
    }
    if field(text, "TRUE_BLOCKER allowed only if")
        != "RECOVERY_EXHAUSTED; INDEPENDENT_WORK_COMPLETE; NO_FEASIBLE_ROUTE; ONE_MISSING_EXTERNAL_INPUT"
    {
        errors.push("TRUE_BLOCKER contract changed".to_string());
    }

    let final_evidence = field(text, "Final evidence path");
    if !permanent_path(&final_evidence) {
        errors.push("Final evidence path must be absolute and permanent".to_string());
    }
    if !concrete(&field(text, "Final verification"), 8)
        || !concrete(&field(text, "Final expected result"), 8)
    {
        errors.push("Final verification contract must be concrete".to_string());
    }

    (errors, context)
}

/// Port of `receipt_errors()`.
pub fn receipt_errors(
    tasklist_path: &Path,
    raw: &[u8],
    validator_bytes: &[u8],
    receipt_path: &Path,
    context: &Context,
) -> Vec<String> {
    let receipt_text = match std::fs::read_to_string(receipt_path) {
        Ok(text) => text,
        Err(exc) => return vec![format!("tasklist receipt unreadable: {exc}")],
    };
    let receipt: Value = match serde_json::from_str(&receipt_text) {
        Ok(v) => v,
        Err(exc) => return vec![format!("tasklist receipt unreadable: {exc}")],
    };

    let route_receipt_bytes = std::fs::read(&context.route_receipt_path).unwrap_or_default();

    let expected: Vec<(&str, Value)> = vec![
        ("schema", Value::String(SCHEMA.to_string())),
        (
            "tasklist_path",
            Value::String(tasklist_path.to_string_lossy().to_string()),
        ),
        ("tasklist_sha256", Value::String(digest(raw))),
        ("validator_version", Value::String(VERSION.to_string())),
        (
            "validator_sha256",
            Value::String(digest(validator_bytes)),
        ),
        (
            "route_path",
            Value::String(context.route_path.to_string_lossy().to_string()),
        ),
        ("route_sha256", Value::String(digest(&context.route_raw))),
        (
            "route_receipt_path",
            Value::String(context.route_receipt_path.to_string_lossy().to_string()),
        ),
        (
            "route_receipt_sha256",
            Value::String(digest(&route_receipt_bytes)),
        ),
        (
            "total_minutes",
            context
                .total_minutes
                .map(Value::from)
                .unwrap_or(Value::Null),
        ),
        (
            "per_task_minute_spans",
            Value::Array(
                context
                    .per_task_minute_spans
                    .iter()
                    .map(|(number, start, end)| {
                        serde_json::json!({"task_number": number, "start": start, "end": end})
                    })
                    .collect(),
            ),
        ),
        (
            "parallelizable_task_count",
            Value::from(context.parallelizable_task_count),
        ),
    ];
    expected
        .into_iter()
        .filter(|(key, value)| receipt.get(*key) != Some(value))
        .map(|(key, _)| format!("receipt {key} mismatch"))
        .collect()
}

/// Port of `template_check()`.
pub fn template_check(text: &str) -> Vec<String> {
    let mut errors: Vec<String> = REQUIRED_HEADINGS
        .iter()
        .filter(|heading| !text.contains(*heading))
        .map(|heading| format!("missing heading: {heading}"))
        .collect();
    for token in [
        "{{TASKLIST_ID}}",
        "{{ROUTE_ID_AND_STEP}}",
        "TRY:",
        "FALLBACK:",
        "RECOMPILE_IF:",
        "TOTAL_MINUTES:",
        "FILES_TOUCHED:",
        "LINES_CHANGED:",
        "LINES_PER_MINUTE:",
        "minute {{START_OFFSET}}-{{END_OFFSET}}",
        "**Basis:**",
        "Parallelizable",
    ] {
        if !text.contains(token) {
            errors.push(format!("template missing token: {token}"));
        }
    }
    errors
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    // Port of `Path.with_suffix()` applied to a compound suffix like ".minimize.json": Python's
    // `with_suffix` replaces only the final extension, so `foo.tasklist.md` -> `foo.tasklist` +
    // suffix.
    let stem = path.with_extension("");
    let mut result = stem.into_os_string();
    result.push(suffix);
    PathBuf::from(result)
}

fn resolve(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_default()
                .join(path)
        }
    })
}

fn py_str(value: &Option<Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => if *b { "True" } else { "False" }.to_string(),
        Some(other) => other.to_string(),
    }
}

fn fmt_g(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        let s = format!("{value}");
        s
    }
}

fn fmt_rate(value: f64) -> String {
    fmt_g(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_extracts_labelled_line() {
        let text = "- **Status:** PLANNED\n- **Owner:** me\n";
        assert_eq!(field(text, "Status"), "PLANNED");
        assert_eq!(field(text, "Owner"), "me");
        assert_eq!(field(text, "Missing"), "");
    }

    #[test]
    fn marker_strips_prefix() {
        assert_eq!(marker("ROUTE_STEP:abc", "ROUTE_STEP:"), "abc");
        assert_eq!(marker("abc", "ROUTE_STEP:"), "");
    }

    #[test]
    fn permanent_path_rejects_temp_and_relative() {
        assert!(permanent_path("/Users/me/x.md"));
        assert!(!permanent_path("relative/x.md"));
        assert!(!permanent_path("/tmp/x.md"));
        assert!(!permanent_path("/var/scratch/x.md"));
    }

    #[test]
    fn concrete_rejects_short_and_placeholder() {
        assert!(concrete("a long enough value", 8));
        assert!(!concrete("short", 8));
        assert!(!concrete("{{PLACEHOLDER}} but long", 8));
    }

    #[test]
    fn parse_tasks_reads_fields() {
        let text = "\
### Task 1 — Do the thing
- **Task status:** TODO
- **Route step:** ROUTE_STEP:s1
- **Action:** ACTION:build
- **Depends on:** START
- **Advances target:** ADVANCES_STATE_B:delta
- **Done check:** CHECK:exists
- **Expected result:** EXPECTED:ok
- **Evidence path:** /tmp/evidence.txt
- **On failure:** TRY: a FALLBACK: b RECOMPILE_IF: c
- **Time span:** minute 0-5
- **Basis:** compile=5
- **Parallelizable:** no

## 4. Recovery & TRUE_BLOCKER
";
        let tasks = parse_tasks(text);
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].number, "1");
        assert_eq!(tasks[0].step, "s1");
        assert_eq!(tasks[0].action, "build");
        assert_eq!(tasks[0].depends, "START");
        assert_eq!(tasks[0].time_span, "minute 0-5");
    }

    #[test]
    fn template_check_flags_missing_tokens() {
        let errors = template_check("nothing here");
        assert!(errors.iter().any(|e| e.contains("missing heading")));
        assert!(errors.iter().any(|e| e.contains("TRY:")));
    }

    #[test]
    fn digest_matches_known_sha256() {
        // sha256("") is the well-known empty-input digest.
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn validate_reports_missing_headings_and_placeholders() {
        let text = "{{X}}";
        let path = std::env::temp_dir().join("wf_w2_057_missing.md");
        let (errors, _ctx) = validate(&path, text);
        assert!(errors.iter().any(|e| e.contains("missing heading")));
        assert!(errors
            .iter()
            .any(|e| e.contains("unresolved template placeholders")));
    }
}
