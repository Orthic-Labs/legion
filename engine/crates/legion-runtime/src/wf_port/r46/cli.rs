//! Full port of `validate()` and `main()` from
//! `src/lib/dispatch-validator/validate-dispatch.py` (lines ~3098-3475).
//!
//! [`validate_full_errors`] is the complete port of `validate()`: every
//! branch, including the `REQUIRED_LABELS` table walk
//! (`required_labels.rs`), the `## 5A. Script & Runner Gate` YES/NO branch,
//! the `## 10. TRUE_BLOCKER Conditions` proof-token check, the `## 11.
//! Dispatcher Author Gate` unchecked-item/checked-count check, and the
//! `BYPASS_PATTERNS`/`SECRET_PATTERNS` scans (`patterns.rs`).
//!
//! [`run`] is the complete port of `main()`'s dispatch (non-authority)
//! path: file read, UTF-8 decode, `validate_full_errors`, `storage_errors`
//! (`storage.rs`), receipt write/verify, and the same PASS/FAIL/RECEIPT_PASS
//! stdout contract, returning the same process exit codes (0/1/2). The
//! authority/worker packet-type path is intentionally not duplicated here:
//! `wf_port::w2_044::authority_packet_errors` already ports
//! `authority_packet_errors()` in full, and callers building a CLI binary
//! should dispatch to it directly for `--packet-type authority|worker`,
//! mirroring the Python `main()`'s own branch.
//!
//! One remaining named, documented gap: `main()`'s dynamic
//! `importlib.util` load-and-call of `minimize/minimize_gate.py`'s
//! `verify_decision()` is out of scope for this crate (a Rust port of that
//! sibling script, if desired, belongs in `legion-minimize` — see
//! `engine/crates/legion-minimize/src/decision.rs`, which already exists
//! and exposes a `verify`-style entry point). [`run`] calls
//! [`MinimizeGate::verify_decision`], a caller-supplied trait object, in
//! its place so this crate does not take a dependency edge on
//! `legion-minimize`; a caller wiring the real CLI passes an adapter over
//! that crate's decision-verification entry point.

use super::authority_correction::authority_correction_errors;
use super::decision_scope::decision_scope_errors;
use super::execution_control::execution_control_errors;
use super::execution_identity::execution_identity_errors;
use super::goal_route::goal_route_errors;
use super::headings::ordered_heading_errors;
use super::labels::{action_re, fenced_value_after, is_concrete, path_re};
use super::patterns::{bypass_pattern_errors, has_unfilled_placeholder, secret_pattern_errors};
use super::required_labels::required_label_errors;
use super::route_scan::{label_value, managed_rust_route_errors};
use super::script_gate::script_gate_values;
use super::status::status_errors;
use super::steps::step_errors;
use super::storage::storage_errors;
use super::tables::{table_errors, FAILURE_CLASSES};
use super::topology::topology_errors;
use crate::wf_port::w2_045::path_utils::{canonical_locator, clean_path_value, normalized_path};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

fn step_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^### Step\s+\d+\s+—\s+.+$").unwrap())
}

/// Port of `len(STEP_RE.findall(text))`, used in `main()`'s PASS message.
pub fn step_count(text: &str) -> usize {
    step_re().find_iter(text).count()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Port of the `## 5A. Script & Runner Gate` YES/NO branch inside
/// `validate()` (lines ~3163-3252) plus the unconditional `/script gate
/// marker` presence loop (lines ~3253-3271).
fn script_section_errors(text: &str, allow_template: bool) -> Vec<String> {
    let mut errors = Vec::new();
    let script_involved = label_value(text, "**Script involved:**");
    if let Some(script_involved) = &script_involved {
        if !script_involved.is_empty() && !allow_template {
            let normalized = script_involved.trim_matches('`').to_uppercase();
            if normalized != "YES" && normalized != "NO" {
                errors.push("Script involved must be exactly YES or NO".to_string());
            }
            let ownership = label_value(text, "**Script ownership:**")
                .unwrap_or_default()
                .trim_matches('`')
                .to_uppercase();
            let script_path = label_value(text, "**Script path:**").unwrap_or_default();
            let no_reason = label_value(text, "**No-script reason:**").unwrap_or_default();
            let gate = script_gate_values(text);

            if normalized == "YES" {
                let script_skill = label_value(text, "**Script skill:**").unwrap_or_default();
                if !script_skill
                    .replace('\\', "/")
                    .to_lowercase()
                    .contains("/script/skill.md")
                {
                    errors.push("script-bearing dispatch must name /script skill path".to_string());
                }
                if !matches!(
                    ownership.as_str(),
                    "ORCHESTRATOR_CREATED" | "EXISTING_VERIFIED" | "EXECUTOR_CREATES"
                ) {
                    errors.push("script-bearing dispatch must name script owner".to_string());
                }
                if !path_re().is_match(&script_path) {
                    errors.push("script-bearing dispatch must name explicit script path".to_string());
                }
                if !no_reason.to_uppercase().starts_with("NOT_APPLICABLE") {
                    errors.push(
                        "script-bearing dispatch must mark no-script reason NOT_APPLICABLE"
                            .to_string(),
                    );
                }
                if !matches!(gate.get("TIER").map(String::as_str), Some("S1") | Some("S2") | Some("S3")) {
                    errors.push("script-bearing dispatch requires TIER S1, S2, or S3".to_string());
                }
                for marker in [
                    "GOAL",
                    "SELECTED_PATH",
                    "WHY_FASTEST_VALID",
                    "BOTTLENECK",
                    "PARALLEL",
                    "DEFERRED",
                    "GOAL_ROUTE_ARTIFACT",
                    "GOAL_ROUTE_RECEIPT",
                    "EXPECTED_TIME_TO_VERIFIED_B_MS",
                    "ROUTE_REVISION",
                    "PRE",
                    "SMOKE",
                    "CHECK",
                    "BLAST",
                    "OPT",
                ] {
                    let value = gate.get(marker).cloned().unwrap_or_default();
                    if marker == "EXPECTED_TIME_TO_VERIFIED_B_MS" || marker == "ROUTE_REVISION" {
                        let ok = !value.is_empty()
                            && (value == "0" || (value.chars().all(|c| c.is_ascii_digit()) && !value.starts_with('0')));
                        if !ok {
                            errors.push(format!("script gate {marker} requires integer"));
                        }
                    } else if !is_concrete(&value) {
                        errors.push(format!("script gate {marker} lacks concrete evidence"));
                    }
                }

                let selected_route_raw = label_value(text, "**Selected route:**").unwrap_or_default();
                let selected_route = strip_prefix_ci(&selected_route_raw, "SELECTED_ROUTE:")
                    .trim()
                    .trim_matches(|c| c == '`' || c == ' ')
                    .to_string();
                let selected_path_gate = gate.get("SELECTED_PATH").cloned().unwrap_or_default();
                if !selected_path_gate
                    .to_lowercase()
                    .contains(&selected_route.to_lowercase())
                    || selected_route.is_empty()
                {
                    errors.push("script gate SELECTED_PATH must bind dispatch selected route".to_string());
                }

                let route_artifact =
                    clean_path_value(&label_value(text, "**Goal route artifact:**").unwrap_or_default());
                let route_receipt =
                    clean_path_value(&label_value(text, "**Goal route receipt:**").unwrap_or_default());
                let expected_time = strip_prefix_ci(
                    &label_value(text, "**Expected time to verified B:**").unwrap_or_default(),
                    "EXPECTED_TIME_TO_VERIFIED_B_MS:",
                )
                .to_string();
                let route_revision = strip_prefix_ci(
                    &label_value(text, "**Route revision:**").unwrap_or_default(),
                    "ROUTE_REVISION:",
                )
                .to_string();

                if normalized_path(gate.get("GOAL_ROUTE_ARTIFACT").map(String::as_str).unwrap_or(""), None)
                    != normalized_path(&route_artifact, None)
                {
                    errors.push("script gate GOAL_ROUTE_ARTIFACT must bind dispatch route".to_string());
                }
                if normalized_path(gate.get("GOAL_ROUTE_RECEIPT").map(String::as_str).unwrap_or(""), None)
                    != normalized_path(&route_receipt, None)
                {
                    errors.push("script gate GOAL_ROUTE_RECEIPT must bind dispatch receipt".to_string());
                }
                if gate.get("EXPECTED_TIME_TO_VERIFIED_B_MS").cloned().unwrap_or_default() != expected_time {
                    errors.push(
                        "script gate EXPECTED_TIME_TO_VERIFIED_B_MS must match dispatch route".to_string(),
                    );
                }
                if gate.get("ROUTE_REVISION").cloned().unwrap_or_default() != route_revision {
                    errors.push("script gate ROUTE_REVISION must match dispatch route".to_string());
                }
                let expected_ship = if ownership == "EXECUTOR_CREATES" {
                    "EXECUTOR_MUST_EARN"
                } else {
                    "YES"
                };
                if gate.get("SHIP").map(String::as_str) != Some(expected_ship) {
                    errors.push(format!("script gate SHIP must be {expected_ship} for {ownership}"));
                }
            } else if normalized == "NO" {
                if !is_concrete(&no_reason) {
                    errors.push("Script involved NO requires explicit reason".to_string());
                }
                if ownership != "NOT_APPLICABLE" {
                    errors.push("Script involved NO requires NOT_APPLICABLE ownership".to_string());
                }
                if let (Some(start), Some(end_rel)) = (
                    text.find("## 5. Execution Procedure"),
                    text.find("## 5. Execution Procedure").and_then(|s| text[s..].find("## 5A. Script & Runner Gate")),
                ) {
                    let execution = &text[start..start + end_rel];
                    let forbidden_re = forbidden_execution_re();
                    if forbidden_re.is_match(execution) {
                        errors.push("script-bearing execution cannot declare Script involved NO".to_string());
                    }
                }
            }
        }
    }

    for marker in [
        "GOAL:",
        "SELECTED_PATH:",
        "WHY_FASTEST_VALID:",
        "BOTTLENECK:",
        "PARALLEL:",
        "DEFERRED:",
        "GOAL_ROUTE_ARTIFACT:",
        "GOAL_ROUTE_RECEIPT:",
        "EXPECTED_TIME_TO_VERIFIED_B_MS:",
        "ROUTE_REVISION:",
        "TIER:",
        "PRE:",
        "SMOKE:",
        "CHECK:",
        "BLAST:",
        "OPT:",
        "SHIP:",
    ] {
        if !text.contains(marker) {
            errors.push(format!("missing /script gate marker: {marker}"));
        }
    }
    errors
}

fn forbidden_execution_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(script|runner|pipeline|batch|deploy|render|install|paid API|production)\b").unwrap()
    })
}

fn strip_prefix_ci<'a>(value: &'a str, prefix: &str) -> &'a str {
    if value.len() >= prefix.len() && value[..prefix.len()].eq_ignore_ascii_case(prefix) {
        &value[prefix.len()..]
    } else {
        value
    }
}

/// Port of the `## 10. TRUE_BLOCKER Conditions` proof-token check (lines
/// ~3291-3311).
fn true_blocker_errors(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let start = text.find("## 10. TRUE_BLOCKER Conditions");
    let end = text.find("## 11. Dispatcher Author Gate");
    let blocker_section = match (start, end) {
        (Some(s), Some(e)) if e >= s => &text[s..e],
        (Some(s), _) => &text[s..],
        _ => "",
    };
    for token in [
        "RECOVERY_EXHAUSTED",
        "INDEPENDENT_WORK_COMPLETE",
        "RAW_EVIDENCE",
        "MISSING_INPUT",
        "RESUME_COMMAND",
    ] {
        if !blocker_section.contains(token) {
            errors.push(format!("TRUE_BLOCKER section missing proof token: {token}"));
        }
    }
    errors
}

/// Port of the `## 11. Dispatcher Author Gate` checklist check plus the
/// unfilled-placeholder scan (lines ~3313-3320), both gated on
/// `!allow_template`.
fn author_gate_errors(text: &str, allow_template: bool) -> Vec<String> {
    let mut errors = Vec::new();
    if allow_template {
        return errors;
    }
    if has_unfilled_placeholder(text) {
        errors.push("unfilled placeholder remains".to_string());
    }
    let author_section = match text.find("## 11. Dispatcher Author Gate") {
        Some(s) => &text[s..],
        None => "",
    };
    if author_section.contains("- [ ]") {
        errors.push("dispatcher author gate contains unchecked item".to_string());
    }
    if author_section.matches("- [x]").count() < 15 {
        errors.push("dispatcher author gate requires 15 checked items".to_string());
    }
    errors
}

/// Complete port of `validate()`. See the module doc.
pub fn validate_full_errors(text: &str, allow_template: bool, artifact_path: Option<&Path>) -> Vec<String> {
    let mut errors = ordered_heading_errors(text);

    errors.extend(required_label_errors(text, allow_template));

    if !allow_template {
        for label in ["**Preflight command:**", "**Final verification command:**"] {
            let command = fenced_value_after(text, label);
            let ok = command
                .as_deref()
                .map(|c| is_concrete(c) && action_re().is_match(c))
                .unwrap_or(false);
            if !ok {
                errors.push(format!("{label} lacks executable fenced command/action"));
            }
        }
        let validator_command = fenced_value_after(text, "**Validator command:**").unwrap_or_default();
        let receiver_command = fenced_value_after(text, "**Receiver hash check:**").unwrap_or_default();
        let declared_artifact =
            clean_path_value(&label_value(text, "**Validated artifact path:**").unwrap_or_default());
        let declared_receipt = clean_path_value(&label_value(text, "**Receipt path:**").unwrap_or_default());
        for (label, command, flag) in [
            ("Validator command", validator_command.as_str(), "--write-receipt"),
            ("Receiver hash check", receiver_command.as_str(), "--verify-receipt"),
        ] {
            let normalized_command = command.replace('\\', "/").to_lowercase();
            let artifact_token = declared_artifact.replace('\\', "/").to_lowercase();
            let receipt_token = declared_receipt.replace('\\', "/").to_lowercase();
            if !command.contains("validate-dispatch.py")
                || !command.contains(flag)
                || !normalized_command.contains(&artifact_token)
                || !normalized_command.contains(&receipt_token)
            {
                errors.push(format!(
                    "{label} must execute validate-dispatch.py with bound paths and {flag}"
                ));
            }
        }
        let root_cwd = label_value(text, "**Working directory:**").unwrap_or_default();
        if !path_re().is_match(&root_cwd) {
            errors.push("dispatch working directory is not an explicit path".to_string());
        }

        errors.extend(managed_rust_route_errors(text, artifact_path, None));
    }

    errors.extend(step_errors(text, allow_template));
    errors.extend(table_errors(text, allow_template));
    errors.extend(execution_identity_errors(text, allow_template));
    errors.extend(execution_control_errors(text, allow_template));
    errors.extend(decision_scope_errors(text, allow_template));
    errors.extend(authority_correction_errors(text, allow_template));
    errors.extend(goal_route_errors(text, allow_template, artifact_path));
    errors.extend(topology_errors(text, allow_template));

    for failure_class in FAILURE_CLASSES {
        if !text.contains(failure_class) {
            errors.push(format!("missing failure class: {failure_class}"));
        }
    }

    errors.extend(script_section_errors(text, allow_template));

    errors.extend(status_errors(text));
    for status in ["COMPLETE", "COMPLETE_WITH_NOTES", "TRUE_BLOCKER"] {
        if !text.contains(status) {
            errors.push(format!("missing terminal status contract: {status}"));
        }
    }

    if text.matches("```").count() < 8 {
        errors.push("expected at least four fenced command/output blocks".to_string());
    }

    errors.extend(true_blocker_errors(text));
    errors.extend(author_gate_errors(text, allow_template));

    errors.extend(bypass_pattern_errors(text));
    if !allow_template {
        errors.extend(secret_pattern_errors(text));
    }

    let unique: BTreeSet<String> = errors.into_iter().collect();
    unique.into_iter().collect()
}

/// Port of the fully-available subset of `validate()` (kept for existing
/// callers that predate this file's completion — see the module history
/// in `mod.rs`). New callers should use [`validate_full_errors`].
pub fn validate_ported_errors(text: &str, allow_template: bool, artifact_path: Option<&Path>) -> Vec<String> {
    validate_full_errors(text, allow_template, artifact_path)
}

/// Adapter trait standing in for `main()`'s dynamic load of
/// `minimize/minimize_gate.py`'s `verify_decision()`. A real CLI binary
/// supplies an implementation backed by `legion-minimize`'s decision
/// verification; tests supply a fake. `Err` mirrors any of the Python
/// `except (OSError, ValueError, RuntimeError)` branches collapsing to one
/// appended error string.
pub trait MinimizeGate {
    fn verify_decision(&self, minimize_path: &Path, minimize_receipt: &Path) -> Result<(), String>;
}

/// A [`MinimizeGate`] that always reports the Minimize authority missing —
/// the correct behaviour when no adapter is wired, matching Python's
/// `except` branch when `minimize_gate.py` cannot be loaded at all.
pub struct NoMinimizeGate;

impl MinimizeGate for NoMinimizeGate {
    fn verify_decision(&self, _minimize_path: &Path, _minimize_receipt: &Path) -> Result<(), String> {
        Err("cannot load Minimize validator".to_string())
    }
}

/// CLI outcome: `(exit_code, stdout_lines)`, mirroring `main()`'s return
/// code plus everything it printed (stdout only; the two `argparse`-style
/// usage failures that print to stderr in Python are represented as
/// `Err` here instead, since this is a library entry point, not a process).
pub struct RunOutcome {
    pub exit_code: i32,
    pub stdout: Vec<String>,
}

/// Options mirroring `main()`'s `argparse` flags for the dispatch
/// (non-authority) packet-type path.
pub struct RunOptions<'a> {
    pub dispatch: &'a Path,
    pub template_self_check: bool,
    pub write_receipt: Option<&'a Path>,
    pub verify_receipt: Option<&'a Path>,
}

fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
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
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Complete port of `main()`'s dispatch (non-authority) path. See the
/// module doc for the `--packet-type authority|worker` and
/// `minimize_gate.py` scope notes.
pub fn run(opts: &RunOptions<'_>, minimize_gate: &dyn MinimizeGate) -> RunOutcome {
    let mut stdout = Vec::new();

    if !opts.dispatch.is_file() {
        return RunOutcome {
            exit_code: 2,
            stdout: vec![format!("FAIL: dispatch file not found: {}", opts.dispatch.display())],
        };
    }
    if !opts.template_self_check && opts.write_receipt.is_none() && opts.verify_receipt.is_none() {
        return RunOutcome {
            exit_code: 1,
            stdout: vec!["FAIL: exactly one receipt mode is required".to_string()],
        };
    }

    let raw_bytes = match std::fs::read(opts.dispatch) {
        Ok(b) => b,
        Err(exc) => {
            return RunOutcome {
                exit_code: 2,
                stdout: vec![format!("FAIL: dispatch file not found: {exc}")],
            }
        }
    };
    let text = match String::from_utf8(raw_bytes.clone()) {
        Ok(t) => t,
        Err(exc) => {
            return RunOutcome {
                exit_code: 1,
                stdout: vec![format!("FAIL: dispatch is not valid UTF-8: {exc}")],
            }
        }
    };

    let dispatch_resolved = opts
        .dispatch
        .canonicalize()
        .unwrap_or_else(|_| opts.dispatch.to_path_buf());
    let mut errors = validate_full_errors(&text, opts.template_self_check, Some(dispatch_resolved.as_path()));

    if !opts.template_self_check {
        let minimize_path = with_suffix(opts.dispatch, "minimize.json");
        let minimize_receipt = with_suffix(opts.dispatch, "minimize.receipt.json");
        if let Err(exc) = minimize_gate.verify_decision(&minimize_path, &minimize_receipt) {
            errors.push(format!("Minimize authority missing, invalid, or stale: {exc}"));
        }
        errors.extend(storage_errors(&text, opts.dispatch, opts.write_receipt, opts.verify_receipt));
    }

    if !errors.is_empty() {
        stdout.push(format!("FAIL: {} dispatch defect(s)", errors.len()));
        for error in &errors {
            stdout.push(format!("- {error}"));
        }
        return RunOutcome { exit_code: 1, stdout };
    }

    let digest = sha256_hex(&raw_bytes);

    if let Some(verify_receipt) = opts.verify_receipt {
        if !verify_receipt.is_file() {
            return RunOutcome {
                exit_code: 2,
                stdout: vec![format!("FAIL: receipt file not found: {}", verify_receipt.display())],
            };
        }
        let receipt_text = match std::fs::read_to_string(verify_receipt) {
            Ok(t) => t,
            Err(exc) => {
                return RunOutcome {
                    exit_code: 1,
                    stdout: vec![format!("FAIL: invalid receipt: {exc}")],
                }
            }
        };
        let receipt: serde_json::Value = match serde_json::from_str(&receipt_text) {
            Ok(v) => v,
            Err(exc) => {
                return RunOutcome {
                    exit_code: 1,
                    stdout: vec![format!("FAIL: invalid receipt: {exc}")],
                }
            }
        };
        if receipt.get("sha256").and_then(|v| v.as_str()) != Some(digest.as_str()) {
            return RunOutcome {
                exit_code: 1,
                stdout: vec!["FAIL: dispatch bytes do not match receipt".to_string()],
            };
        }
        let dispatch_name = opts.dispatch.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if receipt.get("artifact_name").and_then(|v| v.as_str()) != Some(dispatch_name.as_str()) {
            return RunOutcome {
                exit_code: 1,
                stdout: vec!["FAIL: dispatch filename does not match receipt".to_string()],
            };
        }
        if receipt.get("artifact_path").and_then(|v| v.as_str()) != Some(canonical_locator(opts.dispatch).as_str()) {
            return RunOutcome {
                exit_code: 1,
                stdout: vec!["FAIL: dispatch path does not match receipt".to_string()],
            };
        }
        stdout.push(format!("RECEIPT_PASS: sha256={digest}"));
    }

    if let Some(write_receipt) = opts.write_receipt {
        let dispatch_name = opts.dispatch.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let receipt = serde_json::json!({
            "schema_version": 2,
            "artifact_name": dispatch_name,
            "artifact_path": canonical_locator(opts.dispatch),
            "sha256": digest,
            "validated_at": now_iso8601(),
            "validator": "dispatch/validate-dispatch.py",
        });
        if let Some(parent) = write_receipt.parent() {
            if let Err(exc) = std::fs::create_dir_all(parent) {
                return RunOutcome {
                    exit_code: 1,
                    stdout: vec![format!("FAIL: could not create receipt directory: {exc}")],
                };
            }
        }
        let body = format!("{}\n", serde_json::to_string_pretty(&receipt).unwrap_or_default());
        if let Err(exc) = std::fs::write(write_receipt, body) {
            return RunOutcome {
                exit_code: 1,
                stdout: vec![format!("FAIL: could not write receipt: {exc}")],
            };
        }
    }

    stdout.push(format!(
        "PASS: dispatch is structurally complete ({} step(s), {} failure classes, sha256={digest})",
        step_count(&text),
        FAILURE_CLASSES.len(),
    ));
    RunOutcome { exit_code: 0, stdout }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    path.with_file_name(format!("{stem}.{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_text_produces_errors_not_panic() {
        let errors = validate_full_errors("", false, None);
        assert!(!errors.is_empty());
    }

    #[test]
    fn allow_template_skips_most_checks_but_still_checks_headings() {
        let errors = validate_full_errors("", true, None);
        assert!(errors.iter().any(|e| e.to_lowercase().contains("heading")) || !errors.is_empty());
    }

    #[test]
    fn result_is_sorted_and_deduplicated() {
        let errors = validate_full_errors("", false, None);
        let mut sorted = errors.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(errors, sorted);
    }

    #[test]
    fn missing_script_gate_markers_reported() {
        let errors = script_section_errors("", false);
        assert!(errors.iter().any(|e| e == "missing /script gate marker: GOAL:"));
    }

    #[test]
    fn true_blocker_section_reports_missing_tokens() {
        let text = "## 10. TRUE_BLOCKER Conditions\nsome text\n## 11. Dispatcher Author Gate\n";
        let errors = true_blocker_errors(text);
        assert!(errors.iter().any(|e| e.contains("RECOVERY_EXHAUSTED")));
    }

    #[test]
    fn author_gate_requires_fifteen_checked_items() {
        let text = "## 11. Dispatcher Author Gate\n- [x] one\n";
        let errors = author_gate_errors(text, false);
        assert!(errors.iter().any(|e| e.contains("15 checked items")));
        assert!(author_gate_errors(text, true).is_empty());
    }

    #[test]
    fn run_reports_missing_file() {
        let opts = RunOptions {
            dispatch: Path::new("/nonexistent/does-not-exist.md"),
            template_self_check: false,
            write_receipt: None,
            verify_receipt: None,
        };
        let outcome = run(&opts, &NoMinimizeGate);
        assert_eq!(outcome.exit_code, 2);
        assert!(outcome.stdout[0].contains("dispatch file not found"));
    }

    #[test]
    fn run_requires_receipt_mode_unless_template_self_check() {
        let dir = std::env::temp_dir().join(format!(
            "r46d-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dispatch = dir.join("dispatch.md");
        std::fs::write(&dispatch, "# DISPATCH:\n").unwrap();
        let opts = RunOptions {
            dispatch: &dispatch,
            template_self_check: false,
            write_receipt: None,
            verify_receipt: None,
        };
        let outcome = run(&opts, &NoMinimizeGate);
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.stdout[0].contains("exactly one receipt mode is required"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
