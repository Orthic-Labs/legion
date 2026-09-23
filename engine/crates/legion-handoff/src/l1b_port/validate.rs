//! L1 literal port of `src/lib/handoff/validate_handoff.py`.
//!
//! Fail-closed validator for zero-memory cold-start handoffs: heading order,
//! label presence/concreteness, resume-step structure, decision/artifact
//! table shape, readiness/proceed/work-type enums, gap-severity coherence,
//! author-gate checklist, banned phrases, and secret-pattern scanning.
//!
//! The Python CLI (`argparse` + receipt read/write to disk) is not ported:
//! this module exposes the pure validation core (`validate`, `storage_errors`,
//! path normalization) as a library so a caller wires its own I/O.

use regex::Regex;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub const FORBIDDEN_STORAGE_PARTS: &[&str] = &[
    "temp",
    "tmp",
    ".tmp",
    "temporary",
    "cache",
    ".cache",
    "review-run",
    "review-runs",
    ".review-runs",
    ".council-runs",
    "scratch",
];

pub fn clean_path_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('`')
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

/// Mirrors Python's `normalized_path`: does NOT resolve against the real
/// filesystem for non-drive-letter paths in this port (no `Path.resolve()`
/// equivalent without an actual cwd/symlink walk); callers on a POSIX-like
/// absolute path get lexical normalization, matching the common case this
/// validator is exercised against (already-absolute handoff/receipt paths).
pub fn normalized_path(value: &str, windows: bool) -> String {
    let raw = clean_path_value(value).replace('\\', "/");
    let drive_re = drive_re();
    let normalized = if drive_re.is_match(&raw) {
        raw.trim_end_matches('/').to_string()
    } else {
        lexical_resolve(&raw)
    };
    if windows {
        normalized.to_lowercase()
    } else {
        normalized
    }
}

fn lexical_resolve(raw: &str) -> String {
    let is_abs = raw.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join("/");
    let prefixed = if is_abs {
        format!("/{joined}")
    } else {
        joined
    };
    prefixed.trim_end_matches('/').to_string()
}

pub fn is_absolute_path(value: &str) -> bool {
    let raw = clean_path_value(value).replace('\\', "/");
    drive_re().is_match(&raw) || raw.starts_with('/')
}

fn drive_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z]:/").unwrap());
    &RE
}

pub fn storage_errors(
    text: &str,
    artifact: &Path,
    write_receipt: Option<&Path>,
    verify_receipt: Option<&Path>,
    windows: bool,
) -> Vec<String> {
    let mut errors = Vec::new();
    let declared_artifact = clean_path_value(&label_value(text, "**Packet path:**").unwrap_or_default());
    let declared_receipt = clean_path_value(&label_value(text, "**Receipt path:**").unwrap_or_default());
    let actual_artifact = artifact.to_path_buf();
    let receipt_arg = write_receipt.or(verify_receipt);

    if !artifact.is_absolute() {
        errors.push("validator requires absolute handoff file path".to_string());
    }
    if !is_absolute_path(&declared_artifact) {
        errors.push("declared handoff packet path must be absolute".to_string());
    } else if normalized_path(&declared_artifact, windows)
        != normalized_path(&actual_artifact.to_string_lossy(), windows)
    {
        errors.push("declared handoff packet path does not match validated file".to_string());
    }

    let artifact_parts: BTreeSet<String> = normalized_path(&actual_artifact.to_string_lossy(), windows)
        .split('/')
        .map(|s| s.to_string())
        .collect();
    if artifact_parts.iter().any(|p| FORBIDDEN_STORAGE_PARTS.contains(&p.as_str()))
        || artifact_parts.iter().any(|p| p.starts_with(".validator-"))
    {
        errors.push("canonical handoff cannot use temporary/cache/review-run storage".to_string());
    }
    let suffix_is_md = actual_artifact
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase() == "md")
        .unwrap_or(false);
    if !suffix_is_md {
        errors.push("canonical handoff must be Markdown".to_string());
    }

    let Some(receipt_arg) = receipt_arg else {
        errors.push("validation must write or verify sidecar receipt".to_string());
        return errors;
    };
    if !receipt_arg.is_absolute() {
        errors.push("validator requires absolute receipt path".to_string());
    }
    if !is_absolute_path(&declared_receipt) {
        errors.push("declared receipt path must be absolute".to_string());
    } else if normalized_path(&declared_receipt, windows)
        != normalized_path(&receipt_arg.to_string_lossy(), windows)
    {
        errors.push("declared receipt path does not match validator receipt argument".to_string());
    }
    let receipt_parent = receipt_arg.parent().unwrap_or_else(|| Path::new(""));
    let artifact_parent = actual_artifact.parent().unwrap_or_else(|| Path::new(""));
    if normalized_path(&receipt_parent.to_string_lossy(), windows)
        != normalized_path(&artifact_parent.to_string_lossy(), windows)
    {
        errors.push("handoff receipt must be adjacent to canonical packet".to_string());
    }
    let stem = actual_artifact
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let expected_receipt = format!("{stem}.receipt.json");
    let receipt_name = receipt_arg
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    if receipt_name != expected_receipt {
        errors.push(format!("handoff receipt must be named {expected_receipt}"));
    }
    let receipt_parts: BTreeSet<String> = normalized_path(&receipt_arg.to_string_lossy(), windows)
        .split('/')
        .map(|s| s.to_string())
        .collect();
    if receipt_parts.iter().any(|p| FORBIDDEN_STORAGE_PARTS.contains(&p.as_str()))
        || receipt_parts.iter().any(|p| p.starts_with(".validator-"))
    {
        errors.push("handoff receipt cannot use temporary/cache/review-run storage".to_string());
    }
    errors
}

pub const HEADINGS: &[&str] = &[
    "# COLD-START HANDOFF:",
    "## 0. Handoff Control",
    "## 1. Intent & Mission",
    "## 2. Current State",
    "## 3. Environment & Active Work",
    "## 4. Decisions, Invariants & User Corrections",
    "## 5. Artifacts & Evidence",
    "## 6. Failures, Dead Ends & Attempts",
    "## 7. Learnings, Gotchas & Landmines",
    "## 8. Open Loops & Context Gaps",
    "## 9. Safety, Authority & Boundaries",
    "## 10. Exact Resume Sequence",
    "## 11. State Verification & Invalidation",
    "## 12. First Output & Readback Contract",
    "## 13. Ready-to-Paste First Message",
    "## 14. Context Gap Report",
    "## 15. Handoff Author Gate",
];

pub const LABELS: &[&str] = &[
    "**Handoff ID:**", "**Created:**", "**Source task / chat:**", "**Target:**",
    "**Author:**", "**Receiver role:**", "**Proceed mode:**", "**Readiness:**",
    "**Handoff reason:**", "**Source evidence mode:**",
    "**Transcript evidence path:**", "**Source prefix receipt:**",
    "**Packet path:**", "**Receipt path:**",
    "**Original user intent verbatim:**", "**Underlying goal:**",
    "**Current objective:**", "**Definition of success:**", "**Out of scope:**",
    "**First responsibility:**", "**Must not do first:**", "**Phase:**",
    "**Completed:**", "**In progress:**", "**Blocked:**", "**Not started:**",
    "**Last action:**", "**Last observed result:**", "**Active goal / plan:**",
    "**Current hypothesis:**", "**Work type:**", "**Workspace / repo:**",
    "**Branch / version:**", "**Baseline revision:**", "**Dirty state:**",
    "**OS / shell:**", "**Tools / dependencies:**", "**Services / processes:**",
    "**Agents / tasks / threads:**", "**Scheduled work:**",
    "**Credentials / access:**", "**May do:**", "**Do not change:**",
    "**Do not run:**", "**Irreversible / production actions:**",
    "**Spend / external effects:**", "**Secrets handling:**",
    "**Reserved decisions:**", "**Verification command:**", "**Expected state:**",
    "**Invalidated by:**", "**Refresh action:**", "**Validator command:**",
    "**Receiver receipt check:**", "**First deliverable after readback:**",
    "**Gap report format:**", "**Gap summary:**", "**Safe-to-proceed scope:**",
    "**Fatal recovery owner:**", "**Exact recovery sequence:**",
];

pub const STEP_LABELS: &[&str] = &[
    "**Owner:**", "**Working directory / system:**", "**Exact action:**",
    "**Expected result:**", "**Evidence path:**", "**Timeout / retry:**",
    "**If failure:**", "**Depends on:**",
];

const GENERIC: &[&str] = &[
    "", "value", "example", "placeholder", "fixture-value", "todo", "tbd", "n/a", "none",
];
const ENUM_VALUES: &[&str] = &[
    "READY", "READY_WITH_GAPS", "NOT_READY", "IMMEDIATE", "READBACK_ONLY",
    "REVIEW_ONLY", "DECISION", "CODE", "DOCUMENT", "RESEARCH", "OPERATIONS",
    "MIXED", "LOCKED", "ACTIVE_ASSUMPTION", "REVISIT_ON", "FATAL", "HIGH",
    "MEDIUM", "LOW", "NONE",
];

fn banned_patterns() -> &'static [(&'static str, Regex)] {
    static RE: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
        vec![
            ("old-chat dependency", Regex::new(r"(?i)\b(as discussed|see above|previous chat|you already know|prior[- ](?:thread|chat|conversation) context|earlier[- ](?:thread|chat|conversation)|inherited context|remembered state|implicit credentials?|(?:old|earlier|prior)[- ](?:messages?|session|history))\b").unwrap()),
            ("orphan continuation", Regex::new(r"(?i)\b(continue where we left off|just continue|usual constraints apply)\b").unwrap()),
            ("weak gap handling", Regex::new(r"(?i)\b(ask me if anything is unclear|catch up on)\b").unwrap()),
            ("unfinished marker", Regex::new(r"\b(TODO|TBD|TK)\b").unwrap()),
        ]
    });
    &RE
}

fn secret_patterns() -> &'static [(&'static str, Regex)] {
    static RE: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
        vec![
            ("OpenAI-like key", Regex::new(r"\bsk-[A-Za-z0-9_-]{20,}\b").unwrap()),
            ("GitHub token", Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b").unwrap()),
            ("Slack token", Regex::new(r"\bxox[a-z]-[A-Za-z0-9-]{10,}\b").unwrap()),
            ("AWS access key", Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap()),
            ("private key", Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap()),
            ("literal secret assignment", Regex::new(r#"(?i)\b(password|api[_-]?key|secret|token)\s*[:=]\s*[`"']?[A-Za-z0-9+/=_-]{12,}"#).unwrap()),
            ("authorization header", Regex::new(r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}").unwrap()),
            ("bearer credential", Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}").unwrap()),
        ]
    });
    &RE
}

fn step_re() -> &'static Regex {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?m)^### Resume Step\s+\d+\s+—\s+.+$").unwrap());
    &RE
}
fn path_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:[A-Za-z]:[\\/]|/)[^\s`|]+").unwrap());
    &RE
}
fn action_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(run|read|search|inspect|verify|capture|compare|resume|execute|open|check|record|load|query|test)\b").unwrap()
    });
    &RE
}
fn placeholder_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{[^{}\n]+\}\}").unwrap());
    &RE
}

pub fn label_value(text: &str, label: &str) -> Option<String> {
    let escaped = regex::escape(label);
    let re = Regex::new(&format!(r"(?m)^-\s+{escaped}\s*(.*)$")).ok()?;
    re.captures(text).map(|c| c[1].trim().to_string())
}

pub fn concrete(value: &str) -> bool {
    let raw = value.trim().trim_matches('`');
    if ENUM_VALUES.contains(&raw) {
        return true;
    }
    let normalized = raw.to_lowercase();
    normalized.chars().count() >= 8 && !GENERIC.contains(&normalized.as_str())
}

pub fn fenced_after(text: &str, label: &str) -> Option<String> {
    let escaped = regex::escape(label);
    let re = Regex::new(&format!(r"(?s){escaped}\s*\n+\s*```[^\n]*\n(.*?)\n```")).ok()?;
    re.captures(text).map(|c| c[1].trim().to_string())
}

pub fn table_rows(text: &str, start: &str, end: &str) -> Vec<Vec<String>> {
    let Some(left) = text.find(start) else {
        return Vec::new();
    };
    let Some(right_rel) = text[left + start.len()..].find(end) else {
        return Vec::new();
    };
    let right = left + start.len() + right_rel;
    let mut rows = Vec::new();
    let sep_re = Regex::new(r"^:?-{3,}:?$").unwrap();
    for line in text[left..right].lines() {
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<String> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_string())
            .collect();
        if cells.iter().all(|c| sep_re.is_match(c)) {
            continue;
        }
        rows.push(cells);
    }
    rows
}

pub fn table_errors(name: &str, rows: &[Vec<String>], width: usize, template: bool) -> Vec<String> {
    if rows.len() < 2 {
        return vec![format!("{name} requires at least one data row")];
    }
    let mut errors = Vec::new();
    for (row_index, row) in rows[1..].iter().enumerate() {
        let row_index = row_index + 1;
        if row.len() != width {
            errors.push(format!("{name} row {row_index} must contain {width} cells"));
            continue;
        }
        if !template {
            for (cell_index, cell) in row.iter().enumerate() {
                let cell_index = cell_index + 1;
                if !concrete(cell) {
                    errors.push(format!("{name} row {row_index} cell {cell_index} is too vague"));
                }
            }
        }
    }
    errors
}

pub fn ordered_errors(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut cursor: i64 = -1;
    for &heading in HEADINGS {
        match text.find(heading) {
            None => errors.push(format!("missing heading: {heading}")),
            Some(index) => {
                let index = index as i64;
                if index <= cursor {
                    errors.push(format!("heading out of order: {heading}"));
                } else {
                    cursor = index;
                }
            }
        }
    }
    errors
}

pub fn resume_errors(text: &str, template: bool) -> Vec<String> {
    let matches: Vec<_> = step_re().find_iter(text).collect();
    if matches.len() < 3 {
        return vec!["resume sequence requires at least 3 steps".to_string()];
    }
    let mut errors = Vec::new();
    let section_end = text
        .find("## 11. State Verification & Invalidation")
        .unwrap_or(text.len());
    for (index, m) in matches.iter().enumerate() {
        let end = matches.get(index + 1).map(|n| n.start()).unwrap_or(section_end);
        let block = &text[m.start()..end];
        let name = m.as_str();
        for &label in STEP_LABELS {
            if !block.contains(label) {
                errors.push(format!("{name} missing label: {label}"));
            }
        }
        let action = fenced_after(block, "**Exact action:**");
        if action.is_none() {
            errors.push(format!("{name} lacks fenced exact action"));
        }
        if template {
            continue;
        }
        for &label in STEP_LABELS {
            if label == "**Exact action:**" {
                continue;
            }
            let value = label_value(block, label).unwrap_or_default();
            if !concrete(&value) {
                errors.push(format!("{name} has non-concrete value: {label}"));
            }
        }
        let action_ok = action
            .as_ref()
            .map(|a| concrete(a) && action_re().is_match(a))
            .unwrap_or(false);
        if !action_ok {
            errors.push(format!("{name} exact action is not executable/actionable"));
        }
        for label in ["**Working directory / system:**", "**Evidence path:**"] {
            let value = label_value(block, label).unwrap_or_default();
            if !path_re().is_match(&value) {
                errors.push(format!("{name} {label} lacks explicit path"));
            }
        }
        let timeout_value = label_value(block, "**Timeout / retry:**").unwrap_or_default();
        if !timeout_value.chars().any(|c| c.is_ascii_digit()) {
            errors.push(format!("{name} timeout/retry lacks numeric bound"));
        }
    }
    errors
}

pub fn validate(text: &str, template: bool) -> Vec<String> {
    let mut errors = ordered_errors(text);
    for &label in LABELS {
        match label_value(text, label) {
            None => errors.push(format!("missing label: {label}")),
            Some(value) => {
                let is_optional_empty = matches!(
                    label,
                    "**Verification command:**" | "**Validator command:**" | "**Receiver receipt check:**"
                );
                if value.is_empty() && !is_optional_empty {
                    errors.push(format!("empty value: {label}"));
                } else if !template && GENERIC.contains(&value.trim().trim_matches('`').to_lowercase().as_str()) {
                    errors.push(format!("generic filler value: {label}"));
                }
            }
        }
    }

    errors.extend(resume_errors(text, template));

    let tables: [(&str, &str, &str, usize); 5] = [
        ("decision log", "## 4. Decisions, Invariants & User Corrections", "## 5. Artifacts & Evidence", 5),
        ("artifact map", "## 5. Artifacts & Evidence", "## 6. Failures, Dead Ends & Attempts", 6),
        ("failure map", "## 6. Failures, Dead Ends & Attempts", "## 7. Learnings, Gotchas & Landmines", 7),
        ("gotcha map", "## 7. Learnings, Gotchas & Landmines", "## 8. Open Loops & Context Gaps", 4),
        ("gap map", "## 8. Open Loops & Context Gaps", "## 9. Safety, Authority & Boundaries", 6),
    ];
    let mut parsed: std::collections::BTreeMap<&str, Vec<Vec<String>>> = std::collections::BTreeMap::new();
    for (name, start, end, width) in tables {
        let rows = table_rows(text, start, end);
        errors.extend(table_errors(name, &rows, width, template));
        parsed.insert(name, rows);
    }

    if !template {
        let readiness = label_value(text, "**Readiness:**").unwrap_or_default();
        let readiness = readiness.trim_matches('`');
        if !["READY", "READY_WITH_GAPS", "NOT_READY"].contains(&readiness) {
            errors.push("Readiness must be READY, READY_WITH_GAPS, or NOT_READY".to_string());
        }
        let proceed = label_value(text, "**Proceed mode:**").unwrap_or_default();
        let proceed = proceed.trim_matches('`');
        if !["IMMEDIATE", "READBACK_ONLY", "REVIEW_ONLY", "DECISION"].contains(&proceed) {
            errors.push("invalid Proceed mode".to_string());
        }
        let work_type = label_value(text, "**Work type:**").unwrap_or_default();
        let work_type = work_type.trim_matches('`');
        if !["CODE", "DOCUMENT", "RESEARCH", "OPERATIONS", "MIXED"].contains(&work_type) {
            errors.push("invalid Work type".to_string());
        }
        let source_mode = label_value(text, "**Source evidence mode:**").unwrap_or_default();
        let source_mode = source_mode.trim_matches('`').to_string();
        let evidence_path = label_value(text, "**Transcript evidence path:**").unwrap_or_default();
        let source_receipt = label_value(text, "**Source prefix receipt:**").unwrap_or_default();
        if !["TRANSCRIPT_INGEST", "LIVE_CONTEXT"].contains(&source_mode.as_str()) {
            errors.push("Source evidence mode must be TRANSCRIPT_INGEST or LIVE_CONTEXT".to_string());
        }
        if source_mode == "TRANSCRIPT_INGEST" {
            if !path_re().is_match(&evidence_path) {
                errors.push("TRANSCRIPT_INGEST requires absolute Membrane context path".to_string());
            }
            let upper = source_receipt.to_uppercase();
            for token in ["PLATFORM:", "SESSION_ID:", "CUTOFF_BYTES:", "SHA256:", "PARSER_VERSION:"] {
                if !upper.contains(token) {
                    errors.push(format!("TRANSCRIPT_INGEST source prefix receipt missing {token}"));
                }
            }
            if !Regex::new(r"(?i)\bSHA256:[0-9a-f]{64}\b").unwrap().is_match(&source_receipt) {
                errors.push("TRANSCRIPT_INGEST source prefix receipt requires 64-hex SHA256".to_string());
            }
            if !Regex::new(r"(?i)\bCUTOFF_BYTES:[1-9]\d*\b").unwrap().is_match(&source_receipt) {
                errors.push("TRANSCRIPT_INGEST source prefix receipt requires positive cutoff".to_string());
            }
        } else {
            let na_re = Regex::new(r"(?i)^NOT_APPLICABLE:\s*\S").unwrap();
            if !na_re.is_match(&evidence_path) {
                errors.push("LIVE_CONTEXT transcript evidence path requires NOT_APPLICABLE reason".to_string());
            }
            if !na_re.is_match(&source_receipt) {
                errors.push("LIVE_CONTEXT source prefix receipt requires NOT_APPLICABLE reason".to_string());
            }
        }

        let mut severities: Vec<String> = Vec::new();
        if let Some(rows) = parsed.get("gap map") {
            for row in rows.iter().skip(1) {
                if row.len() == 6 {
                    let severity = row[1].trim_matches('`').to_string();
                    if !["FATAL", "HIGH", "MEDIUM", "LOW", "NONE"].contains(&severity.as_str()) {
                        errors.push(format!("invalid gap severity: {severity}"));
                    }
                    severities.push(severity);
                }
            }
        }
        if readiness == "READY" && severities.iter().any(|s| s == "FATAL" || s == "HIGH") {
            errors.push("READY cannot contain FATAL or HIGH gap".to_string());
        }
        if readiness == "NOT_READY" && !severities.iter().any(|s| s == "FATAL") {
            errors.push("NOT_READY requires FATAL gap".to_string());
        }
        if readiness == "READY_WITH_GAPS" && severities.iter().all(|s| s == "NONE") {
            errors.push("READY_WITH_GAPS requires declared gap".to_string());
        }
        if readiness == "READY_WITH_GAPS" && severities.iter().any(|s| s == "FATAL") {
            errors.push("READY_WITH_GAPS cannot contain FATAL gap; use NOT_READY".to_string());
        }

        let verification = fenced_after(text, "**Verification command:**");
        let verification_ok = verification
            .as_ref()
            .map(|v| concrete(v) && action_re().is_match(v))
            .unwrap_or(false);
        if !verification_ok {
            errors.push("state verification lacks executable fenced command/action".to_string());
        }
        let validator_command = fenced_after(text, "**Validator command:**").unwrap_or_default();
        let receiver_command = fenced_after(text, "**Receiver receipt check:**").unwrap_or_default();
        let declared_packet = clean_path_value(&label_value(text, "**Packet path:**").unwrap_or_default());
        let declared_receipt = clean_path_value(&label_value(text, "**Receipt path:**").unwrap_or_default());
        for (label, command, flag) in [
            ("Validator command", &validator_command, "--write-receipt"),
            ("Receiver receipt check", &receiver_command, "--verify-receipt"),
        ] {
            let normalized_command = normalized_path(command, false);
            let ok = command.contains("validate-handoff.py")
                && command.contains(flag)
                && normalized_command.contains(&normalized_path(&declared_packet, false))
                && normalized_command.contains(&normalized_path(&declared_receipt, false));
            if !ok {
                errors.push(format!("{label} must execute validate-handoff.py with bound paths and {flag}"));
            }
        }
        for label in ["**Packet path:**", "**Receipt path:**", "**Workspace / repo:**"] {
            let value = label_value(text, label).unwrap_or_default();
            if !path_re().is_match(&value) {
                errors.push(format!("{label} lacks explicit path"));
            }
        }
        let first_start = text.find("## 13. Ready-to-Paste First Message").unwrap_or(0);
        let first_end = text.find("## 14. Context Gap Report").unwrap_or(text.len());
        let first_message = if first_end > first_start { &text[first_start..first_end] } else { "" };
        if !first_message.contains("READBACK") || !first_message.contains("Proceed mode") {
            errors.push("first message must require READBACK + Proceed mode".to_string());
        }
    }

    let author_start = text.find("## 15. Handoff Author Gate").unwrap_or(text.len());
    let author = &text[author_start..];
    if !template {
        if placeholder_re().is_match(text) {
            errors.push("unfilled placeholder remains".to_string());
        }
        if author.contains("- [ ]") {
            errors.push("handoff author gate contains unchecked item".to_string());
        }
        if author.matches("- [x]").count() < 18 {
            errors.push("handoff author gate requires 18 checked items".to_string());
        }
    }

    for (name, pattern) in banned_patterns() {
        if let Some(m) = pattern.find(text) {
            errors.push(format!("{name}: forbidden phrase '{}'", m.as_str()));
        }
    }
    if !template {
        for (name, pattern) in secret_patterns() {
            if pattern.is_match(text) {
                errors.push(format!("possible secret detected: {name}"));
            }
        }
    }

    let mut unique: Vec<String> = errors.into_iter().collect::<BTreeSet<_>>().into_iter().collect();
    unique.sort();
    unique
}

/// Convenience: absolute-path variant of `normalized_path` for callers that
/// already hold a `PathBuf` (mirrors `Path.resolve()` call sites in Python).
pub fn normalized_pathbuf(value: &Path, windows: bool) -> String {
    normalized_path(&value.to_string_lossy(), windows)
}

#[allow(dead_code)]
fn _unused(_p: PathBuf) {}
