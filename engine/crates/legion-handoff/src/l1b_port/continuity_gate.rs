//! Mechanical packet checks against a verified continuity context.
//!
//! These checks bind a packet to the hash-bound source assertion block and to
//! the declared last-N-turns window of the verified transcript prefix:
//!
//! - the packet may not state, as a LOCKED decision, the old value of a
//!   decision the block lists as changed, and every changed entry must be
//!   accounted for (no unaccounted or unknown deltas);
//! - source memory directory (or explicit absence) and artifact roots from the
//!   block must appear in the packet, and durable roots must resolve
//!   physically outside temp/cache/scratch storage;
//! - typed references (issue/PR numbers, exception ids) in the declared last N
//!   conversation turns must each appear in the packet or in an explicit
//!   omission line with a reason.
//!
//! Identifier accounting is a string-level omission detector. It cannot
//! certify that the packet is semantically complete, that an included
//! reference is described correctly, or that references outside the window or
//! outside these typed patterns were handled.

use regex::Regex;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;

use super::validate::{
    clean_path_value, command_has_flag, fenced_after, has_forbidden_part, label_value,
    normalized_path, physical_norm, resolve_physical_existing, table_rows,
};
use crate::l1_port::continuity::{ContinuityContext, ContinuityEvent};
use crate::l1_port::live_state::{bare_hex, compare_form, SourceBlock};

pub const SOURCE_ASSERTION_LABEL: &str =
    "**Source assertion (hash-bound claim, not transcript evidence):**";
pub const MEMORY_LABEL: &str = "**Source memory:**";
pub const WINDOW_LABEL: &str = "**Identifier accounting window:**";
const MAX_WINDOW_TURNS: usize = 1_000;
const MIN_REASON_CHARS: usize = 8;

fn changed_line_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?m)^-\s+\*\*Changed-since accounted:\*\*\s*([A-Za-z0-9_.-]+?)\s*(?:—|:|\s-\s)\s*(\S.*)$",
        )
        .unwrap()
    });
    &RE
}

fn changed_marker_re() -> &'static Regex {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?m)^-\s+\*\*Changed-since accounted:\*\*").unwrap());
    &RE
}

fn omitted_line_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?m)^-\s+\*\*Omitted identifier:\*\*\s*((?:(?i:exception|exc|issue|pr|pull request|pull)\s+)?\S+?)\s*(?:—|:|\s-\s)\s*(\S.*)$",
        )
        .unwrap()
    });
    &RE
}

fn omitted_marker_re() -> &'static Regex {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?m)^-\s+\*\*Omitted identifier:\*\*").unwrap());
    &RE
}

fn window_re() -> &'static Regex {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\blast\s+(\d{1,4})\s+turns?\b").unwrap());
    &RE
}

fn digest_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{64}\b").unwrap());
    &RE
}

fn prefix_sha_re() -> &'static Regex {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\bSHA256:([0-9a-f]{64})\b").unwrap());
    &RE
}

/// Typed references the accounting understands:
/// `#123`, `owner/repo#123`, `issue 123`, `PR 123`, `pull request 123`
/// (all keyed `#123`; repository prefixes are not distinguished), and
/// `exception M21` (keyed `exception:M21`).
fn typed_ref_patterns() -> &'static [(Regex, &'static str)] {
    static RE: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
        vec![
            (Regex::new(r"[A-Za-z0-9_./-]*#(\d{1,6})\b").unwrap(), "#"),
            (
                Regex::new(r"(?i)\b(?:issues?|prs?|pull requests?|pull)\s+#?(\d{1,6})\b").unwrap(),
                "#",
            ),
            (
                Regex::new(r"\b(?i:exception|exc)\s*[:#]?\s*([A-Z]{1,3}\d{1,4})\b").unwrap(),
                "exception:",
            ),
        ]
    });
    &RE
}

/// Typed reference keys found in `text`.
pub fn extract_refs(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for (pattern, prefix) in typed_ref_patterns() {
        for caps in pattern.captures_iter(text) {
            found.insert(format!("{prefix}{}", &caps[1]));
        }
    }
    found
}

fn is_conversation_turn(event: &ContinuityEvent) -> bool {
    event.kind == "user_message" || event.kind == "assistant_message"
}

/// Conversation events from the Nth-from-last user request onward.
fn window_events(context: &ContinuityContext, turns: usize) -> Vec<&ContinuityEvent> {
    let starts: Vec<u64> = context.user_requests.iter().map(|e| e.sequence).collect();
    let start = if starts.len() > turns {
        starts[starts.len() - turns]
    } else {
        0
    };
    context
        .events
        .iter()
        .filter(|event| is_conversation_turn(event) && event.sequence >= start)
        .collect()
}

fn without_marker_lines(text: &str, marker: &Regex) -> String {
    text.lines()
        .filter(|line| !marker.is_match(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn reason_ok(reason: &str) -> bool {
    reason.trim().chars().count() >= MIN_REASON_CHARS
}

/// All continuity-bound errors for a packet validated with `--context`.
pub fn continuity_errors(
    text: &str,
    context: &ContinuityContext,
    context_path: &Path,
    windows: bool,
) -> Vec<String> {
    let mut errors = Vec::new();
    let mode = label_value(text, "**Source evidence mode:**")
        .unwrap_or_default()
        .trim_matches('`')
        .to_string();
    if mode != "TRANSCRIPT_INGEST" {
        errors.push("--context requires Source evidence mode TRANSCRIPT_INGEST".to_string());
        return errors;
    }
    prefix_errors(text, context, context_path, windows, &mut errors);
    for (label, flag_label) in [
        ("Validator command", "**Validator command:**"),
        ("Receiver receipt check", "**Receiver receipt check:**"),
    ] {
        let command = fenced_after(text, flag_label).unwrap_or_default();
        if !command_has_flag(&command, "--context") {
            errors.push(format!(
                "{label} must include --context <context.json> for a TRANSCRIPT_INGEST packet"
            ));
        }
    }
    match &context.source_assertion {
        Some(block) => {
            let declared = label_value(text, SOURCE_ASSERTION_LABEL).unwrap_or_default();
            let expected = context
                .receipt
                .source_block_sha256
                .as_deref()
                .map(bare_hex)
                .unwrap_or_default();
            let digests: Vec<String> = digest_re()
                .find_iter(&declared)
                .map(|m| m.as_str().to_ascii_lowercase())
                .collect();
            if expected.is_empty() || !digests.contains(&expected) {
                errors.push(
                    "Source assertion label must carry the context's source block SHA-256"
                        .to_string(),
                );
            }
            memory_errors(text, block, &mut errors);
            change_errors(text, block, &mut errors);
            block_artifact_root_errors(text, block, windows, &mut errors);
        }
        None => {
            let declared = label_value(text, SOURCE_ASSERTION_LABEL).unwrap_or_default();
            if digest_re().is_match(&declared) {
                errors.push(
                    "packet declares a source assertion digest but the context has no source block"
                        .to_string(),
                );
            }
            if changed_marker_re().is_match(text) {
                errors.push(
                    "packet accounts for changed-since entries but the context has no source block"
                        .to_string(),
                );
            }
        }
    }
    identifier_errors(text, context, &mut errors);
    errors
}

fn prefix_errors(
    text: &str,
    context: &ContinuityContext,
    context_path: &Path,
    windows: bool,
    errors: &mut Vec<String>,
) {
    let receipt = label_value(text, "**Source prefix receipt:**").unwrap_or_default();
    match prefix_sha_re().captures(&receipt) {
        Some(caps) if caps[1].to_ascii_lowercase() == bare_hex(&context.source.sha256) => {}
        _ => errors.push(
            "packet source prefix SHA256 does not match the verified continuity context"
                .to_string(),
        ),
    }
    let declared =
        clean_path_value(&label_value(text, "**Transcript evidence path:**").unwrap_or_default());
    let lexical = normalized_path(&context_path.to_string_lossy(), windows);
    let physical = resolve_physical_existing(context_path)
        .map(|p| physical_norm(&p, windows))
        .unwrap_or_default();
    let declared = normalized_path(&declared, windows);
    if declared != lexical && declared != physical {
        errors.push(
            "Transcript evidence path does not match the validated --context file".to_string(),
        );
    }
}

fn memory_errors(text: &str, block: &SourceBlock, errors: &mut Vec<String>) {
    let Some(memory) = &block.memory else {
        errors.push(
            "source block does not record a memory directory or explicit absence".to_string(),
        );
        return;
    };
    let value = label_value(text, MEMORY_LABEL).unwrap_or_default();
    let value = value.trim().trim_matches('`').to_string();
    match (&memory.dir, &memory.absent_reason) {
        (Some(dir), _) => {
            if !value.contains(dir.as_str()) {
                errors.push(format!(
                    "{MEMORY_LABEL} must record the source memory directory {dir}"
                ));
            }
        }
        (None, Some(_)) => {
            if !value.to_ascii_uppercase().starts_with("ABSENT:")
                || !reason_ok(&value["ABSENT:".len()..])
            {
                errors.push(format!(
                    "{MEMORY_LABEL} must be `ABSENT: <reason>` because the source recorded no memory"
                ));
            }
        }
        (None, None) => {}
    }
}

fn change_errors(text: &str, block: &SourceBlock, errors: &mut Vec<String>) {
    let accounted: Vec<(String, String)> = changed_line_re()
        .captures_iter(text)
        .map(|c| (c[1].to_string(), c[2].trim().to_string()))
        .collect();
    let marker_count = changed_marker_re().find_iter(text).count();
    if marker_count != accounted.len() {
        errors.push(
            "a Changed-since accounted line is malformed; use `<id> — <how the packet states the new value>`"
                .to_string(),
        );
    }
    let known: BTreeSet<&str> = block.changed_since.iter().map(|c| c.id.as_str()).collect();
    let mut seen = BTreeSet::new();
    for (id, how) in &accounted {
        if !known.contains(id.as_str()) {
            errors.push(format!(
                "Changed-since accounted line names unknown change id {id}"
            ));
            continue;
        }
        if !seen.insert(id.clone()) {
            errors.push(format!("change {id} is accounted for more than once"));
        }
        let change = block.changed_since.iter().find(|c| &c.id == id).unwrap();
        if !reason_ok(how) || !compare_form(how).contains(&compare_form(&change.new)) {
            errors.push(format!(
                "accounting for change {id} must restate the new value `{}`",
                change.new
            ));
        }
    }
    for change in &block.changed_since {
        if !seen.contains(&change.id) {
            errors.push(format!(
                "unaccounted change {}: the source block lists `{}` as changed since its baseline; add a Changed-since accounted line",
                change.id, change.decision
            ));
        }
    }

    let rows = table_rows(
        text,
        "## 4. Decisions, Invariants & User Corrections",
        "## 5. Artifacts & Evidence",
    );
    for (index, row) in rows.iter().enumerate().skip(1) {
        if row.len() != 5 || row[3].trim_matches('`') != "LOCKED" {
            continue;
        }
        let stated = compare_form(&row[1]);
        for change in &block.changed_since {
            if stated.contains(&compare_form(&change.old))
                && !stated.contains(&compare_form(&change.new))
            {
                errors.push(format!(
                    "decision row {index} states changed decision {} as LOCKED with the superseded value `{}`",
                    change.id, change.old
                ));
            }
        }
    }
}

fn block_artifact_root_errors(
    text: &str,
    block: &SourceBlock,
    windows: bool,
    errors: &mut Vec<String>,
) {
    let rows = table_rows(
        text,
        "## 5. Artifacts & Evidence",
        "## 6. Failures, Dead Ends & Attempts",
    );
    for root in &block.artifact_roots {
        let listed = rows.iter().skip(1).any(|row| {
            row.get(1)
                .is_some_and(|cell| cell.replace('`', "").contains(&root.path))
        });
        if !listed {
            errors.push(format!(
                "artifact root {} from the source block is not in the Artifacts & Evidence table",
                root.path
            ));
        }
        if root.durable {
            match resolve_physical_existing(Path::new(&root.path)) {
                Ok(physical) => {
                    let norm = physical_norm(&physical, windows);
                    let lexical = normalized_path(&root.path, windows);
                    if has_forbidden_part(&[norm.as_str(), lexical.as_str()]) {
                        errors.push(format!(
                            "durable artifact root {} resolves into temp/cache/scratch storage",
                            root.path
                        ));
                    }
                }
                Err(e) => errors.push(format!("durable artifact root is not resolvable: {e}")),
            }
        }
    }
}

fn identifier_errors(text: &str, context: &ContinuityContext, errors: &mut Vec<String>) {
    let window = label_value(text, WINDOW_LABEL).unwrap_or_default();
    let turns = window_re()
        .captures(&window)
        .and_then(|caps| caps[1].parse::<usize>().ok())
        .filter(|n| (1..=MAX_WINDOW_TURNS).contains(n));
    let Some(turns) = turns else {
        errors.push(format!(
            "{WINDOW_LABEL} must declare the window as `last <N> turns` (1-{MAX_WINDOW_TURNS})"
        ));
        return;
    };

    let mut window_refs = BTreeSet::new();
    for event in window_events(context, turns) {
        window_refs.extend(extract_refs(&event.text));
    }

    let marker_count = omitted_marker_re().find_iter(text).count();
    let mut omissions: Vec<(String, String)> = Vec::new();
    for caps in omitted_line_re().captures_iter(text) {
        let refs = extract_refs(&caps[1]);
        if refs.len() != 1 {
            errors.push(format!(
                "omitted identifier `{}` is not a single typed reference (#123 or exception M21)",
                &caps[1]
            ));
            continue;
        }
        let key = refs.into_iter().next().unwrap();
        if !reason_ok(&caps[2]) {
            errors.push(format!("omission of {key} needs a concrete reason"));
        }
        omissions.push((key, caps[2].trim().to_string()));
    }
    if marker_count != omitted_line_re().captures_iter(text).count() {
        errors.push(
            "an Omitted identifier line is malformed; use `<reference> — <reason>`".to_string(),
        );
    }

    let body = without_marker_lines(text, omitted_marker_re());
    let body_refs = extract_refs(&body);
    for key in &window_refs {
        let in_packet = body_refs.contains(key)
            || key.strip_prefix("exception:").is_some_and(|id| {
                Regex::new(&format!(r"\b{}\b", regex::escape(id)))
                    .map(|re| re.is_match(&body))
                    .unwrap_or(false)
            });
        let omitted = omissions.iter().any(|(k, _)| k == key);
        if !in_packet && !omitted {
            errors.push(format!(
                "reference {key} appears in the last {turns} turns but is neither in the packet nor in an Omitted identifier line"
            ));
        }
    }
    for (key, _) in &omissions {
        if !window_refs.contains(key) {
            errors.push(format!(
                "omitted identifier {key} does not appear in the last {turns} turns"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_typed_references_only() {
        let refs = extract_refs(
            "see bogusyogi/rightkit#914 and PR 12, issue #7; exception M21 b1; ## 3. heading; #prefix=0",
        );
        let expected: BTreeSet<String> = ["#914", "#12", "#7", "exception:M21"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(refs, expected);
    }
}
