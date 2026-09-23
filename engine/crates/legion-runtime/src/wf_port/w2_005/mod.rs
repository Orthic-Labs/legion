//! Rust port of `skills/covenant/scripts/validate-external-review-packet.py` and its
//! engine dependency `skills/covenant/engine/packet-validator.py`.
//!
//! `validate-external-review-packet.py` is a thin wrapper: it checks the packet's
//! `**Mode:**` label carries the canonical `PACKET_ONLY — DO_NOT_RUN_COVENANT` marker
//! before delegating to the engine validator's `validate()`. The engine validator does
//! the substantive, fail-closed structural/content checks on a Covenant "external review
//! packet" markdown document (heading order, required labels, unfilled placeholders,
//! absolute-path/packet-path agreement, evidence bundle substance, banned old-context
//! phrases, secret-pattern scanning, and response-contract verdict values).
//!
//! This port keeps the same two-layer shape: [`validate_packet`] mirrors
//! `packet-validator.py`'s `validate()`, and [`validate_external_review_packet`] mirrors
//! `validate-external-review-packet.py`'s `validate()` (the `CANONICAL` mode gate, then
//! delegation). Both return the same sorted, de-duplicated list of defect strings the
//! Python CLIs print one per line under a `FAIL: N packet defect(s)` header.
//!
//! Not ported: the two scripts' `main()` / argparse CLI entry points (file I/O, exit
//! codes, stderr messages for a missing packet file). Those are process-boundary
//! concerns; the pure `validate()` functions are what downstream Rust callers need, and
//! the test file exercises both through in-memory strings exactly as
//! `test_validate_external_review_packet.py` does.

use std::path::{Component, Path, PathBuf};

use regex::Regex;

/// The canonical `**Mode:**` value a packet must declare. Mirrors
/// `validate-external-review-packet.py`'s `CANONICAL`.
pub const CANONICAL_EXTERNAL_MODE: &str = "PACKET_ONLY — DO_NOT_RUN_COVENANT";

/// The canonical `**Mode:**` value the engine validator itself checks. Mirrors
/// `packet-validator.py`'s `CANONICAL_MODE` (identical string; kept as a separate
/// constant so each layer mirrors its Python source independently).
pub const CANONICAL_MODE: &str = "PACKET_ONLY — DO_NOT_RUN_COVENANT";

const HEADINGS: &[&str] = &[
    "# EXTERNAL REVIEW PACKET",
    "## 0. Packet Control",
    "## 1. Problem in Plain Language",
    "## 2. User Intent",
    "### Exact request",
    "### Desired outcome",
    "### Definition of success",
    "## 3. What Went Wrong",
    "## 4. Current System & State",
    "## 5. Constraints & Invariants",
    "## 6. Existing Attempts & Inputs",
    "## 7. Evidence Bundle",
    "## 8. Known Unknowns",
    "## 9. Questions for Reviewer",
    "## 10. Response Contract",
];

const LABELS: &[&str] = &[
    "**Created:**",
    "**Mode:**",
    "**Audience:**",
    "**Packet path:**",
    "**Requested response:**",
];

const FORBIDDEN_STORAGE: &[&str] = &[
    "temp",
    "tmp",
    ".tmp",
    "temporary",
    "cache",
    ".cache",
    "review-run",
    "review-runs",
    ".review-runs",
    ".covenant-runs",
    "scratch",
];

const BANNED: &[&str] = &[
    "as discussed",
    "see previous chat",
    "continue where we left off",
    "you already know",
    "prior-thread context",
    "prior chat context",
    "earlier conversation",
    "inherited context",
    "remembered state",
    "implicit credentials",
    "old messages",
    "earlier messages",
    "prior session",
    "old session",
];

/// (name, pattern) pairs mirroring Python's `SECRET_PATTERNS` dict. A `Vec` (not a map)
/// so error emission order is deterministic before the final `sort + dedup`.
const SECRET_PATTERNS: &[(&str, &str)] = &[
    (
        "literal secret",
        r#"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*[`"']?[A-Za-z0-9+/=_-]{12,}"#,
    ),
    (
        "authorization header",
        r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}",
    ),
    (
        "bearer credential",
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}",
    ),
    (
        "private key",
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    ),
    ("OpenAI-like key", r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ("Slack token", r"\bxox[a-z]-[A-Za-z0-9-]{10,}\b"),
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b"),
];

/// Mirrors Python's `label_value(text, label)`: finds a line `- **Label:** value` and
/// returns the trimmed value, or `None` if the label line is absent.
fn label_value(text: &str, label: &str) -> Option<String> {
    let pattern = format!(r"(?m)^-\s*{}\s*(.*)$", regex::escape(label));
    let re = Regex::new(&pattern).expect("static label pattern is valid");
    re.captures(text)
        .map(|c| c.get(1).map(|m| m.as_str()).unwrap_or("").trim().to_string())
}

/// Lexically normalizes a path the way Python's `Path(...).expanduser().resolve()` does
/// for `resolve(strict=False)`: collapses `.`/`..` components against a base directory
/// without requiring the path to exist on disk. `~` is expanded against `$HOME` when
/// present at the start of the path (mirrors `expanduser()`).
fn resolve_lexical(raw: &str, base: &Path) -> PathBuf {
    let expanded: String = if raw == "~" || raw.starts_with("~/") {
        match std::env::var("HOME") {
            Ok(home) => {
                if raw == "~" {
                    home
                } else {
                    format!("{}/{}", home.trim_end_matches('/'), &raw[2..])
                }
            }
            Err(_) => raw.to_string(),
        }
    } else {
        raw.to_string()
    };

    let candidate = Path::new(&expanded);
    let absolute: PathBuf = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    };

    let mut out: Vec<Component> = Vec::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.last(), Some(Component::Normal(_))) {
                    out.pop();
                } else {
                    out.push(component);
                }
            }
            other => out.push(other),
        }
    }
    out.into_iter().collect()
}

/// Mirrors Python's `normalized(value, platform_name=None)`. `platform_windows` stands
/// in for the Python code's `(platform_name or os.name) == "nt"` check (this port is
/// exercised on the platforms Legion builds for; callers on Windows should pass `true`
/// to get casefolded/Windows-drive comparison semantics, matching the Python original's
/// `os.name` default when no explicit `platform_name` is supplied).
fn normalized(value: &str, platform_windows: bool) -> String {
    let raw = value.trim().trim_matches(|c| c == '`' || c == '"' || c == '\'');
    let raw = raw.replace('\\', "/");

    let windows_drive_re = Regex::new(r"^[A-Za-z]:/").expect("static pattern is valid");
    let result = if windows_drive_re.is_match(&raw) {
        raw.trim_end_matches('/').to_string()
    } else {
        let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        let resolved = resolve_lexical(&raw, &base);
        let mut s = resolved.to_string_lossy().replace('\\', "/");
        if s.len() > 1 {
            s = s.trim_end_matches('/').to_string();
        }
        s
    };

    if platform_windows {
        result.to_lowercase()
    } else {
        result
    }
}

/// Mirrors Python's `table_rows(text, start, end)`: within `text[start_idx..end_idx]`,
/// collects pipe-delimited table rows, skipping the `|---|---|` separator row.
fn table_rows(text: &str, start: &str, end: &str) -> Vec<Vec<String>> {
    let Some(a) = text.find(start) else {
        return Vec::new();
    };
    let Some(b) = text.find(end) else {
        return Vec::new();
    };
    if a >= b {
        return Vec::new();
    }
    let separator_re = Regex::new(r"^\|[\s:|-]+\|$").expect("static pattern is valid");
    let mut rows = Vec::new();
    for line in text[a..b].lines() {
        if line.starts_with('|') && !separator_re.is_match(line) {
            let trimmed = line.trim().trim_matches('|');
            rows.push(trimmed.split('|').map(|cell| cell.trim().to_string()).collect());
        }
    }
    rows
}

fn sorted_dedup(mut errors: Vec<String>) -> Vec<String> {
    errors.sort();
    errors.dedup();
    errors
}

/// Rust port of `packet-validator.py`'s `validate(text, path, inline, template=False)`.
///
/// `path` need not exist on disk — mirrors the Python `Path.resolve(strict=False)`
/// behaviour used throughout. `platform_windows` selects the `os.name == "nt"` path-
/// comparison semantics (see [`normalized`]); pass `false` on macOS/Linux.
pub fn validate_packet(
    text: &str,
    path: &Path,
    inline: bool,
    template: bool,
    platform_windows: bool,
) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();
    let mut cursor: i64 = -1;

    for heading in HEADINGS {
        let search_from = (cursor + 1).max(0) as usize;
        let position = if search_from > text.len() {
            None
        } else {
            text[search_from..].find(heading).map(|p| p + search_from)
        };
        match position {
            Some(pos) => cursor = pos as i64,
            None => errors.push(format!("missing or out-of-order heading: {}", heading)),
        }
    }

    for label in LABELS {
        match label_value(text, label) {
            None => errors.push(format!("missing label: {}", label)),
            Some(value) if value.is_empty() => errors.push(format!("empty label: {}", label)),
            Some(_) => {}
        }
    }

    if template {
        return sorted_dedup(errors);
    }

    let placeholder_re = Regex::new(r"\{\{[^{}\n]+\}\}").expect("static pattern is valid");
    if placeholder_re.is_match(text) {
        errors.push("unfilled placeholder remains".to_string());
    }
    if label_value(text, "**Mode:**").as_deref() != Some(CANONICAL_MODE) {
        errors.push(format!("Mode must be {}", CANONICAL_MODE));
    }

    let declared = label_value(text, "**Packet path:**").unwrap_or_default();
    let absolute_re = Regex::new(r"(?:[A-Za-z]:[\\/]|/)[^\n|]+").expect("static pattern is valid");
    if inline {
        if declared.trim_matches('`').to_uppercase() != "INLINE" {
            errors.push("inline packet must declare Packet path INLINE".to_string());
        }
    } else {
        if !path.is_absolute() {
            errors.push("durable packet validator requires absolute file path".to_string());
        }
        if !absolute_re.is_match(&declared) {
            errors.push("durable packet must declare absolute Packet path".to_string());
        } else {
            let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
            let resolved_path = resolve_lexical(&path.to_string_lossy(), &base);
            if normalized(&declared, platform_windows)
                != normalized(&resolved_path.to_string_lossy(), platform_windows)
            {
                errors.push("declared Packet path does not match validated file".to_string());
            }
        }
        let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        let resolved_path = resolve_lexical(&path.to_string_lossy(), &base);
        let normalized_path = normalized(&resolved_path.to_string_lossy(), platform_windows);
        let path_parts: std::collections::HashSet<&str> = normalized_path.split('/').collect();
        let forbidden_hit = FORBIDDEN_STORAGE.iter().any(|s| path_parts.contains(s));
        let validator_dir_hit = path_parts.iter().any(|p| p.starts_with(".validator-"));
        if forbidden_hit || validator_dir_hit {
            errors.push("durable packet cannot use temporary/cache/review-run storage".to_string());
        }
        let suffix_is_md = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase() == "md")
            .unwrap_or(false);
        if !suffix_is_md {
            errors.push("durable packet must be Markdown".to_string());
        }
    }

    let exact_start = text.find("### Exact request");
    let exact_end = exact_start.and_then(|s| text[s..].find("### Desired outcome").map(|e| e + s));
    let exact_block = match (exact_start, exact_end) {
        (Some(s), Some(e)) => &text[s..e],
        (Some(s), None) => &text[s..],
        (None, _) => "",
    };
    let exact_quote_re = Regex::new(r"(?m)^>\s+\S.{15,}$").expect("static pattern is valid");
    if !exact_quote_re.is_match(exact_block) {
        errors.push("Exact request must include substantive verbatim quote".to_string());
    }

    for (name, start, end, width) in [
        ("failure", "## 3. What Went Wrong", "## 4. Current System & State", 3),
        ("attempt", "## 6. Existing Attempts & Inputs", "## 7. Evidence Bundle", 3),
    ] {
        let rows = table_rows(text, start, end);
        if rows.len() < 2 {
            errors.push(format!("{} table requires data row", name));
        }
        for (index, row) in rows.iter().enumerate().skip(1) {
            if row.len() != width || row.iter().any(|cell| cell.len() < 6) {
                errors.push(format!("{} table row {} is incomplete", name, index));
            }
        }
    }

    let evidence_start = text.find("## 7. Evidence Bundle");
    let evidence_end =
        evidence_start.and_then(|s| text[s..].find("## 8. Known Unknowns").map(|e| e + s));
    let evidence = match (evidence_start, evidence_end) {
        (Some(s), Some(e)) => &text[s..e],
        (Some(s), None) => &text[s..],
        (None, _) => "",
    };
    let fenced_re = Regex::new(r"(?s)```(?:text)?\s*\n(.+?)\n```").expect("static pattern is valid");
    let evidence_ok = fenced_re
        .captures(evidence)
        .map(|c| c.get(1).unwrap().as_str().trim().len() >= 60)
        .unwrap_or(false);
    if !evidence_ok {
        errors.push("Evidence Bundle requires substantive embedded evidence".to_string());
    }

    let lower = text.to_lowercase();
    for phrase in BANNED {
        if lower.contains(phrase) {
            errors.push(format!("old-context dependency: {}", phrase));
        }
    }
    for (name, pattern) in SECRET_PATTERNS {
        let re = Regex::new(pattern).expect("static secret pattern is valid");
        if re.is_match(text) {
            errors.push(format!("possible secret detected: {}", name));
        }
    }
    if !text.contains("READY_TO_IMPLEMENT") || !text.contains("REVISE_PACKET") {
        errors.push("response contract lacks required verdict values".to_string());
    }

    sorted_dedup(errors)
}

/// Rust port of `validate-external-review-packet.py`'s `validate(text, path, inline,
/// template=False)`: checks the canonical `PACKET_ONLY — DO_NOT_RUN_COVENANT` mode
/// marker is present anywhere in `text` before delegating to [`validate_packet`]. If the
/// marker is absent, returns exactly `["Mode must be PACKET_ONLY — DO_NOT_RUN_COVENANT"]`
/// without running the deeper structural checks (matching the Python short-circuit).
pub fn validate_external_review_packet(
    text: &str,
    path: &Path,
    inline: bool,
    template: bool,
    platform_windows: bool,
) -> Vec<String> {
    if !text.contains(CANONICAL_EXTERNAL_MODE) {
        return vec![format!("Mode must be {}", CANONICAL_EXTERNAL_MODE)];
    }
    validate_packet(text, path, inline, template, platform_windows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_canonical_marker_short_circuits() {
        let errors = validate_external_review_packet(
            "no marker here",
            Path::new("/tmp/x.md"),
            true,
            false,
            false,
        );
        assert_eq!(errors, vec!["Mode must be PACKET_ONLY — DO_NOT_RUN_COVENANT"]);
    }

    #[test]
    fn table_rows_skips_separator_line() {
        let text = "## 3. What Went Wrong\n\n\
                     | Failure | Exact symptom/evidence | Consequence |\n\
                     |---|---|---|\n\
                     | Crash | some error text | broke build |\n\n\
                     ## 4. Current System & State\n";
        let rows = table_rows(text, "## 3. What Went Wrong", "## 4. Current System & State");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1], vec!["Crash", "some error text", "broke build"]);
    }
}
