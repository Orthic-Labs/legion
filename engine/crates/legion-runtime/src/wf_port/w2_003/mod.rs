//! Port of `skills/covenant/engine/packet-validator.py`.
//!
//! Fail-closed validator for packet-only external review briefs
//! (Covenant-owned). Faithful port: same headings, same labels, same
//! error strings, same ordering rules.

use std::path::Path;

use regex::Regex;
use std::sync::LazyLock;

pub const HEADINGS: &[&str] = &[
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

pub const LABELS: &[&str] = &[
    "**Created:**",
    "**Mode:**",
    "**Audience:**",
    "**Packet path:**",
    "**Requested response:**",
];

pub const CANONICAL_MODE: &str = "PACKET_ONLY — DO_NOT_RUN_COVENANT";

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

/// (name, pattern) pairs, mirroring the Python `SECRET_PATTERNS` dict order.
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

static PLACEHOLDER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{[^{}\n]+\}\}").unwrap());
// Python's ABSOLUTE_RE is `(?:[A-Za-z]:[\\/]|/)[^\n|]+`; Rust's `regex` crate
// has no lookaround needs here so this translates directly.
static ABSOLUTE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:[A-Za-z]:[\\/]|/)[^\n|]+").unwrap());
static EXACT_REQUEST_QUOTE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^>\s+\S.{15,}$").unwrap());
static LABEL_LINE_RES: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    LABELS
        .iter()
        .map(|label| {
            let pattern = format!(r"(?m)^-\s*{}\s*(.*)$", regex::escape(label));
            (*label, Regex::new(&pattern).unwrap())
        })
        .collect()
});
static FENCED_EVIDENCE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)```(?:text)?\s*\n(.+?)\n```").unwrap());
static TABLE_SEPARATOR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\|[\s:|-]+\|$").unwrap());
static SECRET_RES: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    SECRET_PATTERNS
        .iter()
        .map(|(name, pattern)| (*name, Regex::new(pattern).unwrap()))
        .collect()
});

/// Extract the value of a `- **Label:** value` line, mirroring
/// Python's `label_value`. Returns `None` when the label line is absent.
pub fn label_value<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    LABEL_LINE_RES
        .iter()
        .find(|(name, _)| *name == label)
        .and_then(|(_, re)| re.captures(text))
        .map(|caps| caps.get(1).unwrap().as_str().trim())
}

/// Mirrors Python's `normalized`: strips quoting/backslashes, resolves a
/// leading `C:/`-style drive form as-is, otherwise resolves the path
/// against the current directory, and casefolds only on Windows-like
/// platform names (matching `os.name == "nt"` semantics via `platform_name`).
pub fn normalized(value: &str, platform_name: Option<&str>) -> String {
    let raw = value
        .trim()
        .trim_matches(|c| c == '`' || c == '"' || c == '\'')
        .replace('\\', "/");

    let drive_re: &LazyLock<Regex> = &DRIVE_RE;
    let result = if drive_re.is_match(&raw) {
        raw.trim_end_matches('/').to_string()
    } else {
        let path = Path::new(&raw);
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        };
        // Best-effort canonicalize (Python's Path.resolve()); fall back to
        // the joined path when the target does not exist on disk.
        let canonical = std::fs::canonicalize(&resolved).unwrap_or(resolved);
        canonical
            .to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_string()
    };

    let is_nt = platform_name.unwrap_or(std::env::consts::OS) == "nt"
        || platform_name.is_none() && cfg!(target_os = "windows");
    if is_nt {
        result.to_lowercase()
    } else {
        result
    }
}

static DRIVE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z]:/").unwrap());

/// Mirrors Python's `table_rows`: extracts pipe-delimited rows between two
/// markers, skipping markdown separator rows (`|---|---|`).
pub fn table_rows(text: &str, start: &str, end: &str) -> Vec<Vec<String>> {
    let Some(a) = text.find(start) else {
        return Vec::new();
    };
    let Some(b_rel) = text[a..].find(end) else {
        return Vec::new();
    };
    let b = a + b_rel;
    if b < a {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for line in text[a..b].lines() {
        if line.starts_with('|') && !TABLE_SEPARATOR_RE.is_match(line) {
            let trimmed = line.trim().trim_matches('|');
            rows.push(trimmed.split('|').map(|cell| cell.trim().to_string()).collect());
        }
    }
    rows
}

/// Faithful port of Python's `validate(text, path, inline, template)`.
///
/// `path` is the packet path as supplied by the caller (may be relative);
/// pass an already-resolved absolute path when you have one, matching how
/// the Python CLI passes `args.packet` (a `Path`, not yet `.resolve()`d,
/// except where `normalized(path.resolve())` is called explicitly below).
pub fn validate(text: &str, path: &Path, inline: bool, template: bool) -> Vec<String> {
    // Mirrors the production CLI wrapper `validate-external-review-packet.py`,
    // which short-circuits ahead of the engine validator: if the canonical
    // mode marker is absent from the packet anywhere, that is reported
    // immediately regardless of `template`/self-check mode.
    if !text.contains(CANONICAL_MODE) {
        return vec![format!("Mode must be {CANONICAL_MODE}")];
    }

    let mut errors: Vec<String> = Vec::new();

    let mut cursor: isize = -1;
    for heading in HEADINGS {
        let search_start = (cursor + 1).max(0) as usize;
        let position = if search_start <= text.len() {
            text[search_start..].find(heading).map(|p| p + search_start)
        } else {
            None
        };
        match position {
            None => errors.push(format!("missing or out-of-order heading: {heading}")),
            Some(p) => cursor = p as isize,
        }
    }

    for label in LABELS {
        match label_value(text, label) {
            None => errors.push(format!("missing label: {label}")),
            Some(v) if v.is_empty() => errors.push(format!("empty label: {label}")),
            Some(_) => {}
        }
    }

    if template {
        errors.sort();
        errors.dedup();
        return errors;
    }

    if PLACEHOLDER_RE.is_match(text) {
        errors.push("unfilled placeholder remains".to_string());
    }
    if label_value(text, "**Mode:**") != Some(CANONICAL_MODE) {
        errors.push(format!("Mode must be {CANONICAL_MODE}"));
    }

    let declared = label_value(text, "**Packet path:**").unwrap_or("").to_string();
    if inline {
        if declared.trim_matches('`').to_uppercase() != "INLINE" {
            errors.push("inline packet must declare Packet path INLINE".to_string());
        }
    } else {
        if !path.is_absolute() {
            errors.push("durable packet validator requires absolute file path".to_string());
        }
        if !ABSOLUTE_RE.is_match(&declared) {
            errors.push("durable packet must declare absolute Packet path".to_string());
        } else {
            let resolved_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            if normalized(&declared, None) != normalized(&resolved_path.to_string_lossy(), None) {
                errors.push("declared Packet path does not match validated file".to_string());
            }
            let resolved_norm = normalized(&resolved_path.to_string_lossy(), None);
            let path_parts: std::collections::HashSet<&str> = resolved_norm.split('/').collect();
            if FORBIDDEN_STORAGE.iter().any(|f| path_parts.contains(f))
                || path_parts.iter().any(|part| part.starts_with(".validator-"))
            {
                errors.push("durable packet cannot use temporary/cache/review-run storage".to_string());
            }
        }
        let ext_is_md = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase() == "md")
            .unwrap_or(false);
        if !ext_is_md {
            errors.push("durable packet must be Markdown".to_string());
        }
    }

    let exact_start = text.find("### Exact request");
    let exact_block = match exact_start {
        Some(s) => {
            let end = text[s..]
                .find("### Desired outcome")
                .map(|e| s + e)
                .unwrap_or(text.len());
            &text[s..end]
        }
        None => "",
    };
    if !EXACT_REQUEST_QUOTE_RE.is_match(exact_block) {
        errors.push("Exact request must include substantive verbatim quote".to_string());
    }

    for (name, start, end, width) in [
        ("failure", "## 3. What Went Wrong", "## 4. Current System & State", 3usize),
        (
            "attempt",
            "## 6. Existing Attempts & Inputs",
            "## 7. Evidence Bundle",
            3usize,
        ),
    ] {
        let rows = table_rows(text, start, end);
        if rows.len() < 2 {
            errors.push(format!("{name} table requires data row"));
        }
        for (index, row) in rows.iter().enumerate().skip(1) {
            if row.len() != width || row.iter().any(|cell| cell.chars().count() < 6) {
                errors.push(format!("{name} table row {index} is incomplete"));
            }
        }
    }

    let evidence_start = text.find("## 7. Evidence Bundle");
    let evidence = match evidence_start {
        Some(s) => {
            let end = text[s..]
                .find("## 8. Known Unknowns")
                .map(|e| s + e)
                .unwrap_or(text.len());
            &text[s..end]
        }
        None => "",
    };
    let fenced_ok = FENCED_EVIDENCE_RE
        .captures(evidence)
        .map(|caps| caps.get(1).unwrap().as_str().trim().chars().count() >= 60)
        .unwrap_or(false);
    if !fenced_ok {
        errors.push("Evidence Bundle requires substantive embedded evidence".to_string());
    }

    let text_casefold = text.to_lowercase();
    for phrase in BANNED {
        if text_casefold.contains(phrase) {
            errors.push(format!("old-context dependency: {phrase}"));
        }
    }
    for (name, re) in SECRET_RES.iter() {
        if re.is_match(text) {
            errors.push(format!("possible secret detected: {name}"));
        }
    }
    if !text.contains("READY_TO_IMPLEMENT") || !text.contains("REVISE_PACKET") {
        errors.push("response contract lacks required verdict values".to_string());
    }

    errors.sort();
    errors.dedup();
    errors
}

/// Outcome of running the validator, mirroring the Python CLI's stdout
/// shape and exit code (0 = pass, 1 = fail-with-errors, 2 = file-not-found).
pub struct ValidationOutcome {
    pub exit_code: i32,
    pub message: String,
}

/// Faithful port of the Python CLI `main()` body, minus argument parsing.
/// The caller reads the packet file and passes its text plus flags.
pub fn run(text: &str, path: &Path, inline: bool, template_self_check: bool) -> ValidationOutcome {
    let errors = validate(text, path, inline, template_self_check);
    if errors.is_empty() {
        ValidationOutcome {
            exit_code: 0,
            message: "PASS: external-review packet is zero-context complete & packet-only"
                .to_string(),
        }
    } else {
        let mut message = format!("FAIL: {} packet defect(s)", errors.len());
        for error in &errors {
            message.push_str(&format!("\n- {error}"));
        }
        ValidationOutcome { exit_code: 1, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn template_text() -> String {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/wf_w2_003/template.md");
        std::fs::read_to_string(fixture).expect("template fixture present")
    }

    // Ported from skills/covenant/scripts/test_validate_external_review_packet.py
    #[test]
    fn template_self_check_passes_and_mode_rejection_is_detected() {
        let template = template_text();
        let template_path = PathBuf::from("template.md");

        let errors = validate(&template, &template_path, false, true);
        assert!(errors.is_empty(), "canonical template should self-check clean: {errors:?}");

        let mutated = template.replacen(CANONICAL_MODE, "RUN_COVENANT", 1);
        let errors = validate(&mutated, &template_path, false, true);
        assert!(
            errors.iter().any(|e| e.contains("Mode must be")),
            "expected a Mode-must-be error, got {errors:?}"
        );
    }

    #[test]
    fn empty_text_reports_every_missing_heading_and_label() {
        let errors = validate("", &PathBuf::from("x.md"), false, true);
        assert_eq!(errors.len(), HEADINGS.len() + LABELS.len());
        for heading in HEADINGS {
            assert!(errors.contains(&format!("missing or out-of-order heading: {heading}")));
        }
        for label in LABELS {
            assert!(errors.contains(&format!("missing label: {label}")));
        }
    }

    #[test]
    fn out_of_order_headings_are_flagged() {
        // Same headings but with #3 and #4 swapped in the body.
        let template = template_text();
        let mut lines: Vec<&str> = template.lines().collect();
        let idx3 = lines.iter().position(|l| *l == "## 3. What Went Wrong").unwrap();
        let idx4 = lines
            .iter()
            .position(|l| *l == "## 4. Current System & State")
            .unwrap();
        lines.swap(idx3, idx4);
        let swapped = lines.join("\n");
        let errors = validate(&swapped, &PathBuf::from("x.md"), false, true);
        assert!(
            errors.iter().any(|e| e.contains("## 4. Current System & State")),
            "expected an out-of-order complaint, got {errors:?}"
        );
    }

    #[test]
    fn label_value_reads_and_trims() {
        let text = "- **Mode:**   PACKET_ONLY — DO_NOT_RUN_COVENANT  \n";
        assert_eq!(
            label_value(text, "**Mode:**"),
            Some("PACKET_ONLY — DO_NOT_RUN_COVENANT")
        );
        assert_eq!(label_value(text, "**Created:**"), None);
    }

    #[test]
    fn table_rows_skips_separator_and_header_is_included() {
        let text = "## 3. What Went Wrong\n\n| Failure | Exact symptom/evidence | Consequence |\n|---|---|---|\n| Foo bug | it broke badly | users blocked |\n\n## 4. Current System & State\n";
        let rows = table_rows(text, "## 3. What Went Wrong", "## 4. Current System & State");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], vec!["Failure", "Exact symptom/evidence", "Consequence"]);
        assert_eq!(rows[1], vec!["Foo bug", "it broke badly", "users blocked"]);
    }

    #[test]
    fn secret_patterns_are_detected() {
        let text = "api_key: sk-abcdefghijklmnopqrstuvwx";
        assert!(SECRET_RES.iter().any(|(_, re)| re.is_match(text)));
    }

    #[test]
    fn banned_phrases_are_case_insensitive() {
        let text = "As Discussed earlier, please proceed.";
        assert!(BANNED.iter().any(|p| text.to_lowercase().contains(p)));
    }

    #[test]
    fn inline_packet_requires_inline_path_label() {
        let mut template = template_text();
        template = template.replace(
            "- **Packet path:** {{ABSOLUTE_PATH_OR_INLINE}}",
            "- **Packet path:** INLINE",
        );
        // Fill remaining placeholders minimally so we isolate the inline check.
        let filled = fill_all_placeholders(&template);
        let errors = validate(&filled, &PathBuf::from("ignored.md"), true, false);
        assert!(
            !errors.iter().any(|e| e.contains("inline packet must declare")),
            "unexpected inline-path error: {errors:?}"
        );
    }

    #[test]
    fn durable_packet_rejects_temp_storage_path() {
        let mut template = template_text();
        template = template.replace(
            "- **Packet path:** {{ABSOLUTE_PATH_OR_INLINE}}",
            "- **Packet path:** /tmp/scratch/packet.md",
        );
        let filled = fill_all_placeholders(&template);
        let path = PathBuf::from("/tmp/scratch/packet.md");
        let errors = validate(&filled, &path, false, false);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("temporary/cache/review-run storage")),
            "expected forbidden-storage error, got {errors:?}"
        );
    }

    fn fill_all_placeholders(text: &str) -> String {
        let mut out = text.to_string();
        while let Some(m) = PLACEHOLDER_RE.find(&out) {
            let replacement = match m.as_str() {
                "{{ISO_8601_TIMESTAMP}}" => "2026-09-23T00:00:00Z".to_string(),
                "{{USER_WORDS_VERBATIM}}" => {
                    "please investigate the exact failure carefully and report back".to_string()
                }
                "{{EVIDENCE}}" => {
                    "line one of the evidence bundle\nline two with more than sixty characters total here".to_string()
                }
                other => other.trim_start_matches("{{").trim_end_matches("}}").replace('_', " "),
            };
            out.replace_range(m.range(), &replacement);
        }
        out
    }
}
