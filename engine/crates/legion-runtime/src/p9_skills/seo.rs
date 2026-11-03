//! Packet P9-skill-scripts: Rust port of `skills/seo/hooks/pre-commit-seo-check.sh`.
//!
//! The shell hook only does two things that are not pure text checks: (1) discovers staged
//! files via `git diff --cached`, and (2) filters them to HTML-like extensions. Both are ported
//! as thin helpers; the actual per-file checks (placeholder text, title length, missing alt,
//! deprecated schema types, FID vs INP, meta description length) are pure string logic and are
//! ported verbatim below so a Rust caller gets byte-identical verdicts without shelling to git
//! or grep. The severity/exit-code contract matches the original: any error -> exit 2 (blocks
//! commit), warnings only -> exit 0 (allowed), clean -> exit 0.

use serde::Serialize;

/// Case-insensitive `haystack` scan for any of the bracketed placeholder tokens the shell hook
/// greps for: `\[(Business Name|City|State|Phone|Address|Your|INSERT|REPLACE)\]` (case-insensitive).
fn has_placeholder_text(haystack: &str) -> bool {
    const TOKENS: &[&str] = &[
        "[Business Name]",
        "[City]",
        "[State]",
        "[Phone]",
        "[Address]",
        "[Your]",
        "[INSERT]",
        "[REPLACE]",
    ];
    let lower = haystack.to_ascii_lowercase();
    TOKENS
        .iter()
        .any(|t| lower.contains(&t.to_ascii_lowercase()))
}

/// `"@type": "HowTo"` / `"@type": "SpecialAnnouncement"`, matching
/// `"@type"\s*:\s*"(HowTo|SpecialAnnouncement)"` with arbitrary whitespace around the colon.
fn has_deprecated_schema_type(haystack: &str) -> bool {
    for needle in ["HowTo", "SpecialAnnouncement"] {
        let mut idx = 0;
        while let Some(pos) = haystack[idx..].find("\"@type\"") {
            let after = idx + pos + "\"@type\"".len();
            let tail = haystack[after..].trim_start();
            if let Some(tail) = tail.strip_prefix(':') {
                let tail = tail.trim_start();
                if tail.starts_with(&format!("\"{needle}\"")) {
                    return true;
                }
            }
            idx = after;
            if idx >= haystack.len() {
                break;
            }
        }
    }
    false
}

/// One finding from checking a single staged file.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    pub file: String,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

/// The file extensions the hook filters staged files to (`\.(html|htm|php|jsx|tsx|vue|svelte)$`).
pub const HTML_LIKE_EXTENSIONS: &[&str] = &["html", "htm", "php", "jsx", "tsx", "vue", "svelte"];

pub fn is_html_like_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    HTML_LIKE_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(&format!(".{ext}")))
}

/// Check one file's content and return every finding, in the same order the shell script would
/// print them for that file.
pub fn check_file(path: &str, content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if has_placeholder_text(content) {
        findings.push(Finding {
            file: path.to_string(),
            severity: Severity::Error,
            message: "Contains placeholder text in schema markup".to_string(),
        });
    }

    if let Some(title) = extract_first(content, "<title>", "</title>") {
        let len = title.chars().count();
        if !(30..=60).contains(&len) {
            findings.push(Finding {
                file: path.to_string(),
                severity: Severity::Warning,
                message: format!("Title tag length {len} chars (recommend 30-60)"),
            });
        }
    }

    if img_missing_alt(content) {
        findings.push(Finding {
            file: path.to_string(),
            severity: Severity::Warning,
            message: "Images found without alt text".to_string(),
        });
    }

    if has_deprecated_schema_type(content) {
        findings.push(Finding {
            file: path.to_string(),
            severity: Severity::Error,
            message: "Contains deprecated schema type".to_string(),
        });
    }

    if content.contains("First Input Delay") || content.contains("\"FID\"") {
        findings.push(Finding {
            file: path.to_string(),
            severity: Severity::Warning,
            message: "References FID; should use INP (Interaction to Next Paint)".to_string(),
        });
    }

    if let Some(desc) = extract_meta_description(content) {
        let len = desc.chars().count();
        if !(120..=160).contains(&len) {
            findings.push(Finding {
                file: path.to_string(),
                severity: Severity::Warning,
                message: format!("Meta description length {len} chars (recommend 120-160)"),
            });
        }
    }

    findings
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CheckReport {
    pub findings: Vec<Finding>,
    pub errors: usize,
    pub warnings: usize,
    /// Matches the shell script's exit code contract: 2 if any error, else 0.
    pub exit_code: i32,
}

/// Check a batch of (path, content) staged files, already filtered by the caller to whatever
/// set it wants checked (the shell script filters to `HTML_LIKE_EXTENSIONS` first).
pub fn check_files<'a, I: IntoIterator<Item = (&'a str, &'a str)>>(files: I) -> CheckReport {
    let mut findings = Vec::new();
    for (path, content) in files {
        findings.extend(check_file(path, content));
    }
    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let exit_code = if errors > 0 { 2 } else { 0 };
    CheckReport {
        findings,
        errors,
        warnings,
        exit_code,
    }
}

fn extract_first(haystack: &str, open: &str, close: &str) -> Option<String> {
    let start = haystack.find(open)? + open.len();
    let rest = &haystack[start..];
    let end = rest.find(close)?;
    Some(rest[..end].to_string())
}

fn extract_meta_description(haystack: &str) -> Option<String> {
    // Mirrors: grep -oP '(?<=<meta name="description" content=").*?(?=")'
    let needle = "<meta name=\"description\" content=\"";
    let start = haystack.find(needle)? + needle.len();
    let rest = &haystack[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Scans for `<img` tags missing an `alt=` attribute, reproducing the shell hook's
/// `grep -P '<img(?![^>]*alt=)'` without needing a regex crate dependency.
fn img_missing_alt(content: &str) -> bool {
    let mut idx = 0;
    while let Some(pos) = content[idx..].find("<img") {
        let tag_start = idx + pos;
        let tag_end = content[tag_start..]
            .find('>')
            .map(|e| tag_start + e)
            .unwrap_or(content.len());
        let tag = &content[tag_start..tag_end];
        if !tag.contains("alt=") {
            return true;
        }
        idx = tag_end.max(tag_start + 1);
        if idx >= content.len() {
            break;
        }
    }
    false
}
