//! Port of `skills/seo/hooks/pre-commit-seo-check.sh` and
//! `skills/seo/hooks/validate-schema.py` (chunk w2_027).
//!
//! Both scripts are Claude Code hooks that run other-process side effects
//! (`git diff --cached`, reading files off disk, printing to stdout, and
//! exiting the process with a specific code that the hook host interprets
//! as "allow" / "warn" / "block"). Those effects are not ported — instead,
//! the pure, deterministic decision logic each script applies to file
//! content is ported here with the exact same rules, message text, and
//! exit-code semantics, so a caller can reproduce the hook's verdict for
//! given file content without shelling out.
//!
//! ## `pre-commit-seo-check.sh`
//!
//! For each staged file matching [`is_seo_checked_extension`], the script
//! runs six checks against the file's content ([`check_html_file`]):
//! placeholder text, title tag length, images missing `alt`, deprecated
//! schema `@type` values, `FID` references, and meta description length.
//! Each finding is either an error (🛑, blocking) or a warning (⚠️,
//! non-blocking). Across all staged files it accumulates a total error and
//! warning count and exits `2` if any errors were found, `0` otherwise
//! ([`hook_exit_code`], mirroring the script's `ERRORS -gt 0` branch —
//! warnings alone still exit `0`).
//!
//! ## `validate-schema.py`
//!
//! [`validate_jsonld`] extracts every
//! `<script type="application/ld+json">...</script>` block from HTML-like
//! content, parses each as JSON, and validates each schema object
//! ([`validate_schema_object`]) for a missing/wrong `@context`, a missing
//! `@type`, placeholder text, deprecated `@type` values, and the
//! `FAQPage`-restricted-type note. [`schema_exit_code`] mirrors the
//! script's `main()`: `0` with no findings, `2` if any finding is
//! "critical" (message contains `placeholder`, `deprecated`, or `retired`,
//! case-insensitively), `1` if only non-critical findings remain.
//! [`is_schema_checked_extension`] mirrors the script's
//! `valid_extensions` filter.

use regex::Regex;
use serde_json::Value;

// ---------------------------------------------------------------------
// Shared: file extension filters
// ---------------------------------------------------------------------

/// Extensions the pre-commit shell hook's `grep -E` pattern matches:
/// `\.(html|htm|php|jsx|tsx|vue|svelte)$`.
const SEO_CHECK_EXTENSIONS: &[&str] = &["html", "htm", "php", "jsx", "tsx", "vue", "svelte"];

/// Extensions `validate-schema.py`'s `valid_extensions` tuple matches:
/// `(".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".php", ".ejs")`.
const SCHEMA_CHECK_EXTENSIONS: &[&str] = &[
    "html", "htm", "jsx", "tsx", "vue", "svelte", "php", "ejs",
];

/// Port of the shell hook's staged-file filter: does `path` end in one of
/// the checked extensions? Matches `grep -E '\.(html|htm|php|jsx|tsx|vue|svelte)$'`
/// (case-sensitive, like the Python's `str.endswith`).
pub fn is_seo_checked_extension(path: &str) -> bool {
    has_one_of_extensions(path, SEO_CHECK_EXTENSIONS)
}

/// Port of `validate-schema.py`'s `filepath.endswith(valid_extensions)`.
pub fn is_schema_checked_extension(path: &str) -> bool {
    has_one_of_extensions(path, SCHEMA_CHECK_EXTENSIONS)
}

fn has_one_of_extensions(path: &str, exts: &[&str]) -> bool {
    exts.iter()
        .any(|ext| path.len() > ext.len() + 1 && path.ends_with(&format!(".{ext}")))
}

// ---------------------------------------------------------------------
// pre-commit-seo-check.sh
// ---------------------------------------------------------------------

/// Severity of one finding from [`check_html_file`], mirroring the
/// script's 🛑 (error, blocking) vs ⚠️ (warning, non-blocking) findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// One finding from [`check_html_file`]: the message text the script would
/// print (without the emoji/file-name prefix the shell loop adds) and its
/// severity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

impl Finding {
    fn error(message: impl Into<String>) -> Self {
        Finding { severity: Severity::Error, message: message.into() }
    }
    fn warning(message: impl Into<String>) -> Self {
        Finding { severity: Severity::Warning, message: message.into() }
    }
}

/// Placeholder tokens both scripts search for, case-insensitively:
/// `\[(Business Name|City|State|Phone|Address|Your|INSERT|REPLACE)\]` in
/// the shell script's grep -E form.
fn placeholder_regex() -> Regex {
    Regex::new(r"(?i)\[(Business Name|City|State|Phone|Address|Your|INSERT|REPLACE)").unwrap()
}

/// Deprecated schema `@type` values the shell hook's grep checks for
/// directly in raw JSON-LD text: `"@type"\s*:\s*"(HowTo|SpecialAnnouncement)"`.
fn deprecated_type_regex() -> Regex {
    Regex::new(r#""@type"\s*:\s*"(HowTo|SpecialAnnouncement)""#).unwrap()
}

/// Runs the six pure per-file checks `pre-commit-seo-check.sh` performs on
/// one staged file's content, in the script's order. This is
/// [`check_html_file`]'s worker; the shell script's `${file}` existence
/// check (`if [ ! -f ...]; then continue; fi`) is a filesystem concern
/// left to the caller.
pub fn check_html_file(content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Placeholder text.
    if placeholder_regex().is_match(content) {
        findings.push(Finding::error("Contains placeholder text in schema markup"));
    }

    // 2. Title tag length: `grep -oP '(?<=<title>).*?(?=</title>)' | head -1`.
    if let Some(title) = extract_first(content, r"(?s)<title>(.*?)</title>") {
        let len = title.chars().count();
        if !(30..=60).contains(&len) {
            findings.push(Finding::warning(format!(
                "Title tag length {len} chars (recommend 30-60)"
            )));
        }
    }

    // 3. Images without alt text: `<img(?![^>]*alt=)`.
    if has_img_without_alt(content) {
        findings.push(Finding::warning("Images found without alt text"));
    }

    // 4. Deprecated schema types (raw-text grep, unlike the Python's
    //    parsed-JSON check in `validate_jsonld`).
    if deprecated_type_regex().is_match(content) {
        findings.push(Finding::error("Contains deprecated schema type"));
    }

    // 5. FID references: `grep -qi 'First Input Delay\|"FID"'`.
    let lower = content.to_lowercase();
    if lower.contains("first input delay") || lower.contains("\"fid\"") {
        findings.push(Finding::warning(
            "References FID; should use INP (Interaction to Next Paint)",
        ));
    }

    // 6. Meta description length:
    //    `grep -oP '(?<=<meta name="description" content=").*?(?=")' | head -1`.
    if let Some(desc) = extract_first(
        content,
        r#"(?s)<meta name="description" content="(.*?)""#,
    ) {
        let len = desc.chars().count();
        if !(120..=160).contains(&len) {
            findings.push(Finding::warning(format!(
                "Meta description length {len} chars (recommend 120-160)"
            )));
        }
    }

    findings
}

fn extract_first(content: &str, pattern: &str) -> Option<String> {
    Regex::new(pattern).unwrap().captures(content).map(|c| c[1].to_string())
}

/// Port of `<img(?![^>]*alt=)`: a PCRE negative-lookahead the shell script
/// uses via `grep -P`, matching any `<img` not followed (before the next
/// `>`) by `alt=`. `regex` has no lookaround, so this walks each `<img`
/// occurrence and checks whether `alt=` appears before the tag's closing
/// `>` (or before the next `<img` if the tag is unterminated, matching
/// PCRE's own unanchored `[^>]*` behaviour on a truncated tag).
fn has_img_without_alt(content: &str) -> bool {
    let bytes = content.as_bytes();
    let mut idx = 0;
    while let Some(rel) = content[idx..].find("<img") {
        let start = idx + rel;
        let tag_end = content[start..]
            .find('>')
            .map(|p| start + p)
            .unwrap_or(content.len());
        let tag = &content[start..tag_end];
        if !tag.contains("alt=") {
            return true;
        }
        idx = start + 4;
    }
    false
}

/// Aggregated error/warning counts across all staged files, mirroring the
/// shell script's `ERRORS`/`WARNINGS` running totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HookTotals {
    pub errors: u32,
    pub warnings: u32,
}

impl HookTotals {
    /// Folds one file's [`Finding`]s into the running totals, as the shell
    /// loop's `ERRORS=$((ERRORS + 1))` / `WARNINGS=$((WARNINGS + 1))` do.
    pub fn add(&mut self, findings: &[Finding]) {
        for f in findings {
            match f.severity {
                Severity::Error => self.errors += 1,
                Severity::Warning => self.warnings += 1,
            }
        }
    }
}

/// Port of the shell hook's final exit-code decision:
/// `ERRORS -gt 0` → `2` (blocked); else `0` (warnings alone still pass).
pub fn hook_exit_code(totals: HookTotals) -> i32 {
    if totals.errors > 0 {
        2
    } else {
        0
    }
}

/// Port of the shell hook's very first gate: `git diff --cached --quiet`
/// exits non-zero (there ARE staged changes) to proceed, zero (no staged
/// changes) to `exit 0` immediately. `has_staged_changes` is the boolean a
/// caller supplies from its own git integration; `true` means "proceed
/// with checks", matching the script's `if ! git diff --cached --quiet;
/// then : ; else exit 0; fi`.
pub fn should_run_pre_commit_checks(has_staged_changes: bool) -> bool {
    has_staged_changes
}

// ---------------------------------------------------------------------
// validate-schema.py
// ---------------------------------------------------------------------

/// Deprecated `@type` values and their reason, exactly matching the
/// Python `deprecated` dict (declaration order preserved for stable
/// iteration, though only one type is ever looked up per object).
const DEPRECATED_TYPES: &[(&str, &str)] = &[
    ("HowTo", "deprecated September 2023"),
    ("SpecialAnnouncement", "deprecated July 31, 2025"),
    ("CourseInfo", "retired June 2025"),
    ("EstimatedSalary", "retired June 2025"),
    ("LearningVideo", "retired June 2025"),
    ("ClaimReview", "retired June 2025; fact-check rich results discontinued"),
    (
        "VehicleListing",
        "retired June 2025; vehicle listing structured data discontinued",
    ),
];

/// Restricted `@type` values and their note, matching the Python
/// `restricted` dict.
const RESTRICTED_TYPES: &[(&str, &str)] = &[(
    "FAQPage",
    "restricted to government and healthcare sites only (Aug 2023)",
)];

/// Placeholder substrings `validate-schema.py`'s `_validate_schema_object`
/// searches for (case-insensitively) inside the JSON-serialized object,
/// in the Python list's exact order.
const SCHEMA_PLACEHOLDERS: &[&str] = &[
    "[Business Name]",
    "[City]",
    "[State]",
    "[Phone]",
    "[Address]",
    "[Your",
    "[INSERT",
    "REPLACE",
    "[URL]",
    "[Email]",
];

/// Port of the `<script type="application/ld+json">...</script>` extraction
/// regex: `r'<script\s+type=["\']application/ld\+json["\']\s*>(.*?)</script>'`
/// with `re.DOTALL | re.IGNORECASE`.
fn jsonld_block_regex() -> Regex {
    Regex::new(r#"(?is)<script\s+type=["']application/ld\+json["']\s*>(.*?)</script>"#).unwrap()
}

/// Port of `validate_jsonld(content)`: extracts every JSON-LD `<script>`
/// block from `content` and validates each one, returning every finding
/// message across every block in extraction/object order (matching the
/// Python's `errors.extend(...)` accumulation). Returns an empty vec both
/// when no JSON-LD blocks are present (not an error, per the Python's
/// early `return []`) and when all blocks validate cleanly.
///
/// A block whose content is not valid JSON produces exactly one finding —
/// `"Block N: Invalid JSON; <message>"` — and is otherwise skipped, as the
/// Python's `except json.JSONDecodeError` branch does; `<message>` is a
/// `serde_json` error description rather than Python's own, since the two
/// parsers report errors in different words.
pub fn validate_jsonld(content: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut any_block = false;

    for (i, caps) in jsonld_block_regex().captures_iter(content).enumerate() {
        any_block = true;
        let block_num = i + 1;
        let block = caps[1].trim();

        let data: Value = match serde_json::from_str(block) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("Block {block_num}: Invalid JSON; {e}"));
                continue;
            }
        };

        match &data {
            Value::Array(items) => {
                for item in items {
                    if let Value::Object(obj) = item {
                        errors.extend(validate_schema_object(obj, block_num));
                    }
                }
            }
            Value::Object(obj) => {
                errors.extend(validate_schema_object(obj, block_num));
            }
            _ => {}
        }
    }

    if !any_block {
        return Vec::new();
    }
    errors
}

/// Port of `_validate_schema_object(obj, block_num)`, in the Python
/// function's exact check order: `@context` presence/value, `@type`
/// presence, placeholder text, deprecated `@type`, restricted `@type`.
pub fn validate_schema_object(
    obj: &serde_json::Map<String, Value>,
    block_num: usize,
) -> Vec<String> {
    let mut errors = Vec::new();
    let prefix = format!("Block {block_num}");

    match obj.get("@context") {
        None => errors.push(format!("{prefix}: Missing @context")),
        Some(Value::String(s)) if s == "https://schema.org" || s == "http://schema.org" => {}
        Some(_) => errors.push(format!("{prefix}: @context should be 'https://schema.org'")),
    }

    if !obj.contains_key("@type") {
        errors.push(format!("{prefix}: Missing @type"));
    }

    // Placeholder text: case-insensitive substring search over the
    // object's JSON serialization, mirroring `json.dumps(obj)`.
    let text = Value::Object(obj.clone()).to_string().to_lowercase();
    for p in SCHEMA_PLACEHOLDERS {
        if text.contains(&p.to_lowercase()) {
            errors.push(format!("{prefix}: Contains placeholder text: {p}"));
        }
    }

    let schema_type = obj.get("@type").and_then(Value::as_str).unwrap_or("");

    if let Some((_, reason)) = DEPRECATED_TYPES.iter().find(|(t, _)| *t == schema_type) {
        errors.push(format!("{prefix}: @type '{schema_type}' is {reason}"));
    }

    if let Some((_, note)) = RESTRICTED_TYPES.iter().find(|(t, _)| *t == schema_type) {
        errors.push(format!(
            "{prefix}: @type '{schema_type}' is {note}; verify site qualifies"
        ));
    }

    errors
}

/// Port of `main()`'s critical/warning split: a finding is "critical" iff
/// its message contains `placeholder`, `deprecated`, or `retired`
/// (case-insensitively) as a substring, matching Python's
/// `any(kw in e.lower() for kw in critical_keywords)`.
pub fn is_critical_finding(message: &str) -> bool {
    let lower = message.to_lowercase();
    ["placeholder", "deprecated", "retired"]
        .iter()
        .any(|kw| lower.contains(*kw))
}

/// Port of `validate-schema.py`'s `main()` exit-code decision:
/// - no findings → `0`
/// - any [`is_critical_finding`] → `2` (blocks the edit)
/// - only non-critical findings → `1` (warnings only; proceeds)
pub fn schema_exit_code(errors: &[String]) -> i32 {
    if errors.is_empty() {
        return 0;
    }
    if errors.iter().any(|e| is_critical_finding(e)) {
        2
    } else {
        1
    }
}

/// Splits `errors` into `(critical, warnings)` in original order, mirroring
/// `main()`'s `critical` / `warnings` list comprehensions (which iterate
/// the same `errors` list independently, so relative order per bucket is
/// preserved).
pub fn partition_findings(errors: &[String]) -> (Vec<String>, Vec<String>) {
    let mut critical = Vec::new();
    let mut warnings = Vec::new();
    for e in errors {
        if is_critical_finding(e) {
            critical.push(e.clone());
        } else {
            warnings.push(e.clone());
        }
    }
    (critical, warnings)
}
