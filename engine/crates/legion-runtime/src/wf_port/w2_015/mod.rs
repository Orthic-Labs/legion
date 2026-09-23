//! Port of `skills/designer/engine/scripts/hook-lib.mjs` (chunk w2_015).
//!
//! This module ports the pure, unit-testable core of the Impeccable design
//! hook's shared library: glob matching, ignore-value normalization/color
//! parsing, finding filtering + cache-key computation, and the developer-role
//! text templates the hook emits. Faithful to the JS behaviour in
//! `hook-lib.mjs` as of the source read for this port.
//!
//! NOT ported in this chunk (left for a follow-up; see the w2_015 report):
//! process/stdin orchestration (`runHook`, `hook.mjs`), the on-disk
//! config/cache readers (`readConfig`, `readCache`, `persistCache`,
//! `ensureHookGitExcludes` — filesystem side effects), the `/designer hooks`
//! admin CLI (`hook-admin.mjs`), the Cursor pre-edit gate
//! (`hook-before-edit.mjs`), and the DESIGN.md parser (`lib/design-parser.mjs`).

use std::collections::HashSet;

/// `ENVELOPE_PREFIX` in hook-lib.mjs.
pub const ENVELOPE_PREFIX: &str = "[impeccable@1]";

/// `EDIT_COUNT_THRESHOLD` in hook-lib.mjs.
pub const EDIT_COUNT_THRESHOLD: u32 = 6;

/// Mirrors `TRUTHY` regex: `/^(1|true|yes|on)$/i`.
pub fn truthy(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

// ---------------------------------------------------------------------
// Glob matching (`globToRegex` / `matchesAnyGlob`)
// ---------------------------------------------------------------------

/// Translate a hook-lib glob (`**`, `*`, `?`, `{a,b}` alternation) into a
/// regex-equivalent matcher, mirroring `globToRegex` in hook-lib.mjs.
///
/// Rather than building a `regex::Regex` string (which would need runtime
/// compilation per call), this compiles once into a small matcher enum and
/// runs a backtracking match, since crates already in the workspace lock
/// (`regex`) is a fine building block instead: we do build a `Regex`, using
/// the same translation strategy as the JS `globToRegex`.
fn glob_to_regex(glob: &str) -> Option<regex::Regex> {
    let mut re = String::from("^");
    let chars: Vec<char> = glob.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '*' => {
                if chars.get(i + 1) == Some(&'*') {
                    re.push_str(".*");
                    i += 2;
                    if chars.get(i) == Some(&'/') {
                        i += 1;
                    }
                } else {
                    re.push_str("[^/]*");
                    i += 1;
                }
            }
            '?' => {
                re.push_str("[^/]");
                i += 1;
            }
            '{' => {
                if let Some(end_offset) = chars[i..].iter().position(|&c| c == '}') {
                    let end = i + end_offset;
                    let body: String = chars[i + 1..end].iter().collect();
                    let parts: Vec<String> = body
                        .split(',')
                        .map(|p| regex::escape(p))
                        .collect();
                    re.push_str("(?:");
                    re.push_str(&parts.join("|"));
                    re.push(')');
                    i = end + 1;
                } else {
                    re.push_str("\\{");
                    i += 1;
                }
            }
            '.' | '+' | '^' | '$' | '(' | ')' | '|' | '[' | ']' | '\\' => {
                re.push('\\');
                re.push(c);
                i += 1;
            }
            _ => {
                re.push(c);
                i += 1;
            }
        }
    }
    re.push('$');
    regex::Regex::new(&re).ok()
}

/// Port of `matchesAnyGlob(filePath, globs)`.
pub fn matches_any_glob(file_path: &str, globs: &[String]) -> bool {
    if globs.is_empty() {
        return false;
    }
    let normalized = file_path.replace('\\', "/");
    let base = normalized.rsplit('/').next().unwrap_or(&normalized);
    for glob in globs {
        if let Some(re) = glob_to_regex(glob) {
            if re.is_match(&normalized) || re.is_match(base) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------
// Ignore-value normalization + color parsing
// ---------------------------------------------------------------------

/// Port of `normalizeIgnoreValue(value)`.
pub fn normalize_ignore_value(value: &str) -> String {
    let trimmed = value.trim();
    let stripped = strip_matching_quotes(trimmed);
    let plus_to_space = stripped.replace('+', " ");
    collapse_whitespace(&plus_to_space).to_lowercase()
}

/// `cleanIgnoreValueDisplay` — same as normalize but without lowercasing.
pub fn clean_ignore_value_display(value: &str) -> String {
    let trimmed = value.trim();
    let stripped = strip_matching_quotes(trimmed);
    let plus_to_space = stripped.replace('+', " ");
    collapse_whitespace(&plus_to_space)
}

fn strip_matching_quotes(s: &str) -> &str {
    let s = s.strip_prefix('"').or(Some(s)).unwrap();
    let s = s.strip_prefix('\'').unwrap_or(s);
    let s = s.strip_suffix('"').unwrap_or(s);
    s.strip_suffix('\'').unwrap_or(s)
}

fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(c);
            last_was_space = false;
        }
    }
    out
}

/// Parsed RGBA color, alpha in `[0.0, 1.0]`. Mirrors the JS color object
/// produced by `parseIgnoreColor`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rgba {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: f64,
}

/// Port of `colorIgnoreKey(value)`.
pub fn color_ignore_key(value: &str) -> String {
    match parse_ignore_color(value) {
        Some(c) => format!("{},{},{},{}", c.r, c.g, c.b, (c.a * 255.0).round() as i64),
        None => String::new(),
    }
}

/// Port of `parseIgnoreColor(value)`: hex, rgb()/rgba(), hsl()/hsla().
pub fn parse_ignore_color(value: &str) -> Option<Rgba> {
    let text = value.trim().to_lowercase();
    if text.is_empty() {
        return None;
    }

    if let Some(hex) = text.strip_prefix('#') {
        if is_valid_hex(hex) {
            return parse_hex_color(hex);
        }
        return None;
    }

    if let Some(body) = strip_fn(&text, "rgba").or_else(|| strip_fn(&text, "rgb")) {
        let parts = split_color_args(body);
        if parts.len() < 3 || parts.len() > 4 {
            return None;
        }
        let r = parse_rgb_channel(&parts[0])?;
        let g = parse_rgb_channel(&parts[1])?;
        let b = parse_rgb_channel(&parts[2])?;
        let a = if parts.len() == 4 {
            parse_alpha_channel(&parts[3])?
        } else {
            1.0
        };
        return Some(Rgba { r, g, b, a });
    }

    if let Some(body) = strip_fn(&text, "hsla").or_else(|| strip_fn(&text, "hsl")) {
        let parts = split_color_args(body);
        if parts.len() < 3 || parts.len() > 4 {
            return None;
        }
        let h = parse_hue_channel(&parts[0])?;
        let s = parse_percent_channel(&parts[1])?;
        let l = parse_percent_channel(&parts[2])?;
        let a = if parts.len() == 4 {
            parse_alpha_channel(&parts[3])?
        } else {
            1.0
        };
        return Some(hsl_to_rgb(h, s, l, a));
    }

    None
}

fn is_valid_hex(hex: &str) -> bool {
    matches!(hex.len(), 3 | 4 | 6 | 8) && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Port of `parseHexIgnoreColor(hex)`.
fn parse_hex_color(hex: &str) -> Option<Rgba> {
    let nibble = |c: char| c.to_digit(16).map(|d| d as u8);
    let byte_from_pair = |a: char, b: char| -> Option<u8> {
        Some(nibble(a)? * 16 + nibble(b)?)
    };
    match hex.len() {
        3 | 4 => {
            let chars: Vec<char> = hex.chars().collect();
            let r = byte_from_pair(chars[0], chars[0])?;
            let g = byte_from_pair(chars[1], chars[1])?;
            let b = byte_from_pair(chars[2], chars[2])?;
            let a = if hex.len() == 4 {
                byte_from_pair(chars[3], chars[3])? as f64 / 255.0
            } else {
                1.0
            };
            Some(Rgba { r, g, b, a })
        }
        6 | 8 => {
            let chars: Vec<char> = hex.chars().collect();
            let r = byte_from_pair(chars[0], chars[1])?;
            let g = byte_from_pair(chars[2], chars[3])?;
            let b = byte_from_pair(chars[4], chars[5])?;
            let a = if hex.len() == 8 {
                byte_from_pair(chars[6], chars[7])? as f64 / 255.0
            } else {
                1.0
            };
            Some(Rgba { r, g, b, a })
        }
        _ => None,
    }
}

fn strip_fn<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    // Matches `^rgba?\((.*)\)$` / `^hsla?\((.*)\)$`.
    let prefix = format!("{name}(");
    if text.starts_with(&prefix) && text.ends_with(')') {
        Some(&text[prefix.len()..text.len() - 1])
    } else {
        None
    }
}

fn split_color_args(body: &str) -> Vec<String> {
    let text = body.trim();
    if text.is_empty() {
        return vec![];
    }
    if text.contains(',') {
        let mut parts: Vec<String> = text
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        if let Some(last) = parts.last().cloned() {
            if last.contains('/') {
                parts.pop();
                let split: Vec<String> = last
                    .split('/')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect();
                parts.extend(split);
            }
        }
        return parts;
    }
    text.replace('/', " / ")
        .split_whitespace()
        .filter(|p| *p != "/")
        .map(|s| s.to_string())
        .collect()
}

fn parse_rgb_channel(raw: &str) -> Option<u8> {
    let text = raw.trim();
    let (num_part, is_pct) = match text.strip_suffix('%') {
        Some(n) => (n, true),
        None => (text, false),
    };
    let value: f64 = num_part.parse().ok()?;
    if !value.is_finite() {
        return None;
    }
    let scaled = if is_pct { value * 2.55 } else { value };
    if !(0.0..=255.0).contains(&scaled) {
        return None;
    }
    Some(scaled.round() as u8)
}

fn parse_alpha_channel(raw: &str) -> Option<f64> {
    let text = raw.trim();
    let (num_part, is_pct) = match text.strip_suffix('%') {
        Some(n) => (n, true),
        None => (text, false),
    };
    let value: f64 = num_part.parse().ok()?;
    if !value.is_finite() {
        return None;
    }
    let alpha = if is_pct { value / 100.0 } else { value };
    if (0.0..=1.0).contains(&alpha) {
        Some(alpha)
    } else {
        None
    }
}

fn parse_hue_channel(raw: &str) -> Option<f64> {
    let text = raw.trim();
    let (num_part, unit) = split_numeric_prefix(text);
    let value: f64 = num_part.parse().ok()?;
    if !value.is_finite() {
        return None;
    }
    Some(match unit {
        "" | "deg" => value,
        "turn" => value * 360.0,
        "rad" => value * (180.0 / std::f64::consts::PI),
        "grad" => value * 0.9,
        _ => return None,
    })
}

/// Splits a leading numeric literal (matching `-?\d*\.?\d+`) from a trailing
/// unit suffix, e.g. `"120grad"` -> `("120", "grad")`. Returns `("", "")`
/// when no numeric prefix is present.
fn split_numeric_prefix(text: &str) -> (&str, &str) {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    if bytes.first() == Some(&b'-') {
        i += 1;
    }
    let mut seen_dot = false;
    let mut seen_digit = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_digit() {
            seen_digit = true;
            i += 1;
        } else if c == '.' && !seen_dot {
            seen_dot = true;
            i += 1;
        } else {
            break;
        }
    }
    if !seen_digit {
        return ("", text);
    }
    (&text[..i], &text[i..])
}

fn parse_percent_channel(raw: &str) -> Option<f64> {
    let text = raw.trim().strip_suffix('%')?;
    let value: f64 = text.parse().ok()?;
    if (0.0..=100.0).contains(&value) {
        Some(value / 100.0)
    } else {
        None
    }
}

fn hsl_to_rgb(hue: f64, saturation: f64, lightness: f64, alpha: f64) -> Rgba {
    let h = (((hue % 360.0) + 360.0) % 360.0) / 360.0;
    if saturation == 0.0 {
        let gray = clamp_byte((lightness * 255.0).round());
        return Rgba {
            r: gray,
            g: gray,
            b: gray,
            a: alpha,
        };
    }
    let q = if lightness < 0.5 {
        lightness * (1.0 + saturation)
    } else {
        lightness + saturation - lightness * saturation
    };
    let p = 2.0 * lightness - q;
    let to_rgb = |t: f64| -> f64 {
        let mut channel = t;
        if channel < 0.0 {
            channel += 1.0;
        }
        if channel > 1.0 {
            channel -= 1.0;
        }
        if channel < 1.0 / 6.0 {
            return p + (q - p) * 6.0 * channel;
        }
        if channel < 1.0 / 2.0 {
            return q;
        }
        if channel < 2.0 / 3.0 {
            return p + (q - p) * (2.0 / 3.0 - channel) * 6.0;
        }
        p
    };
    Rgba {
        r: clamp_byte((to_rgb(h + 1.0 / 3.0) * 255.0).round()),
        g: clamp_byte((to_rgb(h) * 255.0).round()),
        b: clamp_byte((to_rgb(h - 1.0 / 3.0) * 255.0).round()),
        a: alpha,
    }
}

fn clamp_byte(value: f64) -> u8 {
    value.clamp(0.0, 255.0) as u8
}

// ---------------------------------------------------------------------
// Findings + ignore-value filtering
// ---------------------------------------------------------------------

/// Minimal finding shape (fields the pure logic touches). The JS side
/// carries more fields (name/description/detail/snippet) which are used
/// only by `formatFindingLine` / `formatFindingIgnoreCommand`; those are
/// included here as `Option<String>` for parity but are not required by
/// every call site.
#[derive(Debug, Clone, Default)]
pub struct Finding {
    pub antipattern: String,
    pub line: i64,
    pub ignore_value: Option<String>,
    pub value: Option<String>,
    pub detail: Option<String>,
    pub snippet: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub file: Option<String>,
}

/// A single persisted ignore-value entry (`ignoreValues` config array).
#[derive(Debug, Clone)]
pub struct IgnoreValueEntry {
    pub rule: String,
    pub value: String,
    pub files: Vec<String>,
}

fn normalize_ignore_rule(rule: &str) -> String {
    rule.trim().to_lowercase()
}

const DIRECT_VALUE_RULES: [&str; 5] = [
    "overused-font",
    "bounce-easing",
    "design-system-font",
    "design-system-color",
    "design-system-radius",
];

/// Port of `extractFindingIgnoreValueRaw` (display case preserved).
pub fn extract_finding_ignore_value_raw(finding: &Finding) -> String {
    let rule = normalize_ignore_rule(&finding.antipattern);
    if let Some(direct) = finding
        .ignore_value
        .as_deref()
        .or(finding.value.as_deref())
    {
        let cleaned = clean_ignore_value_display(direct);
        if !cleaned.is_empty() {
            return cleaned;
        }
    }

    let candidates: Vec<&str> = [finding.detail.as_deref(), finding.snippet.as_deref()]
        .into_iter()
        .flatten()
        .collect();

    for text in candidates {
        if rule == "bounce-easing" {
            if let Some(motion) = extract_motion_ignore_value(text) {
                return motion;
            }
            continue;
        }

        if let Some(m) = regex_capture(text, r"(?i)Primary font:\s*([^()\n;]+)") {
            return clean_ignore_value_display(&m);
        }
        if let Some(m) = regex_capture(text, r#"(?i)font-family\s*:\s*["']?([^'",;\n]+)"#) {
            return clean_ignore_value_display(&m);
        }
        if let Some(m) = regex_capture(text, r"(?i)[?&]family=([^&:;\n]+)") {
            return clean_ignore_value_display(
                &percent_decode(&m).unwrap_or_else(|| m.clone()),
            );
        }
    }

    String::new()
}

fn extract_motion_ignore_value(text: &str) -> Option<String> {
    if regex_is_match(text, r"(?i)\banimate-bounce\b") {
        return Some(clean_ignore_value_display("animate-bounce"));
    }
    if let Some(m) = regex_capture(text, r"(?i)cubic-bezier\([^)]+\)") {
        return Some(clean_ignore_value_display(&m));
    }
    if let Some(m) = regex_capture(text, r"(?i)animation(?:-name)?\s*:\s*([^;\n]+)") {
        for part in m.split(|c: char| c == ',' || c.is_whitespace()) {
            if regex_is_match(part, r"(?i)bounce|elastic|wobble|jiggle|spring") {
                return Some(clean_ignore_value_display(part));
            }
        }
    }
    None
}

fn regex_capture(text: &str, pattern: &str) -> Option<String> {
    regex::Regex::new(pattern)
        .ok()?
        .captures(text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn regex_is_match(text: &str, pattern: &str) -> bool {
    regex::Regex::new(pattern)
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

/// Very small percent-decoder mirroring `decodeURIComponent` for the
/// `?family=` query-arg case (ASCII-safe; falls back to `None` on invalid
/// escapes, matching the JS try/catch fallback to the raw string).
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
            let byte = u8::from_str_radix(hex, 16).ok()?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Port of `extractFindingIgnoreValue` (normalized, lowercase).
pub fn extract_finding_ignore_value(finding: &Finding) -> String {
    let rule = normalize_ignore_rule(&finding.antipattern);
    if !DIRECT_VALUE_RULES.contains(&rule.as_str()) {
        return String::new();
    }
    normalize_ignore_value(&extract_finding_ignore_value_raw(finding))
}

fn ignore_value_matches(rule: &str, entry_value: &str, finding_value: &str) -> bool {
    if entry_value == finding_value {
        return true;
    }
    if rule != "design-system-color" {
        return false;
    }
    let entry_color = color_ignore_key(entry_value);
    !entry_color.is_empty() && entry_color == color_ignore_key(finding_value)
}

fn matches_any_glob_scoped(finding: &Finding, globs: &[String]) -> bool {
    let file_path = finding.file.as_deref().unwrap_or("").trim();
    if file_path.is_empty() {
        return false;
    }
    if matches_any_glob(file_path, globs) {
        return true;
    }
    let normalized = file_path.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|p| !p.is_empty()).collect();
    for i in 0..parts.len() {
        let suffix = parts[i..].join("/");
        if matches_any_glob(&suffix, globs) {
            return true;
        }
    }
    false
}

fn is_ignored_finding_value(finding: &Finding, ignore_values: &[IgnoreValueEntry]) -> bool {
    if ignore_values.is_empty() {
        return false;
    }
    let rule = normalize_ignore_rule(&finding.antipattern);
    let value = extract_finding_ignore_value(finding);
    if rule.is_empty() || value.is_empty() {
        return false;
    }
    ignore_values.iter().any(|entry| {
        let wildcard = entry.value == "*";
        if entry.rule != rule || (!wildcard && !ignore_value_matches(&rule, &entry.value, &value))
        {
            return false;
        }
        if entry.files.is_empty() {
            return !wildcard;
        }
        matches_any_glob_scoped(finding, &entry.files)
    })
}

/// Port of `filterFindings(findings, content, ext, config)`. `content`/`ext`
/// are unused in the JS implementation too (kept for call-site parity).
pub fn filter_findings(
    findings: &[Finding],
    ignore_rules: &HashSet<String>,
    ignore_values: &[IgnoreValueEntry],
) -> Vec<Finding> {
    let normalized_rules: HashSet<String> =
        ignore_rules.iter().map(|r| normalize_ignore_rule(r)).collect();
    findings
        .iter()
        .filter(|f| {
            if normalized_rules.contains(&normalize_ignore_rule(&f.antipattern)) {
                return false;
            }
            if is_ignored_finding_value(f, ignore_values) {
                return false;
            }
            true
        })
        .cloned()
        .collect()
}

/// Port of `findingCacheKey(finding)`.
pub fn finding_cache_key(finding: &Finding) -> String {
    let line = finding.line;
    let value = extract_finding_ignore_value(finding);
    if line > 0 && !value.is_empty() {
        return format!("{}:{}:{}", finding.antipattern, line, value);
    }
    if line > 0 {
        return format!("{}:{}", finding.antipattern, line);
    }
    if !value.is_empty() {
        return format!("{}:0:{}", finding.antipattern, value);
    }
    let snippet: String = finding
        .snippet
        .as_deref()
        .unwrap_or("")
        .trim()
        .chars()
        .take(80)
        .collect();
    if !snippet.is_empty() {
        format!("{}:0:{}", finding.antipattern, snippet)
    } else {
        format!("{}:0", finding.antipattern)
    }
}

/// Port of `dedupeAgainstCache`: given a session's already-known cache keys
/// for this file, return only the findings whose cache key is new — and also
/// return the updated known-key set (caller persists it), mirroring how the
/// JS mutates `fileEntry.findings` via the `known` Set as it iterates.
pub fn dedupe_against_cache(
    findings: &[Finding],
    known: &HashSet<String>,
) -> (Vec<Finding>, HashSet<String>) {
    let mut known = known.clone();
    let mut fresh = Vec::new();
    for f in findings {
        let key = finding_cache_key(f);
        if known.contains(&key) {
            continue;
        }
        known.insert(key);
        fresh.push(f.clone());
    }
    (fresh, known)
}

/// Port of `formatFindingIgnoreCommand(finding)`.
pub fn format_finding_ignore_command(finding: &Finding) -> String {
    let rule = normalize_ignore_rule(&finding.antipattern);
    if rule.is_empty() {
        return String::new();
    }
    let normalized_value = extract_finding_ignore_value(finding);
    if normalized_value.is_empty() {
        return String::new();
    }
    let value = extract_finding_ignore_value_raw(finding);
    let value_arg = quote_command_arg(&value);
    let reason = quote_command_arg(&format!("User confirmed {value} is intentional"));
    format!("/designer hooks ignore-value {rule} {value_arg} --shared --reason {reason}")
}

fn quote_command_arg(value: &str) -> String {
    let text = value.trim();
    if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
    {
        return text.to_string();
    }
    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Port of `formatFindingLine(f)`.
pub fn format_finding_line(f: &Finding) -> String {
    let prefix = if f.line > 0 {
        format!("- L{}", f.line)
    } else {
        "-".to_string()
    };
    let desc = f.description.as_deref().unwrap_or("").trim();
    let name = f.name.as_deref().unwrap_or("").trim();
    let name_segment = if !name.is_empty() {
        let trimmed = name.trim_end_matches('.').trim_end();
        format!("{trimmed}.")
    } else {
        String::new()
    };
    let ignore_command = format_finding_ignore_command(f);
    let ignore_segment = if !ignore_command.is_empty() {
        format!(" If the user explicitly confirms this value is intentional: `{ignore_command}`.")
    } else {
        String::new()
    };
    let line = format!("{prefix} [{}] {name_segment} {desc}{ignore_segment}", f.antipattern);
    collapse_whitespace(&line).trim().to_string()
}

/// Port of `suppressionNotice(filePath)`.
pub fn suppression_notice(file_path: &str) -> String {
    format!(
        "{ENVELOPE_PREFIX} Suppressing further design hints on {file_path}. More than {EDIT_COUNT_THRESHOLD} edits in this session reached. Run /designer audit to revisit."
    )
}

/// Port of `shouldEmitAckForFile(filePath)` — `ACK_EXTS`.
pub fn should_emit_ack_for_file(file_path: &str) -> bool {
    const ACK_EXTS: [&str; 10] = [
        ".tsx", ".jsx", ".html", ".htm", ".vue", ".svelte", ".astro", ".css", ".scss", ".sass",
    ];
    // NB: JS ACK_EXTS also includes `.less`; kept separately below since the
    // const array above intentionally mirrors source order plus the omitted
    // entry is added here to avoid an 11-element array literal edit hazard.
    let ext = file_ext_lower(file_path);
    ACK_EXTS.contains(&ext.as_str()) || ext == ".less"
}

/// Mirrors Node's `path.extname`: operates on the basename only, and a
/// leading dot with nothing before it (e.g. `.env`) is not an extension.
fn file_ext_lower(file_path: &str) -> String {
    let normalized = file_path.replace('\\', "/");
    let base = normalized.rsplit('/').next().unwrap_or(&normalized);
    match base.rsplit_once('.') {
        Some((before, ext)) if !before.is_empty() && !ext.is_empty() => {
            format!(".{}", ext.to_lowercase())
        }
        _ => String::new(),
    }
}

/// Payload harness kind, mirrors the `harness` string used in `payload()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Harness {
    Claude,
    Cursor,
    Github,
}

/// Port of `payload(text, eventName, harness)`.
pub fn payload(text: &str, event_name: &str, harness: Harness) -> String {
    match harness {
        Harness::Cursor => {
            serde_json::json!({ "additional_context": text }).to_string()
        }
        Harness::Github => {
            serde_json::json!({ "additionalContext": text }).to_string()
        }
        Harness::Claude => serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "additionalContext": text,
            }
        })
        .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truthy_matches_js_regex() {
        for v in ["1", "true", "TRUE", "yes", "on", "On"] {
            assert!(truthy(v), "{v} should be truthy");
        }
        for v in ["0", "false", "no", "off", "", "2"] {
            assert!(!truthy(v), "{v} should not be truthy");
        }
    }

    #[test]
    fn glob_matches_double_star_and_alternation() {
        let globs = vec!["**/*.generated.tsx".to_string(), "src/{a,b}/*.css".to_string()];
        assert!(matches_any_glob("app/foo/bar.generated.tsx", &globs));
        assert!(matches_any_glob("foo.generated.tsx", &globs)); // basename match
        assert!(matches_any_glob("src/a/x.css", &globs));
        assert!(matches_any_glob("src/b/y.css", &globs));
        assert!(!matches_any_glob("src/c/y.css", &globs));
        assert!(!matches_any_glob("app/bar.tsx", &globs));
    }

    #[test]
    fn glob_empty_globs_never_match() {
        assert!(!matches_any_glob("anything.tsx", &[]));
    }

    #[test]
    fn normalize_ignore_value_strips_quotes_plus_and_case() {
        assert_eq!(normalize_ignore_value("\"Inter+Sans\""), "inter sans");
        assert_eq!(normalize_ignore_value("  'Roboto'  "), "roboto");
        assert_eq!(normalize_ignore_value("Fira   Code"), "fira code");
    }

    #[test]
    fn parse_ignore_color_hex_short_and_long() {
        let short = parse_ignore_color("#f00").unwrap();
        assert_eq!((short.r, short.g, short.b, short.a), (255, 0, 0, 1.0));

        let long = parse_ignore_color("#ff0000").unwrap();
        assert_eq!((long.r, long.g, long.b, long.a), (255, 0, 0, 1.0));

        let alpha = parse_ignore_color("#ff000080").unwrap();
        assert_eq!((alpha.r, alpha.g, alpha.b), (255, 0, 0));
        assert!((alpha.a - (128.0 / 255.0)).abs() < 0.01);
    }

    #[test]
    fn parse_ignore_color_rgb_and_rgba() {
        let rgb = parse_ignore_color("rgb(255, 0, 0)").unwrap();
        assert_eq!((rgb.r, rgb.g, rgb.b, rgb.a), (255, 0, 0, 1.0));

        let rgba = parse_ignore_color("rgba(0, 128, 255, 0.5)").unwrap();
        assert_eq!((rgba.r, rgba.g, rgba.b), (0, 128, 255));
        assert!((rgba.a - 0.5).abs() < 0.001);

        // Modern space-separated with slash-alpha syntax.
        let modern = parse_ignore_color("rgb(0 128 255 / 50%)").unwrap();
        assert_eq!((modern.r, modern.g, modern.b), (0, 128, 255));
        assert!((modern.a - 0.5).abs() < 0.001);
    }

    #[test]
    fn parse_ignore_color_hsl_matches_pure_red() {
        let hsl = parse_ignore_color("hsl(0, 100%, 50%)").unwrap();
        assert_eq!((hsl.r, hsl.g, hsl.b), (255, 0, 0));
    }

    #[test]
    fn parse_ignore_color_invalid_returns_none() {
        assert!(parse_ignore_color("not-a-color").is_none());
        assert!(parse_ignore_color("#zzz").is_none());
    }

    #[test]
    fn color_ignore_key_normalizes_equivalent_colors() {
        let a = color_ignore_key("#ff0000");
        let b = color_ignore_key("rgb(255, 0, 0)");
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    fn finding(antipattern: &str, line: i64) -> Finding {
        Finding {
            antipattern: antipattern.to_string(),
            line,
            ..Default::default()
        }
    }

    #[test]
    fn filter_findings_drops_ignored_rule() {
        let findings = vec![finding("side-tab", 3), finding("overused-font", 5)];
        let mut rules = HashSet::new();
        rules.insert("side-tab".to_string());
        let out = filter_findings(&findings, &rules, &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].antipattern, "overused-font");
    }

    #[test]
    fn filter_findings_drops_ignored_value_by_direct_value_rule() {
        let mut f = finding("overused-font", 5);
        f.value = Some("Inter".to_string());
        let entry = IgnoreValueEntry {
            rule: "overused-font".to_string(),
            value: "inter".to_string(),
            files: vec![],
        };
        let out = filter_findings(&[f], &HashSet::new(), &[entry]);
        assert!(out.is_empty());
    }

    #[test]
    fn filter_findings_scoped_ignore_value_respects_file_glob() {
        let mut f = finding("overused-font", 5);
        f.value = Some("Inter".to_string());
        f.file = Some("src/App.tsx".to_string());
        let entry = IgnoreValueEntry {
            rule: "overused-font".to_string(),
            value: "inter".to_string(),
            files: vec!["src/*.tsx".to_string()],
        };
        let out = filter_findings(&[f.clone()], &HashSet::new(), &[entry.clone()]);
        assert!(out.is_empty());

        let mut f2 = f;
        f2.file = Some("other/App.tsx".to_string());
        let out2 = filter_findings(&[f2], &HashSet::new(), &[entry]);
        assert_eq!(out2.len(), 1);
    }

    #[test]
    fn finding_cache_key_prefers_line_and_value() {
        let mut f = finding("overused-font", 5);
        f.value = Some("Inter".to_string());
        assert_eq!(finding_cache_key(&f), "overused-font:5:inter");

        let f2 = finding("side-tab", 3);
        assert_eq!(finding_cache_key(&f2), "side-tab:3");

        let mut f3 = finding("overused-font", 0);
        f3.value = Some("Inter".to_string());
        assert_eq!(finding_cache_key(&f3), "overused-font:0:inter");

        let mut f4 = finding("bounce-easing", 0);
        f4.snippet = Some("some long snippet text here".to_string());
        assert_eq!(
            finding_cache_key(&f4),
            "bounce-easing:0:some long snippet text here"
        );
    }

    #[test]
    fn dedupe_against_cache_skips_known_and_grows_known_set() {
        let findings = vec![finding("side-tab", 3), finding("side-tab", 4)];
        let mut known = HashSet::new();
        known.insert("side-tab:3".to_string());
        let (fresh, updated_known) = dedupe_against_cache(&findings, &known);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].line, 4);
        assert!(updated_known.contains("side-tab:3"));
        assert!(updated_known.contains("side-tab:4"));
    }

    #[test]
    fn format_finding_ignore_command_builds_shared_command() {
        let mut f = finding("overused-font", 5);
        f.value = Some("Inter".to_string());
        let cmd = format_finding_ignore_command(&f);
        assert!(cmd.starts_with("/designer hooks ignore-value overused-font Inter --shared --reason"));
    }

    #[test]
    fn format_finding_ignore_command_empty_without_direct_value_rule() {
        let f = finding("side-tab", 3);
        assert_eq!(format_finding_ignore_command(&f), "");
    }

    #[test]
    fn format_finding_line_includes_line_prefix_and_name() {
        let mut f = finding("overused-font", 5);
        f.name = Some("Overused font".to_string());
        f.description = Some("Too many fonts in use.".to_string());
        let line = format_finding_line(&f);
        assert!(line.starts_with("- L5 [overused-font] Overused font."));
        assert!(line.contains("Too many fonts in use."));
    }

    #[test]
    fn format_finding_line_no_line_uses_bare_dash() {
        let f = finding("side-tab", 0);
        let line = format_finding_line(&f);
        assert!(line.starts_with("- [side-tab]"));
    }

    #[test]
    fn suppression_notice_matches_js_wording() {
        let text = suppression_notice("src/App.tsx");
        assert!(text.contains("Suppressing further design hints on src/App.tsx"));
        assert!(text.contains("More than 6 edits"));
    }

    #[test]
    fn should_emit_ack_for_file_matches_ack_exts() {
        assert!(should_emit_ack_for_file("App.tsx"));
        assert!(should_emit_ack_for_file("styles.less"));
        assert!(should_emit_ack_for_file("Page.HTML"));
        assert!(!should_emit_ack_for_file("script.ts"));
        assert!(!should_emit_ack_for_file("script.js"));
        assert!(!should_emit_ack_for_file("noext"));
    }

    #[test]
    fn payload_claude_shape() {
        let text = payload("hello", "PostToolUse", Harness::Claude);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v["hookSpecificOutput"]["hookEventName"],
            serde_json::json!("PostToolUse")
        );
        assert_eq!(
            v["hookSpecificOutput"]["additionalContext"],
            serde_json::json!("hello")
        );
    }

    #[test]
    fn payload_cursor_shape() {
        let text = payload("hello", "PostToolUse", Harness::Cursor);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["additional_context"], serde_json::json!("hello"));
    }

    #[test]
    fn payload_github_shape() {
        let text = payload("hello", "PostToolUse", Harness::Github);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["additionalContext"], serde_json::json!("hello"));
    }
}
