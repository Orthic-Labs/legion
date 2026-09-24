//! Port of `skills/designer/engine/scripts/lib/design-parser.mjs` (packet r15).
//!
//! Parses a DESIGN.md (Stitch-spec format) into a structured model: an
//! optional YAML frontmatter (machine-readable tokens) plus a markdown body
//! scraped into six canonical H2 sections (Overview, Colors, Typography,
//! Elevation, Components, Do's and Don'ts). Deterministic, dependency-free,
//! faithful to the JS behaviour.
//!
//! Entry points: [`parse_design_md`] (mirrors `parseDesignMd`) and
//! [`assess_coverage`] (mirrors `assessCoverage`).

use std::collections::BTreeMap;

const CANONICAL_SECTIONS: [&str; 6] = [
    "Overview",
    "Colors",
    "Typography",
    "Elevation",
    "Components",
    "Do's and Don'ts",
];

// ---------------------------------------------------------------------
// YAML value (frontmatter)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum YamlValue {
    Null,
    Bool(bool),
    Number(f64),
    Str(String),
    Map(BTreeMap<String, YamlValue>),
}

impl YamlValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            YamlValue::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_map(&self) -> Option<&BTreeMap<String, YamlValue>> {
        match self {
            YamlValue::Map(m) => Some(m),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------
// Frontmatter
// ---------------------------------------------------------------------

/// `parseFrontmatter` in design-parser.mjs.
fn parse_frontmatter(md: &str) -> (Option<BTreeMap<String, YamlValue>>, String) {
    let lines: Vec<&str> = split_lines(md);
    if lines.first().map(|l| l.trim()) != Some("---") {
        return (None, md.to_string());
    }

    let mut end: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().skip(1) {
        if line.trim() == "---" {
            end = Some(i);
            break;
        }
    }
    let end = match end {
        Some(e) => e,
        None => return (None, md.to_string()),
    };

    let yaml = lines[1..end].join("\n");
    let body = lines[(end + 1)..].join("\n");
    match parse_yaml_subset(&yaml) {
        Ok(map) => (Some(map), body),
        Err(()) => (None, md.to_string()),
    }
}

/// `parseYamlSubset`: minimal YAML reader for the Stitch frontmatter subset —
/// scalar maps with one level of nested objects, 2-space indent convention,
/// no arrays/anchors/multi-line scalars.
fn parse_yaml_subset(yaml: &str) -> Result<BTreeMap<String, YamlValue>, ()> {
    struct Frame {
        indent: i64,
        // Path of keys from root to this map, used to navigate/insert.
        path: Vec<String>,
    }

    let root: BTreeMap<String, YamlValue> = BTreeMap::new();
    let mut stack: Vec<Frame> = vec![Frame {
        indent: -1,
        path: vec![],
    }];
    let mut root_map = root;

    for raw in split_lines(yaml) {
        if raw.trim().is_empty() || is_comment_line(raw) {
            continue;
        }

        let indent = raw.len() - raw.trim_start().len();
        let content = &raw[indent..];

        let colon_idx = match find_top_level_colon(content) {
            Some(i) => i,
            None => continue,
        };

        while stack.len() > 1 && stack.last().unwrap().indent >= indent as i64 {
            stack.pop();
        }

        let key = unquote_yaml_key(content[..colon_idx].trim());
        let rest = strip_inline_yaml_comment(content[colon_idx + 1..].trim());
        let parent_path = stack.last().unwrap().path.clone();

        if rest.is_empty() {
            insert_at_path(&mut root_map, &parent_path, &key, YamlValue::Map(BTreeMap::new()));
            let mut new_path = parent_path.clone();
            new_path.push(key);
            stack.push(Frame {
                indent: indent as i64,
                path: new_path,
            });
        } else {
            let value = parse_scalar(&rest);
            insert_at_path(&mut root_map, &parent_path, &key, value);
        }
    }

    Ok(root_map)
}

fn insert_at_path(
    root: &mut BTreeMap<String, YamlValue>,
    path: &[String],
    key: &str,
    value: YamlValue,
) {
    let mut cur = root;
    for p in path {
        let entry = cur
            .entry(p.clone())
            .or_insert_with(|| YamlValue::Map(BTreeMap::new()));
        if let YamlValue::Map(m) = entry {
            cur = m;
        } else {
            // Shouldn't happen given how frames are constructed, but guard.
            *entry = YamlValue::Map(BTreeMap::new());
            if let YamlValue::Map(m) = entry {
                cur = m;
            } else {
                unreachable!()
            }
        }
    }
    cur.insert(key.to_string(), value);
}

fn is_comment_line(raw: &str) -> bool {
    let trimmed = raw.trim_start();
    trimmed.starts_with('#')
}

/// `findTopLevelColon`
fn find_top_level_colon(s: &str) -> Option<usize> {
    let mut in_quote: Option<char> = None;
    let chars: Vec<char> = s.chars().collect();
    for i in 0..chars.len() {
        let ch = chars[i];
        if let Some(q) = in_quote {
            if ch == q && (i == 0 || chars[i - 1] != '\\') {
                in_quote = None;
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
        } else if ch == ':' {
            // byte index: since we're scanning char-by-char, compute byte offset
            return Some(char_index_to_byte(s, i));
        }
    }
    None
}

fn char_index_to_byte(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

fn unquote_yaml_key(key: &str) -> String {
    let bytes = key.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        key[1..key.len() - 1].to_string()
    } else {
        key.to_string()
    }
}

/// `stripInlineYamlComment`
fn strip_inline_yaml_comment(s: &str) -> String {
    let mut in_quote: Option<char> = None;
    let chars: Vec<char> = s.chars().collect();
    for i in 0..chars.len() {
        let ch = chars[i];
        if let Some(q) = in_quote {
            if ch == q && (i == 0 || chars[i - 1] != '\\') {
                in_quote = None;
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
        } else if ch == '#' && i > 0 && chars[i - 1].is_whitespace() {
            return chars[..i].iter().collect::<String>().trim_end().to_string();
        }
    }
    s.to_string()
}

/// `parseScalar`
fn parse_scalar(raw: &str) -> YamlValue {
    let s = raw.trim();
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        return YamlValue::Str(s[1..s.len() - 1].to_string());
    }
    if s == "true" {
        return YamlValue::Bool(true);
    }
    if s == "false" {
        return YamlValue::Bool(false);
    }
    if s == "null" || s == "~" {
        return YamlValue::Null;
    }
    if is_integer(s) {
        if let Ok(n) = s.parse::<f64>() {
            return YamlValue::Number(n);
        }
    }
    if is_decimal(s) {
        if let Ok(n) = s.parse::<f64>() {
            return YamlValue::Number(n);
        }
    }
    YamlValue::Str(s.to_string())
}

/// `/^-?\d+$/`
fn is_integer(s: &str) -> bool {
    let s = s.strip_prefix('-').unwrap_or(s);
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// `/^-?\d*\.\d+$/`
fn is_decimal(s: &str) -> bool {
    let s = s.strip_prefix('-').unwrap_or(s);
    match s.split_once('.') {
        Some((int_part, frac_part)) => {
            int_part.chars().all(|c| c.is_ascii_digit())
                && !frac_part.is_empty()
                && frac_part.chars().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

fn split_lines(s: &str) -> Vec<&str> {
    // Mirrors `str.split(/\r?\n/)`.
    let mut out = Vec::new();
    let mut start = 0usize;
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            let mut end = i;
            if end > start && bytes[end - 1] == b'\r' {
                end -= 1;
            }
            out.push(&s[start..end]);
            start = i + 1;
        }
        i += 1;
    }
    out.push(&s[start..]);
    out
}

// ---------------------------------------------------------------------
// Section splitting
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub subtitle: Option<String>,
    pub lines: Vec<String>,
}

struct SplitSectionsResult {
    title: Option<String>,
    sections: BTreeMap<String, Section>,
}

/// `splitSections`
fn split_sections(md: &str) -> SplitSectionsResult {
    let lines = split_lines(md);
    let mut title: Option<String> = None;
    let mut sections: BTreeMap<String, Section> = BTreeMap::new();
    let mut current_key: Option<String> = None;

    for raw in lines {
        let line = raw.trim_end();

        if title.is_none() && line.starts_with("# ") && !line.starts_with("## ") {
            title = Some(line.trim_start_matches('#').trim().to_string());
            continue;
        }

        if let Some((raw_name, subtitle)) = match_h2(line) {
            let normalized = normalize_apostrophes(raw_name.trim());
            let canonical = match_canonical_section(&normalized);
            if let Some(canonical) = canonical {
                sections.insert(
                    canonical.clone(),
                    Section {
                        name: canonical.clone(),
                        subtitle,
                        lines: vec![],
                    },
                );
                current_key = Some(canonical);
                continue;
            }
            current_key = None;
            continue;
        }

        if let Some(key) = &current_key {
            if let Some(section) = sections.get_mut(key) {
                section.lines.push(raw.to_string());
            }
        }
    }

    SplitSectionsResult { title, sections }
}

/// `^##\s+(?:\d+\.\s*)?([^:\n]+?)(?::\s*(.+))?$`
fn match_h2(line: &str) -> Option<(String, Option<String>)> {
    let rest = line.strip_prefix("##")?;
    let rest = rest.strip_prefix(|c: char| c.is_whitespace())?;
    let rest = rest.trim_start();
    // strip optional leading "N. "
    let rest = strip_leading_number(rest);

    // Split on ": " (first colon) for subtitle, matching `([^:\n]+?)(?::\s*(.+))?`.
    if let Some(idx) = rest.find(':') {
        let name = rest[..idx].trim_end().to_string();
        let after = rest[idx + 1..].trim_start();
        if !name.trim().is_empty() {
            let subtitle = if after.is_empty() {
                None
            } else {
                Some(after.to_string())
            };
            return Some((name, subtitle));
        }
    }
    let name = rest.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some((name, None))
    }
}

fn strip_leading_number(s: &str) -> &str {
    let trimmed = s.trim_start();
    let digits_end = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    if digits_end > 0 && trimmed[digits_end..].starts_with('.') {
        let after_dot = &trimmed[digits_end + 1..];
        after_dot.trim_start()
    } else {
        trimmed
    }
}

fn normalize_apostrophes(s: &str) -> String {
    s.replace(['\u{2018}', '\u{2019}'], "'")
}

fn match_canonical_section(name: &str) -> Option<String> {
    let normalized = normalize_apostrophes(name).to_lowercase();
    for c in CANONICAL_SECTIONS {
        if normalize_apostrophes(c).to_lowercase() == normalized {
            return Some(c.to_string());
        }
    }
    for c in CANONICAL_SECTIONS {
        let key = normalize_apostrophes(c).to_lowercase();
        if word_boundary_contains(&normalized, &key) {
            return Some(c.to_string());
        }
    }
    None
}

/// Approximates `new RegExp(`\\b${escaped}\\b`)` word-boundary containment
/// for the fixed, known set of canonical-section keywords (plain words plus
/// `do's and don'ts`, which contains apostrophes we've already normalized).
fn word_boundary_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let h: Vec<char> = haystack.chars().collect();
    let n: Vec<char> = needle.chars().collect();
    if n.len() > h.len() {
        return false;
    }
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    for start in 0..=(h.len() - n.len()) {
        if h[start..start + n.len()] == n[..] {
            let before_ok = start == 0 || !is_word(h[start - 1]);
            let end = start + n.len();
            let after_ok = end == h.len() || !is_word(h[end]);
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------
// Subsection splitting
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Subsection {
    name: Option<String>,
    lines: Vec<String>,
}

/// `splitSubsections`
fn split_subsections(lines: &[String]) -> Vec<Subsection> {
    let mut subs: Vec<Subsection> = vec![Subsection {
        name: None,
        lines: vec![],
    }];

    for raw in lines {
        if let Some(name) = match_h3(raw) {
            subs.push(Subsection {
                name: Some(name),
                lines: vec![],
            });
            continue;
        }
        subs.last_mut().unwrap().lines.push(raw.clone());
    }

    subs
}

/// `^###\s+(.+?)\s*$`
fn match_h3(line: &str) -> Option<String> {
    let rest = line.strip_prefix("###")?;
    if rest.is_empty() || !rest.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

// ---------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------

/// `collectParagraphs`
fn collect_paragraphs(lines: &[String]) -> Vec<String> {
    let mut paragraphs = Vec::new();
    let mut buf: Vec<String> = Vec::new();
    let flush = |buf: &mut Vec<String>, paragraphs: &mut Vec<String>| {
        if !buf.is_empty() {
            paragraphs.push(buf.join(" ").trim().to_string());
            buf.clear();
        }
    };
    for raw in lines {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            flush(&mut buf, &mut paragraphs);
            continue;
        }
        if is_hr(trimmed) {
            flush(&mut buf, &mut paragraphs);
            continue;
        }
        if raw.starts_with('#') || starts_with_bullet(raw) {
            flush(&mut buf, &mut paragraphs);
            continue;
        }
        buf.push(trimmed.to_string());
    }
    flush(&mut buf, &mut paragraphs);
    paragraphs.into_iter().filter(|p| !p.is_empty()).collect()
}

/// `/^(?:-{3,}|\*{3,}|_{3,})$/`
fn is_hr(s: &str) -> bool {
    if s.len() < 3 {
        return false;
    }
    let c = s.chars().next().unwrap();
    (c == '-' || c == '*' || c == '_') && s.chars().all(|ch| ch == c)
}

/// `/^[-*]\s/`
fn starts_with_bullet(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some('-') | Some('*') => chars.next().is_some_and(|c| c.is_whitespace()),
        _ => false,
    }
}

/// `collectBullets`
fn collect_bullets(lines: &[String]) -> Vec<String> {
    let mut bullets = Vec::new();
    let mut current: Option<String> = None;
    for raw in lines {
        if let Some(rest) = match_bullet_marker(raw) {
            if let Some(c) = current.take() {
                bullets.push(c);
            }
            current = Some(rest);
            continue;
        }
        // continuation of a bullet (indented line): `/^\s{2,}\S/`
        if current.is_some() && has_indent_continuation(raw) {
            let c = current.as_mut().unwrap();
            c.push(' ');
            c.push_str(raw.trim());
            continue;
        }
        if raw.trim().is_empty() && current.is_some() {
            bullets.push(current.take().unwrap());
        }
    }
    if let Some(c) = current {
        bullets.push(c);
    }
    bullets
}

/// `^\s*[-*]\s+(.+)$`
fn match_bullet_marker(raw: &str) -> Option<String> {
    let trimmed_start = raw.trim_start();
    let rest = trimmed_start
        .strip_prefix('-')
        .or_else(|| trimmed_start.strip_prefix('*'))?;
    let rest_trimmed = rest.strip_prefix(|c: char| c.is_whitespace())?;
    let content = rest_trimmed.trim_start();
    if content.is_empty() {
        None
    } else {
        Some(content.to_string())
    }
}

/// `/^\s{2,}\S/`
fn has_indent_continuation(raw: &str) -> bool {
    let leading = raw.len() - raw.trim_start().len();
    leading >= 2 && raw.trim_start().chars().next().is_some()
}

fn strip_bold(s: &str) -> String {
    // `s.replace(/\*\*(.+?)\*\*/g, '$1')` — non-greedy, no regex crate lookaround
    // needed since `**...**` pairs are simple to scan by hand.
    let mut out = String::new();
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            if let Some(close_rel) = s[i + 2..].find("**") {
                let inner = &s[i + 2..i + 2 + close_rel];
                if !inner.is_empty() {
                    out.push_str(inner);
                    i = i + 2 + close_rel + 2;
                    continue;
                }
            }
        }
        // push current char (handle multi-byte safely)
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

// ---------------------------------------------------------------------
// Public model types
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Overview {
    pub subtitle: Option<String>,
    pub creative_north_star: Option<String>,
    pub philosophy: Vec<String>,
    pub key_characteristics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Color {
    pub name: Option<String>,
    pub value: String,
    pub value_range: Option<Vec<String>>,
    pub format: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ColorGroup {
    pub role: String,
    pub colors: Vec<Color>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NamedRule {
    pub name: String,
    pub body: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Colors {
    pub subtitle: Option<String>,
    pub description: Option<String>,
    pub groups: Vec<ColorGroup>,
    pub rules: Vec<NamedRule>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FontSpec {
    pub family: String,
    pub fallback: Option<String>,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TypeBullet {
    pub name: String,
    pub specs: Vec<String>,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Typography {
    pub subtitle: Option<String>,
    pub fonts: BTreeMap<String, FontSpec>,
    pub character: Option<String>,
    pub hierarchy: Vec<TypeBullet>,
    pub rules: Vec<NamedRule>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Shadow {
    pub name: Option<String>,
    pub value: String,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Elevation {
    pub subtitle: Option<String>,
    pub description: Option<String>,
    pub shadows: Vec<Shadow>,
    pub rules: Vec<NamedRule>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Component {
    pub name: String,
    pub description: Option<String>,
    pub properties: BTreeMap<String, String>,
    pub variants: Vec<NamedRule>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Components {
    pub subtitle: Option<String>,
    pub components: Vec<Component>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DosDonts {
    pub dos: Vec<String>,
    pub donts: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DesignModel {
    pub schema_version: u32,
    pub title: Option<String>,
    pub frontmatter: Option<BTreeMap<String, YamlValue>>,
    pub overview: Option<Overview>,
    pub colors: Option<Colors>,
    pub typography: Option<Typography>,
    pub elevation: Option<Elevation>,
    pub components: Option<Components>,
    pub dos_donts: Option<DosDonts>,
}

// ---------------------------------------------------------------------
// Per-section extractors
// ---------------------------------------------------------------------

/// `extractOverview`
fn extract_overview(section: Option<&Section>) -> Option<Overview> {
    let section = section?;
    let text = section.lines.join("\n");

    let north_star = extract_creative_north_star(&text);

    let mut key_chars = Vec::new();
    if let Some(block) = extract_key_characteristics_block(&text) {
        for line in split_lines(&block) {
            if let Some(rest) = match_bullet_marker(line) {
                key_chars.push(strip_bold(rest.trim()));
            }
        }
    }

    let paragraphs: Vec<String> = collect_paragraphs(&section.lines)
        .into_iter()
        .filter(|p| {
            !p.starts_with("**Creative North Star") && !p.starts_with("**Key Characteristics")
        })
        .collect();

    Some(Overview {
        subtitle: section.subtitle.clone(),
        creative_north_star: north_star,
        philosophy: paragraphs,
        key_characteristics: key_chars,
    })
}

/// `/\*\*Creative North Star:\s*"([^"]+)"\*\*/`
fn extract_creative_north_star(text: &str) -> Option<String> {
    let marker = "**Creative North Star:";
    let idx = text.find(marker)?;
    let rest = &text[idx + marker.len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    let inner = &rest[..end];
    let after = &rest[end + 1..];
    if after.starts_with("**") {
        Some(inner.to_string())
    } else {
        None
    }
}

/// `/\*\*Key Characteristics:\*\*\s*\n([\s\S]+?)(?:\n##|\n###|$)/`
fn extract_key_characteristics_block(text: &str) -> Option<String> {
    let marker = "**Key Characteristics:**";
    let idx = text.find(marker)?;
    let rest = &text[idx + marker.len()..];
    let rest = rest.strip_prefix(char::is_whitespace).unwrap_or(rest);
    // Need a newline right after the (trimmed) marker per the JS `\s*\n`.
    let newline_idx = rest.find('\n')?;
    let body_start = &rest[newline_idx + 1..];
    let end = find_first_of(body_start, &["\n##", "\n###"]).unwrap_or(body_start.len());
    Some(body_start[..end].to_string())
}

fn find_first_of(s: &str, needles: &[&str]) -> Option<usize> {
    needles.iter().filter_map(|n| s.find(n)).min()
}

const HEX_CHARS: &str = "0123456789abcdefABCDEF";

fn collect_hex_colors(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == '#' {
            let mut j = i + 1;
            while j < bytes.len() && HEX_CHARS.contains(bytes[j]) {
                j += 1;
            }
            let len = j - (i + 1);
            if (3..=8).contains(&len) {
                // `\b` after: next char (if any) must not be a word char.
                let boundary_ok = j >= bytes.len() || !(bytes[j].is_alphanumeric() || bytes[j] == '_');
                if boundary_ok {
                    out.push(bytes[i..j].iter().collect());
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

fn collect_oklch_colors(s: &str) -> Vec<String> {
    collect_paren_call(s, "oklch")
}

fn collect_paren_call(s: &str, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = s.to_lowercase();
    let name_lower = name.to_lowercase();
    let mut search_from = 0usize;
    while let Some(rel) = lower[search_from..].find(&name_lower) {
        let start = search_from + rel;
        let after_name = start + name.len();
        if lower[after_name..].starts_with('(') {
            // find matching close paren for [^)]+ i.e. up to first ')'
            if let Some(close_rel) = s[after_name..].find(')') {
                let end = after_name + close_rel + 1;
                out.push(s[start..end].to_string());
                search_from = end;
                continue;
            }
        }
        search_from = start + name.len();
    }
    out
}

fn collect_color_values(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(collect_hex_colors(s));
    out.extend(collect_oklch_colors(s));
    out
}

fn detect_format(v: &str) -> &'static str {
    if v.is_empty() {
        return "unknown";
    }
    if v.starts_with('#') {
        return "hex";
    }
    if v.to_lowercase().starts_with("oklch") {
        return "oklch";
    }
    if v.to_lowercase().starts_with("rgb") {
        return "rgb";
    }
    "unknown"
}

fn build_color(name: Option<&str>, raw_value: &str, description: &str) -> Color {
    let values = collect_color_values(raw_value);
    let primary = values.first().cloned().unwrap_or_else(|| raw_value.trim().to_string());
    let format = detect_format(&primary).to_string();
    let desc = strip_bold(description).trim().to_string();
    Color {
        name: name.map(|n| strip_bold(n).trim().to_string()),
        value: primary,
        value_range: if values.len() > 1 { Some(values) } else { None },
        format,
        description: if desc.is_empty() { None } else { Some(desc) },
    }
}

/// `parseColorBullet`
fn parse_color_bullet(bullet: &str) -> Option<Color> {
    let text = bullet.trim();

    // Case 1 (Impeccable): **Name** (value-with-maybe-nested-parens): description
    if let Some((name, after_bold)) = match_leading_bold(text) {
        let after_bold_trimmed = after_bold.trim_start();
        if after_bold_trimmed.starts_with('(') {
            if let Some(value) = extract_paren_group(after_bold_trimmed) {
                let consumed = value.len() + 2;
                if consumed <= after_bold_trimmed.len() {
                    let after = after_bold_trimmed[consumed..].trim_start();
                    if let Some(rest) = after.strip_prefix(':') {
                        return Some(build_color(Some(&name), &value, rest.trim()));
                    }
                }
            }
        }
    }

    // Case 2 (Stitch): **Name (values):** description
    if let Some((name, values, desc)) = match_stitch_bullet(text) {
        return Some(build_color(Some(&name), &values, &desc));
    }

    // Case 3: bullet without bold, just hex/oklch inside.
    let values = collect_color_values(text);
    if !values.is_empty() {
        return Some(build_color(None, &values.join(" to "), text));
    }
    None
}

/// `^\*\*(.+?)\*\*\s*(.*)$` — returns (name, rest-after-bold).
fn match_leading_bold(text: &str) -> Option<(String, String)> {
    let rest = text.strip_prefix("**")?;
    let close = rest.find("**")?;
    let name = &rest[..close];
    if name.is_empty() {
        return None;
    }
    let after = &rest[close + 2..];
    Some((name.to_string(), after.to_string()))
}

/// `^\*\*([^*]+?)\s*\(([^)]+)\):\*\*\s*(.*)$`
fn match_stitch_bullet(text: &str) -> Option<(String, String, String)> {
    let rest = text.strip_prefix("**")?;
    // find first '*' to end the [^*]+ segment, must be followed eventually by "(...):**"
    let star_idx = rest.find('*')?;
    let head = &rest[..star_idx];
    // head should end with "(...)" — find last '(' before end, with a ')' right before star_idx
    let open = head.find('(')?;
    let name = head[..open].trim_end().to_string();
    if name.is_empty() {
        return None;
    }
    let inner_and_paren = &head[open..];
    if !inner_and_paren.ends_with(')') {
        return None;
    }
    let inner = &inner_and_paren[1..inner_and_paren.len() - 1];
    if inner.contains(')') || inner.contains('(') {
        return None;
    }
    // after head, rest[star_idx..] must start with "*):**" pattern -> actually
    // head already excludes trailing ')' check above; now confirm "**" follows.
    let after_head = &rest[star_idx..];
    let after_head = after_head.strip_prefix("*")?; // second '*' of closing **
    let after_head = after_head.strip_prefix(':')?;
    let after_head = after_head.strip_prefix("**")?;
    let desc = after_head.trim_start().to_string();
    Some((name, inner.to_string(), desc))
}

fn extract_paren_group(s: &str) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.first() != Some(&'(') {
        return None;
    }
    let mut depth = 0i32;
    for (i, &c) in chars.iter().enumerate() {
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
            if depth == 0 {
                return Some(chars[1..i].iter().collect());
            }
        }
    }
    None
}

const ROLE_KEYWORDS: [&str; 5] = ["primary", "secondary", "tertiary", "neutral", "accent"];

fn starts_with_role_keyword(name: &str) -> bool {
    let lower = name.to_lowercase();
    ROLE_KEYWORDS.iter().any(|k| lower.starts_with(k))
}

/// `extractColors`
fn extract_colors(section: Option<&Section>) -> Option<Colors> {
    let section = section?;
    let subs = split_subsections(&section.lines);

    let description = collect_paragraphs(&subs[0].lines).join(" ");

    let mut groups: Vec<ColorGroup> = Vec::new();

    for sub in &subs[1..] {
        let name = match &sub.name {
            Some(n) => n,
            None => continue,
        };
        if is_named_rules_heading(name) || name.trim_start().starts_with("The ") {
            continue;
        }

        let bullets = collect_bullets(&sub.lines);
        let parsed: Vec<Color> = bullets.iter().filter_map(|b| parse_color_bullet(b)).collect();
        if parsed.is_empty() {
            continue;
        }

        let all_role_bullets = parsed
            .iter()
            .all(|p| p.name.as_deref().is_some_and(starts_with_role_keyword));

        if all_role_bullets {
            for p in parsed {
                let role = p.name.clone().unwrap();
                groups.push(ColorGroup {
                    role,
                    colors: vec![p],
                });
            }
        } else {
            groups.push(ColorGroup {
                role: name.clone(),
                colors: parsed,
            });
        }
    }

    if groups.is_empty() {
        let flat: Vec<Color> = collect_bullets(&section.lines)
            .iter()
            .filter_map(|b| parse_color_bullet(b))
            .collect();
        if !flat.is_empty() {
            for p in flat {
                if p.name.as_deref().is_some_and(starts_with_role_keyword) {
                    let role = p.name.clone().unwrap();
                    groups.push(ColorGroup {
                        role,
                        colors: vec![p],
                    });
                } else if let Some(fallback) = groups.iter_mut().find(|g| g.role == "Palette") {
                    fallback.colors.push(p);
                } else {
                    groups.push(ColorGroup {
                        role: "Palette".to_string(),
                        colors: vec![p],
                    });
                }
            }
        }
    }

    Some(Colors {
        subtitle: section.subtitle.clone(),
        description: if description.is_empty() {
            None
        } else {
            Some(description)
        },
        groups,
        rules: extract_named_rules(&section.lines),
    })
}

fn is_named_rules_heading(name: &str) -> bool {
    let n = name.to_lowercase();
    n == "named rule" || n == "named rules"
}

/// `extractNamedRules`
fn extract_named_rules(lines: &[String]) -> Vec<NamedRule> {
    let mut rules: Vec<NamedRule> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let joined = lines.join("\n");

    // Style A (Impeccable): "**The X Rule.** body body body" — can span lines.
    let mut inline_matches: Vec<(String, usize, usize)> = Vec::new();
    {
        let mut search_from = 0usize;
        while let Some(rel) = joined[search_from..].find("**The ") {
            let start = search_from + rel;
            // find ` Rule.**` after start, but scan properly: pattern is
            // `\*\*(The [^*]+?Rule)\.\*\*` — name is non-greedy up to "Rule.**"
            if let Some(name_and_rest) = joined[start + 2..].find("**") {
                let candidate = &joined[start + 2..start + 2 + name_and_rest];
                if candidate.starts_with("The ") && candidate.ends_with("Rule.") && !candidate[..candidate.len() - 1].contains('*') {
                    let name = candidate[..candidate.len() - 1].to_string();
                    let end = start + 2 + name_and_rest + 2;
                    inline_matches.push((name, start, end));
                    search_from = end;
                    continue;
                }
            }
            search_from = start + 2;
        }
    }
    for i in 0..inline_matches.len() {
        let (name, _start, end) = &inline_matches[i];
        let body_end = if i + 1 < inline_matches.len() {
            inline_matches[i + 1].1
        } else {
            joined.len()
        };
        let mut body = joined[*end..body_end].to_string();
        body = strip_trailing_heading_line(&body, "##");
        body = strip_trailing_heading_line(&body, "###");
        let body = body.trim().to_string();
        let clean_name = strip_bold(name).trim().to_string();
        seen.insert(clean_name.to_lowercase());
        rules.push(NamedRule {
            name: clean_name,
            body: strip_bold(&body),
        });
    }

    // Style B (Stitch): `### The "X" Rule` / Fallback / Principle.
    for i in 0..lines.len() {
        let header_name = match match_h3(&lines[i]) {
            Some(h) => h,
            None => continue,
        };
        let header_name = strip_bold(&header_name).replace(['"', '\u{201c}', '\u{201d}'], "");
        let header_name = header_name.trim().to_string();
        if !is_the_x_rule_header(&header_name) {
            continue;
        }
        if seen.contains(&header_name.to_lowercase()) {
            continue;
        }

        let mut body_lines: Vec<String> = Vec::new();
        for line in &lines[(i + 1)..] {
            if line.trim_start().starts_with("##") {
                break;
            }
            body_lines.push(line.clone());
        }
        let body = strip_bold(&collapse_newlines(&body_lines.join("\n")));
        let body = body.trim().to_string();
        if !body.is_empty() {
            seen.insert(header_name.to_lowercase());
            rules.push(NamedRule {
                name: header_name,
                body,
            });
        }
    }

    // Style C (Stitch bullet form): "*   **The Layering Principle:** body"
    for b in collect_bullets(lines) {
        let (name_raw, desc) = match match_bold_prefixed_bullet(&b) {
            Some(v) => v,
            None => continue,
        };
        let name_raw = name_raw
            .trim_end_matches(['.', ':'])
            .replace(['"', '\u{201c}', '\u{201d}'], "");
        let name_raw = name_raw.trim().to_string();
        if !is_the_x_rule_header_strict(&name_raw) {
            continue;
        }
        if seen.contains(&name_raw.to_lowercase()) {
            continue;
        }
        seen.insert(name_raw.to_lowercase());
        rules.push(NamedRule {
            name: name_raw,
            body: strip_bold(desc.trim()),
        });
    }

    rules
}

fn strip_trailing_heading_line(body: &str, marker: &str) -> String {
    // `.replace(/\n##[^\n]*$/s, '')` style, applied for "##" then "###" — since
    // "###" also matches the "##" pattern's prefix, mirror by checking suffix.
    if let Some(idx) = body.rfind('\n') {
        let tail = &body[idx..];
        if tail.trim_start_matches('\n').starts_with(marker)
            && !tail[1..].trim_start().starts_with(&format!("{marker}#"))
        {
            return body[..idx].to_string();
        }
    }
    body.to_string()
}

fn collapse_newlines(s: &str) -> String {
    // `.replace(/\n+/g, ' ')`
    let mut out = String::new();
    let mut in_newlines = false;
    for c in s.chars() {
        if c == '\n' {
            if !in_newlines {
                out.push(' ');
                in_newlines = true;
            }
        } else {
            in_newlines = false;
            out.push(c);
        }
    }
    out
}

fn is_the_x_rule_header(s: &str) -> bool {
    // `/^The\b.*\b(Rule|Fallback|Principle)\b/i`
    let lower = s.to_lowercase();
    if !starts_with_word(&lower, "the") {
        return false;
    }
    ["rule", "fallback", "principle"]
        .iter()
        .any(|kw| ends_with_word_anywhere(&lower, kw))
}

fn is_the_x_rule_header_strict(s: &str) -> bool {
    // `/^The\b.+\b(Rule|Fallback|Principle)$/i`
    let lower = s.to_lowercase();
    if !starts_with_word(&lower, "the") {
        return false;
    }
    ["rule", "fallback", "principle"]
        .iter()
        .any(|kw| lower.ends_with(kw) && (lower.len() == kw.len() || !is_word_char(lower.as_bytes()[lower.len() - kw.len() - 1] as char)))
}

fn starts_with_word(lower: &str, word: &str) -> bool {
    if !lower.starts_with(word) {
        return false;
    }
    match lower.as_bytes().get(word.len()) {
        None => true,
        Some(&b) => !is_word_char(b as char),
    }
}

fn ends_with_word_anywhere(lower: &str, word: &str) -> bool {
    let mut search_from = 0usize;
    while let Some(rel) = lower[search_from..].find(word) {
        let start = search_from + rel;
        let end = start + word.len();
        let before_ok = start == 0 || !is_word_char(lower.as_bytes()[start - 1] as char);
        let after_ok = end == lower.len() || !is_word_char(lower.as_bytes()[end] as char);
        if before_ok && after_ok {
            return true;
        }
        search_from = start + 1;
    }
    false
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `^\*\*([^*]+?)\*\*\s*(.+)$`
fn match_bold_prefixed_bullet(b: &str) -> Option<(String, String)> {
    let rest = b.strip_prefix("**")?;
    let close = rest.find("**")?;
    let name = &rest[..close];
    if name.contains('*') {
        return None;
    }
    let after = rest[close + 2..].trim_start();
    if after.is_empty() {
        None
    } else {
        Some((name.to_string(), after.to_string()))
    }
}

/// `extractTypography`
fn extract_typography(section: Option<&Section>) -> Option<Typography> {
    let section = section?;
    let text = section.lines.join("\n");

    let mut fonts: BTreeMap<String, FontSpec> = BTreeMap::new();

    // Pattern A: **Display Font:** Family (with fallback)
    for (raw_role, family, fallback) in scan_font_line_a(&text) {
        let role_key = raw_role.trim().to_lowercase().replace(char::is_whitespace, "-");
        let role = normalize_font_role(&role_key).unwrap_or_else(|| "display".to_string());
        fonts.insert(
            role,
            FontSpec {
                family: family.trim().to_string(),
                fallback: fallback.map(|f| f.trim().to_string()),
                purpose: None,
            },
        );
    }

    // Pattern B (Stitch): *   **Display & Headlines (Noto Serif):** description
    if fonts.is_empty() {
        for (raw_role, family, purpose) in scan_font_line_b(&text) {
            let role_key = raw_role
                .trim()
                .to_lowercase()
                .replace(" & ", "-")
                .replace('&', "-")
                .replace(char::is_whitespace, "-");
            let role = normalize_font_role(&role_key).unwrap_or(role_key);
            fonts.insert(
                role,
                FontSpec {
                    family: family.trim().to_string(),
                    fallback: None,
                    purpose: Some(purpose.trim().to_string()),
                },
            );
        }
    }

    let character = extract_character(&text, section);

    let subs = split_subsections(&section.lines);
    let mut hierarchy = Vec::new();
    if let Some(hier_sub) = subs.iter().find(|s| {
        s.name
            .as_deref()
            .is_some_and(|n| n.to_lowercase().contains("hierarch"))
    }) {
        let bullets = collect_bullets(&hier_sub.lines);
        hierarchy = bullets.iter().filter_map(|b| parse_type_bullet(b)).collect();
    }

    Some(Typography {
        subtitle: section.subtitle.clone(),
        fonts,
        character,
        hierarchy,
        rules: extract_named_rules(&section.lines),
    })
}

/// `/\*\*([\w\s/]+?)Font:\*\*\s*([^\n(]+?)(?:\s*\(with\s+([^)]+)\))?\s*$/gm`
fn scan_font_line_a(text: &str) -> Vec<(String, String, Option<String>)> {
    let mut out = Vec::new();
    for line in split_lines(text) {
        let rest = match line.find("**") {
            Some(i) => &line[i..],
            None => continue,
        };
        let rest = match rest.strip_prefix("**") {
            Some(r) => r,
            None => continue,
        };
        let font_idx = match rest.find("Font:**") {
            Some(i) => i,
            None => continue,
        };
        let role = &rest[..font_idx];
        if !role.chars().all(|c| c.is_alphanumeric() || c.is_whitespace() || c == '_' || c == '/') {
            continue;
        }
        let after = rest[font_idx + "Font:**".len()..].trim_start();
        // value up to end of line, optional "(with ...)" suffix
        if let Some(paren_idx) = after.rfind('(') {
            let before_paren = after[..paren_idx].trim_end();
            let paren_content = &after[paren_idx..];
            if let Some(inner) = paren_content.strip_prefix("(with ") {
                if let Some(inner) = inner.strip_suffix(')') {
                    out.push((role.to_string(), before_paren.to_string(), Some(inner.to_string())));
                    continue;
                }
            }
        }
        if !after.trim().is_empty() {
            out.push((role.to_string(), after.trim().to_string(), None));
        }
    }
    out
}

/// `/\*\*([\w\s&/]+?)\s*\(([^)]+)\):\*\*\s*(.+)/g`
fn scan_font_line_b(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find("**") {
        let start = search_from + rel;
        let rest = &text[start + 2..];
        let open = match rest.find('(') {
            Some(i) => i,
            None => break,
        };
        let head = rest[..open].trim_end();
        if head.is_empty() || !head.chars().all(|c| c.is_alphanumeric() || c.is_whitespace() || c == '&' || c == '/' || c == '_') {
            search_from = start + 2;
            continue;
        }
        let after_open = &rest[open + 1..];
        let close = match after_open.find(')') {
            Some(i) => i,
            None => {
                search_from = start + 2;
                continue;
            }
        };
        let inner = &after_open[..close];
        let after_close = &after_open[close + 1..];
        let after_close = match after_close.strip_prefix(":**") {
            Some(a) => a,
            None => {
                search_from = start + 2;
                continue;
            }
        };
        let purpose = after_close.trim_start();
        if purpose.is_empty() {
            search_from = start + 2;
            continue;
        }
        // description is `.+` (no newline) — cut at first '\n'
        let purpose_line = purpose.split('\n').next().unwrap_or(purpose);
        out.push((head.to_string(), inner.to_string(), purpose_line.to_string()));
        search_from = start + 2 + open + 1 + close + 1;
    }
    out
}

fn extract_character(text: &str, section: &Section) -> Option<String> {
    if let Some(c) = extract_character_labeled(text) {
        return Some(c);
    }
    let paragraphs: Vec<String> = collect_paragraphs(&section.lines)
        .into_iter()
        .filter(|p| !looks_like_font_line(p))
        .collect();
    paragraphs.into_iter().next()
}

/// `/\*\*Character:\*\*\s*([^\n]+(?:\n[^\n]+)*?)(?=\n\n|\n###|\n##|$)/`
fn extract_character_labeled(text: &str) -> Option<String> {
    let marker = "**Character:**";
    let idx = text.find(marker)?;
    let rest = &text[idx + marker.len()..];
    let rest = rest.strip_prefix(char::is_whitespace).map(|r| {
        // consume all leading whitespace except we must keep at least the
        // first non-blank line; JS `\s*` before the capture consumes runs of
        // whitespace including newlines.
        rest.trim_start()
    }).unwrap_or(rest);
    let end = find_first_of(rest, &["\n\n", "\n###", "\n##"]).unwrap_or(rest.len());
    let captured = &rest[..end];
    if captured.trim().is_empty() {
        None
    } else {
        Some(captured.replace('\n', " ").trim().to_string())
    }
}

fn looks_like_font_line(p: &str) -> bool {
    // `/^\*\*[\w\s/&]+Font/i` or `/^\*\*[\w\s/&]+\([^)]+\)/`
    if let Some(rest) = p.strip_prefix("**") {
        let head_end = rest.find(|c: char| !(c.is_alphanumeric() || c.is_whitespace() || c == '/' || c == '&' || c == '_')).unwrap_or(rest.len());
        let head = &rest[..head_end];
        if !head.is_empty() {
            let after = &rest[head_end..];
            if after.to_lowercase().starts_with("font") {
                return true;
            }
            if after.starts_with('(') && after.contains(')') {
                return true;
            }
        }
    }
    false
}

fn normalize_font_role(raw: &str) -> Option<String> {
    let tokens: Vec<&str> = raw
        .split(|c: char| c == '-' || c == '/' || c == '&' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .collect();
    let priority = ["display", "headline", "body", "ui", "label", "mono"];
    for p in priority {
        if tokens.contains(&p) {
            return Some(match p {
                "headline" => "display".to_string(),
                "ui" => "body".to_string(),
                other => other.to_string(),
            });
        }
    }
    None
}

/// `^\*\*(.+?)\*\*\s*\(([^)]+)\):\s*(.*)$`
fn parse_type_bullet(bullet: &str) -> Option<TypeBullet> {
    let (name, after) = match_leading_bold(bullet)?;
    let after = after.trim_start();
    let open = after.strip_prefix('(')?;
    let close = open.find(')')?;
    let inner = &open[..close];
    let after_close = &open[close + 1..];
    let after_close = after_close.strip_prefix(':')?;
    let purpose = after_close.trim_start();
    let specs: Vec<String> = inner.split(',').map(|s| s.trim().to_string()).collect();
    Some(TypeBullet {
        name: name.trim().to_string(),
        specs,
        purpose: {
            let p = strip_bold(purpose).trim().to_string();
            if p.is_empty() {
                None
            } else {
                Some(p)
            }
        },
    })
}

/// `extractElevation`
fn extract_elevation(section: Option<&Section>) -> Option<Elevation> {
    let section = section?;
    let subs = split_subsections(&section.lines);

    let description = {
        let d = collect_paragraphs(&subs[0].lines).join(" ");
        if d.is_empty() {
            None
        } else {
            Some(d)
        }
    };

    let mut shadows: Vec<Shadow> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut dedupe = |entry: Shadow, shadows: &mut Vec<Shadow>| {
        let key = format!("{}::{}", entry.name.clone().unwrap_or_default(), entry.value);
        if seen.insert(key) {
            shadows.push(entry);
        }
    };

    for b in collect_bullets(&section.lines) {
        if let Some(parsed) = parse_shadow_bullet(&b) {
            dedupe(parsed, &mut shadows);
        }
    }
    for p in collect_paragraphs(&section.lines) {
        for inline in extract_inline_shadows(&p) {
            dedupe(inline, &mut shadows);
        }
    }
    for b in collect_bullets(&section.lines) {
        for inline in extract_inline_shadows(&b) {
            dedupe(inline, &mut shadows);
        }
    }

    Some(Elevation {
        subtitle: section.subtitle.clone(),
        description,
        shadows,
        rules: extract_named_rules(&section.lines),
    })
}

/// `/box-shadow\s*:\s*([^`;\n]+)/gi`
fn extract_inline_shadows(text: &str) -> Vec<Shadow> {
    let mut out = Vec::new();
    let lower = text.to_lowercase();
    let mut search_from = 0usize;
    while let Some(rel) = lower[search_from..].find("box-shadow") {
        let start = search_from + rel;
        let after_kw = &text[start + "box-shadow".len()..];
        let after_kw_trim = after_kw.trim_start();
        let consumed_ws = after_kw.len() - after_kw_trim.len();
        let after_colon = match after_kw_trim.strip_prefix(':') {
            Some(a) => a,
            None => {
                search_from = start + 1;
                continue;
            }
        };
        let value_region = after_colon.trim_start();
        let end = value_region
            .find(['`', ';', '\n'])
            .unwrap_or(value_region.len());
        let raw_value = &value_region[..end];
        let value = raw_value.trim_end_matches(['`', '.', ')']).trim().to_string();
        let match_end_byte = start + "box-shadow".len() + consumed_ws + 1 + (after_colon.len() - value_region.len()) + end;
        if !value.is_empty() {
            let before = &text[..start];
            let name = derive_shadow_name(before);
            out.push(Shadow {
                name,
                value,
                purpose: None,
            });
        }
        search_from = match_end_byte.max(start + 1);
    }
    out
}

/// `\b([A-Za-z][A-Za-z\- ]{2,40})\s+shadow\b[^A-Za-z0-9]*$` applied to `before`.
fn derive_shadow_name(before: &str) -> Option<String> {
    let lower = before.to_lowercase();
    // Find the last occurrence of " shadow" (word-bounded) near the end,
    // allowing trailing non-alnum chars after it.
    let trimmed_end = lower.trim_end_matches(|c: char| !c.is_alphanumeric());
    let trailer_len = lower.len() - trimmed_end.len();
    if !trimmed_end.ends_with("shadow") {
        return None;
    }
    let shadow_start = trimmed_end.len() - "shadow".len();
    if shadow_start == 0 || !before.as_bytes()[shadow_start - 1].is_ascii_whitespace() {
        return None;
    }
    let before_shadow = &trimmed_end[..shadow_start - 1];
    // capture [A-Za-z][A-Za-z\- ]{2,40} immediately preceding, and it must be
    // preceded by a non-alpha char (word boundary) or start of string.
    let bytes: Vec<char> = before_shadow.chars().collect();
    let mut start = bytes.len();
    while start > 0 {
        let c = bytes[start - 1];
        if c.is_ascii_alphabetic() || c == '-' || c == ' ' {
            start -= 1;
        } else {
            break;
        }
    }
    let candidate: String = bytes[start..].iter().collect();
    let candidate = candidate.trim();
    if candidate.len() < 3 || candidate.len() > 41 {
        return None;
    }
    if !candidate.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let _ = trailer_len;

    let stripped = strip_shadow_name_prefix(candidate);
    if stripped.is_empty() {
        return None;
    }
    let mut chars = stripped.chars();
    let first = chars.next().unwrap().to_uppercase().to_string();
    Some(format!("{}{}{} shadow", first, chars.as_str(), ""))
}

fn strip_shadow_name_prefix(s: &str) -> String {
    let lower = s.to_lowercase();
    let verbs = ["use", "using", "apply", "applying", "is", "are", "looks like", "look like"];
    let mut rest = s;
    for v in verbs {
        if lower.starts_with(v) {
            let boundary_idx = v.len();
            if s.as_bytes().get(boundary_idx).is_some_and(|b| b.is_ascii_whitespace()) {
                rest = s[boundary_idx..].trim_start();
                break;
            }
        }
    }
    let lower2 = rest.to_lowercase();
    for a in ["a ", "an ", "the "] {
        if lower2.starts_with(a) {
            rest = rest[a.len()..].trim_start();
            break;
        }
    }
    rest.trim().to_string()
}

/// `^\*\*(.+?)\*\*\s*\(`?([^`]+?)`?\):\s*(.*)$`
fn parse_shadow_bullet(bullet: &str) -> Option<Shadow> {
    let (name, after) = match_leading_bold(bullet)?;
    let after = after.trim_start();
    let after = after.strip_prefix('(')?;
    let after = after.strip_prefix('`').unwrap_or(after);
    // find "):" possibly preceded by a backtick
    let (inner_end, colon_after) = find_close_paren_colon(after)?;
    let mut inner = &after[..inner_end];
    inner = inner.strip_suffix('`').unwrap_or(inner);
    let purpose = colon_after.trim_start();

    let raw_value = strip_prefix_case_insensitive(inner, "box-shadow:").trim().to_string();
    let looks_like_shadow = looks_like_shadow_value(&raw_value);
    if !looks_like_shadow {
        return None;
    }
    Some(Shadow {
        name: Some(strip_bold(&name).trim().to_string()),
        value: raw_value,
        purpose: {
            let p = strip_bold(purpose).trim().to_string();
            if p.is_empty() {
                None
            } else {
                Some(p)
            }
        },
    })
}

fn find_close_paren_colon(s: &str) -> Option<(usize, &str)> {
    let idx = s.find("):")?;
    Some((idx, &s[idx + 2..]))
}

fn strip_prefix_case_insensitive<'a>(s: &'a str, prefix: &str) -> &'a str {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        &s[prefix.len()..]
    } else {
        s
    }
}

/// `/box-shadow|rgba?\(|\bpx\b|\brem\b|^-?\d+\s/i` AND `/\d/`
fn looks_like_shadow_value(raw_value: &str) -> bool {
    if !raw_value.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    let lower = raw_value.to_lowercase();
    if lower.contains("box-shadow") {
        return true;
    }
    if lower.contains("rgba(") || lower.contains("rgb(") {
        return true;
    }
    if word_boundary_contains(&lower, "px") {
        return true;
    }
    if word_boundary_contains(&lower, "rem") {
        return true;
    }
    let trimmed = raw_value.trim_start();
    let after_sign = trimmed.strip_prefix('-').unwrap_or(trimmed);
    let digit_end = after_sign.find(|c: char| !c.is_ascii_digit()).unwrap_or(after_sign.len());
    if digit_end > 0 {
        if let Some(rest) = after_sign.get(digit_end..) {
            if rest.starts_with(char::is_whitespace) {
                return true;
            }
        }
    }
    false
}

/// `extractComponents`
fn extract_components(section: Option<&Section>) -> Option<Components> {
    let section = section?;
    let subs = split_subsections(&section.lines);
    let mut components = Vec::new();

    for sub in &subs[1..] {
        let name = match &sub.name {
            Some(n) => n.clone(),
            None => continue,
        };

        let bullets = collect_bullets(&sub.lines);
        let paragraphs = collect_paragraphs(&sub.lines);

        let mut variants = Vec::new();
        let mut properties: BTreeMap<String, String> = BTreeMap::new();

        for b in &bullets {
            if let Some((key, value)) = match_key_value_bullet(b) {
                let first_token = key.split(|c: char| c.is_whitespace() || c == '/').next().unwrap_or("");
                if is_variant_key(first_token) {
                    variants.push(NamedRule {
                        name: key,
                        body: value,
                    });
                } else {
                    properties.insert(key.to_lowercase(), value);
                }
            }
        }

        let description = {
            let d = paragraphs.join(" ");
            if d.is_empty() {
                None
            } else {
                Some(d)
            }
        };

        components.push(Component {
            name,
            description,
            properties,
            variants,
        });
    }

    Some(Components {
        subtitle: section.subtitle.clone(),
        components,
    })
}

/// `^\*\*(.+?):?\*\*:?\s*(.+)$`
fn match_key_value_bullet(b: &str) -> Option<(String, String)> {
    let rest = b.strip_prefix("**")?;
    let close = rest.find("**")?;
    let mut key = &rest[..close];
    key = key.strip_suffix(':').unwrap_or(key);
    if key.is_empty() {
        return None;
    }
    let after = &rest[close + 2..];
    let after = after.strip_prefix(':').unwrap_or(after);
    let after = after.trim_start();
    if after.is_empty() {
        return None;
    }
    Some((strip_bold(key).trim().to_string(), strip_bold(after).trim().to_string()))
}

fn is_variant_key(first_token: &str) -> bool {
    matches!(
        first_token.to_lowercase().as_str(),
        "primary" | "secondary" | "tertiary" | "ghost" | "hover" | "focus" | "active"
            | "disabled" | "default" | "error" | "selected" | "unselected" | "state"
    )
}

/// `extractDosDonts`
fn extract_dos_donts(section: Option<&Section>) -> Option<DosDonts> {
    let section = section?;
    let subs = split_subsections(&section.lines);
    let mut dos: Vec<String> = Vec::new();
    let mut donts: Vec<String> = Vec::new();

    for sub in &subs[1..] {
        let name = match &sub.name {
            Some(n) => n,
            None => continue,
        };
        let sub_name = normalize_apostrophes(name);
        let bullets: Vec<String> = collect_bullets(&sub.lines)
            .iter()
            .map(|b| strip_bold(b).trim().to_string())
            .collect();
        if is_do_heading(&sub_name) {
            dos.extend(bullets);
        } else if is_dont_heading(&sub_name) {
            donts.extend(bullets);
        }
    }

    for b in collect_bullets(&section.lines) {
        let stripped = normalize_apostrophes(strip_bold(&b).trim());
        let lower = stripped.to_lowercase();
        if starts_with_dont(&lower) {
            if !donts.iter().any(|d| normalize_apostrophes(d) == stripped) {
                donts.push(stripped);
            }
        } else if starts_with_do(&lower) {
            if !dos.iter().any(|d| normalize_apostrophes(d) == stripped) {
                dos.push(stripped);
            }
        }
    }

    Some(DosDonts { dos, donts })
}

/// `/^do'?t?:?$/i` or `/^do:?$/i`
fn is_do_heading(s: &str) -> bool {
    let t = s.trim().trim_end_matches(':').to_lowercase();
    t == "do" || t == "do't" || t == "dot"
}

/// `/^don'?t:?$/i`
fn is_dont_heading(s: &str) -> bool {
    let t = s.trim().trim_end_matches(':').to_lowercase();
    t == "don't" || t == "dont"
}

/// `/^don'?t\b/i`
fn starts_with_dont(lower: &str) -> bool {
    starts_with_word(lower, "don't") || starts_with_word(lower, "dont")
}

/// `/^do\b/i`
fn starts_with_do(lower: &str) -> bool {
    starts_with_word(lower, "do")
}

// ---------------------------------------------------------------------
// Coverage assessment
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum SectionCoverage {
    Missing,
    Overview {
        north_star: bool,
        philosophy: bool,
        key_characteristics: usize,
    },
    Colors {
        groups: usize,
        total_colors: usize,
        rules: usize,
    },
    Typography {
        fonts: usize,
        hierarchy_entries: usize,
        character: bool,
        rules: usize,
    },
    Elevation {
        shadows: usize,
        rules: usize,
        description: bool,
    },
    Components {
        count: usize,
        variant_total: usize,
    },
    DosDonts {
        dos: usize,
        donts: usize,
    },
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CoverageReport {
    pub overview: Option<SectionCoverage>,
    pub colors: Option<SectionCoverage>,
    pub typography: Option<SectionCoverage>,
    pub elevation: Option<SectionCoverage>,
    pub components: Option<SectionCoverage>,
    pub dos_donts: Option<SectionCoverage>,
}

/// `assessCoverage`
pub fn assess_coverage(model: &DesignModel) -> CoverageReport {
    let overview = Some(match &model.overview {
        Some(o) => SectionCoverage::Overview {
            north_star: o.creative_north_star.is_some(),
            philosophy: !o.philosophy.is_empty(),
            key_characteristics: o.key_characteristics.len(),
        },
        None => SectionCoverage::Missing,
    });

    let colors = Some(match &model.colors {
        Some(c) => SectionCoverage::Colors {
            groups: c.groups.len(),
            total_colors: c.groups.iter().map(|g| g.colors.len()).sum(),
            rules: c.rules.len(),
        },
        None => SectionCoverage::Missing,
    });

    let typography = Some(match &model.typography {
        Some(t) => SectionCoverage::Typography {
            fonts: t.fonts.len(),
            hierarchy_entries: t.hierarchy.len(),
            character: t.character.is_some(),
            rules: t.rules.len(),
        },
        None => SectionCoverage::Missing,
    });

    let elevation = Some(match &model.elevation {
        Some(e) => SectionCoverage::Elevation {
            shadows: e.shadows.len(),
            rules: e.rules.len(),
            description: e.description.is_some(),
        },
        None => SectionCoverage::Missing,
    });

    let components = Some(match &model.components {
        Some(c) => SectionCoverage::Components {
            count: c.components.len(),
            variant_total: c.components.iter().map(|comp| comp.variants.len()).sum(),
        },
        None => SectionCoverage::Missing,
    });

    let dos_donts = Some(match &model.dos_donts {
        Some(d) => SectionCoverage::DosDonts {
            dos: d.dos.len(),
            donts: d.donts.len(),
        },
        None => SectionCoverage::Missing,
    });

    CoverageReport {
        overview,
        colors,
        typography,
        elevation,
        components,
        dos_donts,
    }
}

// ---------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------

/// `parseDesignMd`
pub fn parse_design_md(md: &str) -> DesignModel {
    let (frontmatter, body) = parse_frontmatter(md);
    let split = split_sections(&body);

    DesignModel {
        schema_version: 2,
        title: split.title,
        frontmatter,
        overview: extract_overview(split.sections.get("Overview")),
        colors: extract_colors(split.sections.get("Colors")),
        typography: extract_typography(split.sections.get("Typography")),
        elevation: extract_elevation(split.sections.get("Elevation")),
        components: extract_components(split.sections.get("Components")),
        dos_donts: extract_dos_donts(split.sections.get("Do's and Don'ts")),
    }
}
