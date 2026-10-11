//! Pure port of `parseDesignMd` from the historical designer engine
//! (`skills/designer/engine/scripts/lib/design-parser.mjs`, Legion history
//! before `ebb349ae`). It turns DESIGN.md text into the JSON model that the
//! live panel reads from `GET /design-system.json` as `parsed`.
//!
//! The port keeps the JS source's regexes, first-match rules, and
//! `null` / empty-string distinctions. Object key order is preserved because
//! `serde_json` is built with `preserve_order`. Patterns that the JS writes
//! with lookahead are reimplemented by hand (`match_character_block`), and
//! JS's ASCII `\b` is written as `(?-u:\b)`.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};

/// Compiles a static pattern once per call site.
macro_rules! re {
    ($pattern:expr) => {{
        static CELL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        CELL.get_or_init(|| regex::Regex::new($pattern).expect("static design-parser pattern"))
    }};
}

const CANONICAL_SECTIONS: [&str; 6] = [
    "Overview",
    "Colors",
    "Typography",
    "Elevation",
    "Components",
    "Do's and Don'ts",
];

/// Parses a DESIGN.md document. Mirrors the JS `parseDesignMd` output key for
/// key, including `null` for absent sections.
pub fn parse_design_md(md: &str) -> Value {
    let (frontmatter, body) = parse_frontmatter(md);
    let (title, sections) = split_sections(&body);
    json!({
        "schemaVersion": 2,
        "title": title,
        "frontmatter": frontmatter,
        "overview": extract_overview(sections.get("Overview")),
        "colors": extract_colors(sections.get("Colors")),
        "typography": extract_typography(sections.get("Typography")),
        "elevation": extract_elevation(sections.get("Elevation")),
        "components": extract_components(sections.get("Components")),
        "dosDonts": extract_dos_donts(sections.get("Do's and Don'ts")),
    })
}

// ---------- Shared text helpers ----------

/// JS `split(/\r?\n/)`: splits on `\n` and drops one trailing `\r` per line.
fn split_lines(text: &str) -> Vec<&str> {
    text.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect()
}

fn normalize_apostrophes(text: &str) -> String {
    text.replace('\u{2018}', "'").replace('\u{2019}', "'")
}

fn join_lines(lines: &[String]) -> String {
    lines.join("\n")
}

fn nonempty_or_null(text: String) -> Value {
    if text.is_empty() {
        Value::Null
    } else {
        Value::String(text)
    }
}

fn strip_bold(text: &str) -> String {
    re!(r"\*\*(.+?)\*\*").replace_all(text, "${1}").into_owned()
}

/// Removes straight and curly double quotes (JS `/["“”]/g`).
fn strip_quote_chars(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '"' | '\u{201C}' | '\u{201D}'))
        .collect()
}

fn is_quoted(text: &str) -> bool {
    (text.starts_with('"') && text.ends_with('"'))
        || (text.starts_with('\'') && text.ends_with('\''))
}

/// JS `slice(1, -1)` for a value already known to be quoted.
fn strip_quotes(text: &str) -> &str {
    if text.len() >= 2 {
        &text[1..text.len() - 1]
    } else {
        ""
    }
}

/// Mirrors JS `Number(...)`: integer-valued numbers serialize as integers.
fn js_number(n: f64) -> Value {
    if n.is_finite() && n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0 {
        return Value::from(n as i64);
    }
    serde_json::Number::from_f64(n).map_or(Value::Null, Value::Number)
}

// ---------- Frontmatter (Stitch YAML subset) ----------

fn parse_frontmatter(md: &str) -> (Option<Value>, String) {
    let lines = split_lines(md);
    if lines.first().map(|line| line.trim()) != Some("---") {
        return (None, md.to_string());
    }
    let Some(end) = (1..lines.len()).find(|&i| lines[i].trim() == "---") else {
        return (None, md.to_string());
    };
    let yaml = lines[1..end].join("\n");
    let body = lines[end + 1..].join("\n");
    (Some(parse_yaml_subset(&yaml)), body)
}

/// Object storage for the YAML reader. Objects live in an arena so the
/// indentation stack can hold ids without borrowing the tree.
#[derive(Clone)]
enum Slot {
    Scalar(Value),
    Object(usize),
}

struct YamlTree {
    objects: Vec<Vec<(String, Slot)>>,
}

impl YamlTree {
    fn new_object(&mut self) -> usize {
        self.objects.push(Vec::new());
        self.objects.len() - 1
    }

    /// `parent[key] = value`: replaces in place, keeping the first position.
    fn put(&mut self, object: usize, key: String, slot: Slot) {
        let entries = &mut self.objects[object];
        match entries.iter_mut().find(|entry| entry.0 == key) {
            Some(entry) => entry.1 = slot,
            None => entries.push((key, slot)),
        }
    }

    fn to_value(&self, object: usize) -> Value {
        let mut map = Map::new();
        for (key, slot) in &self.objects[object] {
            let value = match slot {
                Slot::Scalar(value) => value.clone(),
                Slot::Object(child) => self.to_value(*child),
            };
            map.insert(key.clone(), value);
        }
        Value::Object(map)
    }
}

/// Minimal YAML reader for the Stitch frontmatter subset: scalar maps with
/// nested objects, indent-based. Mirrors `parseYamlSubset`.
fn parse_yaml_subset(yaml: &str) -> Value {
    let mut tree = YamlTree {
        objects: vec![Vec::new()],
    };
    // (indent, object id); the root sits at indent -1 and is never popped.
    let mut stack: Vec<(isize, usize)> = vec![(-1, 0)];

    for raw in split_lines(yaml) {
        if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        let content = &raw[indent..];
        let Some(colon) = find_top_level_colon(content) else {
            continue;
        };
        while stack.len() > 1 && stack[stack.len() - 1].0 >= indent as isize {
            stack.pop();
        }
        let key = unquote_yaml_key(content[..colon].trim());
        let rest = strip_inline_yaml_comment(content[colon + 1..].trim());
        let parent = stack.last().map_or(0, |entry| entry.1);
        if rest.is_empty() {
            let child = tree.new_object();
            tree.put(parent, key, Slot::Object(child));
            stack.push((indent as isize, child));
        } else {
            tree.put(parent, key, Slot::Scalar(parse_scalar(rest)));
        }
    }
    tree.to_value(0)
}

fn find_top_level_colon(text: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut prev: Option<char> = None;
    for (index, ch) in text.char_indices() {
        match quote {
            Some(open) => {
                if ch == open && prev != Some('\\') {
                    quote = None;
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                } else if ch == ':' {
                    return Some(index);
                }
            }
        }
        prev = Some(ch);
    }
    None
}

fn unquote_yaml_key(key: &str) -> String {
    if is_quoted(key) {
        strip_quotes(key).to_string()
    } else {
        key.to_string()
    }
}

/// Drops ` # comment` tails. A `#` only starts a comment after whitespace and
/// outside quotes, so unquoted hex values survive.
fn strip_inline_yaml_comment(text: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut prev: Option<char> = None;
    for (index, ch) in text.char_indices() {
        match quote {
            Some(open) => {
                if ch == open && prev != Some('\\') {
                    quote = None;
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                } else if ch == '#' && prev.is_some_and(char::is_whitespace) {
                    return text[..index].trim_end();
                }
            }
        }
        prev = Some(ch);
    }
    text
}

fn parse_scalar(raw: &str) -> Value {
    let text = raw.trim();
    if is_quoted(text) {
        return Value::String(strip_quotes(text).to_string());
    }
    match text {
        "true" => return Value::Bool(true),
        "false" => return Value::Bool(false),
        "null" | "~" => return Value::Null,
        _ => {}
    }
    if is_integer_literal(text) || is_decimal_literal(text) {
        if let Ok(number) = text.parse::<f64>() {
            return js_number(number);
        }
    }
    Value::String(text.to_string())
}

/// JS `/^-?\d+$/`.
fn is_integer_literal(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// JS `/^-?\d*\.\d+$/`.
fn is_decimal_literal(text: &str) -> bool {
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    match unsigned.split_once('.') {
        Some((whole, fraction)) => {
            whole.bytes().all(|b| b.is_ascii_digit())
                && !fraction.is_empty()
                && fraction.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

// ---------- Section splitting ----------

struct Section {
    subtitle: Option<String>,
    lines: Vec<String>,
}

fn split_sections(md: &str) -> (Option<String>, HashMap<&'static str, Section>) {
    let mut title: Option<String> = None;
    let mut sections: HashMap<&'static str, Section> = HashMap::new();
    let mut current: Option<&'static str> = None;

    for raw in split_lines(md) {
        let line = raw.trim_end();
        let title_unset = title.as_deref().is_none_or(str::is_empty);
        if title_unset && line.starts_with("# ") && !line.starts_with("## ") {
            title = Some(line[1..].trim().to_string());
            continue;
        }
        if let Some(caps) = re!(r"^##\s+(?:[0-9]+\.\s*)?([^:\n]+?)(?::\s*(.+))?$").captures(line) {
            let raw_name = normalize_apostrophes(caps[1].trim());
            let subtitle = caps.get(2).map(|m| m.as_str().trim().to_string());
            current = match_canonical_section(&raw_name);
            if let Some(name) = current {
                sections.insert(
                    name,
                    Section {
                        subtitle,
                        lines: Vec::new(),
                    },
                );
            }
            continue;
        }
        if let Some(name) = current {
            if let Some(section) = sections.get_mut(name) {
                section.lines.push(raw.to_string());
            }
        }
    }
    (title, sections)
}

fn match_canonical_section(name: &str) -> Option<&'static str> {
    let normalized = normalize_apostrophes(name).to_lowercase();
    for canonical in CANONICAL_SECTIONS {
        if normalize_apostrophes(canonical).to_lowercase() == normalized {
            return Some(canonical);
        }
    }
    // Keyword-contained match: "Overview & Creative North Star" -> "Overview".
    for canonical in CANONICAL_SECTIONS {
        let key = normalize_apostrophes(canonical).to_lowercase();
        if contains_word(&normalized, &key) {
            return Some(canonical);
        }
    }
    None
}

/// Equivalent of the JS test `/\b<needle>\b/` for a plain needle, with
/// ASCII word characters.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut start = 0;
    while let Some(offset) = haystack[start..].find(needle) {
        let at = start + offset;
        let end = at + needle.len();
        let before_ok = haystack[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word(c));
        let after_ok = haystack[end..].chars().next().is_none_or(|c| !is_word(c));
        if before_ok && after_ok {
            return true;
        }
        let Some(next) = haystack[at..].chars().next() else {
            break;
        };
        start = at + next.len_utf8();
    }
    false
}

// ---------- Subsection splitting ----------

struct Sub {
    name: Option<String>,
    lines: Vec<String>,
}

/// The name of a subsection when it is truthy (JS `sub.name`), else `None`.
fn named(sub: &Sub) -> Option<&str> {
    sub.name.as_deref().filter(|name| !name.is_empty())
}

fn split_subsections(lines: &[String]) -> Vec<Sub> {
    let mut subs = vec![Sub {
        name: None,
        lines: Vec::new(),
    }];
    for raw in lines {
        if let Some(caps) = re!(r"^###\s+(.+?)\s*$").captures(raw) {
            subs.push(Sub {
                name: Some(caps[1].trim().to_string()),
                lines: Vec::new(),
            });
            continue;
        }
        if let Some(current) = subs.last_mut() {
            current.lines.push(raw.clone());
        }
    }
    subs
}

// ---------- Generic helpers ----------

fn flush_paragraph(buf: &mut Vec<String>, out: &mut Vec<String>) {
    if !buf.is_empty() {
        out.push(buf.join(" ").trim().to_string());
        buf.clear();
    }
}

fn collect_paragraphs(lines: &[String]) -> Vec<String> {
    let mut paragraphs = Vec::new();
    let mut buf: Vec<String> = Vec::new();
    for raw in lines {
        let trimmed = raw.trim();
        // Blank lines, horizontal rules, headings and bullets all end a paragraph.
        let breaks = trimmed.is_empty()
            || re!(r"^(?:-{3,}|\*{3,}|_{3,})$").is_match(trimmed)
            || raw.starts_with('#')
            || re!(r"^[-*]\s").is_match(raw);
        if breaks {
            flush_paragraph(&mut buf, &mut paragraphs);
            continue;
        }
        buf.push(trimmed.to_string());
    }
    flush_paragraph(&mut buf, &mut paragraphs);
    paragraphs
}

fn collect_bullets(lines: &[String]) -> Vec<String> {
    let mut bullets = Vec::new();
    let mut current: Option<String> = None;
    for raw in lines {
        if let Some(caps) = re!(r"^\s*[-*]\s+(.+)$").captures(raw) {
            if let Some(previous) = current.take() {
                bullets.push(previous);
            }
            current = Some(caps[1].to_string());
            continue;
        }
        // An indented continuation line extends the open bullet.
        if current.is_some() && re!(r"^\s{2,}\S").is_match(raw) {
            if let Some(open) = current.as_mut() {
                open.push(' ');
                open.push_str(raw.trim());
            }
            continue;
        }
        // A blank line closes the open bullet.
        if raw.trim().is_empty() {
            if let Some(previous) = current.take() {
                bullets.push(previous);
            }
        }
    }
    if let Some(last) = current {
        bullets.push(last);
    }
    bullets
}

// ---------- Named rules ----------

struct Rule {
    name: String,
    body: String,
}

fn rules_value(rules: &[Rule]) -> Value {
    Value::Array(
        rules
            .iter()
            .map(|rule| json!({"name": rule.name, "body": rule.body}))
            .collect(),
    )
}

fn extract_named_rules(lines: &[String]) -> Vec<Rule> {
    let mut rules: Vec<Rule> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Style A (Impeccable): "**The X Rule.** body", possibly spanning lines.
    let joined = lines.join("\n");
    let starts: Vec<(String, usize, usize)> = re!(r"\*\*(The [^*]+?Rule)\.\*\*")
        .captures_iter(&joined)
        .filter_map(|caps| {
            let whole = caps.get(0)?;
            Some((caps[1].to_string(), whole.start(), whole.end()))
        })
        .collect();
    for (index, (raw_name, _, end)) in starts.iter().enumerate() {
        let body_end = starts.get(index + 1).map_or(joined.len(), |next| next.1);
        let raw_body = &joined[*end..body_end];
        let raw_body = re!(r"\n##[^\n]*$").replace(raw_body, "");
        let raw_body = re!(r"\n###[^\n]*$").replace(&raw_body, "");
        let body = raw_body.trim().to_string();
        let name = strip_bold(raw_name).trim().to_string();
        seen.insert(name.to_lowercase());
        rules.push(Rule {
            name,
            body: strip_bold(&body),
        });
    }

    // Style B (Stitch): "### The "X" Rule" with the body until the next heading.
    for index in 0..lines.len() {
        let Some(caps) = re!(r"^###\s+(.+?)\s*$").captures(&lines[index]) else {
            continue;
        };
        let header_name = strip_quote_chars(&strip_bold(&caps[1])).trim().to_string();
        if !re!(r"(?i)^The(?-u:\b).*(?-u:\b)(?:Rule|Fallback|Principle)(?-u:\b)")
            .is_match(&header_name)
        {
            continue;
        }
        if seen.contains(&header_name.to_lowercase()) {
            continue;
        }
        let mut body_lines: Vec<&str> = Vec::new();
        for line in &lines[index + 1..] {
            if re!(r"^##\s|^###\s").is_match(line) {
                break;
            }
            body_lines.push(line.as_str());
        }
        let collapsed = re!(r"\n+")
            .replace_all(&body_lines.join("\n"), " ")
            .into_owned();
        let body = strip_bold(&collapsed).trim().to_string();
        if !body.is_empty() {
            seen.insert(header_name.to_lowercase());
            rules.push(Rule {
                name: header_name,
                body,
            });
        }
    }

    // Style C (Stitch bullet form): "*   **The Layering Principle:** body".
    for bullet in collect_bullets(lines) {
        let Some(caps) = re!(r"^\*\*([^*]+?)\*\*\s*(.+)$").captures(&bullet) else {
            continue;
        };
        let without_tail = re!(r"[.:]\s*$").replace(&caps[1], "").into_owned();
        let name_raw = strip_quote_chars(&without_tail).trim().to_string();
        if !re!(r"(?i)^The(?-u:\b).+(?-u:\b)(?:Rule|Fallback|Principle)$").is_match(&name_raw) {
            continue;
        }
        if seen.contains(&name_raw.to_lowercase()) {
            continue;
        }
        seen.insert(name_raw.to_lowercase());
        rules.push(Rule {
            name: name_raw,
            body: strip_bold(&caps[2]).trim().to_string(),
        });
    }
    rules
}

// ---------- Overview ----------

fn extract_overview(section: Option<&Section>) -> Value {
    let Some(section) = section else {
        return Value::Null;
    };
    let text = join_lines(&section.lines);
    let north_star = re!(r#"\*\*Creative North Star:\s*"([^"]+)"\*\*"#)
        .captures(&text)
        .map(|caps| caps[1].to_string());

    let mut key_characteristics: Vec<String> = Vec::new();
    if let Some(caps) =
        re!(r"\*\*Key Characteristics:\*\*\s*\n([\s\S]+?)(?:\n##|\n###|$)").captures(&text)
    {
        for line in caps[1].split('\n') {
            if let Some(bullet) = re!(r"^\s*[-*]\s+(.+)$").captures(line) {
                key_characteristics.push(strip_bold(bullet[1].trim()));
            }
        }
    }

    // Philosophy: every paragraph that is not the north-star or key-characteristics line.
    let philosophy: Vec<String> = collect_paragraphs(&section.lines)
        .into_iter()
        .filter(|p| {
            !p.starts_with("**Creative North Star") && !p.starts_with("**Key Characteristics")
        })
        .collect();

    json!({
        "subtitle": section.subtitle,
        "creativeNorthStar": north_star,
        "philosophy": philosophy,
        "keyCharacteristics": key_characteristics,
    })
}

// ---------- Colors ----------

struct Color {
    name: Option<String>,
    value: String,
    value_range: Option<Vec<String>>,
    format: &'static str,
    description: Option<String>,
}

impl Color {
    fn to_value(&self) -> Value {
        json!({
            "name": self.name,
            "value": self.value,
            "valueRange": self.value_range,
            "format": self.format,
            "description": self.description,
        })
    }
}

struct Group {
    role: String,
    colors: Vec<Color>,
}

fn group_value(group: &Group) -> Value {
    let colors: Vec<Value> = group.colors.iter().map(Color::to_value).collect();
    json!({"role": group.role, "colors": colors})
}

fn is_role_color(color: &Color) -> bool {
    color.name.as_deref().is_some_and(|name| {
        !name.is_empty()
            && re!(r"(?i)^(?:primary|secondary|tertiary|neutral|accent)(?-u:\b)").is_match(name)
    })
}

fn extract_colors(section: Option<&Section>) -> Value {
    let Some(section) = section else {
        return Value::Null;
    };
    let subs = split_subsections(&section.lines);
    let description = subs.first().map_or(String::new(), |sub| {
        collect_paragraphs(&sub.lines).join(" ")
    });

    let mut groups: Vec<Group> = Vec::new();
    for sub in subs.iter().skip(1) {
        let Some(name) = named(sub) else {
            continue;
        };
        if re!(r"(?i)Named Rules?").is_match(name) || re!(r"(?i)^The\s").is_match(name) {
            continue;
        }
        let parsed: Vec<Color> = collect_bullets(&sub.lines)
            .iter()
            .filter_map(|bullet| parse_color_bullet(bullet))
            .collect();
        if parsed.is_empty() {
            continue;
        }
        // When every bullet opens with a role keyword, each bullet becomes its own group.
        if parsed.iter().all(is_role_color) {
            for color in parsed {
                let role = color.name.clone().unwrap_or_default();
                groups.push(Group {
                    role,
                    colors: vec![color],
                });
            }
        } else {
            groups.push(Group {
                role: name.to_string(),
                colors: parsed,
            });
        }
    }

    // Fallback when there are no subsections: scan the section as one flat bullet list.
    if groups.is_empty() {
        let flat: Vec<Color> = collect_bullets(&section.lines)
            .iter()
            .filter_map(|bullet| parse_color_bullet(bullet))
            .collect();
        for color in flat {
            if is_role_color(&color) {
                let role = color.name.clone().unwrap_or_default();
                groups.push(Group {
                    role,
                    colors: vec![color],
                });
            } else {
                let palette = groups.iter().position(|group| group.role == "Palette");
                match palette {
                    Some(index) => groups[index].colors.push(color),
                    None => groups.push(Group {
                        role: "Palette".to_string(),
                        colors: vec![color],
                    }),
                }
            }
        }
    }

    let group_values: Vec<Value> = groups.iter().map(group_value).collect();
    json!({
        "subtitle": section.subtitle,
        "description": nonempty_or_null(description),
        "groups": group_values,
        "rules": rules_value(&extract_named_rules(&section.lines)),
    })
}

fn parse_color_bullet(bullet: &str) -> Option<Color> {
    let text = bullet.trim();

    // Case 1 (Impeccable): **Name** (value, maybe nested parens): description
    if let Some(bold) = re!(r"^\*\*(.+?)\*\*\s*(.*)$").captures(text) {
        let rest = &bold[2];
        if rest.starts_with('(') {
            if let Some(value) = extract_paren_group(rest) {
                let after = rest[value.len() + 2..].trim_start();
                if let Some(description) = after.strip_prefix(':') {
                    return Some(build_color(Some(&bold[1]), value, description.trim()));
                }
            }
        }
    }

    // Case 2 (Stitch): **Name (values):** description
    if let Some(stitch) = re!(r"^\*\*([^*]+?)\s*\(([^)]+)\):\*\*\s*(.*)$").captures(text) {
        return Some(build_color(Some(stitch[1].trim()), &stitch[2], &stitch[3]));
    }

    // Case 3: no bold label, only color values in the text.
    let values = collect_color_values(text);
    if !values.is_empty() {
        return Some(build_color(None, &values.join(" to "), text));
    }
    None
}

/// Returns the text inside a leading balanced `( ... )` group.
fn extract_paren_group(text: &str) -> Option<&str> {
    if !text.starts_with('(') {
        return None;
    }
    let mut depth: i32 = 0;
    for (index, ch) in text.char_indices() {
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth -= 1;
            if depth == 0 {
                return Some(&text[1..index]);
            }
        }
    }
    None
}

fn build_color(name: Option<&str>, raw_value: &str, description: &str) -> Color {
    let values = collect_color_values(raw_value);
    let primary = values
        .first()
        .cloned()
        .unwrap_or_else(|| raw_value.trim().to_string());
    let format = detect_format(&primary);
    let description = strip_bold(description).trim().to_string();
    Color {
        name: name
            .filter(|label| !label.is_empty())
            .map(|label| strip_bold(label).trim().to_string()),
        value: primary,
        value_range: if values.len() > 1 { Some(values) } else { None },
        format,
        description: if description.is_empty() {
            None
        } else {
            Some(description)
        },
    }
}

/// Hex values first, then oklch values, each in text order (JS `collectColorValues`).
fn collect_color_values(text: &str) -> Vec<String> {
    let mut out: Vec<String> = re!(r"#[0-9a-fA-F]{3,8}(?-u:\b)")
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect();
    out.extend(
        re!(r"(?i)oklch\([^)]+\)")
            .find_iter(text)
            .map(|m| m.as_str().to_string()),
    );
    out
}

fn detect_format(value: &str) -> &'static str {
    if value.is_empty() {
        "unknown"
    } else if value.starts_with('#') {
        "hex"
    } else if value.to_ascii_lowercase().starts_with("oklch") {
        "oklch"
    } else if value.to_ascii_lowercase().starts_with("rgb") {
        "rgb"
    } else {
        "unknown"
    }
}

// ---------- Typography ----------

/// Maps a raw font role onto the canonical roles the panel uses.
fn normalize_font_role(raw: &str) -> Option<&'static str> {
    let tokens: Vec<&str> = re!(r"[-/&\s]+")
        .split(raw)
        .filter(|token| !token.is_empty())
        .collect();
    for priority in ["display", "headline", "body", "ui", "label", "mono"] {
        if tokens.contains(&priority) {
            return Some(match priority {
                "headline" => "display",
                "ui" => "body",
                other => other,
            });
        }
    }
    None
}

fn extract_typography(section: Option<&Section>) -> Value {
    let Some(section) = section else {
        return Value::Null;
    };
    let text = join_lines(&section.lines);

    let mut fonts: Map<String, Value> = Map::new();
    // Pattern A: **Display Font:** Family (with fallback)
    for caps in
        re!(r"(?m)\*\*([A-Za-z0-9_\s/]+?)Font:\*\*\s*([^\n(]+?)(?:\s*\(with\s+([^)]+)\))?\s*$")
            .captures_iter(&text)
    {
        let lowered = caps[1].trim().to_lowercase();
        let raw_role = re!(r"\s+").replace_all(&lowered, "-").into_owned();
        let role = normalize_font_role(&raw_role).unwrap_or("display");
        let fallback = caps.get(3).map(|m| m.as_str().trim().to_string());
        fonts.insert(
            role.to_string(),
            json!({"family": caps[2].trim(), "fallback": fallback}),
        );
    }

    // Pattern B (Stitch): *   **Display & Headlines (Noto Serif):** description
    if fonts.is_empty() {
        for caps in re!(r"\*\*([A-Za-z0-9_\s&/]+?)\s*\(([^)]+)\):\*\*\s*(.+)").captures_iter(&text)
        {
            let lowered = caps[1].trim().to_lowercase();
            let dashed = re!(r"\s*&\s*").replace_all(&lowered, "-").into_owned();
            let raw_role = re!(r"\s+").replace_all(&dashed, "-").into_owned();
            let role =
                normalize_font_role(&raw_role).map_or_else(|| raw_role.clone(), str::to_string);
            fonts.insert(
                role,
                json!({
                    "family": caps[2].trim(),
                    "fallback": Value::Null,
                    "purpose": caps[3].trim(),
                }),
            );
        }
    }

    // Character: the **Character:** block, else the first free paragraph.
    let mut character = match_character_block(&text);
    if character.as_deref().is_none_or(str::is_empty) {
        let first = collect_paragraphs(&section.lines).into_iter().find(|p| {
            !re!(r"(?i)^\*\*[A-Za-z0-9_\s/&]+Font").is_match(p)
                && !re!(r"^\*\*[A-Za-z0-9_\s/&]+\([^)]+\)").is_match(p)
        });
        if first.is_some() {
            character = first;
        }
    }

    // Hierarchy bullets under the ### Hierarchy subsection.
    let subs = split_subsections(&section.lines);
    let hierarchy: Vec<Value> = subs
        .iter()
        .find(|sub| named(sub).is_some_and(|name| re!(r"(?i)hierarch").is_match(name)))
        .map(|sub| {
            collect_bullets(&sub.lines)
                .iter()
                .filter_map(|bullet| parse_type_bullet(bullet))
                .collect::<Vec<Value>>()
        })
        .unwrap_or_default();

    json!({
        "subtitle": section.subtitle,
        "fonts": fonts,
        "character": character,
        "hierarchy": hierarchy,
        "rules": rules_value(&extract_named_rules(&section.lines)),
    })
}

/// Finds the first `**Character:**` block (JS lookahead
/// `(?=\n\n|\n###|\n##|$)`), which spans consecutive non-empty lines.
fn match_character_block(text: &str) -> Option<String> {
    const MARKER: &str = "**Character:**";
    let mut from = 0;
    while let Some(offset) = text[from..].find(MARKER) {
        let after_marker = from + offset + MARKER.len();
        let rest = &text[after_marker..];
        let start = after_marker + (rest.len() - rest.trim_start().len());
        if let Some(block) = character_block_from(text, start) {
            return Some(block);
        }
        from += offset + 1;
    }
    None
}

fn character_block_from(text: &str, start: usize) -> Option<String> {
    if start >= text.len() {
        return None;
    }
    let mut end = text[start..]
        .find('\n')
        .map_or(text.len(), |offset| start + offset);
    loop {
        let rest = &text[end..];
        if rest.is_empty() || rest.starts_with("\n\n") || rest.starts_with("\n##") {
            return Some(text[start..end].replace('\n', " ").trim().to_string());
        }
        // Extend by one more line: a newline followed by at least one non-newline char.
        let after = rest.strip_prefix('\n')?;
        if after.is_empty() || after.starts_with('\n') {
            return None;
        }
        end = after
            .find('\n')
            .map_or(text.len(), |offset| end + 1 + offset);
    }
}

fn parse_type_bullet(bullet: &str) -> Option<Value> {
    let caps = re!(r"^\*\*(.+?)\*\*\s*\(([^)]+)\):\s*(.*)$").captures(bullet)?;
    let name = caps[1].trim().to_string();
    let specs: Vec<String> = caps[2]
        .split(',')
        .map(|spec| spec.trim().to_string())
        .collect();
    let purpose = nonempty_or_null(strip_bold(&caps[3]).trim().to_string());
    Some(json!({"name": name, "specs": specs, "purpose": purpose}))
}

// ---------- Elevation ----------

struct Shadow {
    name: Option<String>,
    value: String,
    purpose: Option<String>,
}

fn shadow_value(shadow: &Shadow) -> Value {
    json!({"name": shadow.name, "value": shadow.value, "purpose": shadow.purpose})
}

fn push_shadow(shadows: &mut Vec<Shadow>, seen: &mut HashSet<String>, shadow: Shadow) {
    let key = format!("{}::{}", shadow.name.as_deref().unwrap_or(""), shadow.value);
    if seen.insert(key) {
        shadows.push(shadow);
    }
}

fn extract_elevation(section: Option<&Section>) -> Value {
    let Some(section) = section else {
        return Value::Null;
    };
    let subs = split_subsections(&section.lines);
    let description = subs.first().map_or(String::new(), |sub| {
        collect_paragraphs(&sub.lines).join(" ")
    });

    let mut shadows: Vec<Shadow> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for bullet in collect_bullets(&section.lines) {
        if let Some(shadow) = parse_shadow_bullet(&bullet) {
            push_shadow(&mut shadows, &mut seen, shadow);
        }
    }
    // Fallback: shadows written inline in prose, then inside bullets.
    for paragraph in collect_paragraphs(&section.lines) {
        for shadow in extract_inline_shadows(&paragraph) {
            push_shadow(&mut shadows, &mut seen, shadow);
        }
    }
    for bullet in collect_bullets(&section.lines) {
        for shadow in extract_inline_shadows(&bullet) {
            push_shadow(&mut shadows, &mut seen, shadow);
        }
    }

    let shadow_values: Vec<Value> = shadows.iter().map(shadow_value).collect();
    json!({
        "subtitle": section.subtitle,
        "description": nonempty_or_null(description),
        "shadows": shadow_values,
        "rules": rules_value(&extract_named_rules(&section.lines)),
    })
}

fn extract_inline_shadows(text: &str) -> Vec<Shadow> {
    let mut out = Vec::new();
    for caps in re!(r"(?i)box-shadow\s*:\s*([^`;\n]+)").captures_iter(text) {
        let Some(whole) = caps.get(0) else {
            continue;
        };
        let trimmed = re!(r"[`.)]+$").replace(&caps[1], "").into_owned();
        let value = trimmed.trim().to_string();
        if value.is_empty() {
            continue;
        }
        let before = &text[..whole.start()];
        out.push(Shadow {
            name: shadow_name_before(before),
            value,
            purpose: None,
        });
    }
    out
}

/// The noun phrase immediately before "shadow", e.g. "extra-diffused shadow".
fn shadow_name_before(before: &str) -> Option<String> {
    let caps = re!(r"(?i)(?-u:\b)([A-Za-z][A-Za-z\- ]{2,40})\s+shadow(?-u:\b)[^A-Za-z0-9]*$")
        .captures(before)?;
    let without_verb = re!(r"(?i)^(?:use|using|apply|applying|is|are|looks? like)\s+")
        .replace(&caps[1], "")
        .into_owned();
    let stripped = re!(r"(?i)^(?:a|an|the)\s+")
        .replace(&without_verb, "")
        .trim()
        .to_string();
    if stripped.is_empty() {
        return None;
    }
    let mut chars = stripped.chars();
    let head = chars
        .next()
        .map(|c| c.to_uppercase().collect::<String>())
        .unwrap_or_default();
    Some(format!("{}{} shadow", head, chars.as_str()))
}

fn parse_shadow_bullet(bullet: &str) -> Option<Shadow> {
    // - **Name** (`box-shadow: value`): purpose   or   - **Name** (`value`): purpose
    let caps = re!(r"^\*\*(.+?)\*\*\s*\(`?([^`]+?)`?\):\s*(.*)$").captures(bullet)?;
    let raw_value = re!(r"(?i)^box-shadow:\s*")
        .replace(&caps[2], "")
        .trim()
        .to_string();
    // Only accept values that look like a shadow, which filters out "**Rule Name:**" bullets.
    let looks_like_shadow =
        re!(r"(?i)box-shadow|rgba?\(|(?-u:\b)px(?-u:\b)|(?-u:\b)rem(?-u:\b)|^-?[0-9]+\s")
            .is_match(&raw_value)
            && re!(r"[0-9]").is_match(&raw_value);
    if !looks_like_shadow {
        return None;
    }
    let purpose = strip_bold(&caps[3]).trim().to_string();
    Some(Shadow {
        name: Some(strip_bold(&caps[1]).trim().to_string()),
        value: raw_value,
        purpose: if purpose.is_empty() {
            None
        } else {
            Some(purpose)
        },
    })
}

// ---------- Components ----------

fn extract_components(section: Option<&Section>) -> Value {
    let Some(section) = section else {
        return Value::Null;
    };
    let subs = split_subsections(&section.lines);
    let mut components: Vec<Value> = Vec::new();

    for sub in subs.iter().skip(1) {
        let Some(name) = named(sub) else {
            continue;
        };
        let bullets = collect_bullets(&sub.lines);
        let paragraphs = collect_paragraphs(&sub.lines);

        let mut variants: Vec<Value> = Vec::new();
        let mut properties: Map<String, Value> = Map::new();
        for bullet in &bullets {
            // - **Key:** value
            let Some(caps) = re!(r"^\*\*(.+?):?\*\*:?\s*(.+)$").captures(bullet) else {
                continue;
            };
            let key = strip_bold(&caps[1]).trim().to_string();
            let value = strip_bold(&caps[2]).trim().to_string();
            let first_word = key
                .split(|c: char| c.is_whitespace() || c == '/')
                .next()
                .unwrap_or("");
            // Known state words are variants; everything else is a property.
            if re!(r"(?i)^(?:primary|secondary|tertiary|ghost|hover|focus|active|disabled|default|error|selected|unselected|state)$")
                .is_match(first_word)
            {
                variants.push(json!({"name": key, "description": value}));
            } else {
                properties.insert(key.to_lowercase(), Value::String(value));
            }
        }

        components.push(json!({
            "name": name,
            "description": nonempty_or_null(paragraphs.join(" ")),
            "properties": properties,
            "variants": variants,
        }));
    }

    json!({
        "subtitle": section.subtitle,
        "components": components,
    })
}

// ---------- Do's and Don'ts ----------

fn extract_dos_donts(section: Option<&Section>) -> Value {
    let Some(section) = section else {
        return Value::Null;
    };
    let subs = split_subsections(&section.lines);
    let mut dos: Vec<String> = Vec::new();
    let mut donts: Vec<String> = Vec::new();

    for sub in subs.iter().skip(1) {
        let Some(name) = named(sub) else {
            continue;
        };
        let sub_name = normalize_apostrophes(name);
        let bullets: Vec<String> = collect_bullets(&sub.lines)
            .iter()
            .map(|bullet| strip_bold(bullet).trim().to_string())
            .collect();
        // The JS pattern `^do'?t?:?$` also matches "dot" and "do:"; keep that behaviour.
        if re!(r"(?i)^do'?t?:?$").is_match(&sub_name) || re!(r"(?i)^do:?$").is_match(&sub_name) {
            dos.extend(bullets);
        } else if re!(r"(?i)^don'?t:?$").is_match(&sub_name) {
            donts.extend(bullets);
        }
    }

    // Backup: loose bullets outside an H3 wrapper, classified by their prefix.
    for bullet in collect_bullets(&section.lines) {
        let stripped = normalize_apostrophes(strip_bold(&bullet).trim());
        if re!(r"(?i)^don'?t(?-u:\b)").is_match(&stripped) {
            if !donts.iter().any(|d| normalize_apostrophes(d) == stripped) {
                donts.push(stripped);
            }
        } else if re!(r"(?i)^do(?-u:\b)").is_match(&stripped)
            && !dos.iter().any(|d| normalize_apostrophes(d) == stripped)
        {
            dos.push(stripped);
        }
    }

    json!({"dos": dos, "donts": donts})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_document_yields_null_model() {
        assert_eq!(
            parse_design_md(""),
            json!({
                "schemaVersion": 2,
                "title": null,
                "frontmatter": null,
                "overview": null,
                "colors": null,
                "typography": null,
                "elevation": null,
                "components": null,
                "dosDonts": null,
            })
        );
    }

    #[test]
    fn headings_only_yield_empty_sections() {
        let md = "# Brand\n## Overview\n## Colors\n## Typography\n## Elevation\n## Components\n## Do's and Don'ts\n";
        let parsed = parse_design_md(md);
        assert_eq!(parsed["title"], json!("Brand"));
        assert_eq!(
            parsed["overview"],
            json!({"subtitle": null, "creativeNorthStar": null, "philosophy": [], "keyCharacteristics": []})
        );
        assert_eq!(
            parsed["colors"],
            json!({"subtitle": null, "description": null, "groups": [], "rules": []})
        );
        assert_eq!(
            parsed["typography"],
            json!({"subtitle": null, "fonts": {}, "character": null, "hierarchy": [], "rules": []})
        );
        assert_eq!(
            parsed["elevation"],
            json!({"subtitle": null, "description": null, "shadows": [], "rules": []})
        );
        assert_eq!(
            parsed["components"],
            json!({"subtitle": null, "components": []})
        );
        assert_eq!(parsed["dosDonts"], json!({"dos": [], "donts": []}));
    }

    #[test]
    fn unterminated_frontmatter_is_plain_body_text() {
        let parsed = parse_design_md("---\ncolors:\n  a: 1\n");
        assert_eq!(parsed["frontmatter"], Value::Null);
        assert_eq!(parsed["title"], Value::Null);
        assert_eq!(parsed["colors"], Value::Null);
    }

    #[test]
    fn frontmatter_scalars_keep_their_types() {
        let md = "---\ncolors:\n  primary: \"#1a73e8\"\n  surface: '#ffffff'\nrounded:\n  md: 8\ntypography:\n  body:\n    fontFamily: Inter, sans-serif\n    fontSize: 1rem\n    fontWeight: 400\n    lineHeight: 1.5\n---\n# Tokens\n";
        let parsed = parse_design_md(md);
        assert_eq!(parsed["title"], json!("Tokens"));
        assert_eq!(
            parsed["frontmatter"],
            json!({
                "colors": {"primary": "#1a73e8", "surface": "#ffffff"},
                "rounded": {"md": 8},
                "typography": {"body": {
                    "fontFamily": "Inter, sans-serif",
                    "fontSize": "1rem",
                    "fontWeight": 400,
                    "lineHeight": 1.5,
                }},
            })
        );
    }

    #[test]
    fn malformed_table_collapses_into_one_prose_paragraph() {
        let parsed = parse_design_md("## Overview\n| a | b |\n|---|\n");
        assert_eq!(
            parsed["overview"],
            json!({
                "subtitle": null,
                "creativeNorthStar": null,
                "philosophy": ["| a | b | |---|"],
                "keyCharacteristics": [],
            })
        );
    }

    #[test]
    fn representative_document_matches_js_model() {
        let md = "# Acme

## Overview: Brand voice
**Creative North Star: \"Quiet Precision\"**
Calm, exact interfaces.

**Key Characteristics:**
- Restrained palette
- **Tight** rhythm

## Colors
Brand colors.

### Brand
- **Primary (#1a73e8):** Main action color.
- **Secondary (#5f6368):** Supporting text.

### The Single Accent Rule
Accent is rare.

## Elevation
Flat by default.

- **Card** (`box-shadow: 0 1px 2px rgba(0,0,0,0.2)`): Resting surface.

## Do's and Don'ts
### Do
- Use one accent.

### Don't
- Use gradients.
";
        let parsed = parse_design_md(md);
        assert_eq!(parsed["title"], json!("Acme"));
        assert_eq!(parsed["typography"], Value::Null);
        assert_eq!(parsed["components"], Value::Null);
        // The paragraph "Calm, exact interfaces." is dropped: the JS filter removes
        // any paragraph starting with "**Creative North Star", and this one joins it.
        assert_eq!(
            parsed["overview"],
            json!({
                "subtitle": "Brand voice",
                "creativeNorthStar": "Quiet Precision",
                "philosophy": [],
                "keyCharacteristics": ["Restrained palette", "Tight rhythm"],
            })
        );
        assert_eq!(
            parsed["colors"],
            json!({
                "subtitle": null,
                "description": "Brand colors.",
                "groups": [
                    {"role": "Primary", "colors": [{
                        "name": "Primary", "value": "#1a73e8", "valueRange": null,
                        "format": "hex", "description": "Main action color.",
                    }]},
                    {"role": "Secondary", "colors": [{
                        "name": "Secondary", "value": "#5f6368", "valueRange": null,
                        "format": "hex", "description": "Supporting text.",
                    }]},
                ],
                "rules": [{"name": "The Single Accent Rule", "body": "Accent is rare."}],
            })
        );
        // The inline box-shadow is rescanned from the bullet after the structured
        // parse, so the JS model holds a second, truncated entry (value loses its
        // trailing ")"). This is the JS behaviour, kept on purpose.
        assert_eq!(
            parsed["elevation"],
            json!({
                "subtitle": null,
                "description": "Flat by default.",
                "shadows": [
                    {"name": "Card", "value": "0 1px 2px rgba(0,0,0,0.2)", "purpose": "Resting surface."},
                    {"name": null, "value": "0 1px 2px rgba(0,0,0,0.2", "purpose": null},
                ],
                "rules": [],
            })
        );
        assert_eq!(
            parsed["dosDonts"],
            json!({"dos": ["Use one accent."], "donts": ["Use gradients."]})
        );
    }

    #[test]
    fn typography_font_lines_and_character_fallback() {
        let md = "## Typography\n**Display Font:** Inter (with system-ui)\n**Body Font:** Roboto\n\nClean and neutral.\n";
        let parsed = parse_design_md(md);
        assert_eq!(
            parsed["typography"],
            json!({
                "subtitle": null,
                "fonts": {
                    "display": {"family": "Inter", "fallback": "system-ui"},
                    "body": {"family": "Roboto", "fallback": null},
                },
                "character": "Clean and neutral.",
                "hierarchy": [],
                "rules": [],
            })
        );
    }

    #[test]
    fn components_split_variants_from_properties() {
        let md = "## Components\n### Button\nPill-shaped action.\n- **Primary:** Filled blue.\n- **Shape:** Pill\n";
        let parsed = parse_design_md(md);
        assert_eq!(
            parsed["components"],
            json!({
                "subtitle": null,
                "components": [{
                    "name": "Button",
                    "description": "Pill-shaped action.",
                    "properties": {"shape": "Pill"},
                    "variants": [{"name": "Primary", "description": "Filled blue."}],
                }],
            })
        );
    }

    #[test]
    fn color_bullet_variants_parse_to_exact_fields() {
        let impeccable = parse_color_bullet("**Surface** (oklch(0.98 0.01 250)): Page background.")
            .map(|color| color.to_value());
        assert_eq!(
            impeccable,
            Some(json!({
                "name": "Surface",
                "value": "oklch(0.98 0.01 250)",
                "valueRange": null,
                "format": "oklch",
                "description": "Page background.",
            }))
        );
        let range = parse_color_bullet("**Gradient (#111 to #222):** blend.").map(|c| c.to_value());
        assert_eq!(
            range,
            Some(json!({
                "name": "Gradient",
                "value": "#111",
                "valueRange": ["#111", "#222"],
                "format": "hex",
                "description": "blend.",
            }))
        );
    }
}
