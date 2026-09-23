//! Port of `skills/designer/engine/scripts/lib/impeccable-config.mjs`
//! (chunk w2_016).
//!
//! CLI-side reader/writer for the unified `.impeccable` config. Schema
//! (config.json shared / config.local.json gitignored, per-developer):
//! ```json
//! {
//!   "detector": { "ignoreRules": [], "ignoreFiles": [], "ignoreValues": [], "designSystem": { "enabled": true } },
//!   "hook": { "consent": "accepted" | "declined", ... },
//!   "updateCheck": bool
//! }
//! ```
//!
//! Faithfully mirrors the JS: same file layout, same back-compat reading of
//! detector filters from the legacy `hook.*` section, same ignore-value
//! normalization/matching (including CSS color equivalence for
//! `design-system-color`), and the same `.git/info/exclude` marker-block
//! handling for `config.local.json`.

use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub fn get_config_path(root: &Path) -> PathBuf {
    root.join(".impeccable").join("config.json")
}

pub fn get_local_config_path(root: &Path) -> PathBuf {
    root.join(".impeccable").join("config.local.json")
}

fn safe_read_json(file_path: &Path) -> Option<Map<String, Value>> {
    let raw = fs::read_to_string(file_path).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    match value {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn hook_section(raw: Option<&Map<String, Value>>) -> Option<Map<String, Value>> {
    let raw = raw?;
    match raw.get("hook") {
        Some(Value::Object(map)) => Some(map.clone()),
        _ => None,
    }
}

fn detector_section(raw: Option<&Map<String, Value>>) -> Option<Map<String, Value>> {
    let raw = raw?;
    match raw.get("detector") {
        Some(Value::Object(map)) => Some(map.clone()),
        _ => None,
    }
}

const DETECTOR_CONFIG_KEYS: [&str; 4] =
    ["ignoreRules", "ignoreFiles", "ignoreValues", "designSystem"];

/// Rust mirror of the JS "detection config" plain object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionConfig {
    pub ignore_rules: Vec<String>,
    pub ignore_files: Vec<String>,
    pub ignore_values: Vec<IgnoreValueEntry>,
    pub design_system_enabled: bool,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        DetectionConfig {
            ignore_rules: Vec::new(),
            ignore_files: Vec::new(),
            ignore_values: Vec::new(),
            design_system_enabled: true,
        }
    }
}

/// Raw variant used by `readRawDetectionConfig` (no `designSystem` field).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawDetectionConfig {
    pub ignore_rules: Vec<String>,
    pub ignore_files: Vec<String>,
    pub ignore_values: Vec<IgnoreValueEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreValueEntry {
    pub rule: String,
    pub value: String,
    pub files: Vec<String>,
    pub reason: Option<String>,
    pub created_at: Option<String>,
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for v in values {
        if seen.insert(v.clone()) {
            out.push(v);
        }
    }
    out
}

fn apply_detection_config_source(config: &mut DetectionConfig, raw: Option<&Map<String, Value>>) {
    let Some(raw) = raw else { return };
    if let Some(Value::Object(ds)) = raw.get("designSystem") {
        let enabled = !matches!(ds.get("enabled"), Some(Value::Bool(false)));
        config.design_system_enabled = enabled;
    }
    if let Some(Value::Array(arr)) = raw.get("ignoreRules") {
        let incoming: Vec<String> = arr.iter().map(value_to_string).collect();
        config.ignore_rules = unique_strings(
            config
                .ignore_rules
                .iter()
                .cloned()
                .chain(incoming)
                .collect(),
        );
    }
    if let Some(Value::Array(arr)) = raw.get("ignoreFiles") {
        let incoming: Vec<String> = arr.iter().map(value_to_string).collect();
        config.ignore_files = unique_strings(
            config
                .ignore_files
                .iter()
                .cloned()
                .chain(incoming)
                .collect(),
        );
    }
    if let Some(Value::Array(arr)) = raw.get("ignoreValues") {
        let incoming = parse_ignore_value_entries(arr);
        config.ignore_values = merge_ignore_values(&config.ignore_values, &incoming);
    }
}

fn apply_raw_detection_config_source(
    config: &mut RawDetectionConfig,
    raw: Option<&Map<String, Value>>,
) {
    let Some(raw) = raw else { return };
    if let Some(Value::Array(arr)) = raw.get("ignoreRules") {
        let incoming: Vec<String> = arr.iter().map(value_to_string).collect();
        config.ignore_rules = unique_strings(
            config
                .ignore_rules
                .iter()
                .cloned()
                .chain(incoming)
                .collect(),
        );
    }
    if let Some(Value::Array(arr)) = raw.get("ignoreFiles") {
        let incoming: Vec<String> = arr.iter().map(value_to_string).collect();
        config.ignore_files = unique_strings(
            config
                .ignore_files
                .iter()
                .cloned()
                .chain(incoming)
                .collect(),
        );
    }
    if let Some(Value::Array(arr)) = raw.get("ignoreValues") {
        let incoming = parse_ignore_value_entries(arr);
        config.ignore_values = merge_ignore_values_raw(&config.ignore_values, &incoming);
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Detector filters shared by `npx impeccable detect` and the design hook.
/// Reads config.json then config.local.json, merging (back-compat: old
/// builds stored detector filters under `hook.*`).
pub fn read_detection_config(root: &Path) -> DetectionConfig {
    let mut config = DetectionConfig::default();
    for file_path in [get_config_path(root), get_local_config_path(root)] {
        let raw = safe_read_json(&file_path);
        let hook = hook_section(raw.as_ref());
        apply_detection_config_source(&mut config, hook.as_ref());
        let detector = detector_section(raw.as_ref());
        apply_detection_config_source(&mut config, detector.as_ref());
    }
    config
}

pub fn read_raw_detection_config(root: &Path, local: bool) -> RawDetectionConfig {
    let path = if local {
        get_local_config_path(root)
    } else {
        get_config_path(root)
    };
    let raw = safe_read_json(&path);
    let mut config = RawDetectionConfig::default();
    apply_raw_detection_config_source(&mut config, hook_section(raw.as_ref()).as_ref());
    apply_raw_detection_config_source(&mut config, detector_section(raw.as_ref()).as_ref());
    config
}

pub fn write_detection_config(
    root: &Path,
    detector_config: &RawDetectionConfig,
    local: bool,
) -> io::Result<PathBuf> {
    let file_path = if local {
        get_local_config_path(root)
    } else {
        get_config_path(root)
    };
    if local {
        ensure_config_git_exclude(root);
    }
    let existing = safe_read_json(&file_path).unwrap_or_default();
    let existing_hook = hook_section(Some(&existing));
    let next_hook = strip_detector_keys(existing_hook.as_ref());

    let mut next_detector = detector_section(Some(&existing)).unwrap_or_default();
    for (k, v) in normalize_detection_config_for_write(detector_config) {
        next_detector.insert(k, v);
    }

    let mut next = existing;
    next.insert("detector".to_string(), Value::Object(next_detector));
    match next_hook {
        Some(hook) if !hook.is_empty() => {
            next.insert("hook".to_string(), Value::Object(hook));
        }
        _ => {
            next.remove("hook");
        }
    }

    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let serialized = serde_json::to_string_pretty(&Value::Object(next)).unwrap();
    fs::write(&file_path, format!("{serialized}\n"))?;
    Ok(file_path)
}

fn normalize_detection_config_for_write(config: &RawDetectionConfig) -> Map<String, Value> {
    let mut out = Map::new();
    let rules: Vec<String> = unique_strings(
        config
            .ignore_rules
            .iter()
            .map(|r| normalize_ignore_rule(r))
            .filter(|r| !r.is_empty())
            .collect(),
    );
    out.insert(
        "ignoreRules".to_string(),
        Value::Array(rules.into_iter().map(Value::String).collect()),
    );
    let files: Vec<String> = unique_strings(
        config
            .ignore_files
            .iter()
            .filter(|v| !v.trim().is_empty())
            .map(|v| v.trim().to_string())
            .collect(),
    );
    out.insert(
        "ignoreFiles".to_string(),
        Value::Array(files.into_iter().map(Value::String).collect()),
    );
    let values = normalize_ignore_value_entries(&config.ignore_values);
    out.insert(
        "ignoreValues".to_string(),
        Value::Array(values.into_iter().map(ignore_value_entry_to_json).collect()),
    );
    out
}

fn ignore_value_entry_to_json(entry: IgnoreValueEntry) -> Value {
    let mut map = Map::new();
    map.insert("rule".to_string(), Value::String(entry.rule));
    map.insert("value".to_string(), Value::String(entry.value));
    if !entry.files.is_empty() {
        map.insert(
            "files".to_string(),
            Value::Array(entry.files.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(reason) = entry.reason {
        map.insert("reason".to_string(), Value::String(reason));
    }
    if let Some(created_at) = entry.created_at {
        map.insert("createdAt".to_string(), Value::String(created_at));
    }
    Value::Object(map)
}

fn strip_detector_keys(raw: Option<&Map<String, Value>>) -> Option<Map<String, Value>> {
    let raw = raw?;
    let mut out = Map::new();
    for (key, value) in raw {
        if !DETECTOR_CONFIG_KEYS.contains(&key.as_str()) {
            out.insert(key.clone(), value.clone());
        }
    }
    Some(out)
}

pub fn normalize_ignore_value(value: &str) -> String {
    let trimmed = value.trim();
    let re_quotes = Regex::new(r#"^["']|["']$"#).unwrap();
    let stripped = re_quotes.replace_all(trimmed, "");
    let plus_replaced = stripped.replace('+', " ");
    let re_ws = Regex::new(r"\s+").unwrap();
    re_ws.replace_all(&plus_replaced, " ").trim().to_lowercase()
}

fn normalize_ignore_rule(rule: &str) -> String {
    rule.trim().to_lowercase()
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct RgbaColor {
    r: u8,
    g: u8,
    b: u8,
    a: f64,
}

fn color_ignore_key(value: &str) -> String {
    match parse_ignore_color(value) {
        Some(c) => format!("{},{},{},{}", c.r, c.g, c.b, (c.a * 255.0).round() as i64),
        None => String::new(),
    }
}

static HEX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^#([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$").unwrap());
static RGB_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^rgba?\((.*)\)$").unwrap());
static HSL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^hsla?\((.*)\)$").unwrap());

fn parse_ignore_color(value: &str) -> Option<RgbaColor> {
    let text = value.trim().to_lowercase();
    if text.is_empty() {
        return None;
    }
    if let Some(caps) = HEX_RE.captures(&text) {
        return parse_hex_ignore_color(&caps[1]);
    }
    if let Some(caps) = RGB_RE.captures(&text) {
        let parts = split_color_args(&caps[1]);
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
        return Some(RgbaColor { r, g, b, a });
    }
    if let Some(caps) = HSL_RE.captures(&text) {
        let parts = split_color_args(&caps[1]);
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

fn parse_hex_ignore_color(hex: &str) -> Option<RgbaColor> {
    let chars: Vec<char> = hex.chars().collect();
    if chars.len() == 3 || chars.len() == 4 {
        let r = u8::from_str_radix(&format!("{}{}", chars[0], chars[0]), 16).ok()?;
        let g = u8::from_str_radix(&format!("{}{}", chars[1], chars[1]), 16).ok()?;
        let b = u8::from_str_radix(&format!("{}{}", chars[2], chars[2]), 16).ok()?;
        let a = if chars.len() == 4 {
            u8::from_str_radix(&format!("{}{}", chars[3], chars[3]), 16).ok()? as f64 / 255.0
        } else {
            1.0
        };
        return Some(RgbaColor { r, g, b, a });
    }
    let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
    let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
    let a = if chars.len() == 8 {
        u8::from_str_radix(&hex[6..8], 16).ok()? as f64 / 255.0
    } else {
        1.0
    };
    Some(RgbaColor { r, g, b, a })
}

fn split_color_args(body: &str) -> Vec<String> {
    let text = body.trim();
    if text.is_empty() {
        return Vec::new();
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
    let re_slash = Regex::new(r"\s*/\s*").unwrap();
    let normalized = re_slash.replace_all(text, " / ");
    normalized
        .split_whitespace()
        .filter(|p| *p != "/")
        .map(|p| p.to_string())
        .collect()
}

fn parse_rgb_channel(raw: &str) -> Option<u8> {
    let re = Regex::new(r"^(-?\d*\.?\d+)(%)?$").unwrap();
    let caps = re.captures(raw.trim())?;
    let value: f64 = caps[1].parse().ok()?;
    let scaled = if caps.get(2).is_some() { value * 2.55 } else { value };
    if scaled < 0.0 || scaled > 255.0 {
        return None;
    }
    Some(scaled.round() as u8)
}

fn parse_alpha_channel(raw: &str) -> Option<f64> {
    let re = Regex::new(r"^(-?\d*\.?\d+)(%)?$").unwrap();
    let caps = re.captures(raw.trim())?;
    let value: f64 = caps[1].parse().ok()?;
    let alpha = if caps.get(2).is_some() { value / 100.0 } else { value };
    if (0.0..=1.0).contains(&alpha) {
        Some(alpha)
    } else {
        None
    }
}

fn parse_hue_channel(raw: &str) -> Option<f64> {
    let re = Regex::new(r"^(-?\d*\.?\d+)(deg|rad|turn|grad)?$").unwrap();
    let caps = re.captures(raw.trim())?;
    let value: f64 = caps[1].parse().ok()?;
    let unit = caps.get(2).map(|m| m.as_str()).unwrap_or("deg");
    Some(match unit {
        "turn" => value * 360.0,
        "rad" => value * (180.0 / std::f64::consts::PI),
        "grad" => value * 0.9,
        _ => value,
    })
}

fn parse_percent_channel(raw: &str) -> Option<f64> {
    let re = Regex::new(r"^(-?\d*\.?\d+)%$").unwrap();
    let caps = re.captures(raw.trim())?;
    let value: f64 = caps[1].parse().ok()?;
    if (0.0..=100.0).contains(&value) {
        Some(value / 100.0)
    } else {
        None
    }
}

fn hsl_to_rgb(hue: f64, saturation: f64, lightness: f64, alpha: f64) -> RgbaColor {
    let h = (((hue % 360.0) + 360.0) % 360.0) / 360.0;
    if saturation == 0.0 {
        let gray = clamp_byte((lightness * 255.0).round());
        return RgbaColor { r: gray, g: gray, b: gray, a: alpha };
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
    RgbaColor {
        r: clamp_byte((to_rgb(h + 1.0 / 3.0) * 255.0).round()),
        g: clamp_byte((to_rgb(h) * 255.0).round()),
        b: clamp_byte((to_rgb(h - 1.0 / 3.0) * 255.0).round()),
        a: alpha,
    }
}

fn clamp_byte(value: f64) -> u8 {
    value.clamp(0.0, 255.0) as u8
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

fn parse_ignore_value_entries(entries: &[Value]) -> Vec<IgnoreValueEntry> {
    let mut out = Vec::new();
    for entry in entries {
        let Value::Object(map) = entry else { continue };
        let rule = normalize_ignore_rule(&map.get("rule").map(value_to_string).unwrap_or_default());
        let value = normalize_ignore_value(&map.get("value").map(value_to_string).unwrap_or_default());
        if rule.is_empty() || value.is_empty() {
            continue;
        }
        let mut files: Vec<String> = Vec::new();
        if let Some(Value::String(f)) = map.get("file") {
            if !f.trim().is_empty() {
                files.push(f.trim().to_string());
            }
        }
        if let Some(Value::Array(arr)) = map.get("files") {
            for v in arr {
                if let Value::String(s) = v {
                    if !s.trim().is_empty() {
                        files.push(s.trim().to_string());
                    }
                }
            }
        }
        let files = unique_strings(files);
        let reason = match map.get("reason") {
            Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
            _ => None,
        };
        let created_at = match map.get("createdAt") {
            Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
            _ => None,
        };
        out.push(IgnoreValueEntry {
            rule,
            value,
            files,
            reason,
            created_at,
        });
    }
    out
}

pub fn normalize_ignore_value_entries(entries: &[IgnoreValueEntry]) -> Vec<IgnoreValueEntry> {
    // Mirrors JS normalizeIgnoreValueEntries: entries are already normalized
    // structs in Rust, so this is effectively a pass-through/clone, kept for
    // API parity with the JS export.
    entries.to_vec()
}

fn ignore_value_files_key(files: &[String]) -> String {
    if files.is_empty() {
        String::new()
    } else {
        files.join("\u{1f}")
    }
}

fn merge_ignore_values(
    existing: &[IgnoreValueEntry],
    incoming: &[IgnoreValueEntry],
) -> Vec<IgnoreValueEntry> {
    merge_ignore_values_raw(existing, incoming)
}

fn merge_ignore_values_raw(
    existing: &[IgnoreValueEntry],
    incoming: &[IgnoreValueEntry],
) -> Vec<IgnoreValueEntry> {
    // Preserves insertion order like a JS Map keyed by rule\0value\0filesKey.
    let mut order: Vec<String> = Vec::new();
    let mut map: std::collections::HashMap<String, IgnoreValueEntry> = std::collections::HashMap::new();
    for entry in existing.iter().chain(incoming.iter()) {
        let key = format!(
            "{}\u{0}{}\u{0}{}",
            entry.rule,
            entry.value,
            ignore_value_files_key(&entry.files)
        );
        if !map.contains_key(&key) {
            order.push(key.clone());
        }
        map.insert(key, entry.clone());
    }
    order.into_iter().map(|k| map.remove(&k).unwrap()).collect()
}

// Glob -> Regex. Supports `**`, `*`, `?`, and `{a,b}` alternation.
fn glob_to_regex(glob: &str) -> Option<Regex> {
    let mut re = String::from("^");
    let chars: Vec<char> = glob.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '*' {
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
        } else if c == '?' {
            re.push_str("[^/]");
            i += 1;
        } else if c == '{' {
            if let Some(end) = chars[i..].iter().position(|&ch| ch == '}').map(|p| p + i) {
                let inner: String = chars[i + 1..end].iter().collect();
                let parts: Vec<String> = inner
                    .split(',')
                    .map(|p| regex::escape(p))
                    .collect();
                re.push_str(&format!("(?:{})", parts.join("|")));
                i = end + 1;
            } else {
                re.push_str("\\{");
                i += 1;
            }
        } else if ".+^$()|[]\\".contains(c) {
            re.push('\\');
            re.push(c);
            i += 1;
        } else {
            re.push(c);
            i += 1;
        }
    }
    re.push('$');
    Regex::new(&re).ok()
}

pub fn matches_any_glob(file_path: &str, globs: &[String]) -> bool {
    if globs.is_empty() {
        return false;
    }
    let normalized = file_path.replace(std::path::MAIN_SEPARATOR, "/");
    for glob in globs {
        if let Some(re) = glob_to_regex(glob) {
            if re.is_match(&normalized) {
                return true;
            }
            if let Some(base) = normalized.rsplit('/').next() {
                if re.is_match(base) {
                    return true;
                }
            }
        }
    }
    false
}

pub fn should_ignore_detection_file(file_path: &str, root: &Path, config: &DetectionConfig) -> bool {
    let globs = &config.ignore_files;
    if globs.is_empty() {
        return false;
    }
    let raw = file_path.trim();
    if raw.is_empty() {
        return false;
    }
    if matches_any_glob(raw, globs) {
        return true;
    }
    let raw_path = Path::new(raw);
    let abs = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        root.join(raw_path)
    };
    if matches_any_glob(&abs.to_string_lossy(), globs) {
        return true;
    }
    if let Ok(rel) = abs.strip_prefix(root) {
        return matches_any_glob(&rel.to_string_lossy(), globs);
    }
    false
}

/// Minimal finding shape used by `filterDetectionFindings`.
#[derive(Debug, Clone, Default)]
pub struct Finding {
    pub antipattern: Option<String>,
    pub file: Option<String>,
    pub ignore_value: Option<String>,
    pub value: Option<String>,
    pub detail: Option<String>,
    pub snippet: Option<String>,
}

pub fn filter_detection_findings(findings: &[Finding], config: &DetectionConfig) -> Vec<Finding> {
    if findings.is_empty() {
        return Vec::new();
    }
    let ignore_rules: HashSet<String> = config
        .ignore_rules
        .iter()
        .map(|r| normalize_ignore_rule(r))
        .collect();
    findings
        .iter()
        .filter(|finding| {
            let antipattern = finding
                .antipattern
                .as_deref()
                .map(normalize_ignore_rule)
                .unwrap_or_default();
            if ignore_rules.contains(&antipattern) {
                return false;
            }
            !is_ignored_finding_value(finding, &config.ignore_values)
        })
        .cloned()
        .collect()
}

fn is_ignored_finding_value(finding: &Finding, ignore_values: &[IgnoreValueEntry]) -> bool {
    if ignore_values.is_empty() {
        return false;
    }
    let rule = finding
        .antipattern
        .as_deref()
        .map(normalize_ignore_rule)
        .unwrap_or_default();
    let value = extract_finding_ignore_value(finding);
    if rule.is_empty() || value.is_empty() {
        return false;
    }
    ignore_values.iter().any(|entry| {
        let wildcard_value = entry.value == "*";
        if entry.rule != rule || (!wildcard_value && !ignore_value_matches(&rule, &entry.value, &value)) {
            return false;
        }
        if entry.files.is_empty() {
            return !wildcard_value;
        }
        finding_matches_scoped_ignore_file(finding, &entry.files)
    })
}

fn finding_matches_scoped_ignore_file(finding: &Finding, globs: &[String]) -> bool {
    let file_path = finding.file.as_deref().unwrap_or("").trim().to_string();
    if file_path.is_empty() {
        return false;
    }
    if matches_any_glob(&file_path, globs) {
        return true;
    }
    let normalized = file_path.replace(std::path::MAIN_SEPARATOR, "/");
    let parts: Vec<&str> = normalized.split('/').filter(|p| !p.is_empty()).collect();
    for i in 0..parts.len() {
        let suffix = parts[i..].join("/");
        if matches_any_glob(&suffix, globs) {
            return true;
        }
    }
    false
}

const DIRECT_VALUE_RULES: [&str; 5] = [
    "overused-font",
    "bounce-easing",
    "design-system-font",
    "design-system-color",
    "design-system-radius",
];

pub fn extract_finding_ignore_value(finding: &Finding) -> String {
    let rule = finding
        .antipattern
        .as_deref()
        .map(normalize_ignore_rule)
        .unwrap_or_default();
    if !DIRECT_VALUE_RULES.contains(&rule.as_str()) {
        return String::new();
    }
    normalize_ignore_value(&extract_finding_ignore_value_raw(finding, &rule))
}

fn extract_finding_ignore_value_raw(finding: &Finding, rule: &str) -> String {
    let direct = clean_ignore_value_display(
        finding
            .ignore_value
            .as_deref()
            .or(finding.value.as_deref())
            .unwrap_or(""),
    );
    if !direct.is_empty() {
        return direct;
    }

    let candidates: Vec<&str> = [finding.detail.as_deref(), finding.snippet.as_deref()]
        .into_iter()
        .flatten()
        .collect();

    static PRIMARY_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)Primary font:\s*([^()\n;]+)").unwrap());
    static FAMILY_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?i)font-family\s*:\s*["']?([^'",;\n]+)"#).unwrap());
    static GOOGLE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)[?&]family=([^&:;\n]+)").unwrap());

    for text in candidates {
        if rule == "bounce-easing" {
            let motion = extract_motion_ignore_value(text);
            if !motion.is_empty() {
                return motion;
            }
            continue;
        }

        if let Some(caps) = PRIMARY_RE.captures(text) {
            return clean_ignore_value_display(&caps[1]);
        }
        if let Some(caps) = FAMILY_RE.captures(text) {
            return clean_ignore_value_display(&caps[1]);
        }
        if let Some(caps) = GOOGLE_RE.captures(text) {
            let raw = &caps[1];
            return match urlencoding_decode(raw) {
                Some(decoded) => clean_ignore_value_display(&decoded),
                None => clean_ignore_value_display(raw),
            };
        }
    }

    String::new()
}

/// Minimal `decodeURIComponent` equivalent (percent-decoding) sufficient for
/// Google Fonts `family=` query values; returns `None` on malformed escapes
/// to mirror JS throwing and falling back to the raw string.
fn urlencoding_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
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

fn extract_motion_ignore_value(text: &str) -> String {
    static TAILWIND_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\banimate-bounce\b").unwrap());
    static BEZIER_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)cubic-bezier\([^)]+\)").unwrap());
    static ANIMATION_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)animation(?:-name)?\s*:\s*([^;\n]+)").unwrap());
    static TOKEN_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)bounce|elastic|wobble|jiggle|spring").unwrap());

    if let Some(m) = TAILWIND_RE.find(text) {
        return clean_ignore_value_display(m.as_str());
    }
    if let Some(m) = BEZIER_RE.find(text) {
        return clean_ignore_value_display(m.as_str());
    }
    if let Some(caps) = ANIMATION_RE.captures(text) {
        let token = caps[1]
            .split(|c: char| c == ',' || c.is_whitespace())
            .find(|part| TOKEN_RE.is_match(part));
        if let Some(token) = token {
            return clean_ignore_value_display(token);
        }
    }
    String::new()
}

fn clean_ignore_value_display(value: &str) -> String {
    let trimmed = value.trim();
    let re_quotes = Regex::new(r#"^["']|["']$"#).unwrap();
    let stripped = re_quotes.replace_all(trimmed, "");
    let plus_replaced = stripped.replace('+', " ");
    let re_ws = Regex::new(r"\s+").unwrap();
    re_ws.replace_all(&plus_replaced, " ").to_string()
}

/// The recorded design-hook decision: `Some("accepted"|"declined")` |
/// `None`. `config.local.json` (per-developer) overrides `config.json`.
pub fn get_hook_consent(root: &Path) -> Option<String> {
    let mut consent = None;
    for file_path in [get_config_path(root), get_local_config_path(root)] {
        let raw = safe_read_json(&file_path);
        if let Some(hook) = hook_section(raw.as_ref()) {
            if let Some(Value::String(c)) = hook.get("consent") {
                if c == "accepted" || c == "declined" {
                    consent = Some(c.clone());
                }
            }
        }
    }
    consent
}

/// Persist the per-developer decision to `config.local.json`, preserving any
/// sibling keys, and ensure the file is gitignored.
pub fn set_hook_consent(root: &Path, value: &str) -> io::Result<PathBuf> {
    let file_path = get_local_config_path(root);
    let mut existing = safe_read_json(&file_path).unwrap_or_default();
    let mut hook = hook_section(Some(&existing)).unwrap_or_default();
    hook.insert("consent".to_string(), Value::String(value.to_string()));
    existing.insert("hook".to_string(), Value::Object(hook));
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let serialized = serde_json::to_string_pretty(&Value::Object(existing)).unwrap();
    fs::write(&file_path, format!("{serialized}\n"))?;
    ensure_config_git_exclude(root);
    Ok(file_path)
}

const EXCLUDE_OPEN: &str = "# impeccable-config-ignore-start";
const EXCLUDE_CLOSE: &str = "# impeccable-config-ignore-end";
const EXCLUDE_PATTERNS: [&str; 1] = [".impeccable/config.local.json"];

/// Add `config.local.json` to `.git/info/exclude` so a developer's decision
/// is never committed. Idempotent via marker comments. Best-effort; returns
/// `false` when there is no resolvable git dir.
pub fn ensure_config_git_exclude(root: &Path) -> bool {
    let Some(git_dir) = resolve_git_dir(root) else {
        return false;
    };
    let target = git_dir.join("info").join("exclude");
    let existing = fs::read_to_string(&target).unwrap_or_default();
    let block = format!(
        "{}\n{}\n{}",
        EXCLUDE_OPEN,
        EXCLUDE_PATTERNS.join("\n"),
        EXCLUDE_CLOSE
    );
    let marker_re = Regex::new(&format!(
        "(?s){}.*?{}",
        regex::escape(EXCLUDE_OPEN),
        regex::escape(EXCLUDE_CLOSE)
    ))
    .unwrap();
    let updated = if marker_re.is_match(&existing) {
        marker_re.replace(&existing, block.as_str()).to_string()
    } else {
        let prefix = if existing.is_empty() {
            String::new()
        } else if existing.ends_with('\n') {
            existing.clone()
        } else {
            format!("{existing}\n")
        };
        format!("{prefix}{block}\n")
    };
    if updated != existing {
        if let Some(parent) = target.parent() {
            if fs::create_dir_all(parent).is_err() {
                return false;
            }
        }
        if fs::write(&target, updated).is_err() {
            return false;
        }
    }
    true
}

fn resolve_git_dir(root: &Path) -> Option<PathBuf> {
    let dot_git = root.join(".git");
    if !dot_git.exists() {
        return None;
    }
    if dot_git.is_dir() {
        return Some(dot_git);
    }
    // A linked-worktree `.git` file points elsewhere: "gitdir: <path>".
    let contents = fs::read_to_string(&dot_git).ok()?;
    let re = Regex::new(r"gitdir:\s*(.+)").unwrap();
    let caps = re.captures(&contents)?;
    let resolved = caps[1].trim();
    let path = Path::new(resolved);
    if path.is_absolute() {
        Some(path.to_path_buf())
    } else {
        Some(root.join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "w2-016-impeccable-config-{}-{}",
                std::process::id(),
                n
            ));
            fs::create_dir_all(&path).unwrap();
            TmpDir(path)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn config_paths_match_js_layout() {
        let root = Path::new("/proj");
        assert_eq!(
            get_config_path(root),
            Path::new("/proj/.impeccable/config.json")
        );
        assert_eq!(
            get_local_config_path(root),
            Path::new("/proj/.impeccable/config.local.json")
        );
    }

    #[test]
    fn normalize_ignore_value_strips_quotes_plus_and_case() {
        assert_eq!(normalize_ignore_value("\"Roboto+Mono\""), "roboto mono");
        assert_eq!(normalize_ignore_value("  Foo   Bar  "), "foo bar");
    }

    #[test]
    fn matches_any_glob_supports_star_star_and_braces() {
        let globs = vec!["**/*.{html,jsx}".to_string()];
        assert!(matches_any_glob("src/pages/a.html", &globs));
        assert!(matches_any_glob("a.jsx", &globs));
        assert!(!matches_any_glob("a.css", &globs));
    }

    #[test]
    fn read_write_detection_config_round_trips() {
        let dir = TmpDir::new();
        let cfg = RawDetectionConfig {
            ignore_rules: vec!["Overused-Font".to_string()],
            ignore_files: vec!["dist/**".to_string()],
            ignore_values: vec![IgnoreValueEntry {
                rule: "overused-font".to_string(),
                value: "Roboto".to_string(),
                files: vec![],
                reason: None,
                created_at: None,
            }],
        };
        write_detection_config(&dir.0, &cfg, false).unwrap();
        let read = read_detection_config(&dir.0);
        assert_eq!(read.ignore_rules, vec!["overused-font".to_string()]);
        assert_eq!(read.ignore_files, vec!["dist/**".to_string()]);
        assert_eq!(read.ignore_values.len(), 1);
        assert_eq!(read.ignore_values[0].value, "roboto");
        assert!(read.design_system_enabled);
    }

    #[test]
    fn hook_consent_round_trips_via_local_config() {
        let dir = TmpDir::new();
        assert_eq!(get_hook_consent(&dir.0), None);
        set_hook_consent(&dir.0, "accepted").unwrap();
        assert_eq!(get_hook_consent(&dir.0), Some("accepted".to_string()));
    }

    #[test]
    fn legacy_hook_section_still_feeds_detector_filters() {
        let dir = TmpDir::new();
        let config_path = get_config_path(&dir.0);
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(
            &config_path,
            r#"{"hook":{"ignoreRules":["profanity"],"consent":"accepted"}}"#,
        )
        .unwrap();
        let read = read_detection_config(&dir.0);
        assert_eq!(read.ignore_rules, vec!["profanity".to_string()]);
    }

    #[test]
    fn design_system_color_ignore_matches_equivalent_hex_and_rgb() {
        let entry = IgnoreValueEntry {
            rule: "design-system-color".to_string(),
            value: normalize_ignore_value("#ff0000"),
            files: vec![],
            reason: None,
            created_at: None,
        };
        let config = DetectionConfig {
            ignore_values: vec![entry],
            ..Default::default()
        };
        let finding = Finding {
            antipattern: Some("design-system-color".to_string()),
            value: Some("rgb(255, 0, 0)".to_string()),
            ..Default::default()
        };
        let filtered = filter_detection_findings(&[finding], &config);
        assert!(filtered.is_empty(), "equivalent color should be ignored");
    }

    #[test]
    fn filter_detection_findings_respects_scoped_ignore_files() {
        let entry = IgnoreValueEntry {
            rule: "overused-font".to_string(),
            value: "roboto".to_string(),
            files: vec!["src/marketing/**".to_string()],
            reason: None,
            created_at: None,
        };
        let config = DetectionConfig {
            ignore_values: vec![entry],
            ..Default::default()
        };
        let matching = Finding {
            antipattern: Some("overused-font".to_string()),
            value: Some("Roboto".to_string()),
            file: Some("src/marketing/hero.html".to_string()),
            ..Default::default()
        };
        let outside_scope = Finding {
            antipattern: Some("overused-font".to_string()),
            value: Some("Roboto".to_string()),
            file: Some("src/app/hero.html".to_string()),
            ..Default::default()
        };
        let filtered = filter_detection_findings(&[matching, outside_scope], &config);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].file.as_deref(), Some("src/app/hero.html"));
    }

    #[test]
    fn extract_finding_ignore_value_reads_primary_font_from_detail() {
        let finding = Finding {
            antipattern: Some("overused-font".to_string()),
            detail: Some("Primary font: Inter (weight 400)".to_string()),
            ..Default::default()
        };
        assert_eq!(extract_finding_ignore_value(&finding), "inter");
    }

    #[test]
    fn should_ignore_detection_file_matches_relative_and_absolute() {
        let dir = TmpDir::new();
        let config = DetectionConfig {
            ignore_files: vec!["dist/**".to_string()],
            ..Default::default()
        };
        assert!(should_ignore_detection_file(
            "dist/out.html",
            &dir.0,
            &config
        ));
        let abs = dir.0.join("dist").join("out.html");
        assert!(should_ignore_detection_file(
            abs.to_str().unwrap(),
            &dir.0,
            &config
        ));
    }
}
