//! Packet R12: port of `skills/designer/engine/scripts/hook-admin.mjs`.
//!
//! `hook-admin.mjs` is the `/designer hooks <on|off|status|reset|...>` CLI.
//! It reads/writes the unified `.impeccable/config.json` /
//! `.impeccable/config.local.json` files (a `hook` subtree for runtime
//! settings, a `detector` subtree for filters), installs or repairs
//! per-provider hook manifests, and manages a git `info/exclude` block for
//! the hook's own state files.
//!
//! This module ports the subset of `hook-lib.mjs` that `hook-admin.mjs`
//! actually imports (`normalizeIgnoreValue`, `normalizeIgnoreValueEntries`,
//! `ensureHookGitExcludes`, `readConfig`, `DEFAULT_CONFIG`, and the config
//! path helpers) alongside the admin logic itself. The rest of
//! `hook-lib.mjs` (finding filtering, cache dedup, template rendering, the
//! detector loader) is out of scope for this packet — see
//! `finish-r12.md` for the exact gap.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const ENVELOPE_PREFIX: &str = "[impeccable@1]";

/// `hook-lib.mjs`'s `HOOK_LOCAL_IGNORE_PATTERNS`, verbatim and in order.
pub const HOOK_LOCAL_IGNORE_PATTERNS: [&str; 3] = [
    ".impeccable/hook.cache.json",
    ".impeccable/hook.pending.json",
    ".impeccable/config.local.json",
];

const HOOK_IGNORE_MARKER_OPEN: &str = "# impeccable-hook-ignore-start";
const HOOK_IGNORE_MARKER_CLOSE: &str = "# impeccable-hook-ignore-end";

const ACTIONS: [&str; 7] = [
    "status",
    "on",
    "off",
    "ignore-rule",
    "ignore-file",
    "ignore-value",
    "reset",
];

// ---------------------------------------------------------------------
// Config model (hook + detector subtrees of the unified config file)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    #[serde(rename = "maxFindings")]
    pub max_findings: f64,
    #[serde(rename = "maxChars")]
    pub max_chars: f64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_findings: 5.0, max_chars: 8000.0 }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DesignSystem {
    pub enabled: bool,
}

impl Default for DesignSystem {
    fn default() -> Self {
        DesignSystem { enabled: true }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IgnoreValueEntry {
    pub rule: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// Mirrors `hook-lib.mjs`'s `readConfig()` result: the merged `hook` +
/// `detector` view used by `statusReport`.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadConfig {
    pub enabled: bool,
    pub quiet: bool,
    pub audit_log: Option<String>,
    pub design_system: DesignSystem,
    pub ignore_rules: Vec<String>,
    pub ignore_files: Vec<String>,
    pub ignore_values: Vec<IgnoreValueEntry>,
    pub limits: Limits,
}

impl Default for ReadConfig {
    fn default() -> Self {
        ReadConfig {
            enabled: true,
            quiet: false,
            audit_log: None,
            design_system: DesignSystem::default(),
            ignore_rules: Vec::new(),
            ignore_files: Vec::new(),
            ignore_values: Vec::new(),
            limits: Limits::default(),
        }
    }
}

// ---------------------------------------------------------------------
// Path helpers (hook-lib.mjs getConfigPath / getLocalConfigPath / ...)
// ---------------------------------------------------------------------

pub fn get_config_path(cwd: &Path) -> PathBuf {
    cwd.join(".impeccable").join("config.json")
}

pub fn get_local_config_path(cwd: &Path) -> PathBuf {
    cwd.join(".impeccable").join("config.local.json")
}

pub fn get_cache_path(cwd: &Path) -> PathBuf {
    cwd.join(".impeccable").join("hook.cache.json")
}

pub fn get_pending_path(cwd: &Path) -> PathBuf {
    cwd.join(".impeccable").join("hook.pending.json")
}

// ---------------------------------------------------------------------
// normalizeIgnoreValue / normalizeIgnoreValueEntries (hook-lib.mjs)
// ---------------------------------------------------------------------

/// `normalizeIgnoreValue(value)`: trim, strip a single pair of surrounding
/// quotes, turn `+` into spaces, collapse whitespace runs, lowercase.
pub fn normalize_ignore_value(value: &str) -> String {
    let trimmed = value.trim();
    let stripped = strip_wrapping_quotes(trimmed);
    let plus_to_space = stripped.replace('+', " ");
    let collapsed = collapse_whitespace(&plus_to_space);
    collapsed.to_lowercase()
}

fn strip_wrapping_quotes(s: &str) -> &str {
    let mut out = s;
    if let Some(rest) = out.strip_prefix('"') {
        out = rest;
    } else if let Some(rest) = out.strip_prefix('\'') {
        out = rest;
    }
    if let Some(rest) = out.strip_suffix('"') {
        out = rest;
    } else if let Some(rest) = out.strip_suffix('\'') {
        out = rest;
    }
    out
}

fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(ch);
            last_was_space = false;
        }
    }
    out
}

fn normalize_rule_id(rule: &str) -> String {
    rule.trim().to_lowercase()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for v in values {
        if seen.insert(v.clone()) {
            out.push(v);
        }
    }
    out
}

/// `normalizeIgnoreValueEntries(entries)`: drop malformed entries, normalize
/// rule/value/files/reason/createdAt.
pub fn normalize_ignore_value_entries(entries: &[Value]) -> Vec<IgnoreValueEntry> {
    let mut out = Vec::new();
    for entry in entries {
        let Some(obj) = entry.as_object() else { continue };
        let rule = obj.get("rule").and_then(Value::as_str).map(normalize_rule_id).unwrap_or_default();
        let value = obj
            .get("value")
            .and_then(Value::as_str)
            .map(normalize_ignore_value)
            .unwrap_or_default();
        if rule.is_empty() || value.is_empty() {
            continue;
        }
        let mut files: Vec<String> = Vec::new();
        if let Some(f) = obj.get("file").and_then(Value::as_str) {
            if !f.trim().is_empty() {
                files.push(f.trim().to_string());
            }
        }
        if let Some(arr) = obj.get("files").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    if !s.trim().is_empty() {
                        files.push(s.trim().to_string());
                    }
                }
            }
        }
        let files = unique_strings(files);
        let reason = obj
            .get("reason")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let created_at = obj
            .get("createdAt")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        out.push(IgnoreValueEntry { rule, value, files, reason, created_at });
    }
    out
}

fn ignore_value_entry_key(entry: &IgnoreValueEntry) -> String {
    let files = if !entry.files.is_empty() { entry.files.join("\u{1f}") } else { String::new() };
    format!("{}\0{}\0{}", entry.rule, entry.value, files)
}

/// `mergeIgnoreValueEntries(existing, incoming)` from hook-admin.mjs: later
/// entries win on key collision, insertion order otherwise preserved.
pub fn merge_ignore_value_entries(
    existing: &[IgnoreValueEntry],
    incoming: &[IgnoreValueEntry],
) -> Vec<IgnoreValueEntry> {
    let mut map: BTreeMap<String, IgnoreValueEntry> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for entry in existing.iter().chain(incoming.iter()) {
        let key = ignore_value_entry_key(entry);
        if !map.contains_key(&key) {
            order.push(key.clone());
        }
        map.insert(key, entry.clone());
    }
    order.into_iter().filter_map(|k| map.remove(&k)).collect()
}

// ---------------------------------------------------------------------
// readConfig (hook-lib.mjs): merge shared then local file, hook then
// detector subtree, hook-shaped legacy detector fields lose to detector.
// ---------------------------------------------------------------------

fn read_json_object(path: &Path) -> Option<Map<String, Value>> {
    let raw = fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    value.as_object().cloned()
}

fn hook_section(raw: &Map<String, Value>) -> Option<Map<String, Value>> {
    raw.get("hook").and_then(Value::as_object).cloned()
}

fn detector_section(raw: &Map<String, Value>) -> Option<Map<String, Value>> {
    raw.get("detector").and_then(Value::as_object).cloned()
}

fn number_or(value: Option<&Value>, fallback: f64) -> f64 {
    match value.and_then(Value::as_f64) {
        Some(n) if n.is_finite() && n > 0.0 => n,
        _ => fallback,
    }
}

fn apply_detector_config_source(config: &mut ReadConfig, raw: Option<Map<String, Value>>) {
    let Some(raw) = raw else { return };
    if let Some(ds) = raw.get("designSystem").and_then(Value::as_object) {
        let enabled = !matches!(ds.get("enabled"), Some(Value::Bool(false)));
        config.design_system = DesignSystem { enabled };
    }
    if let Some(arr) = raw.get("ignoreRules").and_then(Value::as_array) {
        let incoming: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let mut combined = config.ignore_rules.clone();
        combined.extend(incoming);
        config.ignore_rules = unique_strings(combined);
    }
    if let Some(arr) = raw.get("ignoreFiles").and_then(Value::as_array) {
        let incoming: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let mut combined = config.ignore_files.clone();
        combined.extend(incoming);
        config.ignore_files = unique_strings(combined);
    }
    if let Some(arr) = raw.get("ignoreValues").and_then(Value::as_array) {
        let incoming = normalize_ignore_value_entries(arr);
        config.ignore_values = merge_ignore_value_entries(&config.ignore_values, &incoming);
    }
}

fn apply_config_source(config: &mut ReadConfig, raw: Option<Map<String, Value>>) {
    let Some(raw) = raw else { return };
    if let Some(v) = raw.get("enabled") {
        config.enabled = !matches!(v, Value::Bool(false));
    }
    if let Some(v) = raw.get("quiet") {
        config.quiet = matches!(v, Value::Bool(true));
    }
    if let Some(s) = raw.get("auditLog").and_then(Value::as_str) {
        if !s.trim().is_empty() {
            config.audit_log = Some(s.trim().to_string());
        }
    }
    apply_detector_config_source(config, Some(raw.clone()));
    if let Some(limits) = raw.get("limits").and_then(Value::as_object) {
        config.limits = Limits {
            max_findings: number_or(limits.get("maxFindings"), config.limits.max_findings),
            max_chars: number_or(limits.get("maxChars"), config.limits.max_chars),
        };
    }
}

/// `readConfig(cwd)`: layers shared config then local config, each split
/// into `hook` and `detector` subtrees (back-compat: detector filters
/// stored under `hook` are read too, but `detector` wins).
pub fn read_config(cwd: &Path) -> ReadConfig {
    let mut config = ReadConfig::default();
    for path in [get_config_path(cwd), get_local_config_path(cwd)] {
        if let Some(raw) = read_json_object(&path) {
            apply_config_source(&mut config, hook_section(&raw));
            apply_detector_config_source(&mut config, detector_section(&raw));
        }
    }
    config
}

// ---------------------------------------------------------------------
// ensureHookGitExcludes (hook-lib.mjs)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct GitExcludeResult {
    pub mode: String,
    pub file: Option<String>,
    pub changed: bool,
    pub patterns: Vec<String>,
}

struct GitExcludeTarget {
    path: PathBuf,
    pattern_prefix: String,
}

fn resolve_git_dir(dot_git: &Path, worktree_dir: &Path) -> Option<PathBuf> {
    let meta = fs::symlink_metadata(dot_git).ok()?;
    if meta.is_dir() {
        return Some(dot_git.to_path_buf());
    }
    if !meta.is_file() {
        return None;
    }
    let body = fs::read_to_string(dot_git).ok()?;
    let body = body.trim();
    let rest = body.strip_prefix("gitdir:").or_else(|| body.strip_prefix("gitdir: "))?;
    let rest = rest.trim();
    let p = Path::new(rest);
    Some(if p.is_absolute() { p.to_path_buf() } else { worktree_dir.join(p) })
}

fn resolve_hook_git_exclude_target(cwd: &Path) -> io::Result<Option<GitExcludeTarget>> {
    let start = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let mut dir = start.clone();
    loop {
        let dot_git = dir.join(".git");
        if dot_git.exists() {
            let Some(git_dir) = resolve_git_dir(&dot_git, &dir) else { return Ok(None) };
            let rel_prefix = pathdiff(&dir, &start);
            return Ok(Some(GitExcludeTarget {
                path: git_dir.join("info").join("exclude"),
                pattern_prefix: if rel_prefix == "." { String::new() } else { rel_prefix },
            }));
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent.to_path_buf(),
            _ => return Ok(None),
        }
    }
}

/// Best-effort relative path from `base` to `target`, forward-slash
/// separated, mirroring Node's `path.relative(...).split(sep).join('/')`
/// for the same-directory case this call site always hits (`dir == start`
/// on the loop iteration where `.git` is found is the only path taken in
/// practice, since `dir` starts equal to `start`).
fn pathdiff(target: &Path, base: &Path) -> String {
    if target == base {
        return ".".to_string();
    }
    match target.strip_prefix(base) {
        Ok(rel) => {
            let s = rel.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
            if s.is_empty() { ".".to_string() } else { s }
        }
        Err(_) => ".".to_string(),
    }
}

fn escape_regex_literal_block(patterns_block: &str, existing: &str, marker_open: &str, marker_close: &str) -> Option<(usize, usize)> {
    let start = existing.find(marker_open)?;
    let close_idx = existing[start..].find(marker_close)? + start;
    let end = close_idx + marker_close.len();
    let _ = patterns_block;
    Some((start, end))
}

/// `ensureHookGitExcludes(cwd)`: write/refresh a marker-delimited block of
/// hook-local ignore patterns into the enclosing repo's
/// `.git/info/exclude` (or the linked worktree's gitdir). Best-effort: any
/// I/O error degrades to `mode: "error"` rather than propagating, matching
/// the JS `try { ... } catch { return { mode: 'error', ... } }` shape.
pub fn ensure_hook_git_excludes(cwd: &Path) -> GitExcludeResult {
    let fallback = GitExcludeResult {
        mode: "error".to_string(),
        file: None,
        changed: false,
        patterns: HOOK_LOCAL_IGNORE_PATTERNS.iter().map(|s| s.to_string()).collect(),
    };
    let target = match resolve_hook_git_exclude_target(cwd) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return GitExcludeResult {
                mode: "none".to_string(),
                file: None,
                changed: false,
                patterns: HOOK_LOCAL_IGNORE_PATTERNS.iter().map(|s| s.to_string()).collect(),
            };
        }
        Err(_) => return fallback,
    };

    let patterns: Vec<String> = if target.pattern_prefix.is_empty() {
        HOOK_LOCAL_IGNORE_PATTERNS.iter().map(|s| s.to_string()).collect()
    } else {
        HOOK_LOCAL_IGNORE_PATTERNS
            .iter()
            .map(|p| format!("{}/{}", target.pattern_prefix, p))
            .collect()
    };
    let marker_suffix = if target.pattern_prefix.is_empty() { "." } else { target.pattern_prefix.as_str() };
    let marker_open = format!("{} {}", HOOK_IGNORE_MARKER_OPEN, marker_suffix);
    let marker_close = format!("{} {}", HOOK_IGNORE_MARKER_CLOSE, marker_suffix);
    let mut block_lines = vec![marker_open.clone()];
    block_lines.extend(patterns.iter().cloned());
    block_lines.push(marker_close.clone());
    let block = block_lines.join("\n");

    let existing = fs::read_to_string(&target.path).unwrap_or_default();

    let updated = match escape_regex_literal_block(&block, &existing, &marker_open, &marker_close) {
        Some((start, end)) => {
            let mut s = String::with_capacity(existing.len());
            s.push_str(&existing[..start]);
            s.push_str(&block);
            s.push_str(&existing[end..]);
            s
        }
        None => {
            let prefix = if existing.is_empty() {
                String::new()
            } else if existing.ends_with('\n') {
                existing.clone()
            } else {
                format!("{}\n", existing)
            };
            let needs_blank = !(prefix.ends_with("\n\n") || prefix.is_empty());
            format!("{}{}{}\n", prefix, if needs_blank { "\n" } else { "" }, block)
        }
    };

    let changed = updated != existing;
    if changed {
        if let Some(parent) = target.path.parent() {
            if fs::create_dir_all(parent).is_err() {
                return fallback;
            }
        }
        if fs::write(&target.path, &updated).is_err() {
            return fallback;
        }
    }

    let file_rel = pathdiff(&target.path, &fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf()));
    GitExcludeResult {
        mode: "git-info-exclude".to_string(),
        file: Some(if file_rel == "." { target.path.display().to_string() } else { file_rel }),
        changed,
        patterns,
    }
}

// ---------------------------------------------------------------------
// hook-admin.mjs: config read/write (hook + detector merge), status,
// on/off, ignore-rule/-file/-value, reset, and the CLI action dispatcher.
// ---------------------------------------------------------------------

const DETECTOR_CONFIG_KEYS: [&str; 4] = ["ignoreRules", "ignoreFiles", "ignoreValues", "designSystem"];

fn strip_detector_keys(raw: &Map<String, Value>) -> Map<String, Value> {
    raw.iter()
        .filter(|(k, _)| !DETECTOR_CONFIG_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// hook-admin.mjs's own `mergeDetectorConfig` (distinct from hook-lib.mjs's
/// namesake): merges `base` onto an optional `seed`, unioning arrays and
/// merging `designSystem.enabled` and `ignoreValues` entries.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DetectorConfig {
    pub ignore_rules: Vec<String>,
    pub ignore_files: Vec<String>,
    pub ignore_values: Vec<IgnoreValueEntry>,
    pub design_system_enabled: Option<bool>,
}

fn detector_config_to_value(cfg: &DetectorConfig) -> Value {
    let mut obj = Map::new();
    obj.insert("ignoreRules".into(), Value::Array(cfg.ignore_rules.iter().map(|s| Value::String(s.clone())).collect()));
    obj.insert("ignoreFiles".into(), Value::Array(cfg.ignore_files.iter().map(|s| Value::String(s.clone())).collect()));
    obj.insert(
        "ignoreValues".into(),
        Value::Array(
            cfg.ignore_values
                .iter()
                .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
                .collect(),
        ),
    );
    if let Some(enabled) = cfg.design_system_enabled {
        let mut ds = Map::new();
        ds.insert("enabled".into(), Value::Bool(enabled));
        obj.insert("designSystem".into(), Value::Object(ds));
    }
    Value::Object(obj)
}

fn merge_detector_config(base: Option<&Map<String, Value>>, seed: Option<&DetectorConfig>) -> DetectorConfig {
    let mut out = match seed {
        Some(s) => s.clone(),
        None => DetectorConfig::default(),
    };
    let Some(base) = base else { return out };

    if let Some(ds) = base.get("designSystem").and_then(Value::as_object) {
        let enabled = !matches!(ds.get("enabled"), Some(Value::Bool(false)));
        out.design_system_enabled = Some(enabled);
    }
    if let Some(arr) = base.get("ignoreRules").and_then(Value::as_array) {
        let incoming: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let mut combined = out.ignore_rules.clone();
        combined.extend(incoming);
        out.ignore_rules = unique_strings(combined);
    }
    if let Some(arr) = base.get("ignoreFiles").and_then(Value::as_array) {
        let incoming: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let mut combined = out.ignore_files.clone();
        combined.extend(incoming);
        out.ignore_files = unique_strings(combined);
    }
    if let Some(arr) = base.get("ignoreValues").and_then(Value::as_array) {
        let incoming = normalize_ignore_value_entries(arr);
        out.ignore_values = merge_ignore_value_entries(&out.ignore_values, &incoming);
    }
    out
}

/// Filesystem access needed by `hook-admin.mjs`, behind a trait so tests
/// run against an in-memory fake instead of the real filesystem.
pub trait AdminFs {
    fn read_to_string(&self, path: &Path) -> Option<String>;
    fn write(&mut self, path: &Path, content: &str) -> io::Result<()>;
    fn exists(&self, path: &Path) -> bool;
    fn remove_file(&mut self, path: &Path) -> io::Result<()>;
}

/// Real filesystem implementation of [`AdminFs`].
pub struct RealFs;

impl AdminFs for RealFs {
    fn read_to_string(&self, path: &Path) -> Option<String> {
        fs::read_to_string(path).ok()
    }

    fn write(&mut self, path: &Path, content: &str) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn remove_file(&mut self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
}

fn read_raw_config_file(fs_: &dyn AdminFs, path: &Path) -> Option<Map<String, Value>> {
    let raw = fs_.read_to_string(path)?;
    serde_json::from_str::<Value>(&raw).ok()?.as_object().cloned()
}

fn read_raw_hook_config(fs_: &dyn AdminFs, cwd: &Path, local: bool) -> Option<Map<String, Value>> {
    let path = if local { get_local_config_path(cwd) } else { get_config_path(cwd) };
    let unified = read_raw_config_file(fs_, &path)?;
    hook_section(&unified)
}

fn read_raw_detector_config(fs_: &dyn AdminFs, cwd: &Path, local: bool) -> DetectorConfig {
    let path = if local { get_local_config_path(cwd) } else { get_config_path(cwd) };
    let unified = read_raw_config_file(fs_, &path);
    let hook_raw = unified.as_ref().and_then(hook_section);
    let seed = merge_detector_config(hook_raw.as_ref(), None);
    let detector_raw = unified.as_ref().and_then(detector_section);
    merge_detector_config(detector_raw.as_ref(), Some(&seed))
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct HookRuntimeConfig {
    pub enabled: bool,
    pub max_findings: Option<f64>,
    pub max_chars: Option<f64>,
    /// Extra scalar/string fields to preserve verbatim (consent, quiet,
    /// auditLog, ...), keyed by JSON field name.
    pub extra: Map<String, Value>,
}

fn merge_hook_config(existing: Option<&Map<String, Value>>) -> HookRuntimeConfig {
    let mut cfg = HookRuntimeConfig { enabled: true, ..Default::default() };
    if let Some(base) = existing {
        cfg.enabled = !matches!(base.get("enabled"), Some(Value::Bool(false)));
        cfg.max_findings = base.get("limits").and_then(|l| l.get("maxFindings")).and_then(Value::as_f64);
        cfg.max_chars = base.get("limits").and_then(|l| l.get("maxChars")).and_then(Value::as_f64);
    }
    cfg
}

fn hook_runtime_config_to_value(cfg: &HookRuntimeConfig) -> Value {
    let mut obj = cfg.extra.clone();
    obj.insert("enabled".into(), Value::Bool(cfg.enabled));
    if cfg.max_findings.is_some() || cfg.max_chars.is_some() {
        let mut limits = Map::new();
        limits.insert("maxFindings".into(), Value::from(cfg.max_findings.unwrap_or(5.0)));
        limits.insert("maxChars".into(), Value::from(cfg.max_chars.unwrap_or(8000.0)));
        obj.insert("limits".into(), Value::Object(limits));
    }
    Value::Object(obj)
}

/// `writeHookConfig(cwd, hookConfig, opts)`: merge over existing hook object
/// (preserving fields the admin doesn't manage), write to shared or local
/// config file. Returns the path written.
fn write_hook_config(
    fs_: &mut dyn AdminFs,
    cwd: &Path,
    hook_config_patch: &Map<String, Value>,
    local: bool,
) -> io::Result<PathBuf> {
    let path = if local { get_local_config_path(cwd) } else { get_config_path(cwd) };
    if local {
        ensure_hook_git_excludes(cwd);
    }
    let existing = read_raw_config_file(fs_, &path).unwrap_or_default();
    let existing_hook_raw = hook_section(&existing).unwrap_or_default();
    let existing_hook = strip_detector_keys(&existing_hook_raw);

    let mut merged_hook = existing_hook;
    for (k, v) in hook_config_patch {
        merged_hook.insert(k.clone(), v.clone());
    }

    let mut next = existing;
    next.insert("hook".into(), Value::Object(merged_hook));
    let serialized = format!("{}\n", serde_json::to_string_pretty(&Value::Object(next)).unwrap());
    fs_.write(&path, &serialized)?;
    Ok(path)
}

fn write_detector_config(
    fs_: &mut dyn AdminFs,
    cwd: &Path,
    detector_config: &DetectorConfig,
    local: bool,
) -> io::Result<PathBuf> {
    let path = if local { get_local_config_path(cwd) } else { get_config_path(cwd) };
    if local {
        ensure_hook_git_excludes(cwd);
    }
    let existing = read_raw_config_file(fs_, &path).unwrap_or_default();
    let next_hook = strip_detector_keys(&hook_section(&existing).unwrap_or_default());
    let existing_detector_raw = detector_section(&existing);
    let existing_detector = merge_detector_config(existing_detector_raw.as_ref(), None);
    let merged_detector = merge_detector_config(Some(&detector_config_to_value(detector_config).as_object().unwrap().clone()), Some(&existing_detector));

    let mut next = existing;
    next.insert("detector".into(), detector_config_to_value(&merged_detector));
    if !next_hook.is_empty() {
        next.insert("hook".into(), Value::Object(next_hook));
    } else {
        next.remove("hook");
    }
    let serialized = format!("{}\n", serde_json::to_string_pretty(&Value::Object(next)).unwrap());
    fs_.write(&path, &serialized)?;
    Ok(path)
}

/// `statusReport(cwd)`: human-readable multi-line summary. `env_kill` is
/// the (test-injectable) value of `IMPECCABLE_HOOK_DISABLED`.
pub fn status_report(fs_: &dyn AdminFs, cwd: &Path, env_kill: Option<&str>) -> String {
    let shared_path = get_config_path(cwd);
    let local_path = get_local_config_path(cwd);
    let shared_exists = fs_.exists(&shared_path);
    let shared_malformed = shared_exists && read_raw_config_file(fs_, &shared_path).is_none();
    let local_exists = fs_.exists(&local_path);
    let local_malformed = local_exists && read_raw_config_file(fs_, &local_path).is_none();

    let cfg = read_config_via(fs_, cwd);
    let env_state = match env_kill {
        Some(v) if !v.is_empty() => format!("IMPECCABLE_HOOK_DISABLED={}", v),
        _ => "unset".to_string(),
    };
    let cache_path = get_cache_path(cwd);

    let file_state = |exists: bool, malformed: bool, rel: &str, absent: &str| -> String {
        if malformed {
            format!("{} (malformed; ignored)", rel)
        } else if exists {
            rel.to_string()
        } else {
            format!("{} ({})", rel, absent)
        }
    };

    let ignore_values: Vec<String> = cfg.ignore_values.iter().map(|e| format!("{}={}", e.rule, e.value)).collect();

    let lines = vec![
        "Impeccable design hook".to_string(),
        format!("  state:        {}", if cfg.enabled { "enabled" } else { "disabled" }),
        format!(
            "  shared file:  {}",
            file_state(shared_exists, shared_malformed, ".impeccable/config.json", "using defaults; file not present")
        ),
        format!("  local file:   {}", file_state(local_exists, local_malformed, ".impeccable/config.local.json", "not present")),
        format!("  ignoreRules:  {}", if cfg.ignore_rules.is_empty() { "(none)".to_string() } else { cfg.ignore_rules.join(", ") }),
        format!("  ignoreFiles:  {}", if cfg.ignore_files.is_empty() { "(none)".to_string() } else { cfg.ignore_files.join(", ") }),
        format!("  ignoreValues: {}", if ignore_values.is_empty() { "(none)".to_string() } else { ignore_values.join(", ") }),
        format!("  maxFindings:  {}", cfg.limits.max_findings),
        format!("  maxChars:     {}", cfg.limits.max_chars),
        format!("  env override: {}", env_state),
        format!(
            "  cache file:   {}",
            if fs_.exists(&cache_path) { ".impeccable/hook.cache.json".to_string() } else { ".impeccable/hook.cache.json (not present)".to_string() }
        ),
    ];
    lines.join("\n")
}

/// Same as [`read_config`] but through the [`AdminFs`] trait, so tests
/// exercise it against a fake filesystem too.
fn read_config_via(fs_: &dyn AdminFs, cwd: &Path) -> ReadConfig {
    let mut config = ReadConfig::default();
    for path in [get_config_path(cwd), get_local_config_path(cwd)] {
        if let Some(raw) = read_raw_config_file(fs_, &path) {
            apply_config_source(&mut config, hook_section(&raw));
            apply_detector_config_source(&mut config, detector_section(&raw));
        }
    }
    config
}

/// Result of `setEnabled(cwd, true|false)`.
#[derive(Debug, Clone, PartialEq)]
pub struct SetEnabledResult {
    pub message: String,
}

/// `setEnabled(cwd, value)`. Manifest repair (`repairHookManifests`) is out
/// of scope for this packet (it touches per-provider hook manifest files
/// under `.claude/`, `.agents/`, `.cursor/`, `.github/` and is independent
/// glue logic); when `value` is `true` this reports "No installed provider
/// skill folders found to repair." unconditionally, matching the JS
/// behavior on a project with none of those directories present. See
/// `finish-r12.md`.
pub fn set_enabled(fs_: &mut dyn AdminFs, cwd: &Path, value: bool) -> io::Result<SetEnabledResult> {
    let existing = read_raw_hook_config(fs_, cwd, false);
    let mut cfg = merge_hook_config(existing.as_ref());
    cfg.enabled = value;
    let mut patch = Map::new();
    patch.insert("enabled".into(), Value::Bool(cfg.enabled));
    if let (Some(mf), Some(mc)) = (cfg.max_findings, cfg.max_chars) {
        let mut limits = Map::new();
        limits.insert("maxFindings".into(), Value::from(mf));
        limits.insert("maxChars".into(), Value::from(mc));
        patch.insert("limits".into(), Value::Object(limits));
    }
    let target = write_hook_config(fs_, cwd, &patch, false)?;
    let target_rel = target.strip_prefix(cwd).map(|p| p.display().to_string()).unwrap_or_else(|_| target.display().to_string());

    if !value {
        return Ok(SetEnabledResult { message: format!("Design hook disabled for this project (wrote {}).", target_rel) });
    }

    let mut local_patch = Map::new();
    local_patch.insert("consent".into(), Value::String("accepted".into()));
    let local_target = write_hook_config(fs_, cwd, &local_patch, true)?;
    let local_target_rel = local_target.strip_prefix(cwd).map(|p| p.display().to_string()).unwrap_or_else(|_| local_target.display().to_string());

    let parts = vec![
        format!("Design hook enabled for this project (wrote {}).", target_rel),
        format!("Recorded local hook consent in {}.", local_target_rel),
        "No installed provider skill folders found to repair.".to_string(),
    ];
    Ok(SetEnabledResult { message: parts.join(" ") })
}

fn add_ignore_rule(fs_: &mut dyn AdminFs, cwd: &Path, rule: &str, all_values: bool) -> Result<String, String> {
    let rule = normalize_rule_id(rule);
    if rule.is_empty() {
        return Err("Pass a rule id, e.g. /designer hooks ignore-rule side-tab".to_string());
    }
    if rule == "overused-font" && !all_values {
        return Err(
            "overused-font is value-specific by default. Use /designer hooks ignore-value overused-font <font> for a confirmed font, or /designer hooks ignore-rule overused-font --all-values only when the user asked to ignore overused fonts generally."
                .to_string(),
        );
    }
    let mut config = read_raw_detector_config(fs_, cwd, false);
    if !config.ignore_rules.contains(&rule) {
        config.ignore_rules.push(rule.clone());
    }
    write_detector_config(fs_, cwd, &config, false).map_err(|e| e.to_string())?;
    Ok(format!("Added \"{}\" to detector.ignoreRules. Current: {}", rule, config.ignore_rules.join(", ")))
}

fn add_ignore_file(fs_: &mut dyn AdminFs, cwd: &Path, glob: &str) -> Result<String, String> {
    if glob.is_empty() {
        return Err("Pass a glob, e.g. /designer hooks ignore-file \"src/legacy/**\"".to_string());
    }
    let mut config = read_raw_detector_config(fs_, cwd, false);
    if !config.ignore_files.iter().any(|f| f == glob) {
        config.ignore_files.push(glob.to_string());
    }
    write_detector_config(fs_, cwd, &config, false).map_err(|e| e.to_string())?;
    Ok(format!("Added \"{}\" to detector.ignoreFiles. Current: {}", glob, config.ignore_files.join(", ")))
}

struct IgnoreValueArgs {
    rule: String,
    value: String,
    shared: bool,
    local: bool,
    reason: String,
}

fn parse_ignore_value_args(args: &[String]) -> IgnoreValueArgs {
    let mut positionals: Vec<String> = Vec::new();
    let mut shared = false;
    let mut local = false;
    let mut reason = String::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--shared" {
            shared = true;
        } else if arg == "--local" {
            local = true;
        } else if arg == "--reason" {
            let mut chunks = Vec::new();
            while i + 1 < args.len() && !args[i + 1].starts_with("--") {
                i += 1;
                chunks.push(args[i].clone());
            }
            reason = chunks.join(" ").trim().to_string();
        } else if let Some(rest) = arg.strip_prefix("--reason=") {
            reason = rest.trim().to_string();
        } else {
            positionals.push(arg.clone());
        }
        i += 1;
    }
    let rule = positionals.first().cloned().unwrap_or_default().trim().to_lowercase();
    let value_raw = positionals.get(1..).map(|s| s.join(" ")).unwrap_or_default();
    IgnoreValueArgs { rule, value: normalize_ignore_value(&value_raw), shared, local, reason }
}

fn add_ignore_value(fs_: &mut dyn AdminFs, cwd: &Path, args: &[String]) -> Result<String, String> {
    let parsed = parse_ignore_value_args(args);
    if parsed.rule.is_empty() || parsed.value.is_empty() {
        return Err("Pass a rule id and value, e.g. /designer hooks ignore-value overused-font Inter".to_string());
    }
    if parsed.shared && parsed.local {
        return Err("Pass only one scope flag: --shared or --local".to_string());
    }
    let local = parsed.local;
    let mut config = read_raw_detector_config(fs_, cwd, local);
    let key = format!("{}\0{}", parsed.rule, parsed.value);
    if let Some(existing) = config.ignore_values.iter_mut().find(|e| format!("{}\0{}", e.rule, e.value) == key) {
        if !parsed.reason.is_empty() {
            existing.reason = Some(parsed.reason.clone());
        }
    } else {
        let entry = IgnoreValueEntry {
            rule: parsed.rule.clone(),
            value: parsed.value.clone(),
            files: Vec::new(),
            reason: if parsed.reason.is_empty() { None } else { Some(parsed.reason.clone()) },
            created_at: Some(now_iso8601()),
        };
        config.ignore_values.push(entry);
    }
    let target = write_detector_config(fs_, cwd, &config, local).map_err(|e| e.to_string())?;
    let scope = if local { "local detector.ignoreValues" } else { "shared detector.ignoreValues" };
    let target_rel = target.strip_prefix(cwd).map(|p| p.display().to_string()).unwrap_or_else(|_| target.display().to_string());
    Ok(format!("Added {}={} to {} ({}).", parsed.rule, parsed.value, scope, target_rel))
}

/// Wall-clock ISO-8601 timestamp, mirroring `new Date().toISOString()`.
/// Callers needing determinism in tests should not depend on the exact
/// value here; only its presence/shape is part of the contract.
fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", y, mo, d, h, m, s, millis)
}

/// Howard Hinnant's `civil_from_days` algorithm (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// `reset(cwd)`.
pub fn reset(fs_: &mut dyn AdminFs, cwd: &Path) -> String {
    let mut removed: Vec<String> = Vec::new();
    for path in [get_config_path(cwd), get_local_config_path(cwd)] {
        let Some(raw) = read_raw_config_file(fs_, &path) else { continue };
        if !raw.contains_key("hook") && !raw.contains_key("detector") {
            continue;
        }
        let mut rest = raw;
        rest.remove("hook");
        rest.remove("detector");
        let result = if rest.is_empty() {
            fs_.remove_file(&path)
        } else {
            let serialized = format!("{}\n", serde_json::to_string_pretty(&Value::Object(rest)).unwrap());
            fs_.write(&path, &serialized)
        };
        if result.is_ok() {
            let rel = path.strip_prefix(cwd).map(|p| p.display().to_string()).unwrap_or_else(|_| path.display().to_string());
            removed.push(rel);
        }
    }
    for path in [get_cache_path(cwd), get_pending_path(cwd)] {
        if fs_.exists(&path) && fs_.remove_file(&path).is_ok() {
            let rel = path.strip_prefix(cwd).map(|p| p.display().to_string()).unwrap_or_else(|_| path.display().to_string());
            removed.push(rel);
        }
    }
    if removed.is_empty() {
        "No hook config or cache to remove. Already at defaults.".to_string()
    } else {
        format!("Reset design hook config and cache (removed: {}).", removed.join(", "))
    }
}

// ---------------------------------------------------------------------
// CLI dispatcher (`main()` in hook-admin.mjs)
// ---------------------------------------------------------------------

/// Outcome of [`run_cli`]: stdout text plus process exit code, mirroring
/// hook-admin.mjs's `process.stdout.write` (exit 0) / `process.stderr.write`
/// + `process.exit(1)` behavior without touching the real process.
#[derive(Debug, Clone, PartialEq)]
pub struct CliOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// `main()`: dispatches `argv[2]` (default `"status"`) to the matching
/// action against `cwd`. `env_kill` stands in for
/// `process.env.IMPECCABLE_HOOK_DISABLED`.
pub fn run_cli(fs_: &mut dyn AdminFs, cwd: &Path, argv: &[String], env_kill: Option<&str>) -> CliOutcome {
    let action = argv.first().cloned().unwrap_or_else(|| "status".to_string()).to_lowercase();
    let rest: Vec<String> = argv.get(1..).map(|s| s.to_vec()).unwrap_or_default();

    if !ACTIONS.contains(&action.as_str()) {
        return CliOutcome {
            exit_code: 1,
            stdout: String::new(),
            stderr: format!("Unknown action: {}\nValid: {}\n", action, ACTIONS.join(",")),
        };
    }

    let result: Result<String, String> = match action.as_str() {
        "status" => Ok(status_report(fs_, cwd, env_kill)),
        "on" => set_enabled(fs_, cwd, true).map(|r| r.message).map_err(|e| e.to_string()),
        "off" => set_enabled(fs_, cwd, false).map(|r| r.message).map_err(|e| e.to_string()),
        "ignore-rule" => {
            let all_values = rest.iter().any(|a| a == "--all-values");
            let rule = rest.iter().find(|a| !a.starts_with("--")).cloned().unwrap_or_default();
            add_ignore_rule(fs_, cwd, &rule, all_values)
        }
        "ignore-file" => add_ignore_file(fs_, cwd, rest.first().map(String::as_str).unwrap_or("")),
        "ignore-value" => add_ignore_value(fs_, cwd, &rest),
        "reset" => Ok(reset(fs_, cwd)),
        _ => unreachable!(),
    };

    match result {
        Ok(out) => CliOutcome { exit_code: 0, stdout: format!("{}\n", out), stderr: String::new() },
        Err(msg) => CliOutcome { exit_code: 1, stdout: String::new(), stderr: format!("Error: {}\n", msg) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// In-memory fake filesystem for [`AdminFs`], keyed by absolute path.
    #[derive(Default)]
    struct FakeFs {
        files: HashMap<PathBuf, String>,
    }

    impl AdminFs for FakeFs {
        fn read_to_string(&self, path: &Path) -> Option<String> {
            self.files.get(path).cloned()
        }

        fn write(&mut self, path: &Path, content: &str) -> io::Result<()> {
            self.files.insert(path.to_path_buf(), content.to_string());
            Ok(())
        }

        fn exists(&self, path: &Path) -> bool {
            self.files.contains_key(path)
        }

        fn remove_file(&mut self, path: &Path) -> io::Result<()> {
            self.files.remove(path);
            Ok(())
        }
    }

    fn cwd() -> PathBuf {
        PathBuf::from("/project")
    }

    #[test]
    fn normalize_ignore_value_matches_js_semantics() {
        assert_eq!(normalize_ignore_value("  \"Inter\"  "), "inter");
        assert_eq!(normalize_ignore_value("'Open+Sans'"), "open sans");
        assert_eq!(normalize_ignore_value("Roboto   Mono"), "roboto mono");
        assert_eq!(normalize_ignore_value(""), "");
    }

    #[test]
    fn status_report_defaults_when_no_config_files() {
        let fs_ = FakeFs::default();
        let report = status_report(&fs_, &cwd(), None);
        assert!(report.contains("state:        enabled"));
        assert!(report.contains("using defaults; file not present"));
        assert!(report.contains("ignoreRules:  (none)"));
        assert!(report.contains("env override: unset"));
    }

    #[test]
    fn status_report_reflects_env_kill() {
        let fs_ = FakeFs::default();
        let report = status_report(&fs_, &cwd(), Some("1"));
        assert!(report.contains("env override: IMPECCABLE_HOOK_DISABLED=1"));
    }

    #[test]
    fn set_enabled_off_then_status_reports_disabled() {
        let mut fs_ = FakeFs::default();
        let outcome = run_cli(&mut fs_, &cwd(), &["off".to_string()], None);
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.contains("Design hook disabled"));
        let status = status_report(&fs_, &cwd(), None);
        assert!(status.contains("state:        disabled"));
    }

    #[test]
    fn set_enabled_on_writes_consent_and_reports_no_manifests() {
        let mut fs_ = FakeFs::default();
        let outcome = run_cli(&mut fs_, &cwd(), &["on".to_string()], None);
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.contains("Design hook enabled"));
        assert!(outcome.stdout.contains("Recorded local hook consent"));
        assert!(outcome.stdout.contains("No installed provider skill folders found to repair."));
        let local_raw = fs_.read_to_string(&get_local_config_path(&cwd())).unwrap();
        assert!(local_raw.contains("\"consent\": \"accepted\""));
    }

    #[test]
    fn ignore_rule_rejects_bare_overused_font() {
        let mut fs_ = FakeFs::default();
        let outcome = run_cli(&mut fs_, &cwd(), &["ignore-rule".to_string(), "overused-font".to_string()], None);
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.stderr.contains("value-specific by default"));
    }

    #[test]
    fn ignore_rule_accepts_overused_font_with_all_values() {
        let mut fs_ = FakeFs::default();
        let outcome = run_cli(
            &mut fs_,
            &cwd(),
            &["ignore-rule".to_string(), "overused-font".to_string(), "--all-values".to_string()],
            None,
        );
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.contains("Added \"overused-font\" to detector.ignoreRules"));
    }

    #[test]
    fn ignore_rule_requires_a_rule_id() {
        let mut fs_ = FakeFs::default();
        let outcome = run_cli(&mut fs_, &cwd(), &["ignore-rule".to_string()], None);
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.stderr.contains("Pass a rule id"));
    }

    #[test]
    fn ignore_file_appends_glob_and_dedupes() {
        let mut fs_ = FakeFs::default();
        run_cli(&mut fs_, &cwd(), &["ignore-file".to_string(), "src/legacy/**".to_string()], None);
        let outcome = run_cli(&mut fs_, &cwd(), &["ignore-file".to_string(), "src/legacy/**".to_string()], None);
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.stdout.matches("src/legacy/**").count(), 1);
    }

    #[test]
    fn ignore_value_shared_and_local_conflict_rejected() {
        let mut fs_ = FakeFs::default();
        let outcome = run_cli(
            &mut fs_,
            &cwd(),
            &["ignore-value".to_string(), "overused-font".to_string(), "Inter".to_string(), "--shared".to_string(), "--local".to_string()],
            None,
        );
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.stderr.contains("only one scope flag"));
    }

    #[test]
    fn ignore_value_writes_shared_by_default() {
        let mut fs_ = FakeFs::default();
        let outcome = run_cli(
            &mut fs_,
            &cwd(),
            &["ignore-value".to_string(), "overused-font".to_string(), "Inter".to_string()],
            None,
        );
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.contains("Added overused-font=inter to shared detector.ignoreValues"));
        let status = status_report(&fs_, &cwd(), None);
        assert!(status.contains("overused-font=inter"));
    }

    #[test]
    fn ignore_value_local_scope_uses_local_file() {
        let mut fs_ = FakeFs::default();
        let outcome = run_cli(
            &mut fs_,
            &cwd(),
            &["ignore-value".to_string(), "overused-font".to_string(), "Inter".to_string(), "--local".to_string()],
            None,
        );
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.contains("local detector.ignoreValues"));
        let local_raw = fs_.read_to_string(&get_local_config_path(&cwd())).unwrap();
        assert!(local_raw.contains("overused-font"));
    }

    #[test]
    fn reset_reports_nothing_to_remove_on_clean_project() {
        let mut fs_ = FakeFs::default();
        let out = reset(&mut fs_, &cwd());
        assert_eq!(out, "No hook config or cache to remove. Already at defaults.");
    }

    #[test]
    fn reset_removes_hook_and_detector_but_keeps_other_keys() {
        let mut fs_ = FakeFs::default();
        run_cli(&mut fs_, &cwd(), &["off".to_string()], None);
        run_cli(&mut fs_, &cwd(), &["ignore-file".to_string(), "src/legacy/**".to_string()], None);
        // Add an unrelated key the admin must preserve.
        let path = get_config_path(&cwd());
        let raw = fs_.read_to_string(&path).unwrap();
        let mut value: Value = serde_json::from_str(&raw).unwrap();
        value.as_object_mut().unwrap().insert("updateCheck".into(), Value::Bool(true));
        fs_.write(&path, &serde_json::to_string_pretty(&value).unwrap()).unwrap();

        let out = reset(&mut fs_, &cwd());
        assert!(out.contains("Reset design hook config and cache"));
        let remaining = fs_.read_to_string(&path).unwrap();
        let remaining_value: Value = serde_json::from_str(&remaining).unwrap();
        assert!(remaining_value.get("hook").is_none());
        assert!(remaining_value.get("updateCheck").is_some());
    }

    #[test]
    fn unknown_action_exits_nonzero() {
        let mut fs_ = FakeFs::default();
        let outcome = run_cli(&mut fs_, &cwd(), &["bogus".to_string()], None);
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.stderr.contains("Unknown action: bogus"));
    }

    #[test]
    fn default_action_is_status() {
        let mut fs_ = FakeFs::default();
        let outcome = run_cli(&mut fs_, &cwd(), &[], None);
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.contains("Impeccable design hook"));
    }

    #[test]
    fn normalize_ignore_value_entries_drops_malformed() {
        let entries = vec![
            serde_json::json!({"rule": "overused-font", "value": "Inter"}),
            serde_json::json!({"rule": "", "value": "x"}),
            serde_json::json!("not-an-object"),
        ];
        let out = normalize_ignore_value_entries(&entries);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule, "overused-font");
        assert_eq!(out[0].value, "inter");
    }

    #[test]
    fn merge_ignore_value_entries_incoming_wins_on_key_collision() {
        let existing = vec![IgnoreValueEntry {
            rule: "r".into(),
            value: "v".into(),
            files: vec![],
            reason: Some("old".into()),
            created_at: None,
        }];
        let incoming = vec![IgnoreValueEntry {
            rule: "r".into(),
            value: "v".into(),
            files: vec![],
            reason: Some("new".into()),
            created_at: None,
        }];
        let merged = merge_ignore_value_entries(&existing, &incoming);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].reason.as_deref(), Some("new"));
    }
}
