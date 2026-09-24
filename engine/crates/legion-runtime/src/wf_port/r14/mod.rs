//! Port of `skills/designer/engine/scripts/hook-lib.mjs` (packet r14).
//!
//! `wf_port::w2_015` already ports the pure, filesystem-free half of
//! hook-lib.mjs (glob matching, ignore-value normalization/color parsing,
//! finding filtering + cache-key computation, and the low-level
//! `format_finding_line` / `payload` helpers). This module ports the rest:
//! on-disk config/cache I/O (`readConfig`, `readCache`, `persistCache`,
//! `ensureHookGitExcludes`), hook-event normalization across harnesses
//! (Claude/Codex, Cursor, GitHub Copilot), scan-target resolution/expansion
//! (co-located stylesheets, static style imports), the developer-role text
//! templates (`renderTemplate`/`renderGroupedTemplate`/`renderCleanAck`/
//! `renderPendingAck`), audit-log writing, and the `runHook` orchestration
//! seam with an injectable `Detector` trait standing in for the dynamically
//! `import()`-ed `detect-antipatterns.mjs` module.
//!
//! Not ported: the detector itself (`detect-antipatterns.mjs`, a separate
//! file outside this packet) — callers supply a `Detector` impl. Real
//! detector wiring, and the `hook.mjs` stdin/stdout process shim, are
//! integration concerns for whichever packet wires up `legion-hook`.

pub mod real_detector_adapter;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::wf_port::w2_015::{
    dedupe_against_cache, filter_findings, finding_cache_key, format_finding_line,
    matches_any_glob, normalize_ignore_value, payload as w2_015_payload, should_emit_ack_for_file,
    suppression_notice, Finding, Harness, IgnoreValueEntry, ENVELOPE_PREFIX,
    EDIT_COUNT_THRESHOLD,
};

// ---------------------------------------------------------------------
// Constants (ALLOWED_EXTS / SENSITIVE_PATH / GENERATED_PATH / TRUTHY)
// ---------------------------------------------------------------------

/// Mirrors `ALLOWED_EXTS` in hook-lib.mjs.
pub fn allowed_exts() -> &'static [&'static str] {
    &[
        ".tsx", ".jsx", ".html", ".htm", ".vue", ".svelte", ".astro", ".css", ".scss", ".sass",
        ".less", ".ts", ".js",
    ]
}

/// Mirrors `ACK_EXTS` in hook-lib.mjs (re-exported here for callers that
/// only depend on r14; `w2_015::should_emit_ack_for_file` is the source of
/// truth and is used internally).
pub fn ack_exts() -> &'static [&'static str] {
    &[
        ".tsx", ".jsx", ".html", ".htm", ".vue", ".svelte", ".astro", ".css", ".scss", ".sass",
        ".less",
    ]
}

fn sensitive_path_re() -> Regex {
    // Mirrors `SENSITIVE_PATH` in hook-lib.mjs.
    Regex::new(
        r"(?ix)
        (?:^|[/\\])\.env(?:\.|$)
        | (?:^|[/\\])\.git(?:[/\\]|$)
        | (?:^|[/\\])id_rsa(?:$|[._-])[^/\\]*$
        | (?:^|[/\\])[^/\\]*\.pem$
        | (?:^|[/\\])(?:[^/\\]*[._-])?(?:secret|secrets|credential|credentials)[._-][^/\\]*\.(?:json|ya?ml|toml|ini|conf|config|env|txt|key|cert|crt|pem|js|ts)$
        ",
    )
    .expect("SENSITIVE_PATH regex must compile")
}

fn generated_path_re() -> Regex {
    // Mirrors `GENERATED_PATH` in hook-lib.mjs.
    Regex::new(
        r"(?ix)
        (?:\.generated\.[a-z]+$
        | \.d\.ts$
        | \.min\.[a-z]+$
        | [/\\]node_modules[/\\]
        | [/\\](?:dist|build|out|\.next|\.cache|coverage)[/\\]
        | [/\\]?[^/\\]+\.lock(?:\.json)?$)
        ",
    )
    .expect("GENERATED_PATH regex must compile")
}

/// Mirrors `SENSITIVE_PATH.test(filePath)`.
pub fn is_sensitive_path(file_path: &str) -> bool {
    sensitive_path_re().is_match(file_path)
}

/// Mirrors `GENERATED_PATH.test(filePath)`.
pub fn is_generated_path(file_path: &str) -> bool {
    generated_path_re().is_match(file_path)
}

/// Mirrors `TRUTHY` regex used by `truthy()` and `depthIsSet()`.
pub fn truthy(value: Option<&str>) -> bool {
    match value {
        Some(v) => crate::wf_port::w2_015::truthy(v),
        None => false,
    }
}

fn depth_is_set(value: Option<&str>) -> bool {
    let Some(v) = value else { return false };
    let text = v.trim();
    if text.is_empty() {
        return false;
    }
    if crate::wf_port::w2_015::truthy(text) {
        return true;
    }
    text.chars().all(|c| c.is_ascii_digit()) && text.parse::<u64>().map(|n| n > 0).unwrap_or(false)
}

// ---------------------------------------------------------------------
// Config (`readConfig` / `DEFAULT_CONFIG` / path helpers)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Limits {
    pub max_findings: u32,
    pub max_chars: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_findings: 5,
            max_chars: 8000,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DesignSystemConfig {
    pub enabled: bool,
}

impl Default for DesignSystemConfig {
    fn default() -> Self {
        DesignSystemConfig { enabled: true }
    }
}

/// Mirrors `DEFAULT_CONFIG` merged with `.impeccable/config.json` and
/// `.impeccable/config.local.json` (local wins) in hook-lib.mjs.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub enabled: bool,
    pub quiet: bool,
    pub audit_log: Option<String>,
    pub design_system: DesignSystemConfig,
    pub ignore_rules: Vec<String>,
    pub ignore_files: Vec<String>,
    pub ignore_values: Vec<IgnoreValueEntry>,
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: true,
            quiet: false,
            audit_log: None,
            design_system: DesignSystemConfig::default(),
            ignore_rules: Vec::new(),
            ignore_files: Vec::new(),
            ignore_values: Vec::new(),
            limits: Limits::default(),
        }
    }
}

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

/// Mirrors `envProjectDir(fallback)`: `$CURSOR_PROJECT_DIR` if set and
/// non-empty, else `fallback`.
fn env_project_dir(env: &HashMap<String, String>, fallback: &str) -> String {
    match env.get("CURSOR_PROJECT_DIR") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => fallback.to_string(),
    }
}

/// Mirrors `resolveProjectCwd(event, fallback = process.cwd())`: prefer
/// `event.cwd`, then the first `event.workspace_roots` entry, then
/// `$CURSOR_PROJECT_DIR`, then `fallback`.
pub fn resolve_project_cwd(event: &Value, env: &HashMap<String, String>, fallback: &str) -> String {
    if let Some(cwd) = event.get("cwd").and_then(|v| v.as_str()) {
        if !cwd.is_empty() {
            return cwd.to_string();
        }
    }
    if let Some(root) = event
        .get("workspace_roots")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
    {
        if !root.is_empty() {
            return root.to_string();
        }
    }
    env_project_dir(env, fallback)
}

fn safe_read_json(path: &Path) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn hook_section(raw: &Value) -> Option<&Value> {
    raw.get("hook").filter(|v| v.is_object())
}

fn detector_section(raw: &Value) -> Option<&Value> {
    raw.get("detector").filter(|v| v.is_object())
}

fn number_or(value: Option<&Value>, fallback: u32) -> u32 {
    match value.and_then(|v| v.as_f64()) {
        Some(n) if n.is_finite() && n > 0.0 => n as u32,
        _ => fallback,
    }
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

fn json_str_vec(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn json_ignore_value_entries(value: &Value, key: &str) -> Vec<IgnoreValueEntry> {
    let Some(arr) = value.get(key).and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in arr {
        let Some(obj) = entry.as_object() else { continue };
        let rule = obj
            .get("rule")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let raw_value = obj.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let val = normalize_ignore_value(raw_value);
        if rule.is_empty() || val.is_empty() {
            continue;
        }
        let mut files: Vec<String> = Vec::new();
        if let Some(f) = obj.get("file").and_then(|v| v.as_str()) {
            let f = f.trim();
            if !f.is_empty() {
                files.push(f.to_string());
            }
        }
        if let Some(arr) = obj.get("files").and_then(|v| v.as_array()) {
            for f in arr {
                if let Some(s) = f.as_str() {
                    let s = s.trim();
                    if !s.is_empty() {
                        files.push(s.to_string());
                    }
                }
            }
        }
        let files = unique_strings(files);
        out.push(IgnoreValueEntry {
            rule,
            value: val,
            files,
        });
    }
    out
}

fn merge_ignore_values(
    existing: &[IgnoreValueEntry],
    incoming: Vec<IgnoreValueEntry>,
) -> Vec<IgnoreValueEntry> {
    // Mirrors `mergeIgnoreValues`: last write per (rule, value, files) wins,
    // insertion order otherwise preserved (JS `Map` iteration order).
    let key = |e: &IgnoreValueEntry| format!("{}\0{}\0{}", e.rule, e.value, e.files.join("\u{1f}"));
    let mut order: Vec<String> = Vec::new();
    let mut map: HashMap<String, IgnoreValueEntry> = HashMap::new();
    for e in existing.iter().cloned().chain(incoming) {
        let k = key(&e);
        if !map.contains_key(&k) {
            order.push(k.clone());
        }
        map.insert(k, e);
    }
    order.into_iter().map(|k| map.remove(&k).unwrap()).collect()
}

fn apply_detector_config_source(config: &mut Config, raw: Option<&Value>) {
    let Some(raw) = raw else { return };
    if let Some(ds) = raw.get("designSystem").filter(|v| v.is_object()) {
        let enabled = ds.get("enabled").and_then(|v| v.as_bool()) != Some(false);
        config.design_system = DesignSystemConfig { enabled };
    }
    if raw.get("ignoreRules").map(|v| v.is_array()) == Some(true) {
        let mut merged = config.ignore_rules.clone();
        merged.extend(json_str_vec(raw, "ignoreRules"));
        config.ignore_rules = unique_strings(merged);
    }
    if raw.get("ignoreFiles").map(|v| v.is_array()) == Some(true) {
        let mut merged = config.ignore_files.clone();
        merged.extend(json_str_vec(raw, "ignoreFiles"));
        config.ignore_files = unique_strings(merged);
    }
    if raw.get("ignoreValues").map(|v| v.is_array()) == Some(true) {
        let incoming = json_ignore_value_entries(raw, "ignoreValues");
        config.ignore_values = merge_ignore_values(&config.ignore_values, incoming);
    }
}

fn apply_config_source(config: &mut Config, raw: Option<&Value>) {
    let Some(raw) = raw else { return };
    if let Some(v) = raw.get("enabled") {
        config.enabled = v.as_bool() != Some(false);
    }
    if let Some(v) = raw.get("quiet") {
        config.quiet = v.as_bool() == Some(true);
    }
    if let Some(v) = raw.get("auditLog").and_then(|v| v.as_str()) {
        let v = v.trim();
        if !v.is_empty() {
            config.audit_log = Some(v.to_string());
        }
    }
    apply_detector_config_source(config, Some(raw));
    if let Some(limits) = raw.get("limits").filter(|v| v.is_object()) {
        config.limits = Limits {
            max_findings: number_or(limits.get("maxFindings"), config.limits.max_findings),
            max_chars: number_or(limits.get("maxChars"), config.limits.max_chars),
        };
    }
}

/// Mirrors `readConfig(cwd)`: reads `config.json` then `config.local.json`,
/// applying `hook.*` and `detector.*` subtrees from each (local wins).
pub fn read_config(cwd: &Path) -> Config {
    let mut config = Config::default();
    for path in [get_config_path(cwd), get_local_config_path(cwd)] {
        let Some(raw) = safe_read_json(&path) else {
            continue;
        };
        if !raw.is_object() {
            continue;
        }
        apply_config_source(&mut config, hook_section(&raw));
        apply_detector_config_source(&mut config, detector_section(&raw));
    }
    config
}

// ---------------------------------------------------------------------
// Cache (`readCache` / `persistCache` / `bumpEditCount` / `rememberFindings`)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileEntry {
    #[serde(rename = "editCount", default)]
    pub edit_count: u32,
    #[serde(default)]
    pub findings: Vec<String>,
    /// Mirrors `fileEntry.cursorDenials`: a map from finding-signature key
    /// (`bumpCursorDenial`'s `findingSignature`) to repeat-denial count,
    /// used only by `hook-before-edit.mjs`'s Cursor preToolUse gate.
    #[serde(rename = "cursorDenials", default, skip_serializing_if = "HashMap::is_empty")]
    pub cursor_denials: HashMap<String, u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Session {
    #[serde(rename = "updatedAt", default)]
    pub updated_at: i64,
    #[serde(default)]
    pub files: HashMap<String, FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cache {
    pub version: u32,
    #[serde(default)]
    pub sessions: HashMap<String, Session>,
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            version: 1,
            sessions: HashMap::new(),
        }
    }
}

const CACHE_MAX_SESSIONS: usize = 8;

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Mirrors `readCache(cwd)`.
pub fn read_cache(cwd: &Path) -> Cache {
    match safe_read_json(&get_cache_path(cwd)) {
        Some(raw) if raw.get("version").and_then(|v| v.as_i64()) == Some(1) => {
            serde_json::from_value(raw).unwrap_or_default()
        }
        _ => Cache::default(),
    }
}

/// Mirrors `persistCache(cwd, cache)`: GCs sessions beyond
/// `CACHE_MAX_SESSIONS` (keeping the most-recently-updated), calls
/// `ensureHookGitExcludes`, then writes the cache JSON. Returns `true` on
/// success, matching the JS boolean return (errors are swallowed).
pub fn persist_cache(cwd: &Path, mut cache: Cache) -> bool {
    if cache.sessions.len() > CACHE_MAX_SESSIONS {
        let mut ids: Vec<(String, i64)> = cache
            .sessions
            .iter()
            .map(|(id, s)| (id.clone(), s.updated_at))
            .collect();
        ids.sort_by(|a, b| b.1.cmp(&a.1));
        ids.truncate(CACHE_MAX_SESSIONS);
        let keep: std::collections::HashSet<String> = ids.into_iter().map(|(id, _)| id).collect();
        cache.sessions.retain(|id, _| keep.contains(id));
    }
    let target = get_cache_path(cwd);
    let _ = ensure_hook_git_excludes(cwd);
    let Some(parent) = target.parent() else {
        return false;
    };
    if fs::create_dir_all(parent).is_err() {
        return false;
    }
    let Ok(json) = serde_json::to_string(&cache) else {
        return false;
    };
    fs::write(&target, json).is_ok()
}

const HOOK_LOCAL_IGNORE_PATTERNS: &[&str] = &[
    ".impeccable/hook.cache.json",
    ".impeccable/hook.pending.json",
    ".impeccable/config.local.json",
];
const HOOK_IGNORE_MARKER_OPEN: &str = "# impeccable-hook-ignore-start";
const HOOK_IGNORE_MARKER_CLOSE: &str = "# impeccable-hook-ignore-end";

#[derive(Debug, Clone, PartialEq)]
pub struct ExcludeResult {
    pub mode: &'static str,
    pub file: Option<String>,
    pub changed: bool,
    pub patterns: Vec<String>,
}

fn resolve_git_dir(dot_git: &Path, worktree_dir: &Path) -> Option<PathBuf> {
    let meta = fs::metadata(dot_git).ok()?;
    if meta.is_dir() {
        return Some(dot_git.to_path_buf());
    }
    if !meta.is_file() {
        return None;
    }
    let body = fs::read_to_string(dot_git).ok()?;
    let body = body.trim();
    let rest = body.strip_prefix("gitdir:")?.trim();
    let candidate = PathBuf::from(rest);
    Some(if candidate.is_absolute() {
        candidate
    } else {
        worktree_dir.join(candidate)
    })
}

struct HookGitExcludeTarget {
    path: PathBuf,
    pattern_prefix: String,
}

fn resolve_hook_git_exclude_target(cwd: &Path) -> Option<HookGitExcludeTarget> {
    let start = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let mut dir = start.clone();
    loop {
        let dot_git = dir.join(".git");
        if dot_git.exists() {
            let git_dir = resolve_git_dir(&dot_git, &dir)?;
            let rel_prefix = start
                .strip_prefix(&dir)
                .ok()
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            let rel_prefix = if rel_prefix == "." { String::new() } else { rel_prefix };
            return Some(HookGitExcludeTarget {
                path: git_dir.join("info").join("exclude"),
                pattern_prefix: rel_prefix,
            });
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent.to_path_buf(),
            _ => return None,
        }
    }
}

/// Mirrors `ensureHookGitExcludes(cwd)`: idempotently maintains a marked
/// block of hook-local ignore patterns in `.git/info/exclude`.
pub fn ensure_hook_git_excludes(cwd: &Path) -> ExcludeResult {
    let Some(target) = resolve_hook_git_exclude_target(cwd) else {
        return ExcludeResult {
            mode: "none",
            file: None,
            changed: false,
            patterns: HOOK_LOCAL_IGNORE_PATTERNS.iter().map(|s| s.to_string()).collect(),
        };
    };

    let patterns: Vec<String> = if target.pattern_prefix.is_empty() {
        HOOK_LOCAL_IGNORE_PATTERNS.iter().map(|s| s.to_string()).collect()
    } else {
        HOOK_LOCAL_IGNORE_PATTERNS
            .iter()
            .map(|p| format!("{}/{}", target.pattern_prefix, p))
            .collect()
    };
    let marker_suffix = if target.pattern_prefix.is_empty() {
        ".".to_string()
    } else {
        target.pattern_prefix.clone()
    };
    let marker_open = format!("{HOOK_IGNORE_MARKER_OPEN} {marker_suffix}");
    let marker_close = format!("{HOOK_IGNORE_MARKER_CLOSE} {marker_suffix}");
    let existing = fs::read_to_string(&target.path).unwrap_or_default();
    let block = {
        let mut lines = vec![marker_open.clone()];
        lines.extend(patterns.iter().cloned());
        lines.push(marker_close.clone());
        lines.join("\n")
    };

    let updated = match (existing.find(&marker_open), existing.find(&marker_close)) {
        (Some(open_idx), Some(close_idx)) if close_idx > open_idx => {
            let end = close_idx + marker_close.len();
            format!("{}{}{}", &existing[..open_idx], block, &existing[end..])
        }
        _ => {
            let prefix = if existing.is_empty() {
                String::new()
            } else if existing.ends_with('\n') {
                existing.clone()
            } else {
                format!("{existing}\n")
            };
            let sep = if prefix.ends_with("\n\n") || prefix.is_empty() { "" } else { "\n" };
            format!("{prefix}{sep}{block}\n")
        }
    };

    let changed = updated != existing;
    if changed {
        if let Some(parent) = target.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&target.path, &updated);
    }

    ExcludeResult {
        mode: "git-info-exclude",
        file: Some(target.path.to_string_lossy().replace('\\', "/")),
        changed,
        patterns,
    }
}

fn ensure_session<'a>(cache: &'a mut Cache, session_id: &str) -> &'a mut Session {
    cache
        .sessions
        .entry(session_id.to_string())
        .or_insert_with(|| Session {
            updated_at: now_millis(),
            files: HashMap::new(),
        })
}

fn ensure_file<'a>(cache: &'a mut Cache, session_id: &str, file_path: &str) -> &'a mut FileEntry {
    let session = ensure_session(cache, session_id);
    session.files.entry(file_path.to_string()).or_default()
}

/// Mirrors `bumpEditCount(cache, sessionId, filePath)`.
pub fn bump_edit_count(cache: &mut Cache, session_id: &str, file_path: &str) -> u32 {
    {
        let entry = ensure_file(cache, session_id, file_path);
        entry.edit_count += 1;
    }
    ensure_session(cache, session_id).updated_at = now_millis();
    cache.sessions[session_id].files[file_path].edit_count
}

/// Mirrors `rememberFindings(cache, sessionId, filePath, findings)`.
pub fn remember_findings(cache: &mut Cache, session_id: &str, file_path: &str, findings: &[Finding]) {
    let known_keys: Vec<String> = {
        let entry = ensure_file(cache, session_id, file_path);
        let mut known: Vec<String> = entry.findings.clone();
        let mut seen: std::collections::HashSet<String> = known.iter().cloned().collect();
        for f in findings {
            let key = finding_cache_key(f);
            if seen.insert(key.clone()) {
                known.push(key);
            }
        }
        known
    };
    ensure_file(cache, session_id, file_path).findings = known_keys;
    ensure_session(cache, session_id).updated_at = now_millis();
}

// ---------------------------------------------------------------------
// Text templates (`renderTemplate` / `renderGroupedTemplate` / acks)
// ---------------------------------------------------------------------

fn relativize(file_path: &str, cwd: &Path) -> String {
    let p = Path::new(file_path);
    match p.strip_prefix(cwd) {
        Ok(rel) if !rel.as_os_str().is_empty() => rel.to_string_lossy().replace('\\', "/"),
        _ => file_path.to_string(),
    }
}

fn directive_footer(display: &str, grouped: bool) -> String {
    let ignore_file_command = format!("/designer hooks ignore-file {}", quote_command_arg(display));
    let file_ignore_guidance = if grouped {
        "run `/designer hooks ignore-file <path>` for the specific file".to_string()
    } else {
        format!("run `{ignore_file_command}`")
    };
    [
        "Handle these before finalizing: fix findings that are real design problems, or explicitly classify contextually intentional findings as false positives. Acknowledge what you changed or why you are leaving a finding unchanged.".to_string(),
        String::new(),
        "Use context judgment before editing. A finding is not automatically a defect; literal or domain-appropriate motion, intentional demos or fixtures, documentation of bad design, and user-confirmed choices can be valid as-is.".to_string(),
        String::new(),
        format!(
            "Do not change intentional design just to satisfy the hook. Do not add source comments such as `impeccable: ignore`; those pollute the code and do not suppress hook findings. Persist hook ignores only after the user explicitly confirms the finding is intentional. Prefer the narrowest persisted exception: run the exact `/designer hooks ignore-value ... --shared` command shown next to a value-specific finding. For `overused-font`, use `ignore-value` for a specific font and use `/designer hooks ignore-rule overused-font --all-values` only when the user asks to ignore overused fonts generally. For file-specific findings without an ignore-value command, {file_ignore_guidance}; use `/designer hooks ignore-rule <id>` only when the user asks to suppress the whole non-value-specific rule. Run /designer audit for the full pass."
        ),
    ]
    .join("\n")
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
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Mirrors `renderTemplate(findings, filePath, config, opts)`.
pub fn render_template(findings: &[Finding], file_path: &str, config: &Config, cwd: &Path) -> String {
    if findings.is_empty() {
        return String::new();
    }
    let cap = config.limits.max_findings.max(1) as usize;
    let max_chars = config.limits.max_chars.max(500) as usize;
    let display = relativize(file_path, cwd);
    let total = findings.len();
    let shown: Vec<&Finding> = findings.iter().take(cap).collect();
    let remaining = total - shown.len();

    let header = format!(
        "{ENVELOPE_PREFIX} Design hook findings requiring review in {display} ({total} issue(s)):"
    );
    let lines: Vec<String> = shown.iter().map(|f| format_finding_line(f)).collect();
    let more = if remaining > 0 {
        Some(format!("... and {remaining} more (see /designer audit)."))
    } else {
        None
    };
    let footer = directive_footer(&display, false);

    let mut blocks = vec![header.clone()];
    blocks.extend(lines.clone());
    if let Some(m) = &more {
        blocks.push(m.clone());
    }
    blocks.push(String::new());
    blocks.push(footer.clone());
    let text = blocks.join("\n");

    if text.chars().count() > max_chars {
        clamp_to_budget(&header, &lines, more, &footer, max_chars)
    } else {
        text
    }
}

fn clamp_to_budget(header: &str, lines: &[String], mut more: Option<String>, footer: &str, max_chars: usize) -> String {
    let assemble = |working: &[String], more: &Option<String>| {
        let mut blocks = vec![header.to_string()];
        blocks.extend(working.iter().cloned());
        if let Some(m) = more {
            blocks.push(m.clone());
        }
        blocks.push(String::new());
        blocks.push(footer.to_string());
        blocks.join("\n")
    };
    let mut working = lines.to_vec();
    let mut assembled = assemble(&working, &more);
    while assembled.chars().count() > max_chars && working.len() > 1 {
        working.pop();
        more = Some("... and more (see /designer audit).".to_string());
        assembled = assemble(&working, &more);
    }
    if assembled.chars().count() > max_chars {
        let truncated: String = assembled.chars().take(max_chars.saturating_sub(1)).collect();
        assembled = format!("{truncated}\u{2026}");
    }
    assembled
}

/// One file's group of fresh findings, for `render_grouped_template`.
pub struct FindingGroup {
    pub file_path: String,
    pub findings: Vec<Finding>,
}

/// Mirrors `renderGroupedTemplate(groups, config, opts)`.
pub fn render_grouped_template(groups: &[FindingGroup], config: &Config, cwd: &Path) -> String {
    let real_groups: Vec<&FindingGroup> = groups.iter().filter(|g| !g.findings.is_empty()).collect();
    if real_groups.is_empty() {
        return String::new();
    }
    if real_groups.len() == 1 {
        let g = real_groups[0];
        return render_template(&g.findings, &g.file_path, config, cwd);
    }

    let cap = config.limits.max_findings.max(1) as usize;
    let max_chars = config.limits.max_chars.max(500) as usize;
    let total: usize = real_groups.iter().map(|g| g.findings.len()).sum();
    let header = format!(
        "{ENVELOPE_PREFIX} Design hook findings requiring review across {} files ({total} issue(s)):",
        real_groups.len()
    );
    let mut lines = Vec::new();
    let mut shown_count = 0usize;
    for group in &real_groups {
        let display = relativize(&group.file_path, cwd);
        lines.push(format!("{display} ({} issue(s)):", group.findings.len()));
        let remaining_cap = cap.saturating_sub(shown_count);
        let shown: Vec<&Finding> = group.findings.iter().take(remaining_cap).collect();
        for f in &shown {
            lines.push(format_finding_line(f));
        }
        shown_count += shown.len();
        let hidden = group.findings.len() - shown.len();
        if hidden > 0 {
            lines.push(format!("- ... {hidden} more in {display} (see /designer audit)."));
        }
    }

    let footer = directive_footer("the affected files", true);
    let text = {
        let mut blocks = vec![header.clone()];
        blocks.extend(lines.clone());
        blocks.push(String::new());
        blocks.push(footer.clone());
        blocks.join("\n")
    };
    if text.chars().count() > max_chars {
        clamp_grouped_to_budget(&header, &lines, &footer, max_chars)
    } else {
        text
    }
}

fn clamp_grouped_to_budget(header: &str, lines: &[String], footer: &str, max_chars: usize) -> String {
    let assemble = |working: &[String], omitted: bool| {
        let mut blocks = vec![header.to_string()];
        blocks.extend(working.iter().cloned());
        if omitted {
            blocks.push("... and more (see /designer audit).".to_string());
        }
        blocks.push(String::new());
        blocks.push(footer.to_string());
        blocks.join("\n")
    };
    let mut working = lines.to_vec();
    let mut omitted = false;
    let mut assembled = assemble(&working, omitted);
    while assembled.chars().count() > max_chars && working.len() > 1 {
        working.pop();
        omitted = true;
        assembled = assemble(&working, omitted);
    }
    if assembled.chars().count() > max_chars {
        let truncated: String = assembled.chars().take(max_chars.saturating_sub(1)).collect();
        assembled = format!("{truncated}\u{2026}");
    }
    assembled
}

const STEER_LINE: &str =
    "Keep typography hierarchy, spacing rhythm, and color contrast intentional on the next change.";

/// Mirrors `renderCleanAck(filePath, opts)`.
pub fn render_clean_ack(file_path: &str, cwd: &Path) -> String {
    let display = relativize(file_path, cwd);
    format!("{ENVELOPE_PREFIX} Design hook scanned {display}. No anti-patterns. {STEER_LINE}")
}

/// Mirrors `renderPendingAck(filePath, knownFindings, opts)`.
pub fn render_pending_ack(file_path: &str, known_findings: &[String], cwd: &Path) -> String {
    let display = relativize(file_path, cwd);
    let count = known_findings.len();
    let sample = known_findings.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    let more = if count > 3 {
        format!(", +{} more", count - 3)
    } else {
        String::new()
    };
    format!(
        "{ENVELOPE_PREFIX} Design hook scanned {display}. Still has {count} finding(s) flagged earlier this session ({sample}{more}). Handle them before finalizing — the previous reminder still applies."
    )
}

/// Mirrors `appendDesignSystemNote(text, scanOptions)`.
pub fn append_design_system_note(text: String, md_newer_than_json: bool) -> String {
    if text.is_empty() || !md_newer_than_json {
        return text;
    }
    format!("{text}\n\n{ENVELOPE_PREFIX} DESIGN.md is newer than .impeccable/design.json. Run /designer document to refresh the design-system sidecar.")
}

// ---------------------------------------------------------------------
// Event/harness normalization
// ---------------------------------------------------------------------

fn apply_patch_file_re() -> Regex {
    Regex::new(r"(?m)^\*\*\* (?:Update|Add) File: (.+)$").expect("APPLY_PATCH_FILE_RE must compile")
}

/// Mirrors `parseApplyPatchPaths(command, projectCwd)`.
pub fn parse_apply_patch_paths(command: &str, project_cwd: &Path) -> Vec<String> {
    let re = apply_patch_file_re();
    let mut out = Vec::new();
    for cap in re.captures_iter(command) {
        let p = cap[1].trim();
        if p.is_empty() {
            continue;
        }
        let path = Path::new(p);
        let abs = if path.is_absolute() {
            path.to_path_buf()
        } else {
            project_cwd.join(path)
        };
        out.push(abs.to_string_lossy().replace('\\', "/"));
    }
    out
}

/// Mirrors `resolveTargetFiles(event, projectCwd)`. `event` is the raw JSON
/// event value (already harness-normalized by `normalize_hook_event`).
pub fn resolve_target_files(event: &Value, project_cwd: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |p: Option<&str>, out: &mut Vec<String>| {
        if let Some(p) = p {
            if !p.is_empty() && !out.iter().any(|x| x == p) {
                out.push(p.to_string());
            }
        }
    };

    let ti = event.get("tool_input");
    let tool_name = event.get("tool_name").and_then(|v| v.as_str());
    if tool_name == Some("apply_patch") {
        if let Some(command) = ti.and_then(|t| t.get("command")).and_then(|v| v.as_str()) {
            for p in parse_apply_patch_paths(command, project_cwd) {
                add(Some(&p), &mut out);
            }
        }
    }
    if let Some(fp) = ti.and_then(|t| t.get("file_path")).and_then(|v| v.as_str()) {
        add(Some(fp), &mut out);
    }
    if let Some(p) = ti.and_then(|t| t.get("path")).and_then(|v| v.as_str()) {
        add(Some(p), &mut out);
    }
    if let Some(fp) = event.get("file_path").and_then(|v| v.as_str()) {
        add(Some(fp), &mut out);
    }
    out
}

/// Mirrors `resolveHarness(env, event)`.
pub fn resolve_harness(env: &HashMap<String, String>, event: Option<&Value>) -> Harness {
    match env.get("IMPECCABLE_HOOK_HARNESS").map(|s| s.as_str()) {
        Some("cursor") => return Harness::Cursor,
        Some("github") => return Harness::Github,
        Some("claude") | Some("codex") => return Harness::Claude,
        _ => {}
    }
    if let Some(event) = event {
        if event.is_object() {
            let has_camel = event.get("toolName").and_then(|v| v.as_str()).is_some()
                || event.get("toolArgs").is_some();
            let has_snake = event.get("tool_name").is_some() || event.get("tool_input").is_some();
            if has_camel && !has_snake {
                return Harness::Github;
            }
        }
        if let Some(cid) = event.get("conversation_id").and_then(|v| v.as_str()) {
            if !cid.is_empty() {
                return Harness::Cursor;
            }
        }
    }
    Harness::Claude
}

fn apply_patch_marker_re() -> Regex {
    Regex::new(r"\*\*\* (?:Begin Patch|Add File:|Update File:|Delete File:)")
        .expect("APPLY_PATCH_MARKER must compile")
}

/// Mirrors `parseGitHubToolArgs(toolArgs)`.
pub fn parse_github_tool_args(tool_args: &Value) -> Value {
    if tool_args.is_object() {
        return tool_args.clone();
    }
    if let Some(s) = tool_args.as_str() {
        if !s.trim().is_empty() {
            if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                if parsed.is_object() {
                    return parsed;
                }
            }
        }
    }
    Value::Object(Default::default())
}

fn looks_like_apply_patch(raw_args: &Value) -> bool {
    let Some(s) = raw_args.as_str() else { return false };
    if !apply_patch_marker_re().is_match(s) {
        return false;
    }
    if let Ok(parsed) = serde_json::from_str::<Value>(s) {
        if parsed.is_object() {
            return false;
        }
    }
    true
}

fn apply_patch_text(raw_args: &Value) -> String {
    if let Some(s) = raw_args.as_str() {
        if apply_patch_marker_re().is_match(s) {
            return s.to_string();
        }
        let parsed = parse_github_tool_args(raw_args);
        return parsed
            .get("patch")
            .or_else(|| parsed.get("input"))
            .or_else(|| parsed.get("command"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
    }
    if raw_args.is_object() {
        return raw_args
            .get("patch")
            .or_else(|| raw_args.get("input"))
            .or_else(|| raw_args.get("command"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
    }
    String::new()
}

fn normalize_github_event(mut event: Value, project_cwd: &str, env: &HashMap<String, String>) -> Value {
    let cwd = event
        .get("cwd")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .map(String::from)
        .unwrap_or_else(|| env_project_dir(env, project_cwd));
    let session_id = event
        .get("sessionId")
        .or_else(|| event.get("session_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let tool_name = event
        .get("toolName")
        .or_else(|| event.get("tool_name"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let mut tool_input = event
        .get("tool_input")
        .filter(|v| v.is_object())
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    let raw_args = event.get("toolArgs").cloned().unwrap_or(Value::Null);

    let mut normalized_tool_name = tool_name.clone();
    if tool_name.as_deref() == Some("apply_patch") || looks_like_apply_patch(&raw_args) {
        let patch = apply_patch_text(&raw_args);
        if !patch.is_empty() {
            tool_input["command"] = Value::String(patch);
            normalized_tool_name = Some("apply_patch".to_string());
        }
    } else {
        let args = parse_github_tool_args(&raw_args);
        let file_path = args
            .get("path")
            .or_else(|| args.get("file_path"))
            .or_else(|| args.get("filePath"))
            .or_else(|| args.get("target_file"))
            .and_then(|v| v.as_str());
        if let Some(fp) = file_path {
            tool_input["file_path"] = Value::String(fp.to_string());
        }
    }

    if let Some(obj) = event.as_object_mut() {
        obj.insert("cwd".to_string(), Value::String(cwd));
        obj.insert("session_id".to_string(), Value::String(session_id));
        obj.insert(
            "tool_name".to_string(),
            normalized_tool_name.map(Value::String).unwrap_or(Value::Null),
        );
        obj.insert("tool_input".to_string(), tool_input);
    }
    event
}

/// Mirrors `normalizeHookEvent(event, projectCwd, harness)`.
pub fn normalize_hook_event(
    mut event: Value,
    project_cwd: &str,
    harness: Harness,
    env: &HashMap<String, String>,
) -> Value {
    if !event.is_object() {
        return event;
    }
    match harness {
        Harness::Github => return normalize_github_event(event, project_cwd, env),
        Harness::Claude => return event,
        Harness::Cursor => {}
    }

    let cwd = event
        .get("cwd")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .map(String::from)
        .or_else(|| {
            event
                .get("workspace_roots")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .unwrap_or_else(|| env_project_dir(env, project_cwd));
    let session_id = event
        .get("session_id")
        .or_else(|| event.get("conversation_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let ti = event
        .get("tool_input")
        .filter(|v| v.is_object())
        .cloned()
        .unwrap_or(Value::Object(Default::default()));
    let file_path = ti
        .get("file_path")
        .or_else(|| ti.get("path"))
        .and_then(|v| v.as_str())
        .or_else(|| event.get("file_path").and_then(|v| v.as_str()))
        .map(String::from);

    if let Some(obj) = event.as_object_mut() {
        obj.insert("cwd".to_string(), Value::String(cwd));
        obj.insert("session_id".to_string(), Value::String(session_id));
        if let Some(fp) = file_path {
            let mut ti = ti;
            ti["file_path"] = Value::String(fp);
            obj.insert("tool_input".to_string(), ti);
        }
    }
    event
}

// ---------------------------------------------------------------------
// Scan-target resolution/expansion
// ---------------------------------------------------------------------

const MAX_SCAN_TARGETS: usize = 6;
const STYLE_EXTS: &[&str] = &[".css", ".scss", ".sass", ".less"];
const UI_CODE_EXTS: &[&str] = &[".jsx", ".tsx", ".vue", ".svelte", ".astro"];
const CO_SCAN_STYLE_NAMES: &[&str] = &[
    "styles.css", "styles.scss", "styles.sass", "styles.less",
    "index.css", "index.scss", "index.sass", "index.less",
    "global.css", "global.scss", "global.sass", "global.less",
    "globals.css", "globals.scss", "globals.sass", "globals.less",
];

fn has_path_traversal(file_path: &str) -> bool {
    file_path.contains("..")
}

fn is_inside_project(file_path: &str, project_cwd: &Path) -> bool {
    if file_path.is_empty() || has_path_traversal(file_path) {
        return false;
    }
    let p = Path::new(file_path);
    match p.strip_prefix(project_cwd) {
        Ok(rel) => rel.as_os_str().is_empty() || !rel.to_string_lossy().starts_with(".."),
        Err(_) => false,
    }
}

fn normalize_target(p: &str, base_cwd: &Path) -> String {
    if has_path_traversal(p) {
        return p.to_string();
    }
    let path = Path::new(p);
    if path.is_absolute() {
        p.to_string()
    } else {
        base_cwd.join(path).to_string_lossy().replace('\\', "/")
    }
}

/// Mirrors `normalizeScanTargets(primaryTargets, projectCwd)`.
pub fn normalize_scan_targets(primary_targets: &[String], project_cwd: &Path) -> Vec<String> {
    let mut ordered = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for p in primary_targets {
        if ordered.len() >= MAX_SCAN_TARGETS {
            break;
        }
        let abs = normalize_target(p, project_cwd);
        if seen.insert(abs.clone()) {
            ordered.push(abs);
        }
    }
    ordered
}

fn static_style_import_re() -> Regex {
    Regex::new(r#"(?i)import\s+(?:[\w*{}\s,$]+\s+from\s+)?['"]([^'"]+\.(?:css|scss|sass|less))['"]"#)
        .expect("STATIC_STYLE_IMPORT_RE must compile")
}

/// Mirrors `parseStaticStyleImports(content, fromFile, projectCwd)`.
pub fn parse_static_style_imports(content: &str, from_file: &str, project_cwd: &Path) -> Vec<String> {
    let dir = Path::new(from_file).parent().unwrap_or(Path::new(""));
    let mut out = Vec::new();
    for cap in static_style_import_re().captures_iter(content) {
        let p = cap[1].trim();
        if p.is_empty() {
            continue;
        }
        let resolved = if p.starts_with('.') {
            dir.join(p)
        } else if Path::new(p).is_absolute() {
            PathBuf::from(p)
        } else {
            project_cwd.join(p)
        };
        let resolved_str = resolved.to_string_lossy().replace('\\', "/");
        if !is_inside_project(&resolved_str, project_cwd) {
            continue;
        }
        out.push(resolved_str);
    }
    out
}

/// Mirrors `coLocatedStylesheets(filePath)`.
pub fn co_located_stylesheets(file_path: &str) -> Vec<String> {
    let path = Path::new(file_path);
    let dir = path.parent().unwrap_or(Path::new(""));
    let stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();

    let mut candidates: Vec<String> = Vec::new();
    let mut push_unique = |p: PathBuf, out: &mut Vec<String>| {
        let s = p.to_string_lossy().replace('\\', "/");
        if !out.contains(&s) {
            out.push(s);
        }
    };
    for ext in ["css", "module.css", "scss", "module.scss", "sass", "module.sass", "less", "module.less"] {
        push_unique(dir.join(format!("{stem}.{ext}")), &mut candidates);
    }
    for name in CO_SCAN_STYLE_NAMES {
        push_unique(dir.join(name), &mut candidates);
    }
    candidates.into_iter().filter(|p| Path::new(p).exists()).collect()
}

/// Mirrors `expandScanTargets(primaryTargets, projectCwd)`.
pub fn expand_scan_targets(primary_targets: &[String], project_cwd: &Path) -> Vec<String> {
    let mut ordered = normalize_scan_targets(primary_targets, project_cwd);
    if ordered.is_empty() {
        return ordered;
    }
    let mut seen: std::collections::HashSet<String> = ordered.iter().cloned().collect();
    let primaries = ordered.clone();

    for p in &primaries {
        if ordered.len() >= MAX_SCAN_TARGETS {
            break;
        }
        if !is_inside_project(p, project_cwd) {
            continue;
        }
        let ext = Path::new(p)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_ascii_lowercase()))
            .unwrap_or_default();
        if STYLE_EXTS.contains(&ext.as_str()) || !UI_CODE_EXTS.contains(&ext.as_str()) {
            continue;
        }
        let content = fs::read_to_string(p).unwrap_or_default();
        for imp in parse_static_style_imports(&content, p, project_cwd) {
            if ordered.len() >= MAX_SCAN_TARGETS {
                break;
            }
            let abs = normalize_target(&imp, project_cwd);
            if seen.insert(abs.clone()) {
                ordered.push(abs);
            }
        }
        for col in co_located_stylesheets(p) {
            if ordered.len() >= MAX_SCAN_TARGETS {
                break;
            }
            let abs = normalize_target(&col, project_cwd);
            if seen.insert(abs.clone()) {
                ordered.push(abs);
            }
        }
    }
    ordered
}

// ---------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------

/// Mirrors `writeAuditLog(env, entry, cwd)`. `entry_cwd` is `entry.cwd` when
/// present (JS reads it off the audit object); callers pass `None` when the
/// audit entry carries no `cwd` field.
pub fn write_audit_log(
    env: &HashMap<String, String>,
    entry: &Value,
    cwd: &Path,
    entry_cwd: Option<&str>,
) -> bool {
    let base_cwd = entry_cwd
        .filter(|c| !c.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| cwd.to_path_buf());
    let target = env
        .get("IMPECCABLE_HOOK_LOG")
        .cloned()
        .or_else(|| read_config(&base_cwd).audit_log);
    let Some(target) = target.filter(|t| !t.is_empty()) else {
        return false;
    };

    let expanded = if let Some(rest) = target.strip_prefix("~/") {
        let home = env
            .get("HOME")
            .or_else(|| env.get("USERPROFILE"))
            .cloned()
            .unwrap_or_else(|| ".".to_string());
        PathBuf::from(home).join(rest)
    } else if Path::new(&target).is_absolute() {
        PathBuf::from(&target)
    } else {
        base_cwd.join(&target)
    };

    let Some(parent) = expanded.parent() else { return false };
    if fs::create_dir_all(parent).is_err() {
        return false;
    }

    let mut record = entry.clone();
    let ts = chrono_ish_now_iso8601();
    if let Some(obj) = record.as_object_mut() {
        let mut merged = serde_json::Map::new();
        merged.insert("ts".to_string(), Value::String(ts));
        merged.extend(obj.clone());
        *obj = merged;
    }
    let Ok(line) = serde_json::to_string(&record) else { return false };
    let line = format!("{line}\n");

    use std::io::Write;
    let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&expanded) else {
        return false;
    };
    file.write_all(line.as_bytes()).is_ok()
}

/// Minimal ISO-8601 UTC timestamp without pulling in a chrono dependency
/// (not in this crate's allowed-crates list for this packet).
fn chrono_ish_now_iso8601() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    // Days since epoch -> proleptic Gregorian civil date (Howard Hinnant's algorithm).
    let z = (secs / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let sod = secs % 86_400;
    let (h, mi, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

// ---------------------------------------------------------------------
// Detector seam (`loadDetector`) + `runHook` orchestration
// ---------------------------------------------------------------------

/// Stands in for the dynamically `import()`-ed `detect-antipatterns.mjs`
/// module. Real wiring supplies a production impl backed by
/// `heardright`-style detector logic; tests supply a fake, per the packet
/// brief's "I/O behind a trait, tested with fakes" rule.
pub trait Detector {
    fn detect_text(&self, content: &str, file_path: &str, scan_options: &ScanOptions) -> Vec<Finding>;
    fn detect_html(&self, file_path: &str, scan_options: &ScanOptions) -> Vec<Finding>;
    /// `None` means "no design-system sidecar" (mirrors a `null` return).
    fn load_design_system_for_cwd(&self, _project_cwd: &Path) -> Option<DesignSystemInfo> {
        None
    }
}

#[derive(Debug, Clone, Default)]
pub struct DesignSystemInfo {
    pub md_newer_than_json: bool,
}

/// Mirrors the `scanOptions` object built by `designSystemOptions` and
/// threaded into `detector.detectText`/`detectHtml`.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub design_system: Option<DesignSystemInfo>,
}

/// Mirrors `designSystemOptions(config, detector, projectCwd)`: `{}` when
/// design-system scanning is disabled in config or the detector has no
/// `loadDesignSystemForCwd`, else `{ designSystem }` when the detector finds
/// one for `project_cwd` (swallowing detector errors, matching the JS
/// `try { } catch { return {} }`).
pub fn design_system_options(
    config: &Config,
    detector: &dyn Detector,
    project_cwd: &Path,
) -> ScanOptions {
    if !config.design_system.enabled {
        return ScanOptions::default();
    }
    ScanOptions {
        design_system: detector.load_design_system_for_cwd(project_cwd),
    }
}

/// Mirrors the three-way return of `runHook`: `{ exitCode, stdout, audit }`.
#[derive(Debug, Clone, Default)]
pub struct HookResult {
    pub exit_code: i32,
    pub stdout: String,
    pub audit: Value,
}

fn audit_result(mut audit: Value, extra: Value) -> HookResult {
    if let (Some(a), Some(e)) = (audit.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            a.insert(k.clone(), v.clone());
        }
    }
    HookResult {
        exit_code: 0,
        stdout: String::new(),
        audit,
    }
}

/// Options bag mirroring `runHook({ stdinJson, env, cwd, now, detector })`.
pub struct RunHookDeps<'a> {
    pub stdin_json: &'a str,
    pub env: HashMap<String, String>,
    pub cwd: PathBuf,
    pub detector: &'a dyn Detector,
}

/// Mirrors `runHook(deps)`. Never panics on malformed input; all error
/// paths return `exit_code: 0` with a descriptive `audit` entry, matching
/// the JS "never break a turn" contract.
pub fn run_hook(deps: RunHookDeps<'_>) -> HookResult {
    let mut audit = serde_json::json!({ "ts": chrono_ish_now_iso8601(), "event": "PostToolUse" });

    if depth_is_set(deps.env.get("IMPECCABLE_HOOK_DEPTH").map(|s| s.as_str()))
        || depth_is_set(deps.env.get("CLAUDE_HOOK_DEPTH").map(|s| s.as_str()))
    {
        return audit_result(audit, serde_json::json!({ "reentrant": true, "durationMs": 0 }));
    }
    if truthy(deps.env.get("IMPECCABLE_HOOK_DISABLED").map(|s| s.as_str())) {
        return audit_result(audit, serde_json::json!({ "skipped": "env-disabled", "durationMs": 0 }));
    }

    let event: Value = match serde_json::from_str(deps.stdin_json) {
        Ok(v) => v,
        Err(_) => {
            return audit_result(audit, serde_json::json!({ "skipped": "stdin-malformed", "durationMs": 0 }));
        }
    };
    if !event.is_object() {
        return audit_result(audit, serde_json::json!({ "skipped": "stdin-empty", "durationMs": 0 }));
    }

    let harness = resolve_harness(&deps.env, Some(&event));
    let cwd_str = deps.cwd.to_string_lossy().to_string();
    let event = normalize_hook_event(event, &cwd_str, harness, &deps.env);
    audit["harness"] = Value::String(format!("{harness:?}").to_lowercase());

    let project_cwd_str = event
        .get("cwd")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .map(String::from)
        .unwrap_or(cwd_str.clone());
    let project_cwd = PathBuf::from(&project_cwd_str);
    audit["cwd"] = Value::String(project_cwd_str.clone());

    let primary_files = normalize_scan_targets(&resolve_target_files(&event, &project_cwd), &project_cwd);
    let primary_file_set: std::collections::HashSet<String> = primary_files.iter().cloned().collect();
    let target_files = expand_scan_targets(&primary_files, &project_cwd);
    let session_id = event.get("session_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
    audit["session"] = Value::String(session_id.clone());
    if let Some(t) = event.get("tool_name").and_then(|v| v.as_str()) {
        audit["tool"] = Value::String(t.to_string());
    }

    if target_files.is_empty() {
        return audit_result(audit, serde_json::json!({ "skipped": "no-file-path" }));
    }

    let config = read_config(&project_cwd);
    if !config.enabled {
        return audit_result(audit, serde_json::json!({ "skipped": "config-disabled" }));
    }

    let mut cache = read_cache(&project_cwd);
    let sensitive_re = sensitive_path_re();
    let generated_re = generated_path_re();
    let scan_options = design_system_options(&config, deps.detector, &project_cwd);
    let md_newer_than_json = scan_options
        .design_system
        .as_ref()
        .map(|d| d.md_newer_than_json)
        .unwrap_or(false);

    let mut pending_winner: Option<(String, Vec<String>)> = None;
    let mut clean_winner: Option<String> = None;
    let mut fresh_groups: Vec<FindingGroup> = Vec::new();
    let mut suppression_winner: Option<String> = None;
    let mut last_skip = "no-scannable-file".to_string();
    let mut suppressed_hit = false;

    for file_path in &target_files {
        audit["file"] = Value::String(file_path.clone());

        if has_path_traversal(file_path) || sensitive_re.is_match(file_path) {
            last_skip = "sensitive".to_string();
            continue;
        }
        if generated_re.is_match(file_path) {
            last_skip = "generated".to_string();
            continue;
        }
        let ext = Path::new(file_path)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_ascii_lowercase()))
            .unwrap_or_default();
        audit["ext"] = Value::String(ext.clone());
        if !allowed_exts().contains(&ext.as_str()) {
            last_skip = "extension".to_string();
            continue;
        }

        let rel_for_match = relativize(file_path, &project_cwd);
        if matches_any_glob(&rel_for_match, &config.ignore_files) || matches_any_glob(file_path, &config.ignore_files) {
            last_skip = "config-ignore-file".to_string();
            continue;
        }
        if !Path::new(file_path).exists() {
            last_skip = "file-missing".to_string();
            continue;
        }

        if primary_file_set.contains(file_path) {
            let edit_count = bump_edit_count(&mut cache, &session_id, file_path);
            audit["editCount"] = Value::from(edit_count);
            if edit_count > EDIT_COUNT_THRESHOLD {
                let was_just_crossed = edit_count == EDIT_COUNT_THRESHOLD + 1;
                if was_just_crossed && suppression_winner.is_none() {
                    suppression_winner = Some(file_path.clone());
                }
                last_skip = "suppressed".to_string();
                suppressed_hit = true;
                continue;
            }
        }

        let Ok(content) = fs::read_to_string(file_path) else {
            last_skip = "file-missing".to_string();
            continue;
        };
        let findings = if ext == ".html" || ext == ".htm" {
            deps.detector.detect_html(file_path, &scan_options)
        } else {
            deps.detector.detect_text(&content, file_path, &scan_options)
        };

        let ignore_rules_set: HashSet<String> = config.ignore_rules.iter().cloned().collect();
        let filtered = filter_findings(&findings, &ignore_rules_set, &config.ignore_values);
        let known: HashSet<String> = ensure_file(&mut cache, &session_id, file_path)
            .findings
            .iter()
            .cloned()
            .collect();
        let (fresh, _updated_known) = dedupe_against_cache(&filtered, &known);
        audit["findings"] = Value::from(findings.len());
        audit["freshFindings"] = Value::from(fresh.len());

        if !fresh.is_empty() {
            remember_findings(&mut cache, &session_id, file_path, &fresh);
            fresh_groups.push(FindingGroup {
                file_path: file_path.clone(),
                findings: fresh,
            });
            continue;
        }

        if !filtered.is_empty() && pending_winner.is_none() {
            let known = ensure_file(&mut cache, &session_id, file_path).findings.clone();
            pending_winner = Some((file_path.clone(), known));
        } else if filtered.is_empty() && clean_winner.is_none() {
            clean_winner = Some(file_path.clone());
        }
    }

    persist_cache(&project_cwd, cache);

    if !fresh_groups.is_empty() {
        let first = &fresh_groups[0];
        let text = append_design_system_note(
            render_grouped_template(&fresh_groups, &config, &project_cwd),
            md_newer_than_json,
        );
        let all_findings: usize = fresh_groups.iter().map(|g| g.findings.len()).sum();
        audit["file"] = Value::String(first.file_path.clone());
        audit["emitted"] = Value::Bool(true);
        audit["freshFiles"] = Value::from(fresh_groups.len());
        audit["freshFindings"] = Value::from(all_findings);
        audit["chars"] = Value::from(text.chars().count());
        return HookResult {
            exit_code: 0,
            stdout: w2_015_payload(&text, "PostToolUse", harness),
            audit,
        };
    }

    if truthy(deps.env.get("IMPECCABLE_HOOK_QUIET").map(|s| s.as_str())) || config.quiet {
        return audit_result(audit, serde_json::json!({ "emitted": false, "quiet": true }));
    }

    if let Some((file_path, known)) = &pending_winner {
        if should_emit_ack_for_file(file_path) {
            let text = append_design_system_note(render_pending_ack(file_path, known, &project_cwd), md_newer_than_json);
            audit["file"] = Value::String(file_path.clone());
            audit["emitted"] = Value::Bool(true);
            audit["kind"] = Value::String("pending".to_string());
            audit["pending"] = Value::from(known.len());
            audit["chars"] = Value::from(text.chars().count());
            return HookResult {
                exit_code: 0,
                stdout: w2_015_payload(&text, "PostToolUse", harness),
                audit,
            };
        }
    }

    if let Some(file_path) = &suppression_winner {
        let text = suppression_notice(&relativize(file_path, &project_cwd));
        audit["file"] = Value::String(file_path.clone());
        audit["suppressed"] = Value::Bool(true);
        audit["emitted"] = Value::Bool(true);
        return HookResult {
            exit_code: 0,
            stdout: w2_015_payload(&text, "PostToolUse", harness),
            audit,
        };
    }

    if let Some(file_path) = &clean_winner {
        if should_emit_ack_for_file(file_path) {
            let text = append_design_system_note(render_clean_ack(file_path, &project_cwd), md_newer_than_json);
            audit["file"] = Value::String(file_path.clone());
            audit["emitted"] = Value::Bool(true);
            audit["kind"] = Value::String("clean".to_string());
            audit["chars"] = Value::from(text.chars().count());
            return HookResult {
                exit_code: 0,
                stdout: w2_015_payload(&text, "PostToolUse", harness),
                audit,
            };
        }
    }

    if pending_winner.is_some() || clean_winner.is_some() {
        return audit_result(audit, serde_json::json!({ "emitted": false, "skipped": "non-ui-ack" }));
    }
    if suppressed_hit {
        return audit_result(audit, serde_json::json!({ "suppressed": true, "emitted": false }));
    }
    audit_result(audit, serde_json::json!({ "skipped": last_skip }))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeDetector {
        text_findings: Vec<Finding>,
        html_findings: Vec<Finding>,
    }

    impl Detector for FakeDetector {
        fn detect_text(&self, _content: &str, _file_path: &str, _scan_options: &ScanOptions) -> Vec<Finding> {
            self.text_findings.clone()
        }
        fn detect_html(&self, _file_path: &str, _scan_options: &ScanOptions) -> Vec<Finding> {
            self.html_findings.clone()
        }
    }

    struct DesignSystemFakeDetector {
        text_findings: Vec<Finding>,
        design_system: Option<DesignSystemInfo>,
        seen_design_system: std::cell::RefCell<Vec<bool>>,
    }

    impl Detector for DesignSystemFakeDetector {
        fn detect_text(&self, _content: &str, _file_path: &str, scan_options: &ScanOptions) -> Vec<Finding> {
            self.seen_design_system
                .borrow_mut()
                .push(scan_options.design_system.is_some());
            self.text_findings.clone()
        }
        fn detect_html(&self, _file_path: &str, _scan_options: &ScanOptions) -> Vec<Finding> {
            Vec::new()
        }
        fn load_design_system_for_cwd(&self, _project_cwd: &Path) -> Option<DesignSystemInfo> {
            self.design_system.clone()
        }
    }

    #[test]
    fn truthy_env_values() {
        assert!(truthy(Some("1")));
        assert!(truthy(Some("TRUE")));
        assert!(!truthy(Some("0")));
        assert!(!truthy(None));
    }

    #[test]
    fn read_config_merges_local_over_base() {
        let dir = tempdir();
        let impeccable = dir.join(".impeccable");
        fs::create_dir_all(&impeccable).unwrap();
        fs::write(
            impeccable.join("config.json"),
            r#"{"hook":{"enabled":true,"quiet":false},"detector":{"ignoreRules":["a"]}}"#,
        )
        .unwrap();
        fs::write(
            impeccable.join("config.local.json"),
            r#"{"hook":{"quiet":true}}"#,
        )
        .unwrap();
        let config = read_config(&dir);
        assert!(config.enabled);
        assert!(config.quiet);
        assert_eq!(config.ignore_rules, vec!["a".to_string()]);
        cleanup(&dir);
    }

    #[test]
    fn cache_round_trips_and_bumps_edit_count() {
        let dir = tempdir();
        let mut cache = read_cache(&dir);
        assert_eq!(cache.version, 1);
        let n1 = bump_edit_count(&mut cache, "s1", "/a/b.tsx");
        let n2 = bump_edit_count(&mut cache, "s1", "/a/b.tsx");
        assert_eq!(n1, 1);
        assert_eq!(n2, 2);
        assert!(persist_cache(&dir, cache));
        let reloaded = read_cache(&dir);
        assert_eq!(reloaded.sessions["s1"].files["/a/b.tsx"].edit_count, 2);
        cleanup(&dir);
    }

    #[test]
    fn render_clean_ack_matches_js_wording() {
        let cwd = Path::new("/proj");
        let text = render_clean_ack("/proj/src/App.tsx", cwd);
        assert!(text.starts_with("[impeccable@1] Design hook scanned src/App.tsx. No anti-patterns."));
    }

    #[test]
    fn render_pending_ack_lists_sample_and_overflow() {
        let cwd = Path::new("/proj");
        let known = vec!["side-tab:3".to_string(), "overused-font:5".to_string(), "x:1".to_string(), "y:2".to_string()];
        let text = render_pending_ack("/proj/App.tsx", &known, cwd);
        assert!(text.contains("Still has 4 finding(s)"));
        assert!(text.contains("+1 more"));
    }

    #[test]
    fn resolve_harness_detects_github_camelcase_shape() {
        let event: Value = serde_json::from_str(r#"{"toolName":"edit","toolArgs":"{}"}"#).unwrap();
        assert_eq!(resolve_harness(&HashMap::new(), Some(&event)), Harness::Github);
    }

    #[test]
    fn resolve_harness_detects_cursor_conversation_id() {
        let event: Value = serde_json::from_str(r#"{"conversation_id":"abc"}"#).unwrap();
        assert_eq!(resolve_harness(&HashMap::new(), Some(&event)), Harness::Cursor);
    }

    #[test]
    fn resolve_target_files_reads_tool_input_file_path() {
        let event: Value = serde_json::from_str(r#"{"tool_input":{"file_path":"/a/b.tsx"}}"#).unwrap();
        let out = resolve_target_files(&event, Path::new("/proj"));
        assert_eq!(out, vec!["/a/b.tsx".to_string()]);
    }

    #[test]
    fn parse_apply_patch_paths_extracts_update_and_add() {
        let cmd = "*** Begin Patch\n*** Update File: src/a.tsx\n*** Add File: src/b.css\n*** End Patch";
        let out = parse_apply_patch_paths(cmd, Path::new("/proj"));
        assert_eq!(out, vec!["/proj/src/a.tsx".to_string(), "/proj/src/b.css".to_string()]);
    }

    #[test]
    fn should_emit_ack_matches_ack_exts() {
        assert!(should_emit_ack_for_file("App.tsx"));
        assert!(!should_emit_ack_for_file("app.ts"));
    }

    #[test]
    fn run_hook_emits_fresh_findings_and_persists_cache() {
        let dir = tempdir();
        let file = dir.join("App.tsx");
        fs::write(&file, "export default function App() {}\n").unwrap();
        let detector = FakeDetector {
            text_findings: vec![Finding {
                antipattern: "side-tab".to_string(),
                line: 3,
                name: Some("Side tab".to_string()),
                description: Some("Uses a side tab pattern.".to_string()),
                ..Default::default()
            }],
            html_findings: vec![],
        };
        let stdin = serde_json::json!({
            "tool_name": "Write",
            "tool_input": { "file_path": file.to_string_lossy() },
            "cwd": dir.to_string_lossy(),
            "session_id": "sess-1",
        })
        .to_string();
        let result = run_hook(RunHookDeps {
            stdin_json: &stdin,
            env: HashMap::new(),
            cwd: dir.clone(),
            detector: &detector,
        });
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("side-tab"));
        assert!(result.audit.get("emitted").and_then(|v| v.as_bool()).unwrap_or(false));
        assert!(get_cache_path(&dir).exists());
        cleanup(&dir);
    }

    #[test]
    fn run_hook_threads_design_system_options_into_detector_and_note() {
        let dir = tempdir();
        let file = dir.join("App.tsx");
        fs::write(&file, "export default function App() {}\n").unwrap();
        let detector = DesignSystemFakeDetector {
            text_findings: vec![Finding {
                antipattern: "side-tab".to_string(),
                line: 3,
                name: Some("Side tab".to_string()),
                description: Some("Uses a side tab pattern.".to_string()),
                ..Default::default()
            }],
            design_system: Some(DesignSystemInfo { md_newer_than_json: true }),
            seen_design_system: std::cell::RefCell::new(Vec::new()),
        };
        let stdin = serde_json::json!({
            "tool_name": "Write",
            "tool_input": { "file_path": file.to_string_lossy() },
            "cwd": dir.to_string_lossy(),
            "session_id": "sess-ds",
        })
        .to_string();
        let result = run_hook(RunHookDeps {
            stdin_json: &stdin,
            env: HashMap::new(),
            cwd: dir.clone(),
            detector: &detector,
        });
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("DESIGN.md is newer than .impeccable/design.json"));
        assert_eq!(*detector.seen_design_system.borrow(), vec![true]);
        cleanup(&dir);
    }

    #[test]
    fn design_system_options_returns_default_when_disabled_in_config() {
        let mut config = Config::default();
        config.design_system.enabled = false;
        let detector = DesignSystemFakeDetector {
            text_findings: vec![],
            design_system: Some(DesignSystemInfo { md_newer_than_json: true }),
            seen_design_system: std::cell::RefCell::new(Vec::new()),
        };
        let opts = design_system_options(&config, &detector, Path::new("/proj"));
        assert!(opts.design_system.is_none());
    }

    #[test]
    fn run_hook_reentrancy_guard_skips_scan() {
        let dir = tempdir();
        let mut env = HashMap::new();
        env.insert("IMPECCABLE_HOOK_DEPTH".to_string(), "1".to_string());
        let detector = FakeDetector { text_findings: vec![], html_findings: vec![] };
        let result = run_hook(RunHookDeps {
            stdin_json: "{}",
            env,
            cwd: dir.clone(),
            detector: &detector,
        });
        assert_eq!(result.audit.get("reentrant").and_then(|v| v.as_bool()), Some(true));
        cleanup(&dir);
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "legion-r14-{}-{}-{}",
            std::process::id(),
            n,
            now_millis()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }
}
