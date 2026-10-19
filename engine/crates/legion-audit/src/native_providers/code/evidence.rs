//! Self-sourced evidence for the `code.*` providers.
//!
//! The language analyzers in this family are accounting-only: they count the
//! files of their language, and they demand tool receipts and context that
//! nothing in the repository produced. This module is that producer. From the
//! frozen denominator alone it
//!
//! * reads each in-language file (bounded per file and in total) and computes
//!   findings natively: debt markers, oversized files, duplicate blocks, and
//!   per-language error-handling / debug-leftover / unsafe-call smells;
//! * derives the analyzer's required context from manifests in the denominator;
//! * discovers the external tools each provider names, so a missing tool is a
//!   typed gap and a present-but-unrun tool is never a pass. Running them is
//!   [`super::tools`]' job, and only on the plan-bound async path.
//!
//! Every file that is not read is reported with its path; `examined` counts
//! only files actually read.

use super::{
    c_family, common::LanguageConfig, dotnet, go, javascript, jvm, long_tail, mobile, php_ruby,
    python, rust,
};
use crate::{inventory::InventoryEntry, AuditError};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{hash_map::DefaultHasher, BTreeSet, HashMap, HashSet},
    fs::File,
    hash::{Hash, Hasher},
    io::Read,
    path::{Component, Path, PathBuf},
};

const PROVIDER_IDS: [&str; 10] = [
    "code.c-family",
    "code.dotnet",
    "code.go",
    "code.javascript",
    "code.jvm",
    "code.long-tail",
    "code.mobile",
    "code.php-ruby",
    "code.python",
    "code.rust",
];

const OVERSIZED_LINES: usize = 1500;
const DUP_WINDOW: usize = 6;
const DUP_MIN_CHARS: usize = 120;

/// Historical generic-source inputs. These are selected for bounded source
/// analysis even when inventory extraction has no language parser. Selection
/// does not confer language/compiler coverage: long-tail retains its typed gap.
pub(super) const HISTORICAL_SOURCE_EXTENSIONS: &[&str] = &[
    "astro", "bash", "bat", "cjs", "cts", "css", "cxx", "dart", "erl", "ex", "exs", "gql",
    "graphql", "hrl", "html", "kts", "mjs", "mts", "nsh", "nsi", "ps1", "psm1", "rb", "sh", "sql",
    "svelte", "vbs", "vue", "zsh",
];

/// Work bounds. Defaults are generous for a source tree and small enough that
/// a pathological repository cannot stall an audit.
#[derive(Clone, Debug)]
pub struct EvidenceLimits {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_findings: usize,
    pub max_duplicate_windows: usize,
    pub max_skip_records: usize,
}

impl Default for EvidenceLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_findings: 500,
            max_duplicate_windows: 500_000,
            max_skip_records: 1000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFinding {
    pub rule: std::borrow::Cow<'static, str>,
    pub severity: &'static str,
    pub path: String,
    pub line: usize,
    pub message: String,
}

/// What the producer built for one provider.
#[derive(Clone, Debug)]
pub struct Produced {
    /// Analyzer input (`files`, `context`, `facts`).
    pub input: Value,
    pub findings: Vec<NativeFinding>,
    /// Findings dropped past `max_findings`.
    pub findings_truncated: usize,
    /// In-language files in the denominator.
    pub expected: u64,
    /// In-language files actually read.
    pub examined: u64,
    /// Frozen Go module manifests & dependency locks selected for context inspection.
    pub context_expected: u64,
    pub context_examined: u64,
    pub context_bytes_read: u64,
    pub bytes_read: u64,
    /// `<reason>:<path>` for every file not read (bounded; see limits).
    pub skips: Vec<String>,
    pub duplicate_detection_truncated: bool,
    /// Tool ids with no resolvable executable.
    pub missing_tools: Vec<&'static str>,
    /// Tool ids whose executable exists but was not run (no receipt).
    pub unrun_tools: Vec<&'static str>,
    pub tool_discovery: Vec<Value>,
    pub rule_ids: Vec<&'static str>,
}

pub fn config_for(provider_id: &str) -> Option<&'static LanguageConfig> {
    Some(match provider_id {
        "code.c-family" => &c_family::CONFIG,
        "code.dotnet" => &dotnet::CONFIG,
        "code.go" => &go::CONFIG,
        "code.javascript" => &javascript::CONFIG,
        "code.jvm" => &jvm::CONFIG,
        "code.long-tail" => &long_tail::CONFIG,
        "code.mobile" => &mobile::CONFIG,
        "code.php-ruby" => &php_ruby::CONFIG,
        "code.python" => &python::CONFIG,
        "code.rust" => &rust::CONFIG,
        _ => return None,
    })
}

fn claimed_extensions() -> BTreeSet<&'static str> {
    let mut claimed = BTreeSet::new();
    for id in PROVIDER_IDS {
        if id == "code.long-tail" {
            continue;
        }
        if let Some(config) = config_for(id) {
            claimed.extend(config.extensions.iter().copied());
        }
    }
    claimed
}

fn extension_of(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rfind('.') {
        Some(index) => name[index + 1..].to_ascii_lowercase(),
        None => String::new(),
    }
}

fn unsupported_language_coverage(selected: &[&InventoryEntry]) -> Vec<Value> {
    let mut by_extension: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for entry in selected {
        let extension = extension_of(&entry.path);
        let extension = if extension.is_empty() {
            "(no extension)".to_owned()
        } else {
            extension
        };
        by_extension
            .entry(extension)
            .or_default()
            .push(entry.path.clone());
    }

    by_extension
        .into_iter()
        .map(|(extension, paths)| {
            json!({
                "extension": extension,
                "pathCount": paths.len(),
                "samplePaths": paths.into_iter().take(20).collect::<Vec<_>>(),
            })
        })
        .collect()
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The denominator entries this provider is responsible for.
pub fn select_entries<'a>(
    config: &LanguageConfig,
    entries: &'a [InventoryEntry],
) -> Vec<&'a InventoryEntry> {
    let wildcard = config.extensions.contains(&"*");
    let claimed = if wildcard {
        claimed_extensions()
    } else {
        BTreeSet::new()
    };
    let mut selected = entries
        .iter()
        .filter(|entry| {
            let ext = extension_of(&entry.path);
            if wildcard {
                (entry.source_file || HISTORICAL_SOURCE_EXTENSIONS.contains(&ext.as_str()))
                    && !claimed.contains(ext.as_str())
            } else {
                config.extensions.contains(&ext.as_str())
            }
        })
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| left.path.cmp(&right.path));
    selected
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// (id, severity, pattern, next non-blank line must trim to, message)
type RuleDef = (
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
    &'static str,
);

const EMPTY_CATCH: RuleDef = (
    "empty-catch",
    "medium",
    r"\bcatch\b[^{]*\{\s*\}",
    None,
    "Empty catch block swallows the error",
);
const EMPTY_CATCH_MULTILINE: RuleDef = (
    "empty-catch",
    "medium",
    r"\bcatch\b[^{]*\{\s*$",
    Some("}"),
    "Empty catch block swallows the error",
);

const RUST_RULES: &[RuleDef] = &[
    (
        "error-swallowed",
        "medium",
        r"\.ok\(\)\s*;",
        None,
        "Result discarded with .ok(); the error is silently dropped",
    ),
    (
        "error-swallowed",
        "medium",
        r"^\s*let\s+_\s*=\s*[\w:.]+\(.*\)\s*;\s*$",
        None,
        "Result bound to `_`; the error is silently dropped",
    ),
    (
        "debug-leftover",
        "low",
        r"\bdbg!\s*\(",
        None,
        "dbg! macro left in source",
    ),
    (
        "placeholder-macro",
        "medium",
        r"\b(?:todo|unimplemented)!\s*\(",
        None,
        "Placeholder macro panics at runtime",
    ),
];
const JS_RULES: &[RuleDef] = &[
    EMPTY_CATCH,
    EMPTY_CATCH_MULTILINE,
    (
        "debug-leftover",
        "low",
        r"^\s*debugger\s*;?\s*$",
        None,
        "debugger statement left in source",
    ),
    (
        "dynamic-eval",
        "medium",
        r"(?:^|[^.\w])eval\s*\(",
        None,
        "eval executes dynamic code",
    ),
];
const PYTHON_RULES: &[RuleDef] = &[
    (
        "bare-except",
        "medium",
        r"^\s*except\s*:",
        None,
        "Bare except catches every exception including KeyboardInterrupt",
    ),
    (
        "swallowed-exception",
        "medium",
        r"^\s*except\b.*:\s*pass\s*$",
        None,
        "Exception handler does nothing",
    ),
    (
        "swallowed-exception",
        "medium",
        r"^\s*except\b.*:\s*$",
        Some("pass"),
        "Exception handler does nothing",
    ),
    (
        "debug-leftover",
        "low",
        r"\bbreakpoint\(\)|\bpdb\.set_trace\(\)",
        None,
        "Debugger breakpoint left in source",
    ),
    (
        "dynamic-eval",
        "medium",
        r"(?:^|[^.\w])(?:eval|exec)\s*\(",
        None,
        "eval/exec runs dynamic code",
    ),
];
const GO_RULES: &[RuleDef] = &[
    (
        "ignored-error",
        "medium",
        r"^\s*_\s*(?:,\s*_\s*)?=\s*\S",
        None,
        "Result assigned to the blank identifier; any error is ignored",
    ),
    (
        "empty-error-branch",
        "medium",
        r"\bif\s+err\s*!=\s*nil\s*\{\s*\}",
        None,
        "err != nil branch is empty",
    ),
    (
        "empty-error-branch",
        "medium",
        r"\bif\s+err\s*!=\s*nil\s*\{\s*$",
        Some("}"),
        "err != nil branch is empty",
    ),
];
const JVM_RULES: &[RuleDef] = &[
    EMPTY_CATCH,
    EMPTY_CATCH_MULTILINE,
    (
        "debug-leftover",
        "low",
        r"\.printStackTrace\s*\(\s*\)|\bSystem\.(?:out|err)\.print",
        None,
        "Console debug output left in source",
    ),
];
const DOTNET_RULES: &[RuleDef] = &[
    EMPTY_CATCH,
    EMPTY_CATCH_MULTILINE,
    (
        "debug-leftover",
        "low",
        r"\bDebugger\.Break\s*\(\s*\)",
        None,
        "Debugger.Break left in source",
    ),
];
const C_RULES: &[RuleDef] = &[(
    "unsafe-call",
    "medium",
    r"(?:^|[^.\w>])(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\(",
    None,
    "Unbounded string function; use a length-checked variant",
)];
const MOBILE_RULES: &[RuleDef] = &[
    (
        "force-try",
        "medium",
        r"\btry!",
        None,
        "try! crashes on any thrown error",
    ),
    (
        "force-cast",
        "low",
        r"\bas!\s",
        None,
        "as! crashes when the cast fails",
    ),
    (
        "debug-leftover",
        "low",
        r"\bNSLog\s*\(|\bdebugPrint\s*\(",
        None,
        "Debug logging left in source",
    ),
];
const PHP_RULES: &[RuleDef] = &[
    EMPTY_CATCH,
    EMPTY_CATCH_MULTILINE,
    (
        "debug-leftover",
        "low",
        r"(?:^|[^.\w>:$])(?:var_dump|print_r|dd)\s*\(",
        None,
        "Debug dump left in source",
    ),
    (
        "dynamic-eval",
        "medium",
        r"(?:^|[^.\w>:$])eval\s*\(",
        None,
        "eval executes dynamic code",
    ),
];
const RUBY_RULES: &[RuleDef] = &[
    (
        "debug-leftover",
        "low",
        r"\bbinding\.(?:pry|irb)\b",
        None,
        "Interactive debugger left in Ruby source",
    ),
    (
        "error-swallowed",
        "medium",
        r"^\s*rescue(?:\s+[\w:]+)?\s*$",
        Some("end"),
        "Empty rescue block swallows the error",
    ),
];

fn rule_defs(provider_id: &str) -> &'static [RuleDef] {
    match provider_id {
        "code.rust" => RUST_RULES,
        "code.javascript" => JS_RULES,
        "code.python" => PYTHON_RULES,
        "code.go" => GO_RULES,
        "code.jvm" => JVM_RULES,
        "code.dotnet" => DOTNET_RULES,
        "code.c-family" => C_RULES,
        "code.mobile" => MOBILE_RULES,
        "code.php-ruby" => PHP_RULES,
        _ => &[],
    }
}

struct Rule {
    id: &'static str,
    severity: &'static str,
    re: Regex,
    next_line: Option<&'static str>,
    message: &'static str,
}

fn compile_rules(provider_id: &str) -> Result<Vec<Rule>, AuditError> {
    rule_defs(provider_id).iter().map(compile_rule).collect()
}

fn compile_rule(
    &(id, severity, pattern, next_line, message): &RuleDef,
) -> Result<Rule, AuditError> {
    Regex::new(pattern)
        .map(|re| Rule {
            id,
            severity,
            re,
            next_line,
            message,
        })
        .map_err(|error| AuditError::Provider(format!("invalid code rule {id}: {error}")))
}

fn ruby_rules() -> Result<Vec<Rule>, AuditError> {
    RUBY_RULES.iter().map(compile_rule).collect()
}

fn is_comment_line(trimmed: &str) -> bool {
    ["//", "#", "/*", "*", "--"]
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
}

fn normalize_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || is_comment_line(trimmed) {
        return None;
    }
    if [
        "use ", "import ", "from ", "package ", "using ", "require", "include",
    ]
    .iter()
    .any(|prefix| trimmed.starts_with(prefix))
    {
        return None;
    }
    if !trimmed.chars().any(char::is_alphanumeric) {
        return None;
    }
    let normalized = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
    (normalized.chars().count() >= 10).then_some(normalized)
}

fn hash_str(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// One significant line: (1-based line number, hash, character count).
type Significant = (usize, u64, usize);

struct DuplicateIndex {
    seen: HashMap<u64, (String, usize, usize)>,
    cap: usize,
    truncated: bool,
}

impl DuplicateIndex {
    fn scan(&mut self, path: &str, sig: &[Significant], out: &mut Vec<NativeFinding>) {
        let mut i = 0usize;
        while i + DUP_WINDOW <= sig.len() {
            let window = &sig[i..i + DUP_WINDOW];
            if window.iter().map(|s| s.2).sum::<usize>() < DUP_MIN_CHARS {
                i += 1;
                continue;
            }
            let mut hasher = DefaultHasher::new();
            for s in window {
                s.1.hash(&mut hasher);
            }
            let key = hasher.finish();
            let hit = self.seen.get(&key).cloned();
            match hit {
                Some((first_path, first_line, first_index))
                    if first_path.as_str() != path || first_index + DUP_WINDOW <= i =>
                {
                    out.push(NativeFinding {
                        rule: "duplicate-block".into(),
                        severity: "low",
                        path: path.to_string(),
                        line: window[0].0,
                        message: format!(
                            "{DUP_WINDOW}-line block duplicates {first_path}:{first_line}"
                        ),
                    });
                    i += DUP_WINDOW;
                    continue;
                }
                Some(_) => {}
                None => {
                    if self.seen.len() < self.cap {
                        self.seen.insert(key, (path.to_string(), window[0].0, i));
                    } else {
                        self.truncated = true;
                    }
                }
            }
            i += 1;
        }
    }
}

fn scan_text(
    path: &str,
    text: &str,
    rules: &[Rule],
    debt: &Regex,
    out: &mut Vec<NativeFinding>,
) -> Vec<Significant> {
    let lines = text.lines().collect::<Vec<_>>();
    let mut reported: HashSet<(&'static str, usize)> = HashSet::new();
    let mut sig = Vec::new();
    if lines.len() > OVERSIZED_LINES {
        out.push(NativeFinding {
            rule: "oversized-file".into(),
            severity: "low",
            path: path.to_string(),
            line: 1,
            message: format!("file has {} lines (limit {OVERSIZED_LINES})", lines.len()),
        });
    }
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        let trimmed = line.trim_start();
        let comment = is_comment_line(trimmed);
        if let Some(found) = debt.find(line) {
            let prefix = &line[..found.start()];
            let commented = trimmed.starts_with('*')
                || ["//", "#", "/*", "--", "<!--"]
                    .iter()
                    .any(|leader| prefix.contains(leader));
            if commented && reported.insert(("debt-marker", number)) {
                out.push(NativeFinding {
                    rule: "debt-marker".into(),
                    severity: "low",
                    path: path.to_string(),
                    line: number,
                    message: format!("{} marker left in source", found.as_str()),
                });
            }
        }
        if comment {
            continue;
        }
        for rule in rules {
            if !rule.re.is_match(line) {
                continue;
            }
            if let Some(want) = rule.next_line {
                let next = lines[index + 1..]
                    .iter()
                    .find(|candidate| !candidate.trim().is_empty());
                if next.map(|candidate| candidate.trim()) != Some(want) {
                    continue;
                }
            }
            if reported.insert((rule.id, number)) {
                out.push(NativeFinding {
                    rule: rule.id.into(),
                    severity: rule.severity,
                    path: path.to_string(),
                    line: number,
                    message: rule.message.to_string(),
                });
            }
        }
        if let Some(normalized) = normalize_line(line) {
            sig.push((number, hash_str(&normalized), normalized.chars().count()));
        }
    }
    sig
}

// ---------------------------------------------------------------------------
// Bounded reads
// ---------------------------------------------------------------------------

enum Skip {
    UnsafePath,
    Symlink,
    Missing,
    Unreadable,
    TooLarge,
    TotalCap,
    NotUtf8,
    Changed,
    Unbound,
}

impl Skip {
    fn label(&self) -> &'static str {
        match self {
            Skip::UnsafePath => "unsafe-path",
            Skip::Symlink => "symlink",
            Skip::Missing => "missing",
            Skip::Unreadable => "unreadable",
            Skip::TooLarge => "file-size-cap",
            Skip::TotalCap => "total-size-cap",
            Skip::NotUtf8 => "not-utf8",
            Skip::Changed => "changed-since-inventory",
            Skip::Unbound => "context-inventory-digest-missing",
        }
    }
}

fn read_entry(
    root: &Path,
    entry: &InventoryEntry,
    per_file: u64,
    remaining: u64,
) -> Result<String, Skip> {
    let relative = Path::new(&entry.path);
    if entry.path.is_empty()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(Skip::UnsafePath);
    }
    let mut ancestor = root.to_path_buf();
    for component in relative.components() {
        ancestor.push(component.as_os_str());
        if std::fs::symlink_metadata(&ancestor)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    Skip::Missing
                } else {
                    Skip::Unreadable
                }
            })?
            .file_type()
            .is_symlink()
        {
            return Err(Skip::Symlink);
        }
    }
    let full = root.join(relative);
    let meta = std::fs::symlink_metadata(&full).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Skip::Missing
        } else {
            Skip::Unreadable
        }
    })?;
    if meta.file_type().is_symlink() {
        return Err(Skip::Symlink);
    }
    if !meta.is_file() {
        return Err(Skip::Unreadable);
    }
    if meta.len() > per_file {
        return Err(Skip::TooLarge);
    }
    if meta.len() > remaining {
        return Err(Skip::TotalCap);
    }
    let mut buffer = Vec::new();
    File::open(&full)
        .map_err(|_| Skip::Unreadable)?
        .take(per_file + 1)
        .read_to_end(&mut buffer)
        .map_err(|_| Skip::Unreadable)?;
    if buffer.len() as u64 > per_file {
        return Err(Skip::TooLarge);
    }
    if buffer.len() as u64 > remaining {
        return Err(Skip::TotalCap);
    }
    if let Some(expected) = &entry.digest {
        let actual = format!("sha256:{}", hex::encode(Sha256::digest(&buffer)));
        if &actual != expected {
            return Err(Skip::Changed);
        }
    }
    String::from_utf8(buffer).map_err(|_| Skip::NotUtf8)
}

/// Syntax adapters stage only bounded, digest-verified source, never a path
/// that could cause an interpreter to follow an unchecked repository symlink.
pub(super) fn syntax_source(root: &Path, entry: &InventoryEntry) -> Option<String> {
    let canonical_root = root.canonicalize().ok()?;
    let mut ancestor = root.to_path_buf();
    for component in Path::new(&entry.path).components() {
        let Component::Normal(part) = component else {
            return None;
        };
        ancestor.push(part);
        if std::fs::symlink_metadata(&ancestor)
            .ok()?
            .file_type()
            .is_symlink()
        {
            return None;
        }
    }
    if !ancestor.canonicalize().ok()?.starts_with(canonical_root) {
        return None;
    }
    read_entry(root, entry, 1024 * 1024, 1024 * 1024).ok()
}

// ---------------------------------------------------------------------------
// Context and tools
// ---------------------------------------------------------------------------

fn manifest_paths(entries: &[InventoryEntry], keep: impl Fn(&str) -> bool) -> Option<Value> {
    let paths = entries
        .iter()
        .filter(|entry| keep(file_name(&entry.path)))
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>();
    (!paths.is_empty()).then(|| json!(paths))
}

fn manifest_dirs(entries: &[InventoryEntry], keep: impl Fn(&str) -> bool) -> Option<Value> {
    let dirs = entries
        .iter()
        .filter(|entry| keep(file_name(&entry.path)))
        .map(|entry| match entry.path.rfind('/') {
            Some(index) => entry.path[..index].to_string(),
            None => ".".to_string(),
        })
        .collect::<BTreeSet<_>>();
    (!dirs.is_empty()).then(|| json!(dirs))
}

fn derive_context(
    entries: &[InventoryEntry],
    required: &[&str],
    build_tags: Option<BTreeSet<String>>,
) -> Map<String, Value> {
    let mut context = Map::new();
    for key in required {
        let value = match *key {
            "packageRoots" => manifest_dirs(entries, |name| {
                matches!(
                    name,
                    "pyproject.toml" | "setup.py" | "setup.cfg" | "requirements.txt" | "Pipfile"
                )
            }),
            "sourceSets" => manifest_dirs(entries, |name| {
                matches!(
                    name,
                    "build.gradle"
                        | "build.gradle.kts"
                        | "settings.gradle"
                        | "settings.gradle.kts"
                        | "pom.xml"
                )
            }),
            "targetFrameworks" => manifest_paths(entries, |name| {
                name.ends_with(".csproj")
                    || name.ends_with(".fsproj")
                    || name.ends_with(".vbproj")
                    || name == "Directory.Build.props"
            }),
            "platform" => manifest_paths(entries, |name| {
                name == "Package.swift" || name == "project.pbxproj"
            }),
            "compileDatabase" => manifest_paths(entries, |name| name == "compile_commands.json"),
            "features" | "targets" => manifest_paths(entries, |name| name == "Cargo.toml"),
            "modules" => manifest_paths(entries, |name| name == "go.mod"),
            "buildTags" => build_tags.as_ref().map(|tags| json!(tags)),
            _ => None,
        };
        if let Some(value) = value {
            context.insert((*key).to_string(), value);
        }
    }
    context
}

fn tool_candidates(provider_id: &str, tool: &str) -> &'static [&'static str] {
    match (provider_id, tool) {
        ("code.rust", _) => &["cargo"],
        ("code.javascript", "type") => &["tsc"],
        ("code.javascript", "lint") => &["eslint"],
        ("code.javascript", _) => &["node"],
        ("code.python", "lint") => &["ruff", "flake8"],
        ("code.python", "type") => &["mypy", "pyright"],
        ("code.python", "test") => &["pytest"],
        ("code.python", _) => &["python3", "python"],
        ("code.go", "vulnerability") => &["govulncheck"],
        ("code.go", _) => &["go"],
        ("code.jvm", "wrapper") => &["gradlew", "mvnw"],
        ("code.jvm", "compile") => &["javac", "kotlinc"],
        ("code.jvm", "lint") => &["ktlint", "checkstyle"],
        ("code.jvm", _) => &["gradle", "mvn"],
        ("code.dotnet", _) => &["dotnet"],
        ("code.c-family", "compiler" | "sanitizer") => &["clang", "gcc", "cc"],
        ("code.c-family", "lint") => &["clang-tidy"],
        ("code.c-family", "analyzer") => &["clang-tidy", "cppcheck"],
        ("code.c-family", _) => &["ctest"],
        ("code.mobile", "compiler") => &["swiftc", "swift", "clang", "xcodebuild"],
        ("code.mobile", "analyzer") => &["clang", "swiftlint", "xcodebuild"],
        ("code.mobile", _) => &["xcodebuild", "swift"],
        ("code.php-ruby", "package" | "security") => &["composer"],
        ("code.php-ruby", "lint") => &["php"],
        ("code.php-ruby", "ruby-lint") => &["rubocop"],
        ("code.php-ruby", "type") => &["phpstan", "psalm"],
        ("code.php-ruby", _) => &["phpunit"],
        _ => &[],
    }
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let names: Vec<String> = if cfg!(windows) {
        vec![
            name.to_string(),
            format!("{name}.exe"),
            format!("{name}.cmd"),
            format!("{name}.bat"),
        ]
    } else {
        vec![name.to_string()]
    };
    std::env::split_paths(&path)
        .flat_map(|dir| names.iter().map(move |candidate| dir.join(candidate)))
        .find(|candidate| is_executable(candidate))
}

fn resolve_tool(candidates: &[&str], entries: &[InventoryEntry]) -> Option<String> {
    candidates.iter().find_map(|candidate| {
        if matches!(*candidate, "gradlew" | "mvnw") {
            entries
                .iter()
                .find(|entry| file_name(&entry.path) == *candidate)
                .map(|entry| entry.path.clone())
        } else {
            find_on_path(candidate).map(|path| path.to_string_lossy().into_owned())
        }
    })
}

// ---------------------------------------------------------------------------
// Producer
// ---------------------------------------------------------------------------

/// Build the analyzer input and native findings for `provider_id` from the
/// denominator `entries`. `root` is the repository root the entries are
/// relative to; with no root every selected file is a recorded skip.
pub fn produce(
    provider_id: &str,
    config: &LanguageConfig,
    root: Option<&Path>,
    entries: &[InventoryEntry],
    limits: &EvidenceLimits,
) -> Result<Produced, AuditError> {
    let selected = select_entries(config, entries);
    let rules = compile_rules(provider_id)?;
    let ruby = if provider_id == "code.php-ruby" {
        ruby_rules()?
    } else {
        Vec::new()
    };
    let debt = Regex::new(r"\b(?:TODO|FIXME|HACK|XXX)\b")
        .map_err(|error| AuditError::Provider(format!("invalid debt rule: {error}")))?;
    let long_tail = provider_id == "code.long-tail";
    let mut duplicates = DuplicateIndex {
        seen: HashMap::new(),
        cap: limits.max_duplicate_windows,
        truncated: false,
    };

    let mut findings = Vec::new();
    let mut skips = Vec::new();
    let mut skip_overflow = 0usize;
    let mut examined = 0u64;
    let mut bytes_read = 0u64;
    let mut lines_read = 0u64;
    let mut build_tags: BTreeSet<String> = BTreeSet::new();
    let mut source_accounting = Vec::new();

    for entry in &selected {
        let outcome = match root {
            Some(root) => read_entry(
                root,
                entry,
                limits.max_file_bytes,
                limits.max_total_bytes.saturating_sub(bytes_read),
            ),
            None => Err(Skip::Unreadable),
        };
        match outcome {
            Ok(text) => {
                examined += 1;
                bytes_read += text.len() as u64;
                lines_read += text.lines().count() as u64;
                if config.id == "go" {
                    for line in text.lines() {
                        let trimmed = line.trim();
                        if let Some(tag) = trimmed
                            .strip_prefix("//go:build ")
                            .or_else(|| trimmed.strip_prefix("// +build "))
                        {
                            build_tags.insert(tag.trim().to_string());
                        }
                    }
                }
                let active_rules =
                    if provider_id == "code.php-ruby" && extension_of(&entry.path) == "rb" {
                        &ruby
                    } else {
                        &rules
                    };
                let sig = scan_text(&entry.path, &text, active_rules, &debt, &mut findings);
                duplicates.scan(&entry.path, &sig, &mut findings);
                source_accounting.push(json!({
                    "path": entry.path, "extension": extension_of(&entry.path),
                    "status": "examined", "bytes": text.len(),
                    "digest": format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes()))),
                    "analysis": if long_tail { "generic-source" } else { "language-source" },
                }));
            }
            Err(skip) => {
                source_accounting.push(json!({
                    "path": entry.path, "extension": extension_of(&entry.path),
                    "status": "skipped", "reason": skip.label(),
                }));
                if skips.len() < limits.max_skip_records {
                    skips.push(format!("{}:{}", skip.label(), entry.path));
                } else {
                    skip_overflow += 1;
                }
            }
        }
    }
    // Manifest membership alone is not an inspection. Go module/lock & Python package context is
    // admitted only after reading the original, frozen digest-bound bytes with
    // the same path, symlink & shared byte limits as language source. Source
    // analysis/facts remain separate from this context inspection.
    let source_bytes_read = bytes_read;
    let mut context_expected = 0u64;
    let mut context_examined = 0u64;
    let mut context_accounting = Vec::new();
    let mut verified_context = Vec::new();
    if matches!(provider_id, "code.go" | "code.python") {
        if provider_id == "code.python" {
            // setup.py already belongs to Python source coverage. Reuse only
            // its actual digest-bound source read; never count it twice.
            verified_context.extend(
                entries
                    .iter()
                    .filter(|entry| {
                        file_name(&entry.path) == "setup.py"
                            && entry.digest.is_some()
                            && source_accounting
                                .iter()
                                .any(|row| row["path"] == entry.path && row["status"] == "examined")
                    })
                    .cloned(),
            );
        }
        for entry in entries.iter().filter(|entry| match provider_id {
            "code.go" => matches!(file_name(&entry.path), "go.mod" | "go.sum"),
            "code.python" => matches!(
                file_name(&entry.path),
                "pyproject.toml" | "setup.cfg" | "requirements.txt" | "Pipfile"
            ),
            _ => false,
        }) {
            context_expected += 1;
            let outcome = if entry.digest.is_none() {
                Err(Skip::Unbound)
            } else {
                match root {
                    Some(root) => read_entry(
                        root,
                        entry,
                        limits.max_file_bytes,
                        limits.max_total_bytes.saturating_sub(bytes_read),
                    ),
                    None => Err(Skip::Unreadable),
                }
            };
            match outcome {
                Ok(text) => {
                    context_examined += 1;
                    bytes_read += text.len() as u64;
                    verified_context.push(entry.clone());
                    context_accounting.push(json!({
                        "path": entry.path, "status": "examined",
                        "analysis": if provider_id == "code.python" { "package-root-context" } else if file_name(&entry.path) == "go.mod" { "module-context" } else { "dependency-lock-context" },
                        "bytes": text.len(), "digest": entry.digest,
                    }));
                }
                Err(skip) => {
                    context_accounting.push(json!({
                        "path": entry.path, "status": "skipped", "reason": skip.label(),
                    }));
                    if skips.len() < limits.max_skip_records {
                        skips.push(format!("{}:{}", skip.label(), entry.path));
                    } else {
                        skip_overflow += 1;
                    }
                }
            }
        }
    }
    if skip_overflow > 0 {
        skips.push(format!("more-files-skipped:{skip_overflow}"));
    }

    let findings_truncated = findings.len().saturating_sub(limits.max_findings);
    findings.truncate(limits.max_findings);

    // Go build tags are only a complete fact when every Go file was read.
    let tags = (examined as usize == selected.len()).then_some(build_tags);
    let context_entries = if matches!(provider_id, "code.go" | "code.python") {
        verified_context.as_slice()
    } else {
        entries
    };
    let context = derive_context(context_entries, config.required_context, tags);

    let mut rule_ids = rules.iter().map(|rule| rule.id).collect::<Vec<_>>();
    rule_ids.extend(ruby.iter().map(|rule| rule.id));
    rule_ids.extend(["debt-marker", "oversized-file"]);
    rule_ids.push("duplicate-block");
    rule_ids.sort_unstable();
    rule_ids.dedup();

    let mut missing_tools = Vec::new();
    let mut unrun_tools = Vec::new();
    let mut tool_discovery = Vec::new();
    for tool in config.tools {
        let candidates = tool_candidates(provider_id, tool);
        let resolved = resolve_tool(candidates, entries);
        match &resolved {
            Some(_) => unrun_tools.push(*tool),
            None => missing_tools.push(*tool),
        }
        tool_discovery.push(json!({
            "tool": tool,
            "candidates": candidates,
            "resolved": resolved,
            "executed": false,
        }));
    }

    let mut input = json!({
        "files": selected.iter().map(|entry| json!({"path": entry.path})).collect::<Vec<_>>(),
        "context": Value::Object(context),
        "sourceAccounting": source_accounting,
        "facts": [{
            "kind": "native-metrics",
            "filesRead": examined,
            "linesRead": lines_read,
            "bytesRead": source_bytes_read,
            "rules": rule_ids,
        }],
    });
    if matches!(provider_id, "code.go" | "code.python") {
        input["contextAccounting"] = json!(context_accounting);
    }
    if long_tail {
        input["unsupportedLanguageCoverage"] = json!(unsupported_language_coverage(&selected));
    }

    Ok(Produced {
        input,
        findings,
        findings_truncated,
        expected: selected.len() as u64,
        examined,
        context_expected,
        context_examined,
        context_bytes_read: bytes_read - source_bytes_read,
        bytes_read,
        skips,
        duplicate_detection_truncated: duplicates.truncated,
        missing_tools,
        unrun_tools,
        tool_discovery,
        rule_ids,
    })
}

#[cfg(test)]
mod historical_source_tests {
    use super::*;

    fn entry(path: String) -> InventoryEntry {
        InventoryEntry {
            path,
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: false,
            digest: None,
        }
    }

    #[test]
    fn all_29_historical_extensions_are_read_and_analyzed_once_without_whitelist_pass() {
        let root = std::env::temp_dir().join(format!(
            "historical-source-accounting-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let entries = HISTORICAL_SOURCE_EXTENSIONS
            .iter()
            .map(|extension| {
                let entry = entry(format!("fixture.{extension}"));
                std::fs::write(
                    root.join(&entry.path),
                    "// TODO historical coverage fixture\n",
                )
                .unwrap();
                entry
            })
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 29);
        let mut read = 0;
        let mut debts = 0;
        for provider in PROVIDER_IDS {
            let config = config_for(provider).unwrap();
            let made = produce(
                provider,
                config,
                Some(&root),
                &entries,
                &EvidenceLimits::default(),
            )
            .unwrap();
            read += made.examined;
            debts += made
                .findings
                .iter()
                .filter(|finding| finding.rule == "debt-marker")
                .count();
            assert_eq!(made.examined, made.expected);
            assert!(made.input["sourceAccounting"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["status"] == "examined"
                    && item["digest"].as_str().unwrap().starts_with("sha256:")));
            if provider == "code.long-tail" {
                let analysis = long_tail::analyze(&made.input);
                assert_eq!(analysis["complete"], false);
                assert!(!analysis["coverageGaps"].as_array().unwrap().is_empty());
            }
        }
        assert_eq!(read, 29);
        assert_eq!(debts, 29);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_historical_source_is_a_skip_not_examined() {
        let entries = [entry("fixture.vue".into())];
        let made = produce(
            "code.long-tail",
            &long_tail::CONFIG,
            None,
            &entries,
            &EvidenceLimits::default(),
        )
        .unwrap();
        assert_eq!((made.expected, made.examined), (1, 0));
        assert_eq!(made.input["sourceAccounting"][0]["status"], "skipped");
        assert_eq!(long_tail::analyze(&made.input)["complete"], false);
    }

    #[test]
    fn ruby_has_its_own_static_rules() {
        let rules = ruby_rules().unwrap();
        let mut findings = Vec::new();
        scan_text(
            "app.rb",
            "binding.pry\nbegin\nrescue\nend\n",
            &rules,
            &Regex::new("TODO").unwrap(),
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "debug-leftover"));
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "error-swallowed"));
    }
}

#[cfg(test)]
mod go_context_tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "go-context-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }
        fn file(&self, path: &str, text: &str) -> InventoryEntry {
            std::fs::write(self.0.join(path), text).unwrap();
            InventoryEntry {
                path: path.into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: path.ends_with(".go"),
                digest: Some(format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(text.as_bytes()))
                )),
            }
        }
        fn produce(&self, entries: &[InventoryEntry], limits: &EvidenceLimits) -> Produced {
            produce("code.go", &go::CONFIG, Some(&self.0), entries, limits).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn python_package_context_requires_bound_reads_without_counting_setup_twice() {
        let fixture = Fixture::new();
        let entries = [
            fixture.file(
                "pyproject.toml",
                "[project]\nname='fixture'\nversion='0.0.0'\n",
            ),
            fixture.file("answer.py", "answer = 42\n"),
            fixture.file("setup.py", "pass\n"),
            fixture.file("README.md", "unrelated\n"),
        ];
        let made = produce(
            "code.python",
            &python::CONFIG,
            Some(&fixture.0),
            &entries,
            &EvidenceLimits::default(),
        )
        .unwrap();
        assert_eq!((made.expected, made.examined), (2, 2));
        assert_eq!((made.context_expected, made.context_examined), (1, 1));
        assert_eq!(made.input["context"]["packageRoots"], json!(["."]));
        assert_eq!(made.input["contextAccounting"].as_array().unwrap().len(), 1);
        assert!(made.expected + made.context_expected < entries.len() as u64);
        let mut changed = entries.to_vec();
        changed[0].digest = None;
        changed.retain(|entry| entry.path != "setup.py");
        let missing = produce(
            "code.python",
            &python::CONFIG,
            Some(&fixture.0),
            &changed,
            &EvidenceLimits::default(),
        )
        .unwrap();
        assert_eq!((missing.context_expected, missing.context_examined), (1, 0));
        assert!(missing.input["context"].get("packageRoots").is_none());
        assert_eq!(
            missing.input["contextAccounting"][0]["reason"],
            "context-inventory-digest-missing"
        );
    }

    #[test]
    fn go_context_reads_preserve_source_facts_and_leave_unrelated_denominator_unexamined() {
        let fixture = Fixture::new();
        let source = "package sample\n";
        let module = "module example.invalid/sample\n\ngo 1.26\n";
        let entries = [
            fixture.file("go.mod", module),
            fixture.file("main.go", source),
            fixture.file("main_test.go", source),
            fixture.file("README.md", "unrelated\n"),
            fixture.file(
                "go.sum",
                "example.invalid/dependency v1.0.0 h1:opaque-fixture-digest\n",
            ),
            fixture.file("go.work", "go 1.26\n\nuse .\n"),
            fixture.file("go.work.sum", "unsupported workspace lock fixture\n"),
        ];
        let made = fixture.produce(&entries, &EvidenceLimits::default());
        assert_eq!((made.expected, made.examined), (2, 2));
        assert_eq!((made.context_expected, made.context_examined), (2, 2));
        let context_bytes =
            module.len() as u64 + std::fs::metadata(fixture.0.join("go.sum")).unwrap().len();
        assert_eq!(made.context_bytes_read, context_bytes);
        assert_eq!(made.bytes_read, 2 * source.len() as u64 + context_bytes);
        assert_eq!(made.input["facts"][0]["filesRead"], 2);
        assert_eq!(made.input["facts"][0]["bytesRead"], 2 * source.len());
        assert_eq!(made.input["sourceAccounting"].as_array().unwrap().len(), 2);
        assert_eq!(made.input["contextAccounting"].as_array().unwrap().len(), 2);
        assert_eq!(
            made.input["contextAccounting"][0]["digest"],
            entries[0].digest.as_ref().unwrap().as_str()
        );
        assert_eq!(made.input["context"]["modules"], json!(["go.mod"]));
        assert_eq!(made.input["context"]["buildTags"], json!([]));
        assert_eq!(
            made.input["contextAccounting"][0]["analysis"],
            "module-context"
        );
        assert_eq!(
            made.input["contextAccounting"][1]["analysis"],
            "dependency-lock-context"
        );
        assert!(made.input["contextAccounting"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| {
                !matches!(
                    item["path"].as_str(),
                    Some("go.work" | "go.work.sum" | "README.md")
                )
            }));
        assert!(made.skips.is_empty());
        assert!(made.expected + made.context_expected < entries.len() as u64);
    }

    #[test]
    fn go_context_only_read_is_never_language_source_or_a_tool_pass() {
        let fixture = Fixture::new();
        let entries = [fixture.file("go.mod", "module example.invalid/sample\n")];
        let made = fixture.produce(&entries, &EvidenceLimits::default());
        assert_eq!((made.expected, made.examined), (0, 0));
        assert_eq!((made.context_expected, made.context_examined), (1, 1));
        assert_eq!(made.input["facts"][0]["filesRead"], 0);
        assert_eq!(made.input["facts"][0]["bytesRead"], 0);
        assert!(made.input["files"].as_array().unwrap().is_empty());
        assert!(made.findings.is_empty());
        assert!(made
            .tool_discovery
            .iter()
            .all(|item| item["executed"] == false));
    }

    #[test]
    fn changed_missing_unreadable_unbound_and_capped_context_never_receive_credit() {
        for path in ["go.mod", "go.sum"] {
            for (control, reason) in [
                ("changed", "changed-since-inventory"),
                ("missing", "missing"),
                ("unreadable", "unreadable"),
                ("unbound", "context-inventory-digest-missing"),
                ("file-cap", "file-size-cap"),
                ("total-cap", "total-size-cap"),
            ] {
                let fixture = Fixture::new();
                let text = "module example.invalid/sample\n";
                let mut entry = fixture.file(path, text);
                let mut limits = EvidenceLimits::default();
                match control {
                    "changed" => {
                        std::fs::write(fixture.0.join(path), "module changed.invalid/sample\n")
                            .unwrap()
                    }
                    "missing" => std::fs::remove_file(fixture.0.join(path)).unwrap(),
                    "unreadable" => {
                        std::fs::remove_file(fixture.0.join(path)).unwrap();
                        std::fs::create_dir(fixture.0.join(path)).unwrap();
                    }
                    "unbound" => entry.digest = None,
                    "file-cap" => limits.max_file_bytes = text.len() as u64 - 1,
                    "total-cap" => limits.max_total_bytes = text.len() as u64 - 1,
                    _ => unreachable!(),
                }
                let made = fixture.produce(&[entry], &limits);
                assert_eq!((made.expected, made.examined), (0, 0), "{control}");
                assert_eq!(
                    (made.context_expected, made.context_examined),
                    (1, 0),
                    "{control}"
                );
                assert_eq!(made.context_bytes_read, 0, "{control}");
                assert!(made.input["context"].get("modules").is_none(), "{control}");
                assert_eq!(
                    made.input["contextAccounting"][0]["reason"], reason,
                    "{control}"
                );
                assert_eq!(made.skips, vec![format!("{reason}:{path}")], "{control}");
            }
        }
    }

    #[test]
    fn go_context_and_source_share_total_byte_budget() {
        let fixture = Fixture::new();
        let source = "package sample\n";
        let module = "module example.invalid/sample\n";
        let entries = [
            fixture.file("main.go", source),
            fixture.file("go.mod", module),
        ];
        let mut limits = EvidenceLimits::default();
        limits.max_total_bytes = (source.len() + module.len() - 1) as u64;
        let made = fixture.produce(&entries, &limits);
        assert_eq!((made.expected, made.examined), (1, 1));
        assert_eq!((made.context_expected, made.context_examined), (1, 0));
        assert_eq!(made.bytes_read, source.len() as u64);
        assert_eq!(
            made.input["contextAccounting"][0]["reason"],
            "total-size-cap"
        );
    }
}
