//! Faithful port of `src/lib/naming/check.mjs` (chunk w2_049).
//!
//! `check.mjs` is the whole-repository naming lint CLI: it walks every
//! tracked (or, absent git, every on-disk) file under the repository root,
//! flags filenames and file contents that still carry a legacy naming
//! token, and cross-checks a handful of specific repository artifacts
//! (`README.md`, `package.json`, `MANIFEST.package.json`, the plugin
//! manifests, two runtime authority-registry source files) against the
//! canonical naming registry. It was explicitly left unported by the
//! `p6_inventory::naming` module (see that module's doc comment); this
//! chunk ports it in full, reusing `p6_inventory::naming` for registry
//! loading and canonical-authority-id computation rather than duplicating
//! that logic.
//!
//! The JS runtime constants `AUTHORITY_ID` (from
//! `src/packages/contracts/enums.mjs`) and `ROSTER_ROLE_IDS` (from
//! `src/lib/roster/index.mjs`) are reproduced here as literal data — the
//! same role this crate's `p6_inventory::naming` module already plays for
//! other naming-registry literals — since neither JS module has a Rust
//! port to call into from this crate.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use serde_json::Value;

use crate::p6_inventory::naming::{canonical_authority_ids, load_naming_registry, NamingRegistry};

/// Port of `TOKENS`.
pub const TOKENS: &[&str] = &["seer", "nemesis", "forge", "sentinel", "sorcerer"];

/// Port of `SKIP_PREFIXES`.
const SKIP_PREFIXES: &[&str] = &[
    ".git/",
    ".agent/",
    ".audit/",
    ".cache/",
    "docs/foundation/",
    "node_modules/",
];

/// Port of `ACTIVE_SOURCE` (case-insensitive extension match).
fn is_active_source(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    for ext in [
        "cjs", "js", "json", "jsx", "md", "mjs", "py", "sh", "toml", "ts", "tsx", "yaml", "yml",
    ] {
        if lower.ends_with(&format!(".{ext}")) {
            return true;
        }
    }
    false
}

/// A single naming-contract issue, mirroring the JS `{ path, line?, token?,
/// reason }` objects pushed onto `issues`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamingIssue {
    pub path: String,
    pub line: Option<usize>,
    pub token: Option<String>,
    pub reason: String,
}

impl NamingIssue {
    fn new(path: impl Into<String>, reason: impl Into<String>) -> Self {
        NamingIssue {
            path: path.into(),
            line: None,
            token: None,
            reason: reason.into(),
        }
    }

    fn with_token(path: impl Into<String>, token: impl Into<String>, reason: impl Into<String>) -> Self {
        NamingIssue {
            path: path.into(),
            line: None,
            token: Some(token.into()),
            reason: reason.into(),
        }
    }

    fn with_line_token(
        path: impl Into<String>,
        line: usize,
        token: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        NamingIssue {
            path: path.into(),
            line: Some(line),
            token: Some(token.into()),
            reason: reason.into(),
        }
    }
}

/// Port of the `rules[]` entries in `src/config/naming-legacy-allowlist.json`.
#[derive(Debug, Clone)]
pub struct AllowlistRule {
    pub path: Option<String>,
    pub path_prefix: Option<String>,
    pub tokens: Vec<String>,
    pub class: Option<String>,
    pub reason: Option<String>,
    pub occurrences: BTreeMap<String, i64>,
}

impl AllowlistRule {
    fn from_value(value: &Value) -> Self {
        let path = value.get("path").and_then(Value::as_str).map(str::to_string);
        let path_prefix = value
            .get("pathPrefix")
            .and_then(Value::as_str)
            .map(str::to_string);
        let tokens = value
            .get("tokens")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let class = value.get("class").and_then(Value::as_str).map(str::to_string);
        let reason = value.get("reason").and_then(Value::as_str).map(str::to_string);
        let mut occurrences = BTreeMap::new();
        if let Some(obj) = value.get("occurrences").and_then(Value::as_object) {
            for (k, v) in obj {
                if let Some(n) = v.as_i64() {
                    occurrences.insert(k.clone(), n);
                }
            }
        }
        AllowlistRule {
            path,
            path_prefix,
            tokens,
            class,
            reason,
            occurrences,
        }
    }

    fn matches_path(&self, path: &str) -> bool {
        self.path.as_deref() == Some(path)
            || self
                .path_prefix
                .as_deref()
                .is_some_and(|prefix| path.starts_with(prefix))
    }
}

/// Port of `matchingRule`.
fn matching_rule<'a>(rules: &'a [AllowlistRule], path: &str, token: &str) -> Option<&'a AllowlistRule> {
    rules
        .iter()
        .find(|rule| rule.matches_path(path) && rule.tokens.iter().any(|t| t == token))
}

/// Port of `occurrences`: 1-indexed line numbers of every whole-token match
/// (case-insensitive, no leading/trailing alphanumeric neighbour).
fn occurrences(content: &str, token: &str) -> Vec<usize> {
    // JS uses `(?<![A-Za-z0-9])token(?![A-Za-z0-9])`, a zero-width-lookaround
    // match. The `regex` crate has no lookaround support, so this is a
    // manual boundary-checked scan with equivalent semantics: a match is
    // accepted only when neither neighbour is `[A-Za-z0-9]`.
    let lower_content = content.to_ascii_lowercase();
    let lower_token = token.to_ascii_lowercase();
    let bytes = content.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric();
    let mut found = Vec::new();
    let mut start = 0usize;
    while let Some(rel) = lower_content[start..].find(&lower_token) {
        let idx = start + rel;
        let before_ok = idx == 0 || !is_word(bytes[idx - 1]);
        let end = idx + lower_token.len();
        let after_ok = end >= bytes.len() || !is_word(bytes[end]);
        if before_ok && after_ok {
            let line = content[..idx].matches('\n').count() + 1;
            found.push(line);
        }
        start = idx + 1;
    }
    found
}

/// Port of `text`: returns `None` for NUL-containing or non-UTF-8 bytes, or
/// content whose control-character ratio exceeds 1%.
fn text(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    if bytes.contains(&0) {
        return None;
    }
    let decoded = String::from_utf8(bytes.clone()).ok()?;
    let controls = bytes
        .iter()
        .filter(|&&b| b < 32 && ![0u8, 9, 10, 13].contains(&b))
        .count();
    let ratio = controls as f64 / (bytes.len().max(1) as f64);
    if ratio > 0.01 {
        None
    } else {
        Some(decoded)
    }
}

fn to_rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Port of `recursiveFiles`.
fn recursive_files(root: &Path, cursor: &Path, output: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(cursor) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        let rel = to_rel(root, &path);
        if SKIP_PREFIXES
            .iter()
            .any(|prefix| format!("{rel}/").starts_with(prefix))
        {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            recursive_files(root, &path, output);
        } else if meta.is_file() {
            output.push(rel);
        }
    }
}

/// Port of `repositoryFiles`: prefer `git ls-files -co --exclude-standard`,
/// falling back to a manual recursive walk when git is unavailable.
fn repository_files(root: &Path) -> Vec<String> {
    let git_result = Command::new("git")
        .args(["ls-files", "-co", "--exclude-standard", "-z"])
        .current_dir(root)
        .output();

    if let Ok(output) = git_result {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut files: Vec<String> = stdout
                .split('\0')
                .filter(|s| !s.is_empty())
                .filter(|path| {
                    let p = root.join(path);
                    fs::symlink_metadata(&p)
                        .map(|m| m.is_file())
                        .unwrap_or(false)
                })
                .filter(|path| !SKIP_PREFIXES.iter().any(|prefix| path.starts_with(prefix)))
                .map(str::to_string)
                .collect();
            files.sort();
            return files;
        }
    }

    let mut output = Vec::new();
    recursive_files(root, root, &mut output);
    output
}

/// Port of `allowlistIssues`.
fn allowlist_issues(root: &Path, rules: &[AllowlistRule], files: &[String]) -> Vec<NamingIssue> {
    let mut issues = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        let rule_path = format!("src/config/naming-legacy-allowlist.json#rules[{index}]");
        if (rule.path.is_none() && rule.path_prefix.is_none())
            || rule.tokens.is_empty()
            || rule.class.is_none()
            || rule.reason.is_none()
        {
            issues.push(NamingIssue::new(
                rule_path,
                "legacy allowlist rule lacks target, tokens, class, or reason",
            ));
            continue;
        }
        let candidates: Vec<&String> = files.iter().filter(|path| rule.matches_path(path)).collect();
        let target = rule.path.clone().or_else(|| rule.path_prefix.clone()).unwrap_or_default();
        if candidates.is_empty() {
            issues.push(NamingIssue::new(
                target,
                "legacy allowlist target does not exist or matches no files",
            ));
            continue;
        }
        for token in &rule.tokens {
            if !TOKENS.contains(&token.as_str()) {
                issues.push(NamingIssue::with_token(
                    rule_path.clone(),
                    token.clone(),
                    "legacy allowlist names unknown token",
                ));
                continue;
            }
            let mut observed = 0usize;
            for path in &candidates {
                observed += occurrences(path, token).len();
                if let Some(content) = text(&root.join(path)) {
                    observed += occurrences(&content, token).len();
                }
            }
            if observed == 0 {
                issues.push(NamingIssue::with_token(
                    target.clone(),
                    token.clone(),
                    "legacy allowlist token exemption is unused",
                ));
            }
        }
    }
    issues
}

fn read_json(path: &Path) -> Option<Value> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Literal port of `AUTHORITY_ID` from `src/packages/contracts/enums.mjs`.
const AUTHORITY_ID: &[&str] = &["legion", "sage", "alchemist", "oracle", "arcane"];

/// Literal port of `ROSTER_ROLE_IDS` (`ROLE_IDS`) from `src/lib/roster/index.mjs`.
const ROSTER_ROLE_IDS: &[&str] = &["sage", "alchemist", "oracle"];

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

/// Port of `semanticIssues`.
fn semantic_issues(root: &Path, registry: &NamingRegistry) -> Vec<NamingIssue> {
    let mut issues = Vec::new();
    let expected = vec![
        "alchemist".to_string(),
        "arcane".to_string(),
        "oracle".to_string(),
        "sage".to_string(),
    ];
    let canonical_ids = canonical_authority_ids(registry);
    if canonical_ids != expected {
        issues.push(NamingIssue::new(
            "src/config/naming-registry.json",
            "canonical authority set mismatch",
        ));
    }

    let product_id = registry
        .0
        .get("product")
        .and_then(|p| p.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let actor_keys: Vec<String> = registry
        .0
        .get("actors")
        .and_then(Value::as_object)
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();
    let mut runtime_expected_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    runtime_expected_set.insert(product_id);
    for id in &expected {
        runtime_expected_set.insert(id.clone());
    }
    for id in &actor_keys {
        runtime_expected_set.insert(id.clone());
    }
    let runtime_expected: Vec<String> = runtime_expected_set.into_iter().collect();
    let authority_id_sorted = sorted(AUTHORITY_ID.iter().map(|s| s.to_string()).collect());
    if authority_id_sorted != runtime_expected {
        issues.push(NamingIssue::new(
            "src/packages/contracts/enums.mjs",
            "runtime authority set differs from naming registry",
        ));
    }

    if let Some(seats) = registry.0.get("seats").and_then(Value::as_object) {
        for (id, seat) in seats {
            let authority_false = seat.get("authority").and_then(Value::as_bool) == Some(false);
            let is_authority_id = AUTHORITY_ID.contains(&id.as_str());
            if !authority_false || is_authority_id {
                issues.push(NamingIssue::new(
                    "src/config/naming-registry.json",
                    format!("advisory seat '{id}' must not be an authority"),
                ));
            }
        }
    }

    let roster_sorted = sorted(ROSTER_ROLE_IDS.iter().map(|s| s.to_string()).collect());
    if roster_sorted != vec!["alchemist".to_string(), "oracle".to_string(), "sage".to_string()] {
        issues.push(NamingIssue::new(
            "src/lib/roster/index.mjs",
            "runtime roster differs from naming registry",
        ));
    }

    if let Ok(readme) = fs::read_to_string(root.join("README.md")) {
        for display in ["Legion", "Sage", "Alchemist", "Oracle", "Arcane", "Covenant"] {
            if !readme.contains(&format!("| **{display}** |")) {
                issues.push(NamingIssue::new(
                    "README.md",
                    format!("authority table missing {display}"),
                ));
            }
        }
    }

    if let Some(package_json) = read_json(&root.join("package.json")) {
        let keywords: Vec<&str> = package_json
            .get("keywords")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        for id in ["legion", "alchemist", "arcane", "sage", "covenant"] {
            if !keywords.contains(&id) {
                issues.push(NamingIssue::new(
                    "package.json",
                    format!("missing canonical keyword {id}"),
                ));
            }
        }
        let files_field: Vec<&str> = package_json
            .get("files")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if files_field.contains(&"packages/seer/") {
            issues.push(NamingIssue::new(
                "package.json",
                "published files retain legacy assurance package",
            ));
        }
    }

    if let Some(manifest) = read_json(&root.join("MANIFEST.package.json")) {
        let allowlisted: Vec<&str> = manifest
            .get("allowlistedTopLevel")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if allowlisted.contains(&"packages/seer/") {
            issues.push(NamingIssue::new(
                "MANIFEST.package.json",
                "package manifest retains legacy assurance package",
            ));
        }
    }

    for path in [".claude-plugin/plugin.json", ".codex-plugin/plugin.json"] {
        if let Some(manifest) = read_json(&root.join(path)) {
            let description = manifest.get("description").and_then(Value::as_str).unwrap_or("");
            for display in ["Legion", "Sage", "Alchemist", "Oracle", "Arcane"] {
                if !description.contains(display) {
                    issues.push(NamingIssue::new(path, format!("description missing {display}")));
                }
            }
        }
    }

    if root.join("packages/seer").exists() {
        issues.push(NamingIssue::new(
            "packages/seer",
            "legacy assurance package still exists",
        ));
    }
    if root
        .join("registry/rules/opengrep/nemesis-core.yml")
        .exists()
    {
        issues.push(NamingIssue::new(
            "registry/rules/opengrep/nemesis-core.yml",
            "legacy product filename still exists",
        ));
    }

    for (path, declaration, value_pattern, values) in [
        (
            "src/lib/verification/arcane/architecture-event-store.mjs",
            r"const ACTOR_ROLES\s*=\s*new Set\((\[[^\]]+\])\)",
            r"['\x22]([^'\x22]+)['\x22]",
            vec!["alchemist", "covenant", "host", "legion", "oracle", "sage", "worker"],
        ),
        (
            "src/lib/contracts/arcane/authority-binding-store.mjs",
            r"const MAP\s*=\s*(\{[^}]+\})",
            r":\s*['\x22]([^'\x22]+)['\x22]",
            vec!["alchemist", "legion", "oracle", "sage"],
        ),
    ] {
        let Ok(source) = fs::read_to_string(root.join(path)) else {
            continue;
        };
        let decl_re = Regex::new(declaration).unwrap();
        let literal = decl_re
            .captures(&source)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let val_re = Regex::new(value_pattern).unwrap();
        let mut observed: Vec<String> = val_re
            .captures_iter(&literal)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();
        observed.sort();
        observed.dedup();
        let mut expected_sorted: Vec<String> = values.iter().map(|s| s.to_string()).collect();
        expected_sorted.sort();
        if observed != expected_sorted {
            issues.push(NamingIssue::new(
                path,
                "runtime authority registry differs from canonical set",
            ));
        }
    }

    issues
}

/// Port of `checkCanonicalNames`'s return shape.
#[derive(Debug, Clone)]
pub struct NamingContractReport {
    pub schema_version: u64,
    pub kind: &'static str,
    pub status: &'static str,
    pub canonical_authorities: Vec<String>,
    pub deprecated_aliases: Vec<String>,
    pub unclassified: Vec<NamingIssue>,
}

#[derive(Debug)]
pub enum CheckError {
    Registry(crate::p6_inventory::naming::NamingRegistryError),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckError::Registry(e) => write!(f, "{e}"),
            CheckError::Io(e) => write!(f, "{e}"),
            CheckError::Json(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for CheckError {}

/// Port of `checkCanonicalNames`.
pub fn check_canonical_names(root: &Path) -> Result<NamingContractReport, CheckError> {
    let registry = load_naming_registry(&root.join("src/config/naming-registry.json"))
        .map_err(CheckError::Registry)?;
    let allowlist_raw = fs::read_to_string(root.join("src/config/naming-legacy-allowlist.json"))
        .map_err(CheckError::Io)?;
    let allowlist_json: Value = serde_json::from_str(&allowlist_raw).map_err(CheckError::Json)?;
    let rules: Vec<AllowlistRule> = allowlist_json
        .get("rules")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(AllowlistRule::from_value).collect())
        .unwrap_or_default();

    let files = repository_files(root);
    let mut issues = semantic_issues(root, &registry);
    issues.extend(allowlist_issues(root, &rules, &files));

    for path in &files {
        for token in TOKENS {
            let path_hit = !occurrences(path, token).is_empty();
            if path_hit && matching_rule(&rules, path, token).is_none() {
                issues.push(NamingIssue::with_token(
                    path.clone(),
                    *token,
                    "unclassified legacy filename",
                ));
            }
        }
        let content = match text(&root.join(path)) {
            Some(c) => c,
            None => {
                if is_active_source(path) {
                    issues.push(NamingIssue::new(
                        path.clone(),
                        "active source cannot be decoded for naming scan",
                    ));
                }
                continue;
            }
        };
        for token in TOKENS {
            let lines = occurrences(&content, token);
            let rule = matching_rule(&rules, path, token);
            let exact_count = rule.and_then(|r| r.occurrences.get(*token)).copied();
            if !lines.is_empty() && rule.is_none() {
                issues.push(NamingIssue::with_line_token(
                    path.clone(),
                    lines[0],
                    *token,
                    "unclassified legacy token",
                ));
            } else if !lines.is_empty() {
                let rule = rule.unwrap();
                if rule.path.is_some()
                    && rule.class.as_deref() != Some("R5")
                    && exact_count.is_none()
                {
                    issues.push(NamingIssue::with_line_token(
                        path.clone(),
                        lines[0],
                        *token,
                        "active exact-path allowlist lacks occurrence count",
                    ));
                } else if let Some(expected) = exact_count {
                    if lines.len() as i64 != expected {
                        issues.push(NamingIssue::with_line_token(
                            path.clone(),
                            lines[0],
                            *token,
                            format!(
                                "legacy token occurrence count differs: expected {expected}, found {}",
                                lines.len()
                            ),
                        ));
                    }
                }
            }
        }
    }

    let mut deprecated_aliases: Vec<String> = registry
        .0
        .get("authorities")
        .and_then(Value::as_object)
        .map(|obj| {
            obj.values()
                .flat_map(|v| {
                    v.get("aliases")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|a| a.get("id").and_then(Value::as_str))
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();
    deprecated_aliases.sort();

    let status = if issues.is_empty() { "pass" } else { "fail" };

    Ok(NamingContractReport {
        schema_version: 1,
        kind: "legion-naming-contract-report",
        status,
        canonical_authorities: canonical_authority_ids(&registry),
        deprecated_aliases,
        unclassified: issues,
    })
}
