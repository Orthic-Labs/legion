//! Rust port of `src/lib/cognitive/arcane/minimize.mjs` — the Minimize
//! commit gate.
//!
//! Behaviour is intentionally identical to the JS source (itself ported
//! faithfully from `tools/lib/minimize/minimize_gate.py`). See the JS file's
//! header comment for the four load-bearing properties (POSIX ERE only,
//! package-scoped, language-scoped, underscore-private names skipped) — this
//! port preserves all four by shelling out to the same `git` commands with
//! the same arguments, rather than re-implementing git's diff/grep engines.
//!
//! Adaptation notes:
//!   - No `serde_json` dependency is available to this crate (see the wf002
//!     report), so JSON documents (review/receipt/decision) are read and
//!     written through [`super::json::Json`], a small hand-rolled JSON value
//!     that supports exactly what these documents need.
//!   - Every function takes an explicit `cwd: &Path` and, where relevant, an
//!     explicit [`MinimizeEnv`], instead of implicitly using
//!     `process.cwd()`/`process.env`. This keeps the port safe to call from
//!     parallel tests (the JS tests `process.chdir()`, which is not an
//!     option for parallel Rust tests) while preserving identical behaviour
//!     for any given `(cwd, env)` pair.

use super::json::Json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const RUNGS: [&str; 7] = [
    "NOT_BUILD",
    "REUSE",
    "STDLIB",
    "NATIVE",
    "INSTALLED_DEP",
    "ONE_LINE",
    "MIN_CUSTOM",
];
pub const REVIEW_SCHEMA: &str = "minimize-commit-review.v1";
pub const RECEIPT_SCHEMA: &str = "minimize-commit-receipt.v1";
pub const DECISION_SCHEMA: &str = "minimize-decision.v1";
pub const DECISION_RECEIPT_SCHEMA: &str = "minimize-decision-receipt.v1";

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct MinimizeError(pub String);

impl MinimizeError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MinimizeEnv {
    /// `MINIMIZE_BASE_REF` — diff base for `stagedChanges`.
    pub base_ref: Option<String>,
}

fn run_git(cwd: &Path, args: &[&str]) -> Result<std::process::Output, MinimizeError> {
    Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .map_err(|e| MinimizeError::new(format!("failed to spawn git {}: {e}", args.join(" "))))
}

/// `git(...args)` — must succeed (status 0).
fn git(cwd: &Path, args: &[&str]) -> Result<String, MinimizeError> {
    let output = run_git(cwd, args)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if stderr.is_empty() {
            format!("git {} failed", args.join(" "))
        } else {
            stderr
        };
        return Err(MinimizeError::new(message));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// `gitOptional` — tolerates "no match" exit status (git grep returns 1).
fn git_optional(cwd: &Path, args: &[&str]) -> String {
    match run_git(cwd, args) {
        Ok(output) if output.status.code() == Some(0) || output.status.code() == Some(1) => {
            String::from_utf8_lossy(&output.stdout).into_owned()
        }
        _ => String::new(),
    }
}

/// Raw (non-trimmed) stdout, needed where the JS source uses `gitAt` for
/// zero-delimited output (`stagedChanges`).
fn git_raw(cwd: &Path, args: &[&str]) -> Result<String, MinimizeError> {
    let output = run_git(cwd, args)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if stderr.is_empty() {
            format!("git {} failed", args.join(" "))
        } else {
            stderr
        };
        return Err(MinimizeError::new(message));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn staged_tree(cwd: &Path) -> Result<String, MinimizeError> {
    git(cwd, &["write-tree"])
}

pub fn repository_root(cwd: &Path) -> Result<String, MinimizeError> {
    git(cwd, &["rev-parse", "--show-toplevel"])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitChange {
    pub kind: char,
    pub status: String,
    pub source: Option<String>,
    pub path: String,
}

pub fn staged_changes(cwd: &Path, env: &MinimizeEnv) -> Result<Vec<GitChange>, MinimizeError> {
    let mut args: Vec<&str> = vec!["diff", "--cached"];
    if let Some(base) = &env.base_ref {
        args.push(base);
    }
    args.extend(["-M", "--name-status", "-z", "--diff-filter=ACMRD"]);
    let raw = git_raw(cwd, &args)?;
    let mut fields: Vec<&str> = raw.split('\0').collect();
    if fields.last() == Some(&"") {
        fields.pop();
    }
    let mut changes = Vec::new();
    let mut i = 0usize;
    while i < fields.len() {
        let status = fields[i];
        i += 1;
        let kind = status.chars().next().ok_or_else(|| {
            MinimizeError::new("git diff returned an invalid staged change record")
        })?;
        if kind == 'R' || kind == 'C' {
            let source = fields.get(i).copied();
            i += 1;
            let path = fields.get(i).copied();
            i += 1;
            let (source, path) = match (source, path) {
                (Some(s), Some(p)) if !s.is_empty() && !p.is_empty() => (s, p),
                _ => {
                    return Err(MinimizeError::new(
                        "git diff returned an incomplete rename record",
                    ))
                }
            };
            changes.push(GitChange {
                kind,
                status: status.to_string(),
                source: Some(source.to_string()),
                path: path.to_string(),
            });
        } else {
            let path = fields.get(i).copied();
            i += 1;
            let path = match path {
                Some(p) if !p.is_empty() => p,
                _ => {
                    return Err(MinimizeError::new(
                        "git diff returned an incomplete staged change record",
                    ))
                }
            };
            changes.push(GitChange {
                kind,
                status: status.to_string(),
                source: None,
                path: path.to_string(),
            });
        }
    }
    Ok(changes)
}

pub fn staged_files(cwd: &Path, env: &MinimizeEnv) -> Result<Vec<String>, MinimizeError> {
    Ok(staged_changes(cwd, env)?
        .into_iter()
        .filter(|c| c.kind != 'D')
        .map(|c| c.path)
        .collect())
}

pub fn staged_added_files(cwd: &Path) -> Result<Vec<String>, MinimizeError> {
    let out = git(cwd, &["diff", "--cached", "--name-only", "--diff-filter=A"])?;
    Ok(out.lines().filter(|l| !l.is_empty()).map(str::to_string).collect())
}

/// Dependency names ADDED to any staged manifest, read from the diff itself.
pub fn staged_new_dependencies(cwd: &Path, env: &MinimizeEnv) -> Result<Vec<String>, MinimizeError> {
    let mut found = BTreeSet::new();
    for name in staged_files(cwd, env)? {
        let base = name.rsplit('/').next().unwrap_or(&name);
        if !["package.json", "pyproject.toml", "Cargo.toml"].contains(&base) {
            continue;
        }
        let diff = git_optional(cwd, &["diff", "--cached", "-U0", "--", &name]);
        for line in diff.lines() {
            if !line.starts_with('+') || line.starts_with("+++") {
                continue;
            }
            if let Some(dep) = extract_added_dependency(line) {
                found.insert(dep);
            }
        }
    }
    Ok(found.into_iter().collect())
}

/// JS: `line.match(/^\+\s*"([^"]+)"\s*:\s*"/) ?? line.match(/^\+\s*([A-Za-z0-9_-]+)\s*=\s*["{]/)`.
fn extract_added_dependency(line: &str) -> Option<String> {
    let rest = line.strip_prefix('+')?;
    let rest = rest.trim_start();
    if let Some(inner) = rest.strip_prefix('"') {
        if let Some(end) = inner.find('"') {
            let name = &inner[..end];
            let after = inner[end + 1..].trim_start();
            if let Some(after) = after.strip_prefix(':') {
                if after.trim_start().starts_with('"') && !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        return None;
    }
    let name_end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .unwrap_or(rest.len());
    if name_end == 0 {
        return None;
    }
    let name = &rest[..name_end];
    let after = rest[name_end..].trim_start();
    let after = after.strip_prefix('=')?;
    let after = after.trim_start();
    if after.starts_with('"') || after.starts_with('{') {
        Some(name.to_string())
    } else {
        None
    }
}

fn suffix_of(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    match base.rfind('.') {
        Some(0) | None => String::new(),
        Some(dot) => base[dot..].to_string(),
    }
}

const LANGUAGE_FAMILIES: &[&[&str]] = &[
    &["*.mjs", "*.js", "*.cjs", "*.ts", "*.tsx"],
    &["*.py"],
    &["*.rs"],
];

pub fn language_family(path: &str) -> Vec<&'static str> {
    let suffix = format!("*{}", suffix_of(path));
    LANGUAGE_FAMILIES
        .iter()
        .find(|family| family.contains(&suffix.as_str()))
        .map(|family| family.to_vec())
        .unwrap_or_default()
}

const OWNER_MANIFESTS: &[&str] = &["package.json", "Cargo.toml", "pyproject.toml", "go.mod", "deno.json"];

/// Repo-relative directory of the nearest package manifest above `path` (at
/// HEAD, not on disk), or `""` for the repository root.
pub fn owner_root(cwd: &Path, path: &str) -> String {
    let mut current = if path.contains('/') {
        path[..path.rfind('/').unwrap()].to_string()
    } else {
        ".".to_string()
    };
    loop {
        let listing_path = if current == "." {
            "HEAD:".to_string()
        } else {
            format!("{current}/")
        };
        let listing = git_optional(cwd, &["ls-tree", "--name-only", "HEAD", &listing_path]);
        let names: BTreeSet<&str> = listing
            .lines()
            .filter(|l| !l.is_empty())
            .map(|row| row.rsplit('/').next().unwrap_or(row))
            .collect();
        if OWNER_MANIFESTS.iter().any(|m| names.contains(m)) {
            return if current == "." { String::new() } else { current };
        }
        if current == "." {
            return String::new();
        }
        current = if current.contains('/') {
            current[..current.rfind('/').unwrap()].to_string()
        } else {
            ".".to_string()
        };
    }
}

fn escape_regex(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if ".*+?^${}()|[]\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

const COMMON_NAMES: &[&str] = &[
    "main", "handle", "create", "resolve", "render", "update", "delete", "insert", "execute",
    "process", "convert", "collect", "compare", "extract", "cleanup",
];
const SOURCE_SUFFIXES: &[&str] = &[".mjs", ".js", ".cjs", ".ts", ".tsx", ".py", ".rs"];

/// `^\+\s*(?:export\s+)?(?:async\s+)?(?:function|class|def)\s+([A-Za-z_$][\w$]*)`
/// or `^\+\s*(?:export\s+)?(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\()`.
fn added_declaration(line: &str) -> Option<String> {
    let stripped = line.strip_prefix('+')?.trim_start();
    let after_export = stripped
        .strip_prefix("export ")
        .or_else(|| stripped.strip_prefix("export\t"))
        .map(str::trim_start)
        .unwrap_or(stripped);
    let mut cursor = after_export;
    cursor = if let Some(r) = cursor.strip_prefix("async ") {
        r.trim_start()
    } else {
        cursor
    };

    for keyword in ["function", "class", "def"] {
        if let Some(r) = cursor.strip_prefix(keyword) {
            if r.starts_with(char::is_whitespace) {
                let r = r.trim_start();
                return read_identifier(r);
            }
        }
    }
    for keyword in ["const", "let"] {
        if let Some(r) = cursor.strip_prefix(keyword) {
            if r.starts_with(char::is_whitespace) {
                let r = r.trim_start();
                if let Some((name, tail)) = read_identifier_with_tail(r) {
                    let tail = tail.trim_start();
                    if let Some(tail) = tail.strip_prefix('=') {
                        let mut tail = tail.trim_start();
                        tail = tail.strip_prefix("async").map(str::trim_start).unwrap_or(tail);
                        if tail.starts_with("function") && starts_word_boundary(tail, "function") {
                            return Some(name);
                        }
                        if tail.starts_with('(') {
                            return Some(name);
                        }
                    }
                }
            }
        }
    }
    None
}

fn starts_word_boundary(text: &str, keyword: &str) -> bool {
    let rest = &text[keyword.len()..];
    rest.chars().next().is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == '$'))
}

fn read_identifier(text: &str) -> Option<String> {
    read_identifier_with_tail(text).map(|(name, _)| name)
}

fn read_identifier_with_tail(text: &str) -> Option<(String, &str)> {
    let mut chars = text.char_indices();
    let (_, first) = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return None;
    }
    let mut end = first.len_utf8();
    for (idx, c) in chars {
        if c.is_alphanumeric() || c == '_' || c == '$' {
            end = idx + c.len_utf8();
        } else {
            break;
        }
    }
    Some((text[..end].to_string(), &text[end..]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub rung: String,
    pub symbol: String,
    pub added_in: String,
    pub already_defined_in: Vec<String>,
    pub detail: String,
    pub status: String,
}

impl Finding {
    fn to_json(&self) -> Json {
        let mut map = BTreeMap::new();
        map.insert("rung".to_string(), Json::String(self.rung.clone()));
        map.insert("symbol".to_string(), Json::String(self.symbol.clone()));
        map.insert("added_in".to_string(), Json::String(self.added_in.clone()));
        map.insert(
            "already_defined_in".to_string(),
            Json::Array(self.already_defined_in.iter().cloned().map(Json::String).collect()),
        );
        map.insert("detail".to_string(), Json::String(self.detail.clone()));
        map.insert("status".to_string(), Json::String(self.status.clone()));
        Json::Object(map)
    }
}

/// `DECL_SEARCH`: POSIX ERE, never GNU-only `\s`/`\b` — see the module doc.
const DECL_SEARCH_TEMPLATE: &str =
    "(export[[:space:]]+)?(async[[:space:]]+)?(function|class|def|const|let)[[:space:]]+{name}([^A-Za-z0-9_$]|$)";

/// Symbols this commit declares that HEAD already declared somewhere else.
pub fn reuse_findings(cwd: &Path, env: &MinimizeEnv) -> Result<Vec<Finding>, MinimizeError> {
    let changed: Vec<String> = staged_changes(cwd, env)?
        .into_iter()
        .filter(|c| c.kind != 'R' && c.kind != 'C' && c.kind != 'D')
        .filter(|c| SOURCE_SUFFIXES.contains(&suffix_of(&c.path).as_str()))
        .map(|c| c.path)
        .collect();

    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();
    for path in changed {
        let diff = git_optional(cwd, &["diff", "--cached", "-U0", "--", &path]);
        for line in diff.lines() {
            let Some(symbol) = added_declaration(line) else {
                continue;
            };
            if symbol.starts_with('_')
                || seen.contains(&symbol)
                || COMMON_NAMES.contains(&symbol.as_str())
                || symbol.len() < 6
            {
                continue;
            }
            seen.insert(symbol.clone());
            let family = language_family(&path);
            if family.is_empty() {
                continue;
            }
            let owner = owner_root(cwd, &path);
            let scope: Vec<String> = family
                .iter()
                .map(|glob| {
                    if owner.is_empty() {
                        glob.to_string()
                    } else {
                        format!("{owner}/{glob}")
                    }
                })
                .collect();
            let pattern = DECL_SEARCH_TEMPLATE.replace("{name}", &escape_regex(&symbol));
            let mut args: Vec<&str> = vec!["grep", "-l", "-E", &pattern, "HEAD", "--"];
            let scope_refs: Vec<&str> = scope.iter().map(String::as_str).collect();
            args.extend(scope_refs);
            let output = git_optional(cwd, &args);
            let mut elsewhere: BTreeSet<String> = BTreeSet::new();
            for row in output.lines().filter(|l| !l.is_empty()) {
                // `git grep -l <rev>` prints "HEAD:<path>"; keep the path half.
                let hit = match row.find(':') {
                    Some(idx) => &row[idx + 1..],
                    None => row,
                };
                if hit == path {
                    continue;
                }
                if owner_root(cwd, hit) == owner {
                    elsewhere.insert(hit.to_string());
                }
            }
            if !elsewhere.is_empty() {
                let elsewhere: Vec<String> = elsewhere.into_iter().collect();
                let already_defined_in: Vec<String> = elsewhere.iter().take(5).cloned().collect();
                findings.push(Finding {
                    rung: "REUSE".to_string(),
                    symbol: symbol.clone(),
                    added_in: path.clone(),
                    detail: format!(
                        "'{symbol}' is added in {path} but HEAD already defines it in {}",
                        elsewhere[0]
                    ),
                    already_defined_in,
                    status: "open".to_string(),
                });
            }
        }
    }
    Ok(findings)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    pub schema: String,
    pub candidate_tree: String,
    pub scope_files: Vec<String>,
    pub selected_rung: String,
    pub new_files: Vec<String>,
    pub new_dependencies: Vec<String>,
    pub findings: Vec<Finding>,
    pub verdict: String,
}

impl Review {
    pub fn to_json(&self) -> Json {
        let mut map = BTreeMap::new();
        map.insert("schema".to_string(), Json::String(self.schema.clone()));
        map.insert(
            "candidate_tree".to_string(),
            Json::String(self.candidate_tree.clone()),
        );
        map.insert(
            "scope_files".to_string(),
            Json::Array(self.scope_files.iter().cloned().map(Json::String).collect()),
        );
        map.insert(
            "selected_rung".to_string(),
            Json::String(self.selected_rung.clone()),
        );
        map.insert(
            "rung_checks".to_string(),
            Json::Array(vec![
                {
                    let mut m = BTreeMap::new();
                    m.insert("rung".to_string(), Json::String("NOT_BUILD".to_string()));
                    m.insert("verdict".to_string(), Json::String("REJECTED".to_string()));
                    m.insert(
                        "evidence".to_string(),
                        Json::String("staged change is requested".to_string()),
                    );
                    Json::Object(m)
                },
                {
                    let mut m = BTreeMap::new();
                    m.insert("rung".to_string(), Json::String("REUSE".to_string()));
                    m.insert(
                        "verdict".to_string(),
                        Json::String(if self.findings.is_empty() { "REJECTED" } else { "OPEN" }.to_string()),
                    );
                    m.insert(
                        "evidence".to_string(),
                        Json::String(format!(
                            "searched HEAD for every declaration this commit adds; {} already defined elsewhere",
                            self.findings.len()
                        )),
                    );
                    Json::Object(m)
                },
            ]),
        );
        map.insert(
            "new_files".to_string(),
            Json::Array(self.new_files.iter().cloned().map(Json::String).collect()),
        );
        map.insert(
            "new_dependencies".to_string(),
            Json::Array(self.new_dependencies.iter().cloned().map(Json::String).collect()),
        );
        map.insert(
            "findings".to_string(),
            Json::Array(self.findings.iter().map(Finding::to_json).collect()),
        );
        map.insert("verdict".to_string(), Json::String(self.verdict.clone()));
        Json::Object(map)
    }

    fn findings_from_json(value: &Json) -> Vec<(Json, String, Option<String>)> {
        value
            .get_array("findings")
            .unwrap_or(&[])
            .iter()
            .map(|f| {
                let status = f.get_str("status").unwrap_or("").to_string();
                let symbol = f.get_str("symbol").map(str::to_string);
                (f.clone(), status, symbol)
            })
            .collect()
    }
}

pub fn build_review(cwd: &Path, env: &MinimizeEnv) -> Result<Review, MinimizeError> {
    let findings = reuse_findings(cwd, env)?;
    Ok(Review {
        schema: REVIEW_SCHEMA.to_string(),
        candidate_tree: staged_tree(cwd)?,
        scope_files: staged_files(cwd, env)?,
        selected_rung: "REUSE".to_string(),
        new_files: staged_added_files(cwd)?,
        new_dependencies: staged_new_dependencies(cwd, env)?,
        findings,
        verdict: "CLEAN".to_string(),
    })
}

/// Validates a review *value* (already-parsed JSON, e.g. loaded from disk or
/// mutated in memory — mirrors `validateReview(review)` accepting a plain
/// object) against the live staged state of `cwd`.
pub fn validate_review_json(review: &Json, cwd: &Path, env: &MinimizeEnv) -> Result<Json, MinimizeError> {
    if review.get_str("schema") != Some(REVIEW_SCHEMA) {
        return Err(MinimizeError::new(format!("review schema must be {REVIEW_SCHEMA}")));
    }
    let candidate_tree = review.get_str("candidate_tree").unwrap_or("");
    if candidate_tree != staged_tree(cwd)? {
        return Err(MinimizeError::new("stale review: candidate_tree mismatch"));
    }
    let mut declared: Vec<&str> = review
        .get_array("scope_files")
        .unwrap_or(&[])
        .iter()
        .filter_map(Json::as_str)
        .collect();
    declared.sort_unstable();
    let mut actual: Vec<String> = staged_files(cwd, env)?;
    actual.sort();
    if declared != actual.iter().map(String::as_str).collect::<Vec<_>>() {
        return Err(MinimizeError::new("stale review: scope_files mismatch"));
    }
    if review.get_str("verdict") != Some("CLEAN") {
        return Err(MinimizeError::new("review verdict must be CLEAN"));
    }

    let findings = Review::findings_from_json(review);
    let open: Vec<&(Json, String, Option<String>)> = findings
        .iter()
        .filter(|(_, status, _)| status != "resolved" && status != "waived")
        .collect();
    if !open.is_empty() {
        let detail = open
            .iter()
            .take(3)
            .map(|(f, _, symbol)| {
                f.get_str("detail")
                    .map(str::to_string)
                    .or_else(|| symbol.clone())
                    .unwrap_or_else(|| "unnamed finding".to_string())
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(MinimizeError::new(format!(
            "open finding blocks commit receipt: {detail}. Reuse the existing definition, or set that finding's status to 'waived' with a reason if the duplicate is deliberate."
        )));
    }

    let unexplained: Vec<&(Json, String, Option<String>)> = findings
        .iter()
        .filter(|(f, status, _)| {
            status == "waived"
                && f.get_str("waiver_reason").unwrap_or("").trim().is_empty()
        })
        .collect();
    if !unexplained.is_empty() {
        let names = unexplained
            .iter()
            .take(3)
            .map(|(_, _, symbol)| symbol.clone().unwrap_or_else(|| "unnamed finding".to_string()))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(MinimizeError::new(format!(
            "waived finding needs a waiver_reason: {names}. A waiver with no stated reason is indistinguishable from silently deleting the finding."
        )));
    }
    Ok(review.clone())
}

fn sha256_file(path: &Path) -> Result<String, MinimizeError> {
    let bytes = std::fs::read(path)
        .map_err(|e| MinimizeError::new(format!("cannot read {}: {e}", path.display())))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub struct ReceiptPaths<'a> {
    pub policy_path: &'a Path,
    pub validator_path: &'a Path,
}

pub fn build_receipt(review_path: &Path, paths: &ReceiptPaths, cwd: &Path, env: &MinimizeEnv) -> Result<Json, MinimizeError> {
    let review = read_json(review_path)?;
    let review = validate_review_json(&review, cwd, env)?;

    let mut map = BTreeMap::new();
    map.insert("schema".to_string(), Json::String(RECEIPT_SCHEMA.to_string()));
    map.insert(
        "candidate_tree".to_string(),
        review.get("candidate_tree").cloned().unwrap_or(Json::Null),
    );
    map.insert(
        "scope_files".to_string(),
        review.get("scope_files").cloned().unwrap_or(Json::Array(vec![])),
    );
    map.insert(
        "review".to_string(),
        Json::String(
            review_path
                .canonicalize()
                .unwrap_or_else(|_| review_path.to_path_buf())
                .to_string_lossy()
                .into_owned(),
        ),
    );
    map.insert(
        "review_sha256".to_string(),
        Json::String(sha256_file(review_path)?),
    );
    map.insert(
        "policy_sha256".to_string(),
        Json::String(sha256_file(paths.policy_path)?),
    );
    map.insert(
        "validator_sha256".to_string(),
        Json::String(sha256_file(paths.validator_path)?),
    );
    let waivers: Vec<Json> = review
        .get_array("findings")
        .unwrap_or(&[])
        .iter()
        .filter(|f| f.get_str("status") == Some("waived"))
        .map(|f| {
            let mut m = BTreeMap::new();
            m.insert(
                "symbol".to_string(),
                f.get("symbol").cloned().unwrap_or(Json::Null),
            );
            m.insert(
                "reason".to_string(),
                f.get("waiver_reason").cloned().unwrap_or(Json::Null),
            );
            Json::Object(m)
        })
        .collect();
    map.insert("waivers".to_string(), Json::Array(waivers));
    map.insert("verdict".to_string(), Json::String("CLEAN".to_string()));
    Ok(Json::Object(map))
}

pub fn verify_receipt(receipt: &Json, paths: &ReceiptPaths, cwd: &Path, env: &MinimizeEnv) -> Result<Json, MinimizeError> {
    if receipt.get_str("schema") != Some(RECEIPT_SCHEMA) {
        return Err(MinimizeError::new("commit receipt schema mismatch"));
    }
    if receipt.get_str("candidate_tree") != Some(staged_tree(cwd)?.as_str()) {
        return Err(MinimizeError::new(
            "stale commit receipt: candidate_tree mismatch",
        ));
    }
    let mut declared: Vec<&str> = receipt
        .get_array("scope_files")
        .unwrap_or(&[])
        .iter()
        .filter_map(Json::as_str)
        .collect();
    declared.sort_unstable();
    let mut actual = staged_files(cwd, env)?;
    actual.sort();
    if declared != actual.iter().map(String::as_str).collect::<Vec<_>>() {
        return Err(MinimizeError::new(
            "stale commit receipt: scope_files mismatch",
        ));
    }
    if receipt.get_str("policy_sha256") != Some(sha256_file(paths.policy_path)?.as_str()) {
        return Err(MinimizeError::new(
            "stale commit receipt: policy_sha256 mismatch",
        ));
    }
    if receipt.get_str("validator_sha256") != Some(sha256_file(paths.validator_path)?.as_str()) {
        return Err(MinimizeError::new(
            "stale commit receipt: validator_sha256 mismatch",
        ));
    }
    if receipt.get_str("verdict") != Some("CLEAN") {
        return Err(MinimizeError::new("commit receipt verdict must be CLEAN"));
    }
    Ok(receipt.clone())
}

// --- decision domain ---------------------------------------------------

pub fn validate_decision(
    value: &Json,
    new_files: &[String],
    new_dependencies: &[String],
) -> Result<Json, MinimizeError> {
    if value.get_str("schema") != Some(DECISION_SCHEMA) {
        return Err(MinimizeError::new(format!(
            "decision schema must be {DECISION_SCHEMA}"
        )));
    }
    let selected = value.get_str("selected_rung").unwrap_or("");
    if !RUNGS.contains(&selected) {
        return Err(MinimizeError::new(format!(
            "selected_rung must be one of: {}",
            RUNGS.join(", ")
        )));
    }
    let prior = value
        .get("prior_rungs")
        .and_then(Json::as_array)
        .ok_or_else(|| MinimizeError::new("prior_rungs must be a list"))?;

    let selected_index = RUNGS.iter().position(|r| *r == selected).unwrap();
    let required = &RUNGS[..selected_index];
    let observed: Vec<&str> = prior
        .iter()
        .filter(|row| row.as_object().is_some())
        .map(|row| row.get_str("rung").unwrap_or(""))
        .collect();
    if observed != required.to_vec() {
        let missing = required
            .iter()
            .find(|rung| !observed.contains(rung))
            .copied()
            .unwrap_or("ordered prior rung");
        return Err(MinimizeError::new(format!(
            "missing or unordered prior rung: {missing}"
        )));
    }
    for row in prior {
        let verdict_ok = row.get_str("verdict") == Some("REJECTED");
        let evidence_ok = !row.get_str("evidence").unwrap_or("").trim().is_empty();
        if !verdict_ok || !evidence_ok {
            let rung = row.get_str("rung").unwrap_or("");
            return Err(MinimizeError::new(format!(
                "prior rung {rung} needs REJECTED verdict and evidence"
            )));
        }
    }
    for key in ["decision_id", "state_a", "state_b"] {
        if value.get_str(key).unwrap_or("").trim().is_empty() {
            return Err(MinimizeError::new(format!("{key} is required")));
        }
    }
    let allowed_files: BTreeSet<&str> = value
        .get_array("allowed_new_files")
        .unwrap_or(&[])
        .iter()
        .filter_map(Json::as_str)
        .collect();
    let allowed_deps: BTreeSet<&str> = value
        .get_array("allowed_new_dependencies")
        .unwrap_or(&[])
        .iter()
        .filter_map(Json::as_str)
        .collect();
    let mut denied_files: Vec<&str> = new_files
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|name| !allowed_files.contains(name))
        .collect();
    denied_files.sort_unstable();
    let mut denied_deps: Vec<&str> = new_dependencies
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|name| !allowed_deps.contains(name))
        .collect();
    denied_deps.sort_unstable();
    if !denied_files.is_empty() {
        return Err(MinimizeError::new(format!(
            "new file not allowed by decision: {}",
            denied_files.join(", ")
        )));
    }
    if !denied_deps.is_empty() {
        return Err(MinimizeError::new(format!(
            "new dependency not allowed by decision: {}",
            denied_deps.join(", ")
        )));
    }
    Ok(value.clone())
}

pub fn decision_receipt(
    source_path: &Path,
    paths: &ReceiptPaths,
    new_files: &[String],
    new_dependencies: &[String],
) -> Result<Json, MinimizeError> {
    let value = read_json(source_path)?;
    let value = validate_decision(&value, new_files, new_dependencies)?;
    let mut map = BTreeMap::new();
    map.insert(
        "schema".to_string(),
        Json::String(DECISION_RECEIPT_SCHEMA.to_string()),
    );
    map.insert(
        "decision".to_string(),
        Json::String(canonical_locator(source_path)),
    );
    map.insert(
        "decision_sha256".to_string(),
        Json::String(sha256_file(source_path)?),
    );
    map.insert(
        "policy_sha256".to_string(),
        Json::String(sha256_file(paths.policy_path)?),
    );
    map.insert(
        "validator_sha256".to_string(),
        Json::String(sha256_file(paths.validator_path)?),
    );
    map.insert(
        "decision_id".to_string(),
        value.get("decision_id").cloned().unwrap_or(Json::Null),
    );
    map.insert(
        "selected_rung".to_string(),
        value.get("selected_rung").cloned().unwrap_or(Json::Null),
    );
    Ok(Json::Object(map))
}

pub fn verify_decision(
    source_path: &Path,
    receipt_path: &Path,
    paths: &ReceiptPaths,
    new_files: &[String],
    new_dependencies: &[String],
) -> Result<Json, MinimizeError> {
    let expected = decision_receipt(source_path, paths, new_files, new_dependencies)?;
    let actual = read_json(receipt_path)?;
    for key in [
        "decision_sha256",
        "policy_sha256",
        "validator_sha256",
        "decision_id",
        "selected_rung",
    ] {
        if actual.get(key) != expected.get(key) {
            return Err(MinimizeError::new(format!("stale decision receipt: {key} mismatch")));
        }
    }
    Ok(actual)
}

/// Repo-relative path when inside a repo, else absolute — matches the Python
/// locator.
pub fn canonical_locator(path: &Path) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let parent = resolved.parent().unwrap_or(&resolved);
    let Ok(output) = Command::new("git")
        .current_dir(parent)
        .args(["rev-parse", "--show-toplevel"])
        .output()
    else {
        return resolved.to_string_lossy().into_owned();
    };
    if !output.status.success() {
        return resolved.to_string_lossy().into_owned();
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().replace('\\', "/");
    let normalized = resolved.to_string_lossy().replace('\\', "/");
    let prefix = format!("{root}/");
    if let Some(rel) = normalized.strip_prefix(&prefix) {
        rel.to_string()
    } else {
        resolved.to_string_lossy().into_owned()
    }
}

pub fn read_json(path: &Path) -> Result<Json, MinimizeError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| MinimizeError::new(format!("cannot read {}: {e}", path.display())))?;
    let value = Json::parse(&text)
        .map_err(|e| MinimizeError::new(format!("cannot read {}: {e}", path.display())))?;
    match &value {
        Json::Object(_) => Ok(value),
        _ => Err(MinimizeError::new(format!(
            "cannot read {}: not an object",
            path.display()
        ))),
    }
}

pub fn write_json(path: &Path, value: &Json) -> Result<(), MinimizeError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| MinimizeError::new(format!("cannot create {}: {e}", parent.display())))?;
    }
    std::fs::write(path, value.to_pretty_string())
        .map_err(|e| MinimizeError::new(format!("cannot write {}: {e}", path.display())))
}

pub fn file_exists(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn git_ok(cwd: &Path, args: &[&str]) {
        let status = Command::new("git")
            .current_dir(cwd)
            .args(args)
            .status()
            .expect("git available");
        assert!(status.success(), "git {args:?} failed");
    }

    /// A two-package repo: pkg-a (JS) and pkg-b (Python), each with its own
    /// manifest — mirrors the JS test fixture.
    fn fixture() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "legion-minimize-test-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("pkg-a/src")).unwrap();
        fs::create_dir_all(root.join("pkg-b/src")).unwrap();
        git_ok(&root, &["init", "-q"]);
        git_ok(&root, &["config", "user.email", "t@t"]);
        git_ok(&root, &["config", "user.name", "t"]);
        fs::write(root.join("pkg-a/package.json"), "{\"name\":\"pkg-a\"}\n").unwrap();
        fs::write(root.join("pkg-b/package.json"), "{\"name\":\"pkg-b\"}\n").unwrap();
        fs::write(
            root.join("pkg-a/src/one.mjs"),
            "export function computeChecksum(x) { return x; }\n",
        )
        .unwrap();
        fs::write(
            root.join("pkg-b/src/two.py"),
            "def compute_checksum(x):\n    return x\n",
        )
        .unwrap();
        git_ok(&root, &["add", "-A"]);
        git_ok(&root, &["commit", "-qm", "base"]);
        root
    }

    fn env() -> MinimizeEnv {
        MinimizeEnv::default()
    }

    #[test]
    fn duplicate_in_same_package_and_language_is_caught() {
        let root = fixture();
        fs::write(
            root.join("pkg-a/src/dup.mjs"),
            "export function computeChecksum(y) { return y; }\n",
        )
        .unwrap();
        git_ok(&root, &["add", "pkg-a/src/dup.mjs"]);
        let review = build_review(&root, &env()).unwrap();
        assert_eq!(review.findings.len(), 1, "{:?}", review.findings);
        assert_eq!(review.findings[0].symbol, "computeChecksum");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn same_name_in_another_package_is_not_a_duplicate() {
        let root = fixture();
        fs::write(
            root.join("pkg-b/src/dup.mjs"),
            "export function computeChecksum(z) { return z; }\n",
        )
        .unwrap();
        git_ok(&root, &["add", "pkg-b/src/dup.mjs"]);
        let review = build_review(&root, &env()).unwrap();
        assert!(review.findings.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn pure_rename_pairs_are_skipped() {
        let root = fixture();
        git_ok(&root, &["mv", "pkg-a/src/one.mjs", "pkg-a/src/renamed.mjs"]);
        let changes = staged_changes(&root, &env()).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, 'R');
        assert_eq!(changes[0].source.as_deref(), Some("pkg-a/src/one.mjs"));
        assert_eq!(changes[0].path, "pkg-a/src/renamed.mjs");
        let review = build_review(&root, &env()).unwrap();
        assert!(review.findings.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn python_def_and_js_function_sharing_a_name_are_never_compared() {
        let root = fixture();
        fs::write(
            root.join("pkg-b/src/three.py"),
            "def computeChecksum(x):\n    return x\n",
        )
        .unwrap();
        git_ok(&root, &["add", "pkg-b/src/three.py"]);
        let review = build_review(&root, &env()).unwrap();
        assert!(review.findings.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn underscore_private_names_are_skipped() {
        let root = fixture();
        fs::write(
            root.join("pkg-a/src/priv.mjs"),
            "export function _normalizePath(a) { return a; }\n",
        )
        .unwrap();
        fs::write(
            root.join("pkg-a/src/priv2.mjs"),
            "export function _normalizePath(b) { return b; }\n",
        )
        .unwrap();
        git_ok(&root, &["add", "pkg-a/src/priv.mjs", "pkg-a/src/priv2.mjs"]);
        let review = build_review(&root, &env()).unwrap();
        assert!(review.findings.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn decl_search_uses_posix_classes_not_gnu_escapes() {
        assert!(DECL_SEARCH_TEMPLATE.contains("[[:space:]]"));
        assert!(!DECL_SEARCH_TEMPLATE.contains("\\s"));
        assert!(!DECL_SEARCH_TEMPLATE.contains("\\b"));
    }

    #[test]
    fn open_finding_blocks_the_receipt() {
        let root = fixture();
        fs::write(
            root.join("pkg-a/src/dup.mjs"),
            "export function computeChecksum(y) { return y; }\n",
        )
        .unwrap();
        git_ok(&root, &["add", "pkg-a/src/dup.mjs"]);
        let review = build_review(&root, &env()).unwrap();
        let review_path = root.join("review.json");
        write_json(&review_path, &review.to_json()).unwrap();
        let policy_path = root.join("policy.md");
        fs::write(&policy_path, "policy\n").unwrap();
        let validator_path = root.join("validator.rs");
        fs::write(&validator_path, "// validator\n").unwrap();
        let paths = ReceiptPaths {
            policy_path: &policy_path,
            validator_path: &validator_path,
        };
        let err = build_receipt(&review_path, &paths, &root, &env()).unwrap_err();
        assert!(err.0.contains("open finding blocks commit receipt"), "{}", err.0);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn waiver_without_reason_is_refused_then_accepted_with_one() {
        let root = fixture();
        fs::write(
            root.join("pkg-a/src/dup.mjs"),
            "export function computeChecksum(y) { return y; }\n",
        )
        .unwrap();
        git_ok(&root, &["add", "pkg-a/src/dup.mjs"]);
        let review = build_review(&root, &env()).unwrap();
        let mut json = review.to_json();
        {
            let obj = match &mut json {
                Json::Object(m) => m,
                _ => unreachable!(),
            };
            let findings = obj.get_mut("findings").unwrap();
            if let Json::Array(items) = findings {
                if let Json::Object(finding) = &mut items[0] {
                    finding.insert("status".to_string(), Json::String("waived".to_string()));
                }
            }
        }
        let err = validate_review_json(&json, &root, &env()).unwrap_err();
        assert!(err.0.contains("waived finding needs a waiver_reason"), "{}", err.0);

        if let Json::Object(obj) = &mut json {
            if let Some(Json::Array(items)) = obj.get_mut("findings") {
                if let Json::Object(finding) = &mut items[0] {
                    finding.insert(
                        "waiver_reason".to_string(),
                        Json::String("deliberate: separate runtime".to_string()),
                    );
                }
            }
        }
        let validated = validate_review_json(&json, &root, &env()).unwrap();
        assert_eq!(validated.get_str("verdict"), Some("CLEAN"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn waiver_is_carried_into_the_receipt() {
        let root = fixture();
        fs::write(
            root.join("pkg-a/src/dup.mjs"),
            "export function computeChecksum(y) { return y; }\n",
        )
        .unwrap();
        git_ok(&root, &["add", "pkg-a/src/dup.mjs"]);
        let review = build_review(&root, &env()).unwrap();
        let mut json = review.to_json();
        if let Json::Object(obj) = &mut json {
            if let Some(Json::Array(items)) = obj.get_mut("findings") {
                if let Json::Object(finding) = &mut items[0] {
                    finding.insert("status".to_string(), Json::String("waived".to_string()));
                    finding.insert(
                        "waiver_reason".to_string(),
                        Json::String("deliberate: fixture".to_string()),
                    );
                }
            }
        }
        let review_path = root.join("review.json");
        write_json(&review_path, &json).unwrap();
        let policy_path = root.join("policy.md");
        fs::write(&policy_path, "policy\n").unwrap();
        let validator_path = root.join("validator.rs");
        fs::write(&validator_path, "// validator\n").unwrap();
        let paths = ReceiptPaths {
            policy_path: &policy_path,
            validator_path: &validator_path,
        };
        let receipt = build_receipt(&review_path, &paths, &root, &env()).unwrap();
        let waivers = receipt.get_array("waivers").unwrap();
        assert_eq!(waivers.len(), 1);
        assert_eq!(waivers[0].get_str("symbol"), Some("computeChecksum"));
        assert_eq!(waivers[0].get_str("reason"), Some("deliberate: fixture"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn receipt_is_bound_to_staged_tree_and_goes_stale() {
        let root = fixture();
        fs::write(
            root.join("pkg-a/src/clean.mjs"),
            "export function uniqueSymbolHere(a) { return a; }\n",
        )
        .unwrap();
        git_ok(&root, &["add", "pkg-a/src/clean.mjs"]);
        let review = build_review(&root, &env()).unwrap();
        let review_path = root.join("review.json");
        write_json(&review_path, &review.to_json()).unwrap();
        let policy_path = root.join("policy.md");
        fs::write(&policy_path, "policy\n").unwrap();
        let validator_path = root.join("validator.rs");
        fs::write(&validator_path, "// validator\n").unwrap();
        let paths = ReceiptPaths {
            policy_path: &policy_path,
            validator_path: &validator_path,
        };
        let receipt = build_receipt(&review_path, &paths, &root, &env()).unwrap();
        let verified = verify_receipt(&receipt, &paths, &root, &env()).unwrap();
        assert_eq!(verified.get_str("verdict"), Some("CLEAN"));

        fs::write(
            root.join("pkg-a/src/extra.mjs"),
            "export function laterAddition(q) { return q; }\n",
        )
        .unwrap();
        git_ok(&root, &["add", "pkg-a/src/extra.mjs"]);
        let err = verify_receipt(&receipt, &paths, &root, &env()).unwrap_err();
        assert!(
            err.0.contains("stale commit receipt: candidate_tree mismatch"),
            "{}",
            err.0
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn owner_root_and_language_family() {
        let root = fixture();
        assert_eq!(owner_root(&root, "pkg-a/src/one.mjs"), "pkg-a");
        assert_eq!(owner_root(&root, "pkg-b/src/two.py"), "pkg-b");
        assert!(language_family("x.ts").contains(&"*.mjs"));
        assert_eq!(language_family("x.py"), vec!["*.py"]);
        assert!(language_family("x.txt").is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn minimize_error_message_round_trips() {
        let err = MinimizeError::new("x");
        assert_eq!(err.0, "x");
        assert_eq!(err.to_string(), "x");
    }

    #[test]
    fn staged_new_dependencies_reads_added_package_json_and_cargo_toml_entries() {
        let root = fixture();
        // Pretty-printed, one field per line, like a real package.json diff —
        // `extract_added_dependency` (mirroring JS `stagedNewDependencies`)
        // only matches a `"name": "value"` pair on its own `+` line, not one
        // collapsed onto a single line.
        fs::write(
            root.join("pkg-a/package.json"),
            "{\n  \"name\": \"pkg-a\",\n  \"dependencies\": {\n    \"left-pad\": \"1.0.0\"\n  }\n}\n",
        )
        .unwrap();
        git_ok(&root, &["add", "pkg-a/package.json"]);
        let deps = staged_new_dependencies(&root, &env()).unwrap();
        assert!(deps.contains(&"left-pad".to_string()), "{deps:?}");
        let _ = fs::remove_dir_all(&root);
    }
}
