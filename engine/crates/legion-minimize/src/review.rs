use crate::error::MinimizeError;
use crate::git::{GitContext, StagedChange};
use crate::json_util::{read_json, sha256_file};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{HashSet, BTreeSet};
use std::path::{Path, PathBuf};

pub const RUNGS: &[&str] = &[
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

const COMMON_NAMES: &[&str] = &[
    "main", "handle", "create", "resolve", "render", "update", "delete", "insert",
    "execute", "process", "convert", "collect", "compare", "extract", "cleanup",
];
const SOURCE_SUFFIXES: &[&str] = &[".mjs", ".js", ".cjs", ".ts", ".tsx", ".py", ".rs"];
const LANGUAGE_FAMILIES: &[&[&str]] = &[
    &["*.mjs", "*.js", "*.cjs", "*.ts", "*.tsx"],
    &["*.py"],
    &["*.rs"],
];
const OWNER_MANIFESTS: &[&str] = &[
    "package.json",
    "Cargo.toml",
    "pyproject.toml",
    "go.mod",
    "deno.json",
];

fn added_decl_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\+\s*(?:export\s+)?(?:async\s+)?(?:function|class|def)\s+([A-Za-z_$][\w$]*)|^\+\s*(?:export\s+)?(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\()",
        )
        .expect("valid regex")
    })
}

fn dep_json_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^\+\s*"([^"]+)"\s*:\s*""#).expect("valid regex"))
}

fn dep_toml_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"^\+\s*([A-Za-z0-9_-]+)\s*=\s*["{]"#).expect("valid regex")
    })
}

fn suffix_of(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    match base.rfind('.') {
        Some(index) if index > 0 => base[index..].to_string(),
        _ => String::new(),
    }
}

fn language_family(path: &str) -> Vec<String> {
    let suffix = format!("*{}", suffix_of(path));
    LANGUAGE_FAMILIES
        .iter()
        .find(|family| family.iter().any(|glob| glob == &suffix))
        .map(|family| family.iter().map(|glob| (*glob).to_string()).collect())
        .unwrap_or_default()
}

fn escape_regex(value: &str) -> String {
    regex::escape(value)
}

fn owner_root(git: &GitContext, path: &str) -> Result<String, MinimizeError> {
    let mut current = if path.contains('/') {
        path.rsplit_once('/').map(|(prefix, _)| prefix).unwrap_or(".")
    } else {
        "."
    };
    loop {
        let listing_arg = if current == "." {
            "HEAD:".to_string()
        } else {
            format!("{current}/")
        };
        let listing = git.git_optional_at(
            &git.cwd,
            &["ls-tree", "--name-only", "HEAD", listing_arg.as_str()],
        );
        let names = listing
            .lines()
            .filter(|line| !line.is_empty())
            .map(|row| row.rsplit('/').next().unwrap_or(row))
            .collect::<HashSet<_>>();
        if OWNER_MANIFESTS.iter().any(|manifest| names.contains(manifest)) {
            return Ok(if current == "." {
                String::new()
            } else {
                current.to_string()
            });
        }
        if current == "." {
            return Ok(String::new());
        }
        current = if current.contains('/') {
            current.rsplit_once('/').map(|(prefix, _)| prefix).unwrap_or(".")
        } else {
            "."
        };
    }
}

pub fn staged_new_dependencies(git: &GitContext) -> Result<Vec<String>, MinimizeError> {
    let mut found = BTreeSet::new();
    for name in git.staged_files()? {
        let base = name.rsplit('/').next().unwrap_or(&name);
        if !["package.json", "pyproject.toml", "Cargo.toml"].contains(&base) {
            continue;
        }
        let diff = git.git_optional_at(&git.cwd, &["diff", "--cached", "-U0", "--", &name]);
        for line in diff.lines() {
            if !line.starts_with('+') || line.starts_with("+++") {
                continue;
            }
            if let Some(captures) = dep_json_re().captures(line) {
                found.insert(captures[1].to_string());
            } else if let Some(captures) = dep_toml_re().captures(line) {
                found.insert(captures[1].to_string());
            }
        }
    }
    Ok(found.into_iter().collect())
}

pub fn reuse_findings(git: &GitContext) -> Result<Vec<Value>, MinimizeError> {
    let suffixes: HashSet<&str> = SOURCE_SUFFIXES.iter().copied().collect();
    let common: HashSet<&str> = COMMON_NAMES.iter().copied().collect();
    let changed = git
        .staged_changes()?
        .into_iter()
        .filter(|change: &StagedChange| {
            change.kind != 'R'
                && change.kind != 'C'
                && change.kind != 'D'
                && suffixes.contains(suffix_of(&change.path).as_str())
        })
        .map(|change| change.path)
        .collect::<Vec<_>>();
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    for path in changed {
        let diff = git.git_optional_at(&git.cwd, &["diff", "--cached", "-U0", "--", &path]);
        for line in diff.lines() {
            let captures = added_decl_re().captures(line);
            let Some(captures) = captures else {
                continue;
            };
            let symbol = captures
                .get(1)
                .or_else(|| captures.get(2))
                .map(|m| m.as_str())
                .unwrap_or("");
            if symbol.is_empty()
                || symbol.starts_with('_')
                || seen.contains(symbol)
                || common.contains(symbol)
                || symbol.len() < 6
            {
                continue;
            }
            seen.insert(symbol.to_string());
            let family = language_family(&path);
            if family.is_empty() {
                continue;
            }
            let owner = owner_root(git, &path)?;
            let scope = family
                .iter()
                .map(|glob| {
                    if owner.is_empty() {
                        glob.clone()
                    } else {
                        format!("{owner}/{glob}")
                    }
                })
                .collect::<Vec<_>>();
            let pattern = format!(
                "(export[[:space:]]+)?(async[[:space:]]+)?(function|class|def|const|let)[[:space:]]+{}([^A-Za-z0-9_$]|$)",
                escape_regex(symbol)
            );
            let mut grep_args = vec!["grep", "-l", "-E", &pattern, "HEAD", "--"];
            grep_args.extend(scope.iter().map(String::as_str));
            let hits = git
                .git_optional_at(&git.cwd, &grep_args)
                .lines()
                .filter(|line| !line.is_empty())
                .map(|row| row.split_once(':').map(|(_, path)| path).unwrap_or(row).to_string())
                .collect::<Vec<_>>();
            let mut elsewhere = Vec::new();
            for hit in hits {
                if hit == path {
                    continue;
                }
                if owner_root(git, &hit)? == owner {
                    elsewhere.push(hit);
                }
            }
            elsewhere.sort();
            elsewhere.dedup();
            if !elsewhere.is_empty() {
                let preview = elsewhere.iter().take(5).cloned().collect::<Vec<_>>();
                findings.push(json!({
                    "rung": "REUSE",
                    "symbol": symbol,
                    "added_in": path,
                    "already_defined_in": preview,
                    "detail": format!(
                        "\"{symbol}\" is added in {path} but HEAD already defines it in {}",
                        elsewhere[0]
                    ),
                    "status": "open",
                }));
            }
        }
    }
    Ok(findings)
}

pub fn build_review(git: &GitContext) -> Result<Value, MinimizeError> {
    let findings = reuse_findings(git)?;
    Ok(json!({
        "schema": REVIEW_SCHEMA,
        "candidate_tree": git.staged_tree()?,
        "scope_files": git.staged_files()?,
        "selected_rung": "REUSE",
        "rung_checks": [
            {"rung": "NOT_BUILD", "verdict": "REJECTED", "evidence": "staged change is requested"},
            {
                "rung": "REUSE",
                "verdict": if findings.is_empty() { "REJECTED" } else { "OPEN" },
                "evidence": format!(
                    "searched HEAD for every declaration this commit adds; {} already defined elsewhere",
                    findings.len()
                ),
            },
        ],
        "new_files": git.staged_added_files()?,
        "new_dependencies": staged_new_dependencies(git)?,
        "findings": findings,
        "verdict": "CLEAN",
    }))
}

pub fn validate_review(git: &GitContext, review: &Value) -> Result<Value, MinimizeError> {
    if review.get("schema").and_then(Value::as_str) != Some(REVIEW_SCHEMA) {
        return Err(MinimizeError::new(format!(
            "review schema must be {}",
            REVIEW_SCHEMA
        )));
    }
    if review.get("candidate_tree").and_then(Value::as_str) != Some(git.staged_tree()?.as_str()) {
        return Err(MinimizeError::new("stale review: candidate_tree mismatch"));
    }
    let declared = review
        .get("scope_files")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut declared_sorted = declared;
    declared_sorted.sort();
    let mut actual = git.staged_files()?;
    actual.sort();
    if serde_json::to_string(&declared_sorted).map_err(|error| MinimizeError::new(error.to_string()))?
        != serde_json::to_string(&actual).map_err(|error| MinimizeError::new(error.to_string()))?
    {
        return Err(MinimizeError::new("stale review: scope_files mismatch"));
    }
    if review.get("verdict").and_then(Value::as_str) != Some("CLEAN") {
        return Err(MinimizeError::new("review verdict must be CLEAN"));
    }
    let open = review
        .get("findings")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|row| {
                    !matches!(
                        row.get("status").and_then(Value::as_str),
                        Some("resolved") | Some("waived")
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !open.is_empty() {
        let detail = open
            .iter()
            .take(3)
            .map(|row| {
                row.get("detail")
                    .or_else(|| row.get("symbol"))
                    .and_then(Value::as_str)
                    .unwrap_or("unnamed finding")
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(MinimizeError::new(format!(
            "open finding blocks commit receipt: {detail}. Reuse the existing definition, or set that finding status to \"waived\" with a reason if the duplicate is deliberate."
        )));
    }
    let unexplained = review
        .get("findings")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|row| {
                    row.get("status").and_then(Value::as_str) == Some("waived")
                        && row
                            .get("waiver_reason")
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .unwrap_or("")
                            .is_empty()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !unexplained.is_empty() {
        let names = unexplained
            .iter()
            .take(3)
            .map(|row| {
                row.get("symbol")
                    .and_then(Value::as_str)
                    .unwrap_or("unnamed finding")
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(MinimizeError::new(format!(
            "waived finding needs a waiver_reason: {names}. A waiver with no stated reason is indistinguishable from silently deleting the finding."
        )));
    }
    Ok(review.clone())
}

pub struct MinimizePaths {
    pub policy_path: PathBuf,
    pub validator_path: PathBuf,
}

pub fn build_receipt(
    git: &GitContext,
    review_path: &Path,
    paths: &MinimizePaths,
) -> Result<Value, MinimizeError> {
    let review = validate_review(git, &read_json(review_path)?)?;
    let waivers = review
        .get("findings")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|row| row.get("status").and_then(Value::as_str) == Some("waived"))
                .map(|row| {
                    json!({
                        "symbol": row.get("symbol").cloned().unwrap_or(Value::Null),
                        "reason": row.get("waiver_reason").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(json!({
        "schema": RECEIPT_SCHEMA,
        "candidate_tree": review.get("candidate_tree").cloned().unwrap_or(Value::Null),
        "scope_files": review.get("scope_files").cloned().unwrap_or(Value::Null),
        "review": review_path
            .canonicalize()
            .unwrap_or_else(|_| review_path.to_path_buf())
            .to_string_lossy()
            .into_owned(),
        "review_sha256": sha256_file(review_path)?,
        "policy_sha256": sha256_file(&paths.policy_path)?,
        "validator_sha256": sha256_file(&paths.validator_path)?,
        "waivers": waivers,
        "verdict": "CLEAN",
    }))
}

pub fn verify_receipt(
    git: &GitContext,
    receipt: &Value,
    paths: &MinimizePaths,
) -> Result<Value, MinimizeError> {
    if receipt.get("schema").and_then(Value::as_str) != Some(RECEIPT_SCHEMA) {
        return Err(MinimizeError::new("commit receipt schema mismatch"));
    }
    if receipt.get("candidate_tree").and_then(Value::as_str) != Some(git.staged_tree()?.as_str()) {
        return Err(MinimizeError::new("stale commit receipt: candidate_tree mismatch"));
    }
    let declared = receipt
        .get("scope_files")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut declared_sorted = declared;
    declared_sorted.sort();
    let mut actual = git.staged_files()?;
    actual.sort();
    if serde_json::to_string(&declared_sorted).map_err(|error| MinimizeError::new(error.to_string()))?
        != serde_json::to_string(&actual).map_err(|error| MinimizeError::new(error.to_string()))?
    {
        return Err(MinimizeError::new("stale commit receipt: scope_files mismatch"));
    }
    if receipt.get("policy_sha256").and_then(Value::as_str)
        != Some(sha256_file(&paths.policy_path)?.as_str())
    {
        return Err(MinimizeError::new("stale commit receipt: policy_sha256 mismatch"));
    }
    if receipt.get("validator_sha256").and_then(Value::as_str)
        != Some(sha256_file(&paths.validator_path)?.as_str())
    {
        return Err(MinimizeError::new("stale commit receipt: validator_sha256 mismatch"));
    }
    if receipt.get("verdict").and_then(Value::as_str) != Some("CLEAN") {
        return Err(MinimizeError::new("commit receipt verdict must be CLEAN"));
    }
    Ok(receipt.clone())
}
