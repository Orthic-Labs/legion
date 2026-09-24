use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use walkdir::{DirEntry, WalkDir};

use crate::{error::AuditError, integrity::digest};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryEntry {
    pub path: String,
    #[serde(default)]
    pub symbols: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub package_scripts: Vec<String>,
    #[serde(default)]
    pub source_file: bool,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryEnvelope {
    pub schema_version: u32,
    pub repository_id: String,
    pub generation: String,
    pub entries: Vec<InventoryEntry>,
    pub digest: String,
}

/// Read-only repository inventory source. `FilesystemInventorySource` (Audit's
/// own local walk) is the sole production implementation; the trait exists so
/// tests can supply a fixed `StaticInventorySource` fixture instead.
pub trait InventorySource: Send + Sync {
    fn inventory(&self, repository_id: &str) -> Result<InventoryEnvelope, AuditError>;
}

/// Audit-owned read-only repository inventory: the sole inventory source.
/// Legion (Rust) has no dependency on an external context engine — this walk
/// is the only fact source a frozen plan's denominator is computed from.
#[derive(Clone, Debug)]
pub struct FilesystemInventorySource {
    root: PathBuf,
}

pub type InventorySourceDyn = dyn InventorySource;
pub type InventorySnapshot = InventoryEnvelope;

impl FilesystemInventorySource {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, AuditError> {
        let root = std::fs::canonicalize(root.as_ref()).map_err(|error| {
            AuditError::Invalid(format!("could not resolve Audit root: {error}"))
        })?;
        if !root.is_dir() {
            return Err(AuditError::Invalid("Audit root must be a directory".into()));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl InventorySource for FilesystemInventorySource {
    fn inventory(&self, repository_id: &str) -> Result<InventoryEnvelope, AuditError> {
        let mut entries = Vec::new();
        // Inside a git work tree the audit denominator is what git considers
        // part of the project: tracked files plus untracked files that are not
        // ignored. Build output, caches and vendored trees stay out, as they did
        // under the JavaScript engine's git-aware inventory.
        let git_files = git_project_files(&self.root);
        let walker = WalkDir::new(&self.root)
            .follow_links(false)
            .into_iter()
            .filter_entry(included_entry);
        for entry in walker {
            let entry = entry.map_err(|error| {
                AuditError::Invalid(format!("could not inventory repository: {error}"))
            })?;
            if entry.depth() == 0 {
                continue;
            }
            let file_type = entry.file_type();
            if !file_type.is_file() && !file_type.is_symlink() {
                continue;
            }
            let relative = entry.path().strip_prefix(&self.root).map_err(|error| {
                AuditError::Invalid(format!("inventory path escaped Audit root: {error}"))
            })?;
            let path = relative.to_string_lossy().replace('\\', "/");
            if git_files.as_ref().is_some_and(|files| !files.contains(&path)) {
                continue;
            }
            let bytes = if file_type.is_symlink() {
                std::fs::read_link(entry.path())
                    .map_err(|error| {
                        AuditError::Invalid(format!(
                            "could not read inventory symlink {}: {error}",
                            entry.path().display()
                        ))
                    })?
                    .to_string_lossy()
                    .into_owned()
                    .into_bytes()
            } else {
                std::fs::read(entry.path()).map_err(|error| {
                    AuditError::Invalid(format!(
                        "could not read inventory file {}: {error}",
                        entry.path().display()
                    ))
                })?
            };
            entries.push(InventoryEntry {
                path,
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: if relative.file_name().and_then(|name| name.to_str())
                    == Some("package.json")
                {
                    let mut scripts: Vec<String> = serde_json::from_slice::<Value>(&bytes)
                        .ok()
                        .and_then(|value| value.get("scripts").and_then(Value::as_object).cloned())
                        .map(|scripts| scripts.keys().cloned().collect())
                        .unwrap_or_default();
                    scripts.sort();
                    scripts
                } else {
                    Vec::new()
                },
                source_file: is_source_path(relative),
                digest: Some(format!("sha256:{}", hex::encode(Sha256::digest(bytes)))),
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let content_digest = legion_contracts::canonical_digest(&entries)
            .map_err(|error| AuditError::Invalid(error.to_string()))?;
        InventoryEnvelope::new(
            repository_id,
            format!("filesystem:{content_digest}"),
            entries,
        )
    }
}

/// Paths (relative to `root`, `/`-separated) git treats as part of the
/// project, or `None` when `root` is not inside a git work tree or git is
/// unavailable, in which case the plain walk is the inventory.
fn git_project_files(root: &Path) -> Option<std::collections::HashSet<String>> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .collect(),
    )
}

fn included_entry(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() || entry.depth() == 0 {
        return true;
    }
    !matches!(
        entry.file_name().to_str(),
        Some(".git" | ".audit" | "node_modules" | "target")
    )
}

impl InventoryEnvelope {
    pub fn new(
        repository_id: impl Into<String>,
        generation: impl Into<String>,
        mut entries: Vec<InventoryEntry>,
    ) -> Result<Self, AuditError> {
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let envelope = Self {
            schema_version: 1,
            repository_id: repository_id.into(),
            generation: generation.into(),
            entries,
            digest: String::new(),
        };
        envelope.validate_without_digest()?;
        let digest = digest(&envelope.without_digest())?;
        Ok(Self { digest, ..envelope })
    }

    fn without_digest(&self) -> impl Serialize + '_ {
        (
            &self.schema_version,
            &self.repository_id,
            &self.generation,
            &self.entries,
        )
    }

    fn validate_without_digest(&self) -> Result<(), AuditError> {
        if self.schema_version != 1 {
            return Err(AuditError::Invalid("unsupported inventory schema".into()));
        }
        if self.repository_id.trim().is_empty() || self.generation.trim().is_empty() {
            return Err(AuditError::Invalid(
                "repository and generation are required".into(),
            ));
        }
        let mut paths = BTreeSet::new();
        for entry in &self.entries {
            if entry.path.trim().is_empty() || !paths.insert(&entry.path) {
                return Err(AuditError::Invalid(
                    "inventory paths must be unique and non-empty".into(),
                ));
            }
            if entry.path.starts_with('/')
                || entry.path.contains('\\')
                || entry.path.contains('\0')
                || entry
                    .path
                    .split('/')
                    .next()
                    .is_some_and(|component| component.ends_with(':'))
                || entry
                    .path
                    .split('/')
                    .any(|component| component.is_empty() || component == "." || component == "..")
            {
                return Err(AuditError::Invalid(format!(
                    "inventory path is not canonical: {}",
                    entry.path
                )));
            }
            if entry.symbols.windows(2).any(|pair| pair[0] > pair[1])
                || entry.dependencies.windows(2).any(|pair| pair[0] > pair[1])
                || entry
                    .package_scripts
                    .windows(2)
                    .any(|pair| pair[0] > pair[1])
            {
                return Err(AuditError::Invalid("inventory lists must be sorted".into()));
            }
        }
        if self
            .entries
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(AuditError::Invalid(
                "inventory paths must be sorted and unique".into(),
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuditError> {
        self.validate_without_digest()?;
        if self.digest != digest(&self.without_digest())? {
            return Err(AuditError::SourceDrift("inventory digest mismatch".into()));
        }
        Ok(())
    }

    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.path.as_str())
    }

    pub fn denominator(&self, selector: &Value) -> Result<(usize, String), AuditError> {
        let denominator = self.denominator_entries(selector)?;
        Ok((denominator.entries.len(), denominator.digest))
    }

    pub fn denominator_entries(
        &self,
        selector: &Value,
    ) -> Result<InventoryDenominator, AuditError> {
        self.denominator_entries_with_candidates(selector, &[])
    }

    pub fn denominator_entries_with_candidates(
        &self,
        selector: &Value,
        candidates: &[InventoryDenominator],
    ) -> Result<InventoryDenominator, AuditError> {
        let normalized = normalize_selector(selector)?;
        let selector = &normalized;
        let op = selector.get("op").and_then(Value::as_str).unwrap_or("all");
        let selected = match op {
            "always" => self.entries.clone(),
            "all" | "any" => {
                let selectors = selector
                    .get("selectors")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        AuditError::Invalid(format!("selector.{op} requires selectors"))
                    })?;
                if selectors.is_empty() {
                    return Err(AuditError::Invalid(format!(
                        "selector.{op} requires selectors"
                    )));
                }
                let mut selected = Vec::new();
                for nested in selectors {
                    let nested = self.denominator_entries_with_candidates(nested, candidates)?;
                    if op == "all" && nested.entries.is_empty() {
                        return Ok(InventoryDenominator {
                            entries: Vec::new(),
                            digest: digest(&(
                                self.digest.as_str(),
                                selector,
                                &Vec::<InventoryEntry>::new(),
                            ))?,
                        });
                    }
                    selected.extend(nested.entries);
                }
                dedup_entries(selected)
            }
            "anyPath" => {
                let patterns = selector
                    .get("patterns")
                    .or_else(|| selector.get("paths"))
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        AuditError::Invalid("selector.patterns must be an array".into())
                    })?;
                if patterns.is_empty() {
                    return Err(AuditError::Invalid(
                        "selector.anyPath requires non-empty patterns".into(),
                    ));
                }
                let patterns = patterns
                    .iter()
                    .map(|pattern| {
                        pattern
                            .as_str()
                            .map(normalize_path)
                            .filter(|pattern| !pattern.is_empty())
                            .ok_or_else(|| {
                                AuditError::Invalid("selector patterns must be strings".into())
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.entries
                    .iter()
                    .filter(|entry| {
                        patterns
                            .iter()
                            .any(|pattern| glob_match(pattern, &entry.path))
                    })
                    .cloned()
                    .collect()
            }
            "paths" => {
                let paths = selector
                    .get("paths")
                    .and_then(Value::as_array)
                    .ok_or_else(|| AuditError::Invalid("selector.paths must be an array".into()))?;
                if paths.is_empty() {
                    return Err(AuditError::Invalid(
                        "selector.paths requires non-empty paths".into(),
                    ));
                }
                let paths = paths
                    .iter()
                    .map(|path| {
                        path.as_str()
                            .map(normalize_path)
                            .filter(|path| !path.is_empty())
                            .ok_or_else(|| {
                                AuditError::Invalid(
                                    "selector.paths must contain non-empty strings".into(),
                                )
                            })
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?;
                self.entries
                    .iter()
                    .filter(|entry| paths.contains(&entry.path))
                    .cloned()
                    .collect()
            }
            "anyExtension" => {
                let extensions = selector
                    .get("extensions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        AuditError::Invalid("selector.extensions must be an array".into())
                    })?;
                let extensions = extensions
                    .iter()
                    .map(|extension| {
                        extension
                            .as_str()
                            .map(|extension| extension.trim_start_matches('.').to_ascii_lowercase())
                            .filter(|extension| !extension.is_empty())
                            .ok_or_else(|| {
                                AuditError::Invalid(
                                    "selector.extensions must contain strings".into(),
                                )
                            })
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?;
                self.entries
                    .iter()
                    .filter(|entry| {
                        Path::new(&entry.path)
                            .extension()
                            .and_then(|extension| extension.to_str())
                            .is_some_and(|extension| {
                                extensions.contains(&extension.to_ascii_lowercase())
                            })
                    })
                    .cloned()
                    .collect()
            }
            "anyDependency" => {
                let names = selector
                    .get("names")
                    .and_then(Value::as_array)
                    .ok_or_else(|| AuditError::Invalid("selector.names must be an array".into()))?;
                let names = names
                    .iter()
                    .map(|name| {
                        name.as_str().ok_or_else(|| {
                            AuditError::Invalid("selector.names must contain strings".into())
                        })
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?;
                let matched = self
                    .entries
                    .iter()
                    .filter(|entry| {
                        entry
                            .dependencies
                            .iter()
                            .any(|name| names.contains(name.as_str()))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if matched.is_empty() {
                    matched
                } else {
                    let source = self
                        .entries
                        .iter()
                        .filter(|entry| entry.source_file)
                        .cloned()
                        .collect::<Vec<_>>();
                    if source.is_empty() {
                        matched
                    } else {
                        source
                    }
                }
            }
            "anyPackageScript" => {
                let names = selector
                    .get("names")
                    .and_then(Value::as_array)
                    .ok_or_else(|| AuditError::Invalid("selector.names must be an array".into()))?;
                let names = names
                    .iter()
                    .map(|name| {
                        name.as_str().ok_or_else(|| {
                            AuditError::Invalid("selector.names must contain strings".into())
                        })
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?;
                let matched = self
                    .entries
                    .iter()
                    .filter(|entry| {
                        entry
                            .package_scripts
                            .iter()
                            .any(|name| names.contains(name.as_str()))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if matched.is_empty() {
                    matched
                } else {
                    let source = self
                        .entries
                        .iter()
                        .filter(|entry| entry.source_file)
                        .cloned()
                        .collect::<Vec<_>>();
                    if source.is_empty() {
                        matched
                    } else {
                        source
                    }
                }
            }
            "sourceFilesAtLeast" => {
                let count = selector.get("count").and_then(Value::as_u64).unwrap_or(1);
                let source = self
                    .entries
                    .iter()
                    .filter(|entry| entry.source_file)
                    .cloned()
                    .collect::<Vec<_>>();
                if source.len() as u64 >= count {
                    source
                } else {
                    Vec::new()
                }
            }
            "securityCandidatesSelected" => {
                let mut selected = Vec::new();
                for candidate in candidates {
                    selected.extend(candidate.entries.clone());
                }
                dedup_entries(selected)
            }
            "confirmedSecurityFinding" => Vec::new(),
            other => {
                return Err(AuditError::Invalid(format!(
                    "unsupported provider selector operation: {other}"
                )))
            }
        };
        let digest = if op == "always" {
            self.digest.clone()
        } else {
            digest(&(self.digest.as_str(), selector, &selected))?
        };
        Ok(InventoryDenominator {
            entries: selected,
            digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryDenominator {
    pub entries: Vec<InventoryEntry>,
    pub digest: String,
}

fn dedup_entries(mut entries: Vec<InventoryEntry>) -> Vec<InventoryEntry> {
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries.dedup_by(|left, right| left.path == right.path);
    entries
}

fn normalize_selector(selector: &Value) -> Result<Value, AuditError> {
    if let Some(compact) = selector.as_str() {
        if matches!(
            compact,
            "always" | "securityCandidatesSelected" | "confirmedSecurityFinding"
        ) {
            return Ok(serde_json::json!({"op": compact}));
        }
        return Err(AuditError::Invalid(format!(
            "unsupported compact selector {compact}"
        )));
    }
    let object = selector
        .as_object()
        .ok_or_else(|| AuditError::Invalid("provider selector must be string or object".into()))?;
    if let Some(op) = object.get("op").and_then(Value::as_str) {
        if matches!(op, "any" | "all") {
            let selectors = object
                .get("selectors")
                .and_then(Value::as_array)
                .ok_or_else(|| AuditError::Invalid(format!("selector.{op} requires selectors")))?;
            let selectors = selectors
                .iter()
                .map(normalize_selector)
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(serde_json::json!({"op": op, "selectors": selectors}));
        }
        return Ok(selector.clone());
    }
    for (field, op, key) in [
        ("paths", "anyPath", "patterns"),
        ("ext", "anyExtension", "extensions"),
        ("deps", "anyDependency", "names"),
        ("scripts", "anyPackageScript", "names"),
    ] {
        if let Some(value) = object.get(field) {
            return Ok(serde_json::json!({"op": op, key: value}));
        }
    }
    if let Some(value) = object.get("sourceAtLeast") {
        return Ok(serde_json::json!({"op": "sourceFilesAtLeast", "count": value}));
    }
    for op in ["any", "all"] {
        if let Some(values) = object.get(op).and_then(Value::as_array) {
            let selectors = values
                .iter()
                .map(normalize_selector)
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(serde_json::json!({"op": op, "selectors": selectors}));
        }
    }
    Err(AuditError::Invalid(
        "selector has no supported operation".into(),
    ))
}

fn normalize_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    normalized
        .strip_prefix("./")
        .unwrap_or(&normalized)
        .trim_end_matches('/')
        .to_owned()
}

fn glob_match(pattern: &str, path: &str) -> bool {
    fn segment(pattern: &[u8], path: &[u8]) -> bool {
        if pattern.is_empty() {
            return path.is_empty();
        }
        if pattern[0] == b'*' {
            return segment(&pattern[1..], path)
                || (!path.is_empty() && segment(pattern, &path[1..]));
        }
        !path.is_empty()
            && (pattern[0] == b'?' || pattern[0] == path[0])
            && segment(&pattern[1..], &path[1..])
    }
    fn matches(pattern: &[&str], path: &[&str]) -> bool {
        if pattern.is_empty() {
            return path.is_empty();
        }
        if pattern[0] == "**" {
            return matches(&pattern[1..], path)
                || (!path.is_empty() && matches(pattern, &path[1..]));
        }
        !path.is_empty()
            && segment(pattern[0].as_bytes(), path[0].as_bytes())
            && matches(&pattern[1..], &path[1..])
    }
    let pattern = normalize_path(pattern);
    let path = normalize_path(path);
    matches(
        &pattern.split('/').collect::<Vec<_>>(),
        &path.split('/').collect::<Vec<_>>(),
    )
}

fn is_source_path(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some(
            "c" | "cc"
                | "cpp"
                | "go"
                | "h"
                | "hpp"
                | "java"
                | "js"
                | "jsx"
                | "mjs"
                | "py"
                | "rb"
                | "rs"
                | "sh"
                | "swift"
                | "ts"
                | "tsx"
                | "vue"
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_source_is_deterministic_and_detects_content_drift() {
        let root = std::env::temp_dir().join(format!(
            "legion-filesystem-inventory-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join(".audit")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "fn one() {}\n").unwrap();
        std::fs::write(root.join(".audit/report.json"), "ignored").unwrap();
        let source = FilesystemInventorySource::new(&root).unwrap();
        let first = source.inventory("repo").unwrap();
        let repeated = source.inventory("repo").unwrap();
        assert_eq!(first, repeated);
        assert_eq!(first.paths().collect::<Vec<_>>(), ["src/lib.rs"]);

        std::fs::write(root.join("src/lib.rs"), "fn two() {}\n").unwrap();
        let changed = source.inventory("repo").unwrap();
        assert_ne!(first.generation, changed.generation);
        assert_ne!(first.digest, changed.digest);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn git_work_tree_inventory_excludes_ignored_build_output() {
        let root = std::env::temp_dir().join(format!(
            "legion-git-inventory-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("dist")).unwrap();
        std::fs::write(root.join(".gitignore"), "dist/\n").unwrap();
        std::fs::write(root.join("src/lib.rs"), "fn one() {}\n").unwrap();
        std::fs::write(root.join("dist/bundle.js"), "generated\n").unwrap();
        let init = std::process::Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["init", "-q"])
            .status();
        if !init.is_ok_and(|status| status.success()) {
            // No git on this host: the plain walk applies and is covered above.
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        let source = FilesystemInventorySource::new(&root).unwrap();
        let inventory = source.inventory("repo").unwrap();
        let paths: Vec<_> = inventory.paths().collect();
        assert!(paths.contains(&"src/lib.rs"), "{paths:?}");
        assert!(paths.contains(&".gitignore"), "{paths:?}");
        assert!(!paths.iter().any(|path| path.starts_with("dist/")), "{paths:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_path_selector_arrays_are_rejected() {
        let inventory = InventoryEnvelope::new(
            "repo",
            "generation",
            vec![InventoryEntry {
                path: "src/lib.rs".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            }],
        )
        .unwrap();
        for selector in [
            serde_json::json!({"op": "anyPath", "patterns": []}),
            serde_json::json!({"op": "anyPath", "paths": []}),
            serde_json::json!({"op": "paths", "paths": []}),
            serde_json::json!({"op": "paths", "paths": [""]}),
            serde_json::json!({"paths": []}),
        ] {
            let result = inventory.denominator_entries(&selector);
            assert!(
                matches!(
                    &result,
                    Err(AuditError::Invalid(message))
                        if message.contains("non-empty")
                ),
                "selector {selector} returned {result:?}"
            );
        }
    }
}
