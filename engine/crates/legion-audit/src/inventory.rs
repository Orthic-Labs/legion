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
    /// When set, only these repository-relative paths enter the inventory
    /// (diff-scoped audits: the denominator is the changed-file set).
    only_paths: Option<BTreeSet<String>>,
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
        Ok(Self {
            root,
            only_paths: None,
        })
    }

    /// Restricts the inventory to `paths` (repository-relative, `/`
    /// separated). Paths absent from the work tree are simply not listed.
    pub fn with_only_paths(mut self, paths: Option<BTreeSet<String>>) -> Self {
        self.only_paths = paths;
        self
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
            if git_files
                .as_ref()
                .is_some_and(|files| !files.contains(&path))
            {
                continue;
            }
            if self
                .only_paths
                .as_ref()
                .is_some_and(|only| !only.contains(&path))
            {
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
                dependencies: relative
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| manifest_dependencies(name, &bytes))
                    .unwrap_or_default(),
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

/// Dependency names declared by a recognised manifest (`Cargo.toml`,
/// `package.json`, `pyproject.toml`, `go.mod`, `Package.swift`, `pom.xml`,
/// `build.gradle`, `build.gradle.kts`, `Gemfile`, `mix.exs`, `pubspec.yaml`,
/// `requirements.txt`); empty for any other file. Sorted and unique, as
/// inventory validation requires. Parsing is deliberately shallow: names only,
/// no resolution. Malformed input yields fewer names, never an error.
fn manifest_dependencies(file_name: &str, bytes: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let names: BTreeSet<String> = match file_name {
        "package.json" => package_json_dependencies(text),
        "Cargo.toml" => cargo_dependencies(text),
        "pyproject.toml" => pyproject_dependencies(text),
        "go.mod" => go_mod_dependencies(text),
        "Package.swift" => swift_package_dependencies(text),
        "pom.xml" => maven_dependencies(text),
        "build.gradle" | "build.gradle.kts" => gradle_dependencies(text),
        "Gemfile" => gemfile_dependencies(text),
        "mix.exs" => mix_dependencies(text),
        "pubspec.yaml" => pubspec_dependencies(text),
        "requirements.txt" => requirements_dependencies(text),
        _ => BTreeSet::new(),
    };
    names.into_iter().collect()
}

/// `group:artifact` for a Maven or Gradle coordinate, when both halves are
/// plain names (a `${property}` or an empty half is rejected).
fn coordinate_key(group: &str, artifact: &str) -> Option<String> {
    Some(format!(
        "{}:{}",
        dependency_key(group)?,
        dependency_key(artifact)?
    ))
}

/// Maven: `groupId:artifactId` of every `<dependency>` and of the `<parent>`
/// (for example `org.springframework.boot:spring-boot-starter-parent`).
fn maven_dependencies(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let (Ok(block), Ok(group), Ok(artifact)) = (
        regex::Regex::new(r"(?s)<(dependency|parent)>(.*?)</(?:dependency|parent)>"),
        regex::Regex::new(r"<groupId>\s*([^<\s]+)\s*</groupId>"),
        regex::Regex::new(r"<artifactId>\s*([^<\s]+)\s*</artifactId>"),
    ) else {
        return names;
    };
    for capture in block.captures_iter(text) {
        let body = &capture[2];
        let (Some(group), Some(artifact)) = (group.captures(body), artifact.captures(body)) else {
            continue;
        };
        names.extend(coordinate_key(&group[1], &artifact[1]));
    }
    names
}

/// Gradle (Groovy and Kotlin DSL): `group:artifact` from implementation, api,
/// compile-style lines, plus plugin ids (`id("io.ktor.plugin")`,
/// `id 'org.springframework.boot'`, `apply plugin: '...'`).
fn gradle_dependencies(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let (Ok(coordinate), Ok(plugin)) = (
        regex::Regex::new(
            r#"(?m)^\s*(?:implementation|api|compile|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*["']([^"':\s]+):([^"':\s]+)"#,
        ),
        regex::Regex::new(r#"(?m)(?:\bid\s*\(?\s*|apply\s+plugin:\s*)["']([^"'\s]+)["']"#),
    ) else {
        return names;
    };
    for capture in coordinate.captures_iter(text) {
        names.extend(coordinate_key(&capture[1], &capture[2]));
    }
    for capture in plugin.captures_iter(text) {
        names.extend(dependency_key(&capture[1]));
    }
    names
}

/// Bundler: the gem name of each `gem 'name', ...` line.
fn gemfile_dependencies(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let Ok(gem) = regex::Regex::new(r#"(?m)^\s*gem\s*\(?\s*["']([^"']+)["']"#) else {
        return names;
    };
    for capture in gem.captures_iter(text) {
        names.extend(dependency_key(&capture[1]));
    }
    names
}

/// Mix: the atom of each dependency tuple, such as `{:phoenix, "~> 1.7"}`.
fn mix_dependencies(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let Ok(dep) = regex::Regex::new(r"\{\s*:([A-Za-z][A-Za-z0-9_]*)\s*,") else {
        return names;
    };
    for capture in dep.captures_iter(text) {
        names.insert(capture[1].to_owned());
    }
    names
}

/// Pub: the keys directly under the top-level `dependencies:` mapping. The
/// Flutter SDK dependency appears as the key `flutter` (with `sdk: flutter`).
fn pubspec_dependencies(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut in_dependencies = false;
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_dependencies = line.trim_end() == "dependencies:";
            continue;
        }
        if !in_dependencies {
            continue;
        }
        // Direct children sit at exactly two spaces of indentation.
        if let Some(rest) = line.strip_prefix("  ") {
            if !rest.starts_with(' ') && !rest.starts_with('#') {
                if let Some((key, _)) = rest.split_once(':') {
                    names.extend(dependency_key(key));
                }
            }
        }
    }
    names
}

/// pip requirements: the name of each requirement line. Options (`-r`, `-e`),
/// comments and URL requirements are skipped.
fn requirements_dependencies(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| !line.is_empty() && !line.starts_with('-') && !line.contains("://"))
        .filter_map(pep508_name)
        .collect()
}

fn package_json_dependencies(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        for table in [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ] {
            if let Some(object) = value.get(table).and_then(Value::as_object) {
                names.extend(object.keys().cloned());
            }
        }
    }
    names
}

fn dependency_key(raw: &str) -> Option<String> {
    let name = raw
        .trim()
        .trim_matches(|c: char| c == '"' || c == '\'')
        .trim();
    (!name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '@')))
    .then(|| name.to_owned())
}

fn cargo_dependencies(text: &str) -> BTreeSet<String> {
    const KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    let mut names = BTreeSet::new();
    let mut in_dependency_table = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            let header = line.trim_start_matches('[').trim_end_matches(']').trim();
            in_dependency_table = false;
            for kind in KINDS {
                let suffix = format!(".{kind}");
                let infix = format!(".{kind}.");
                let prefix = format!("{kind}.");
                if header == kind || header.ends_with(&suffix) {
                    in_dependency_table = true;
                } else if let Some(rest) = header.strip_prefix(&prefix) {
                    names.extend(dependency_key(rest));
                } else if let Some((_, rest)) = header.split_once(&infix) {
                    names.extend(dependency_key(rest));
                }
            }
            continue;
        }
        if in_dependency_table && !line.starts_with('#') {
            if let Some((key, _)) = line.split_once('=') {
                let key = key.trim().split('.').next().unwrap_or_default();
                names.extend(dependency_key(key));
            }
        }
    }
    names
}

fn quoted_strings(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut quote: Option<char> = None;
    let mut text = String::new();
    for c in line.chars() {
        match quote {
            Some(open) if c == open => {
                found.push(std::mem::take(&mut text));
                quote = None;
            }
            Some(_) => text.push(c),
            None if c == '"' || c == '\'' => quote = Some(c),
            None => {}
        }
    }
    found
}

fn pep508_name(requirement: &str) -> Option<String> {
    let name = requirement
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect::<String>();
    name.chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        .then_some(name)
}

fn pyproject_dependencies(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut section = String::new();
    let mut collecting = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') && !collecting {
            section = line
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .to_owned();
            continue;
        }
        let starts = section == "project"
            && !collecting
            && line.split('=').next().map(str::trim) == Some("dependencies")
            && line.contains('=');
        let array_section =
            section == "project.optional-dependencies" || section == "dependency-groups";
        if starts || collecting || array_section {
            let body = if starts {
                line.split_once('=').map_or("", |(_, rest)| rest)
            } else {
                line
            };
            if !body.contains("include-group") {
                names.extend(
                    quoted_strings(body)
                        .iter()
                        .filter_map(|item| pep508_name(item)),
                );
            }
            if starts || collecting {
                collecting = !body.trim_end().trim_end_matches(',').ends_with(']');
            }
        } else if section.starts_with("tool.poetry") && section.ends_with("dependencies") {
            if let Some((key, _)) = line.split_once('=') {
                if let Some(name) = dependency_key(key).filter(|name| name != "python") {
                    names.insert(name);
                }
            }
        }
    }
    names
}

fn go_mod_dependencies(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut in_block = false;
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or_default().trim();
        if in_block {
            if line == ")" {
                in_block = false;
            } else if let Some(module) = line.split_whitespace().next() {
                names.insert(module.to_owned());
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("require") {
            let rest = rest.trim();
            if rest.starts_with('(') {
                in_block = true;
            } else if let Some(module) = rest.split_whitespace().next() {
                names.insert(module.to_owned());
            }
        }
    }
    names
}

fn swift_package_dependencies(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Ok(url) = regex::Regex::new(r#"url:\s*"([^"]+)""#) {
        for capture in url.captures_iter(text) {
            let last = capture[1]
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or_default();
            let name = last.trim_end_matches(".git");
            if !name.is_empty() {
                names.insert(name.to_owned());
            }
        }
    }
    if let Ok(product) = regex::Regex::new(r#"\.product\(\s*name:\s*"([^"]+)""#) {
        for capture in product.captures_iter(text) {
            names.insert(capture[1].to_owned());
        }
    }
    names
}

/// Paths (relative to `root`, `/`-separated) git treats as part of the
/// project, or `None` when `root` is not inside a git work tree or git is
/// unavailable, in which case the plain walk is the inventory.
fn git_project_files(root: &Path) -> Option<std::collections::HashSet<String>> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
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

/// Directory names the audit inventory never descends into, at any depth.
pub(crate) fn excluded_directory_name(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".audit" | ".legion-cache" | "node_modules" | "target"
    )
}

/// True when any parent directory of the `/`-separated relative `path` is an
/// excluded directory (the file name itself is not considered).
pub(crate) fn path_in_excluded_directory(path: &str) -> bool {
    let mut parts = path.split('/').collect::<Vec<_>>();
    parts.pop();
    parts.into_iter().any(excluded_directory_name)
}

pub(crate) fn included_entry(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() || entry.depth() == 0 {
        return true;
    }
    !entry
        .file_name()
        .to_str()
        .is_some_and(excluded_directory_name)
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
        self.denominator_entries_with_security_context(selector, candidates, &[])
    }

    /// Like `denominator_entries_with_candidates`, plus the paths of security
    /// findings an independent adjudicator confirmed (ingested surviving
    /// verdicts). `confirmedSecurityFinding` selects exactly those paths, so
    /// variant analysis is triggered by a verdict, never by a scanner claim.
    /// With no confirmed paths the selector is empty, as before.
    pub fn denominator_entries_with_security_context(
        &self,
        selector: &Value,
        candidates: &[InventoryDenominator],
        confirmed_paths: &[String],
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
                    let nested = self.denominator_entries_with_security_context(
                        nested,
                        candidates,
                        confirmed_paths,
                    )?;
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
            "anyDependencyGroup" => {
                let patterns = selector
                    .get("patterns")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        AuditError::Invalid("selector.patterns must be an array".into())
                    })?;
                let patterns = patterns
                    .iter()
                    .map(|pattern| {
                        pattern.as_str().ok_or_else(|| {
                            AuditError::Invalid("selector.patterns must contain strings".into())
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let matched = self
                    .entries
                    .iter()
                    .filter(|entry| {
                        entry.dependencies.iter().any(|dependency| {
                            let Some((group, artifact)) = dependency.split_once(':') else {
                                return false;
                            };
                            !group.is_empty()
                                && !artifact.is_empty()
                                && patterns.iter().any(|pattern| glob_match(pattern, group))
                        })
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
            "confirmedSecurityFinding" => {
                // A follow-up plan freezes its confirmed paths into the
                // selector itself (`paths`), so every re-derivation of the
                // denominator (execution, reasoning host, ingest) reproduces
                // it from the plan alone. The parent plan's selector carries
                // none and stays empty without an explicit context.
                let frozen = selector
                    .get("paths")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str);
                let confirmed = confirmed_paths
                    .iter()
                    .map(String::as_str)
                    .chain(frozen)
                    .map(normalize_path)
                    .collect::<BTreeSet<_>>();
                self.entries
                    .iter()
                    .filter(|entry| confirmed.contains(&entry.path))
                    .cloned()
                    .collect()
            }
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

pub(crate) fn glob_match(pattern: &str, path: &str) -> bool {
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
            "astro"
                | "bash"
                | "c"
                | "cc"
                | "cjs"
                | "cpp"
                | "cs"
                | "cts"
                | "cxx"
                | "dart"
                | "erb"
                | "erl"
                | "ex"
                | "exs"
                | "fs"
                | "fsx"
                | "go"
                | "h"
                | "hh"
                | "hpp"
                | "hs"
                | "java"
                | "jl"
                | "js"
                | "jsx"
                | "kt"
                | "kts"
                | "lua"
                | "m"
                | "mjs"
                | "mm"
                | "mts"
                | "php"
                | "phtml"
                | "pl"
                | "pm"
                | "ps1"
                | "psm1"
                | "py"
                | "r"
                | "rb"
                | "rs"
                | "scala"
                | "sh"
                | "sql"
                | "svelte"
                | "swift"
                | "ts"
                | "tsx"
                | "vb"
                | "vue"
                | "zsh"
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_classification_covers_common_source_languages() {
        for path in [
            "app/index.php",
            "src/Program.cs",
            "ui/Main.kt",
            "App/View.swift",
            "web/App.vue",
        ] {
            assert!(is_source_path(Path::new(path)), "{path} should be source");
        }
        for path in ["docs/README.md", "assets/logo.png", "Cargo.lock"] {
            assert!(
                !is_source_path(Path::new(path)),
                "{path} should not be source"
            );
        }
    }

    #[test]
    fn filesystem_source_is_deterministic_and_detects_content_drift() {
        let root = std::env::temp_dir().join(format!(
            "legion-filesystem-inventory-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join(".audit")).unwrap();
        std::fs::create_dir_all(root.join(".legion-cache/audit-sandbox")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "fn one() {}\n").unwrap();
        std::fs::write(root.join(".audit/report.json"), "ignored").unwrap();
        std::fs::write(
            root.join(".legion-cache/audit-sandbox/profile.sb"),
            "ignored",
        )
        .unwrap();
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
    fn only_paths_narrows_the_denominator_to_the_changed_set() {
        let root = std::env::temp_dir().join(format!(
            "legion-only-paths-inventory-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(root.join("src/b.rs"), "fn b() {}\n").unwrap();
        std::fs::write(root.join("src/c.rs"), "fn c() {}\n").unwrap();
        let only: BTreeSet<String> = ["src/b.rs", "src/gone.rs"]
            .into_iter()
            .map(String::from)
            .collect();
        let source = FilesystemInventorySource::new(&root)
            .unwrap()
            .with_only_paths(Some(only));
        let narrowed = source.inventory("repo").unwrap();
        assert_eq!(narrowed.paths().collect::<Vec<_>>(), ["src/b.rs"]);
        let whole = FilesystemInventorySource::new(&root)
            .unwrap()
            .inventory("repo")
            .unwrap();
        assert_eq!(whole.paths().count(), 3);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn git_work_tree_inventory_excludes_ignored_build_output() {
        let root = std::env::temp_dir().join(format!(
            "legion-git-inventory-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            {
                static NEXT: ::std::sync::atomic::AtomicU64 =
                    ::std::sync::atomic::AtomicU64::new(0);
                NEXT.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed)
            }
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
        assert!(
            !paths.iter().any(|path| path.starts_with("dist/")),
            "{paths:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn manifest_dependencies_are_extracted_sorted_and_unique() {
        let package =
            br#"{"dependencies":{"react":"1"},"devDependencies":{"vite":"1","react":"1"}}"#;
        assert_eq!(
            manifest_dependencies("package.json", package),
            ["react", "vite"]
        );

        let cargo = b"[package]\nname = \"x\"\n[dependencies]\nserde = \"1\"\ntokio = { version = \"1\" }\n[dev-dependencies]\ntempfile.workspace = true\n[dependencies.regex]\nversion = \"1\"\n[workspace.dependencies]\nhex = \"0.4\"\n";
        assert_eq!(
            manifest_dependencies("Cargo.toml", cargo),
            ["hex", "regex", "serde", "tempfile", "tokio"]
        );

        let pyproject = b"[project]\nname = \"x\"\ndependencies = [\n  \"requests>=2\",\n  \"Flask[async]\",\n]\n[tool.poetry.dependencies]\npython = \"^3.11\"\nnumpy = \"1\"\n";
        assert_eq!(
            manifest_dependencies("pyproject.toml", pyproject),
            ["Flask", "numpy", "requests"]
        );

        let go_mod = b"module x\n\nrequire github.com/a/b v1.0.0\nrequire (\n\tgithub.com/c/d v2.0.0 // indirect\n)\n";
        assert_eq!(
            manifest_dependencies("go.mod", go_mod),
            ["github.com/a/b", "github.com/c/d"]
        );

        let swift = b".package(url: \"https://github.com/pointfreeco/swift-composable-architecture.git\", from: \"1.0.0\"),\n.product(name: \"ComposableArchitecture\", package: \"x\")";
        assert_eq!(
            manifest_dependencies("Package.swift", swift),
            ["ComposableArchitecture", "swift-composable-architecture"]
        );

        assert!(manifest_dependencies("README.md", b"react").is_empty());
    }

    #[test]
    fn jvm_ruby_elixir_dart_and_python_manifests_yield_dependencies() {
        let pom = br#"<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
  </parent>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>internal</artifactId>
    </dependency>
  </dependencies>
</project>"#;
        assert_eq!(
            manifest_dependencies("pom.xml", pom),
            [
                "org.springframework.boot:spring-boot-starter-parent",
                "org.springframework.boot:spring-boot-starter-web"
            ]
        );

        let gradle = b"plugins {\n  id 'org.springframework.boot' version '3.2.0'\n}\ndependencies {\n  implementation 'org.springframework.boot:spring-boot-starter-web'\n  testImplementation(\"junit:junit:4.13\")\n}\n";
        assert_eq!(
            manifest_dependencies("build.gradle", gradle),
            [
                "junit:junit",
                "org.springframework.boot",
                "org.springframework.boot:spring-boot-starter-web"
            ]
        );

        let kts = b"plugins {\n    id(\"io.ktor.plugin\") version \"2.3.0\"\n}\ndependencies {\n    implementation(\"io.ktor:ktor-server-core:2.3.0\")\n}\n";
        assert_eq!(
            manifest_dependencies("build.gradle.kts", kts),
            ["io.ktor.plugin", "io.ktor:ktor-server-core"]
        );

        let gemfile = b"source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\n  gem \"pg\"\n# gem 'commented'\n";
        assert_eq!(manifest_dependencies("Gemfile", gemfile), ["pg", "rails"]);

        let mix = b"defp deps do\n  [{:phoenix, \"~> 1.7.0\"}, {:jason, \"~> 1.4\"}]\nend\n";
        assert_eq!(manifest_dependencies("mix.exs", mix), ["jason", "phoenix"]);

        let pubspec = b"name: app\ndependencies:\n  flutter:\n    sdk: flutter\n  http: ^1.2.0\ndev_dependencies:\n  test: any\n";
        assert_eq!(
            manifest_dependencies("pubspec.yaml", pubspec),
            ["flutter", "http"]
        );

        let requirements = b"# pins\nDjango==4.2\n-r base.txt\nflask[async]>=2 ; python_version>\"3\"\ngit+https://github.com/x/y.git\n";
        assert_eq!(
            manifest_dependencies("requirements.txt", requirements),
            ["Django", "flask"]
        );
    }

    #[test]
    fn malformed_new_manifests_yield_no_dependencies_and_no_panic() {
        for (name, body) in [
            (
                "pom.xml",
                &b"<dependency><groupId>org.x</groupId><artifactId>y"[..],
            ),
            ("build.gradle.kts", &b"implementation(\"io.ktor:"[..]),
            ("build.gradle", &b"id '"[..]),
            ("Gemfile", &b"gem '"[..]),
            ("mix.exs", &b"{:"[..]),
            ("pubspec.yaml", &b"dependencies:\n\t:::\n"[..]),
            ("requirements.txt", &b"\xff\xfe"[..]),
        ] {
            assert!(manifest_dependencies(name, body).is_empty(), "{name}");
        }
    }

    #[test]
    fn filesystem_inventory_populates_dependencies_for_any_dependency_selectors() {
        let root =
            std::env::temp_dir().join(format!("legion-inventory-deps-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"react":"18"}}"#,
        )
        .unwrap();
        std::fs::write(root.join("src/app.tsx"), "export const a = 1;\n").unwrap();
        let inventory = FilesystemInventorySource::new(&root)
            .unwrap()
            .inventory("repo")
            .unwrap();
        let manifest = inventory
            .entries
            .iter()
            .find(|entry| entry.path == "package.json")
            .unwrap();
        assert_eq!(manifest.dependencies, ["react"]);
        let selected = inventory
            .denominator_entries(&serde_json::json!({"op":"anyDependency","names":["react"]}))
            .unwrap();
        assert_eq!(selected.entries.len(), 1);
        assert_eq!(selected.entries[0].path, "src/app.tsx");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dependency_group_selector_expands_source_denominator_and_rejects_prefix_or_malformed_groups()
    {
        let inventory = InventoryEnvelope::new(
            "repo",
            "generation",
            vec![
                InventoryEntry {
                    path: "pom.xml".into(),
                    symbols: vec![],
                    dependencies: vec![
                        ":missing-group".into(),
                        ":org.springframework".into(),
                        "io.ktor:ktor-unlisted-artifact".into(),
                        "io.ktorx:lookalike".into(),
                        "malformed-coordinate".into(),
                        "missing-artifact:".into(),
                        "org.springframework".into(),
                        "org.springframework.data:spring-data-jpa".into(),
                        "org.springframework.security:spring-security-config".into(),
                        "org.springframework:".into(),
                        "org.springframework:framework-core".into(),
                        "org.springframeworkevil:lookalike".into(),
                    ],
                    package_scripts: vec![],
                    source_file: false,
                    digest: None,
                },
                InventoryEntry {
                    path: "src/main.java".into(),
                    symbols: vec![],
                    dependencies: vec![],
                    package_scripts: vec![],
                    source_file: true,
                    digest: None,
                },
            ],
        )
        .unwrap();
        let selector = serde_json::json!({
            "op": "anyDependencyGroup",
            "patterns": ["org.springframework", "org.springframework.*", "io.ktor"]
        });
        let selected = inventory.denominator_entries(&selector).unwrap();
        assert_eq!(selected.entries.len(), 1);
        assert_eq!(selected.entries[0].path, "src/main.java");

        let lookalikes_only = InventoryEnvelope::new(
            "repo",
            "lookalikes",
            vec![InventoryEntry {
                path: "pom.xml".into(),
                symbols: vec![],
                dependencies: vec![
                    ":missing-group".into(),
                    ":org.springframework".into(),
                    "io.ktorx:lookalike".into(),
                    "malformed-coordinate".into(),
                    "missing-artifact:".into(),
                    "org.springframework".into(),
                    "org.springframework:".into(),
                    "org.springframeworkevil:lookalike".into(),
                    "org.springframeworkx.security:lookalike".into(),
                ],
                package_scripts: vec![],
                source_file: false,
                digest: None,
            }],
        )
        .unwrap();
        let unmatched = lookalikes_only
            .denominator_entries(&serde_json::json!({
                "op": "anyDependencyGroup",
                "patterns": ["org.springframework", "org.springframework.*", "io.ktor"]
            }))
            .unwrap();
        assert!(unmatched.entries.is_empty());
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

    #[test]
    fn confirmed_security_finding_selects_only_confirmed_paths() {
        let entry = |path: &str| InventoryEntry {
            path: path.into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: None,
        };
        let inventory = InventoryEnvelope::new(
            "repo",
            "generation",
            vec![entry("src/a.rs"), entry("src/b.rs")],
        )
        .unwrap();
        let selector = serde_json::json!({"op": "confirmedSecurityFinding"});
        assert!(inventory
            .denominator_entries(&selector)
            .unwrap()
            .entries
            .is_empty());
        let confirmed = inventory
            .denominator_entries_with_security_context(&selector, &[], &["src/b.rs".to_owned()])
            .unwrap();
        assert_eq!(
            confirmed
                .entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec!["src/b.rs"]
        );
        // Composes under any/all like every other selector.
        let nested = inventory
            .denominator_entries_with_security_context(
                &serde_json::json!({"op": "any", "selectors": [selector]}),
                &[],
                &["src/a.rs".to_owned()],
            )
            .unwrap();
        assert_eq!(nested.entries.len(), 1);
    }
}
