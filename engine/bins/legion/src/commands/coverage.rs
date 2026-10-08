//! Repository coverage shared by `legion languages` and `legion doctor`.
//!
//! Detection is manifest-driven and bounded: a depth- and entry-limited walk
//! that skips build output and vendored trees, plus a provider-selection pass
//! that reuses the audit inventory and the registry's own selectors, so the
//! status commands answer from the repository instead of from a fixed list.

use super::CommandError;
use legion_audit::InventorySource as _;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const PROVIDER_REGISTRY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../src/registry/providers.json"
));

const MAX_DEPTH: usize = 6;
const MAX_ENTRIES: usize = 50_000;
const MAX_EVIDENCE_PER_ID: usize = 5;
const MAX_MANIFEST_BYTES: u64 = 1_048_576;
const SKIP_DIRS: &[&str] = &[
    ".git",
    ".audit",
    ".build",
    ".next",
    ".venv",
    "DerivedData",
    "Pods",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
    // Test and sample trees declare languages the repository does not ship.
    "tests",
    "test",
    "fixtures",
    "__fixtures__",
    "examples",
    "bench",
    "migration",
    "testdata",
    "third_party",
    ".github",
];

/// id, kind, provider ids (registry ids without the `legacy.` prefix).
const FAMILIES: &[(&str, &str, &[&str])] = &[
    (
        "language.rust",
        "language",
        &[
            "code.rust",
            "security.rust-advisories",
            "security.rust-policy",
            "security.rust-unsafe",
            "stack.rust-outdated",
            "quality.rust-unused-deps",
        ],
    ),
    (
        "language.javascript",
        "language",
        &[
            "code.javascript",
            "security.node-dependencies",
            "security.js-licenses",
            "stack.node-outdated",
        ],
    ),
    (
        "language.typescript",
        "language",
        &["code.javascript", "quality.types"],
    ),
    (
        "language.swift",
        "language",
        &["quality.swift-lint", "apple.platform", "code.mobile"],
    ),
    (
        "language.python",
        "language",
        &["code.python", "security.python-dependencies"],
    ),
    ("language.go", "language", &["code.go"]),
    (
        "framework.react",
        "framework",
        &["react.hooks-config", "framework.frontend"],
    ),
    ("framework.next", "framework", &["framework.frontend"]),
    (
        "framework.tauri",
        "framework",
        &["tauri.capabilities", "tauri.contract-mirror"],
    ),
];

pub struct Scan {
    pub found: BTreeMap<String, Vec<String>>,
    pub entries_seen: usize,
    /// The entry budget ran out: coverage is partial and provider selection is skipped.
    pub entries_truncated: bool,
    /// At least one directory was deeper than the walk goes.
    pub depth_limited: bool,
}

impl Scan {
    fn note(&mut self, id: &str, relative: &str) {
        let list = self.found.entry(id.to_owned()).or_default();
        if list.len() < MAX_EVIDENCE_PER_ID && !list.iter().any(|item| item == relative) {
            list.push(relative.to_owned());
        }
    }

    fn visit_file(&mut self, name: &str, path: &Path, relative: &str) {
        match name {
            "Cargo.toml" => {
                self.note("language.rust", relative);
                if manifest_text(path).is_some_and(|text| mentions_tauri_crate(&text)) {
                    self.note("framework.tauri", relative);
                }
            }
            "package.json" => {
                self.note("language.javascript", relative);
                let manifest =
                    manifest_text(path).and_then(|text| serde_json::from_str::<Value>(&text).ok());
                if let Some(manifest) = manifest {
                    let mut dependencies = BTreeSet::new();
                    for key in ["dependencies", "devDependencies", "peerDependencies"] {
                        if let Some(object) = manifest.get(key).and_then(Value::as_object) {
                            dependencies.extend(object.keys().cloned());
                        }
                    }
                    if dependencies.contains("typescript") {
                        self.note("language.typescript", relative);
                    }
                    if dependencies.contains("react") || dependencies.contains("react-dom") {
                        self.note("framework.react", relative);
                    }
                    if dependencies.contains("next") {
                        self.note("framework.next", relative);
                    }
                    if dependencies
                        .iter()
                        .any(|name| name.starts_with("@tauri-apps/"))
                    {
                        self.note("framework.tauri", relative);
                    }
                }
            }
            "tsconfig.json" => self.note("language.typescript", relative),
            "tauri.conf.json" | "tauri.conf.json5" | "Tauri.toml" => {
                self.note("framework.tauri", relative)
            }
            "Package.swift" => self.note("language.swift", relative),
            "pyproject.toml" | "requirements.txt" | "setup.py" | "Pipfile" => {
                self.note("language.python", relative)
            }
            "go.mod" => self.note("language.go", relative),
            _ => {}
        }
    }
}

fn manifest_text(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

fn mentions_tauri_crate(text: &str) -> bool {
    text.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("[dependencies.tauri")
            || trimmed.starts_with("[build-dependencies.tauri")
            || trimmed
                .strip_prefix("tauri")
                .is_some_and(|rest| rest.starts_with([' ', '=', '-', '.']))
    })
}

/// Walk `root` and record which languages and frameworks its manifests declare.
pub fn scan(root: &Path) -> Scan {
    let mut scan = Scan {
        found: BTreeMap::new(),
        entries_seen: 0,
        entries_truncated: false,
        depth_limited: false,
    };
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    while let Some((directory, depth)) = pending.pop() {
        let Ok(read) = std::fs::read_dir(&directory) else {
            continue;
        };
        let mut entries = read.filter_map(Result::ok).collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if scan.entries_seen >= MAX_ENTRIES {
                scan.entries_truncated = true;
                return scan;
            }
            scan.entries_seen += 1;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if file_type.is_dir() {
                let slashed = format!("/{relative}/");
                if SKIP_DIRS.contains(&name.as_str())
                    || slashed.contains("/tests/")
                    || slashed.contains("/fixtures/")
                {
                    continue;
                }
                if name.ends_with(".xcodeproj") || name.ends_with(".xcworkspace") {
                    scan.note("language.swift", &relative);
                    continue;
                }
                if depth + 1 > MAX_DEPTH {
                    scan.depth_limited = true;
                    continue;
                }
                pending.push((path, depth + 1));
            } else if file_type.is_file() {
                scan.visit_file(&name, &path, &relative);
            }
        }
    }
    scan
}

fn registry_ids() -> Result<BTreeSet<String>, CommandError> {
    let source: Value = serde_json::from_str(PROVIDER_REGISTRY).map_err(|error| {
        CommandError::internal(format!("embedded provider registry invalid: {error}"))
    })?;
    Ok(source
        .get("providers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|provider| provider.get("selectable").and_then(Value::as_bool) != Some(false))
        .filter_map(|provider| provider.get("id").and_then(Value::as_str))
        .map(|id| id.strip_prefix("legacy.").unwrap_or(id).to_owned())
        .collect())
}

/// One row per detected language or framework, with the providers that cover it.
pub fn rows(scan: &Scan) -> Result<Vec<Value>, CommandError> {
    let registry = registry_ids()?;
    Ok(FAMILIES
        .iter()
        .filter(|(id, _, _)| scan.found.contains_key(*id))
        .map(|(id, kind, providers)| {
            json!({
                "id": id,
                "kind": kind,
                "qualification": "unproven",
                "providers": providers
                    .iter()
                    .filter(|provider| registry.contains(**provider))
                    .copied()
                    .collect::<Vec<&str>>(),
                "evidence": scan.found.get(*id),
            })
        })
        .collect())
}

/// Summary of the scan for `doctor`: ids by kind plus detected ids no provider covers.
pub fn coverage_summary(scan: &Scan, rows: &[Value]) -> Value {
    let ids_of = |kind: &str| -> Vec<String> {
        rows.iter()
            .filter(|row| row["kind"] == kind)
            .filter_map(|row| row["id"].as_str().map(str::to_owned))
            .collect()
    };
    let unsupported = rows
        .iter()
        .filter(|row| row["providers"].as_array().is_some_and(Vec::is_empty))
        .filter_map(|row| row["id"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    json!({
        "basis": "repository manifests (Cargo.toml, package.json, Package.swift, *.xcodeproj, pyproject.toml, requirements.txt, go.mod)",
        "languages": ids_of("language"),
        "frameworks": ids_of("framework"),
        "unsupported": unsupported,
        "scan": {
            "entriesSeen": scan.entries_seen,
            "entriesTruncated": scan.entries_truncated,
            "depthLimited": scan.depth_limited,
            "maxDepth": MAX_DEPTH,
            "maxEntries": MAX_ENTRIES,
        },
    })
}

/// A legacy-check provider names the tool it shells out to in `runner.tool`,
/// sometimes as alternatives (`a|b`) or as a non-executable marker (`fs`,
/// `<project build>`). Return the alternatives when none is on PATH.
fn missing_tools(provider: &Value) -> Vec<String> {
    let Some(runner) = provider.get("runner") else {
        return Vec::new();
    };
    if runner.get("kind").and_then(Value::as_str) != Some("legacy-check") {
        return Vec::new();
    }
    let Some(tool) = runner.get("tool").and_then(Value::as_str) else {
        return Vec::new();
    };
    let candidates = tool
        .split('|')
        .filter_map(|alternative| alternative.split_whitespace().next())
        .filter(|name| {
            !matches!(*name, "fs" | "grep")
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        .collect::<Vec<&str>>();
    if candidates.is_empty()
        || candidates
            .iter()
            .any(|name| super::doctor::command_path(name).is_some())
    {
        return Vec::new();
    }
    candidates.into_iter().map(str::to_owned).collect()
}

/// Which registry providers the planner would select for this repository, and
/// which of those lack a tool on PATH. Reports `computed: false` with a reason
/// instead of empty arrays when it cannot answer.
pub fn provider_selection(root: &Path, scan: &Scan) -> Value {
    let not_computed = |reason: String| -> Value {
        json!({
            "computed": false,
            "reason": reason,
            "selected": null,
            "blocked": null,
            "missingTools": null,
        })
    };
    if scan.entries_truncated {
        return not_computed(format!(
            "repository exceeds {MAX_ENTRIES} entries; provider selection skipped to keep doctor bounded"
        ));
    }
    let registry: Value = match serde_json::from_str(PROVIDER_REGISTRY) {
        Ok(registry) => registry,
        Err(error) => return not_computed(format!("embedded provider registry invalid: {error}")),
    };
    let source = match super::audit_inventory_source(root) {
        Ok(source) => source,
        Err(error) => {
            return not_computed(format!(
                "repository inventory unavailable: {}",
                error.message
            ))
        }
    };
    let inventory = match source.inventory(&root.to_string_lossy()) {
        Ok(inventory) => inventory,
        Err(error) => return not_computed(format!("repository inventory failed: {error}")),
    };
    let mut selected = Vec::new();
    let mut blocked = Vec::new();
    let mut missing = BTreeSet::new();
    let mut unevaluated = Vec::new();
    for provider in registry
        .get("providers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if provider.get("selectable").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let (Some(id), Some(selector)) = (
            provider.get("id").and_then(Value::as_str),
            provider.get("selector"),
        ) else {
            continue;
        };
        match inventory.denominator(selector) {
            Ok((count, _)) if count > 0 => {
                selected.push(id.to_owned());
                let absent = missing_tools(provider);
                if !absent.is_empty() {
                    missing.extend(absent.iter().cloned());
                    blocked.push(json!({"id": id, "reason": "missing-tool", "tools": absent}));
                }
            }
            Ok(_) => {}
            Err(_) => unevaluated.push(id.to_owned()),
        }
    }
    json!({
        "computed": true,
        "basis": "embedded provider registry selectors evaluated against the repository inventory; tool presence probed on PATH. Signing and sandbox gating are not evaluated here.",
        "selected": selected,
        "blocked": blocked,
        "missingTools": missing.into_iter().collect::<Vec<String>>(),
        "unevaluated": unevaluated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_repo(label: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("legion-coverage-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn manifests_drive_language_and_framework_detection() {
        let root = temp_repo("manifests");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"x\"\n[dependencies]\ntauri = \"2\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"react":"18"},"devDependencies":{"typescript":"5"}}"#,
        )
        .unwrap();
        std::fs::write(root.join("go.mod"), "module x\n").unwrap();
        std::fs::create_dir_all(root.join("node_modules/dep")).unwrap();
        std::fs::write(root.join("node_modules/dep/pyproject.toml"), "").unwrap();
        let scan = scan(&root);
        for id in [
            "language.rust",
            "language.javascript",
            "language.typescript",
            "language.go",
            "framework.react",
            "framework.tauri",
        ] {
            assert!(scan.found.contains_key(id), "{id} not detected");
        }
        assert!(!scan.found.contains_key("language.python"));
        assert!(!scan.found.contains_key("language.swift"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_and_fixture_trees_do_not_report_languages() {
        let root = temp_repo("fixtures");
        std::fs::write(root.join("go.mod"), "module x\n").unwrap();
        for dir in [
            "tests/app",
            "src/fixtures",
            "examples/demo",
            "engine/crates/a/tests",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join("pyproject.toml"), "").unwrap();
            std::fs::write(root.join(dir).join("Package.swift"), "").unwrap();
        }
        let scan = scan(&root);
        assert!(scan.found.contains_key("language.go"));
        assert!(!scan.found.contains_key("language.python"));
        assert!(!scan.found.contains_key("language.swift"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn empty_repository_has_no_coverage() {
        let root = temp_repo("empty");
        let scan = scan(&root);
        assert!(rows(&scan).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn registry_covers_every_family_provider() {
        let registry = registry_ids().unwrap();
        for (id, _, providers) in FAMILIES {
            for provider in *providers {
                assert!(
                    registry.contains(*provider),
                    "{id}: {provider} missing from the registry"
                );
            }
        }
    }
}
