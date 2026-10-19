// Port of `scripts/check-version-parity.mjs`. `release/version.json` is the
// canonical release version; every other version-bearing file must agree
// with it exactly.

use super::read_json;
use regex::Regex;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct Issue {
    path: String,
    reason: String,
}

#[derive(Serialize)]
struct Report {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    kind: &'static str,
    version: String,
    stable: bool,
    status: &'static str,
    issues: Vec<Issue>,
}

pub fn is_development_version(version: &str) -> bool {
    Regex::new(r"-dev(\.|$)").unwrap().is_match(version)
}

// Cargo membership is explicit members plus recursively referenced in-tree
// path dependencies. Independent fixture manifests are never discovered by
// directory recursion. Unsupported ownership overrides fail closed.
fn cargo_manifests(root: &Path) -> Result<Vec<PathBuf>, String> {
    fn manifest(path: &Path) -> Result<toml::Value, String> {
        let source = fs::read_to_string(path).map_err(|error| {
            format!("workspace manifest {} unreadable: {error}", path.display())
        })?;
        toml::from_str::<toml::Value>(&source)
            .map_err(|error| format!("workspace manifest {} invalid: {error}", path.display()))
    }
    fn member_path(
        engine: &Path,
        directory: &Path,
        explicit: bool,
    ) -> Result<Option<PathBuf>, String> {
        let directory = fs::canonicalize(directory).map_err(|error| {
            format!(
                "workspace dependency {} unreadable: {error}",
                directory.display()
            )
        })?;
        if !directory.starts_with(engine) {
            return if explicit {
                Err("explicit workspace member outside engine unsupported".into())
            } else {
                Ok(None)
            };
        }
        let path = directory.join("Cargo.toml");
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!("workspace manifest {} unreadable: {error}", path.display())
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("workspace member manifest is not a regular owned file".into());
        }
        Ok(Some(path))
    }
    let engine = fs::canonicalize(root.join("engine"))
        .map_err(|error| format!("workspace root unreadable: {error}"))?;
    let document = manifest(&engine.join("Cargo.toml"))?;
    let workspace = document
        .get("workspace")
        .and_then(toml::Value::as_table)
        .ok_or("workspace membership section missing")?;
    if document.get("package").is_some()
        || workspace.get("exclude").is_some()
        || document.get("patch").is_some()
        || document.get("replace").is_some()
    {
        return Err("workspace root package/exclude/patch/replace ownership unsupported".into());
    }
    let members = workspace
        .get("members")
        .and_then(toml::Value::as_array)
        .ok_or("explicit workspace members missing")?;
    let mut pending = Vec::new();
    let mut declared = std::collections::BTreeSet::new();
    for member in members {
        let member = member
            .as_str()
            .ok_or("workspace member must be a literal path")?;
        if member.is_empty()
            || member
                .chars()
                .any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}' | '\\'))
            || Path::new(member)
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(
                "unsupported/noncanonical workspace member; literal relative paths required".into(),
            );
        }
        let path = member_path(&engine, &engine.join(member), true)?.unwrap();
        if !declared.insert(path.clone()) {
            return Err("duplicate workspace member".into());
        }
        pending.push(path);
    }
    if pending.is_empty() {
        return Err("workspace member inventory is empty".into());
    }
    let mut owned = std::collections::BTreeSet::new();
    while let Some(path) = pending.pop() {
        if !owned.insert(path.clone()) {
            continue;
        }
        let member = manifest(&path)?;
        if member.get("workspace").is_some() {
            return Err(format!(
                "nested workspace ownership unsupported: {}",
                path.display()
            ));
        }
        if let Some(owner) = member
            .get("package")
            .and_then(|package| package.get("workspace"))
        {
            let owner = owner
                .as_str()
                .ok_or("package.workspace must name owning workspace")?;
            let owner = fs::canonicalize(path.parent().unwrap().join(owner))
                .map_err(|error| format!("package.workspace unreadable: {error}"))?;
            if owner != engine {
                return Err("different package.workspace ownership unsupported".into());
            }
        }
        let mut tables = vec![&member];
        if let Some(targets) = member.get("target") {
            tables.extend(
                targets
                    .as_table()
                    .ok_or("invalid target dependency table")?
                    .values(),
            );
        }
        for table in tables {
            for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
                let Some(dependencies) = table.get(kind) else {
                    continue;
                };
                for (name, dependency) in
                    dependencies.as_table().ok_or("invalid dependency table")?
                {
                    if dependency.is_str() {
                        continue;
                    }
                    let mut dependency = dependency
                        .as_table()
                        .ok_or("invalid dependency specification")?;
                    let mut base = path.parent().unwrap();
                    if let Some(inherited) = dependency.get("workspace") {
                        if inherited.as_bool() != Some(true) || dependency.contains_key("path") {
                            return Err("invalid inherited path dependency".into());
                        }
                        let inherited = workspace
                            .get("dependencies")
                            .and_then(toml::Value::as_table)
                            .and_then(|dependencies| dependencies.get(name))
                            .ok_or("inherited dependency missing")?;
                        if inherited.is_str() {
                            continue;
                        }
                        dependency = inherited.as_table().ok_or("invalid inherited dependency")?;
                        base = &engine;
                    }
                    if let Some(relative) = dependency.get("path") {
                        let relative = relative
                            .as_str()
                            .ok_or("dependency path must be a string")?;
                        if let Some(dependency) = member_path(&engine, &base.join(relative), false)?
                        {
                            pending.push(dependency);
                        }
                    }
                }
            }
        }
    }
    Ok(owned.into_iter().collect())
}

fn cargo_package_name(source: &str) -> Option<String> {
    let package_start = source.find("[package]")?;
    let remaining = &source[package_start + "[package]".len()..];
    let next_section = Regex::new(r"(?m)^\[").unwrap().find(remaining);
    let package_section = match next_section {
        Some(m) => &remaining[..m.start()],
        None => remaining,
    };
    Regex::new(r#"(?m)^name\s*=\s*"([^"]+)"$"#)
        .unwrap()
        .captures(package_section)
        .map(|c| c[1].to_string())
}

struct LockPackage {
    name: Option<String>,
    version: Option<String>,
    has_source: bool,
}

fn cargo_lock_packages(lock: &str) -> Vec<LockPackage> {
    let name_re = Regex::new(r#"(?m)^\s*name\s*=\s*"([^"]+)""#).unwrap();
    let version_re = Regex::new(r#"(?m)^\s*version\s*=\s*"([^"]+)""#).unwrap();
    let source_re = Regex::new(r"(?m)^\s*source\s*=").unwrap();
    lock.split("[[package]]")
        .skip(1)
        .map(|section| LockPackage {
            name: name_re.captures(section).map(|c| c[1].to_string()),
            version: version_re.captures(section).map(|c| c[1].to_string()),
            has_source: source_re.is_match(section),
        })
        .collect()
}

pub fn report(root: &Path, stable: bool) -> Report {
    let mut issues = Vec::new();

    let release =
        read_json(&root.join("release/version.json")).unwrap_or_else(|_| serde_json::json!({}));
    let expected = release
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let schema_version_ok = release.get("schemaVersion").and_then(|v| v.as_i64()) == Some(1);
    let kind_ok = release.get("kind").and_then(|v| v.as_str()) == Some("legion-release-version");
    let version_is_string = release
        .get("version")
        .map(|v| v.is_string())
        .unwrap_or(false);
    if !schema_version_ok || !kind_ok || !version_is_string {
        issues.push(Issue {
            path: "release/version.json".to_string(),
            reason: "invalid canonical release version record".to_string(),
        });
    }
    if stable && is_development_version(&expected) {
        issues.push(Issue {
            path: "release/version.json".to_string(),
            reason: format!("stable release cannot use development version {expected}"),
        });
    }

    for path in [
        "package.json",
        ".claude-plugin/plugin.json",
        ".codex-plugin/plugin.json",
        "engine/assets/legion-plugin/plugin.json",
        "src/registry/plugin-surface.json",
    ] {
        match read_json(&root.join(path)) {
            Ok(v) => {
                let observed = v.get("version").and_then(|v| v.as_str());
                if observed != Some(expected.as_str()) {
                    issues.push(Issue {
                        path: path.to_string(),
                        reason: format!(
                            "version {} differs from {expected}",
                            observed.unwrap_or("<missing>")
                        ),
                    });
                }
            }
            Err(e) => issues.push(Issue {
                path: path.to_string(),
                reason: format!("unreadable: {e}"),
            }),
        }
    }

    let workspace = fs::read_to_string(root.join("engine/Cargo.toml")).unwrap_or_default();
    let workspace_version = Regex::new(r#"(?m)^version\s*=\s*"([^"]+)"$"#)
        .unwrap()
        .captures(&workspace)
        .map(|c| c[1].to_string());
    if workspace_version.as_deref() != Some(expected.as_str()) {
        issues.push(Issue {
            path: "engine/Cargo.toml".to_string(),
            reason: format!(
                "workspace version {} differs from {expected}",
                workspace_version.as_deref().unwrap_or("<missing>")
            ),
        });
    }

    let manifests = cargo_manifests(root).unwrap_or_else(|reason| {
        issues.push(Issue {
            path: "engine/Cargo.toml".into(),
            reason,
        });
        Vec::new()
    });
    let mut workspace_package_names = std::collections::BTreeSet::new();
    let inherits_re = Regex::new(r"(?m)^version\.workspace\s*=\s*true$").unwrap();
    for path in manifests {
        let source = fs::read_to_string(&path).unwrap_or_default();
        match cargo_package_name(&source) {
            Some(name) if workspace_package_names.insert(name.clone()) => {}
            _ => issues.push(Issue {
                path: path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/"),
                reason: "workspace package name missing, unreadable or duplicated".into(),
            }),
        }
        if !inherits_re.is_match(&source) {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            issues.push(Issue {
                path: rel,
                reason: "crate version does not inherit workspace release version".to_string(),
            });
        }
    }

    let lock = fs::read_to_string(root.join("engine/Cargo.lock")).unwrap_or_default();
    let locked_packages = cargo_lock_packages(&lock);
    for name in workspace_package_names {
        let workspace_entries: Vec<&LockPackage> = locked_packages
            .iter()
            .filter(|e| e.name.as_deref() == Some(name.as_str()) && !e.has_source)
            .collect();
        if workspace_entries.len() != 1 {
            issues.push(Issue {
                path: "engine/Cargo.lock".to_string(),
                reason: format!(
                    "{name} workspace lock block is missing, malformed, or sourced externally"
                ),
            });
            continue;
        }
        let observed = workspace_entries[0].version.as_deref();
        if observed != Some(expected.as_str()) {
            issues.push(Issue {
                path: "engine/Cargo.lock".to_string(),
                reason: format!(
                    "{name} lock version {} differs from {expected}",
                    observed.unwrap_or("<missing>")
                ),
            });
        }
    }

    let library =
        fs::read_to_string(root.join("engine/crates/legion-runtime/src/wf_port/u03/version.rs"))
            .unwrap_or_default();
    if !library.contains("release/version.json") {
        issues.push(Issue {
            path: "engine/crates/legion-runtime/src/wf_port/u03/version.rs".to_string(),
            reason: "library version does not consume canonical release version record".to_string(),
        });
    }

    let cli = fs::read_to_string(root.join("engine/bins/legion/src/cli.rs")).unwrap_or_default();
    if !cli.contains("env!(\"CARGO_PKG_VERSION\")") {
        issues.push(Issue {
            path: "engine/bins/legion/src/cli.rs".to_string(),
            reason: "CLI version does not consume Cargo package version".to_string(),
        });
    }

    let status = if issues.is_empty() { "pass" } else { "fail" };
    Report {
        schema_version: 1,
        kind: "legion-version-parity-report",
        version: expected,
        stable,
        status,
        issues,
    }
}

pub fn run(root: &Path, json: bool, stable: bool) -> bool {
    let report = report(root, stable);
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else if report.status == "pass" {
        println!("version parity: PASS ({})", report.version);
    } else {
        for issue in &report.issues {
            eprintln!("{}: {}", issue.path, issue.reason);
        }
    }
    report.status == "pass"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "legion-version-parity-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let fixture = Self(root);
            fixture.write(
                "release/version.json",
                r#"{"schemaVersion":1,"kind":"legion-release-version","version":"1.2.3"}"#,
            );
            for path in [
                "package.json",
                ".claude-plugin/plugin.json",
                ".codex-plugin/plugin.json",
                "engine/assets/legion-plugin/plugin.json",
                "src/registry/plugin-surface.json",
            ] {
                fixture.write(path, r#"{"version":"1.2.3"}"#);
            }
            fixture.workspace(r#""crates/owned""#);
            fixture.write(
                "engine/crates/owned/Cargo.toml",
                "[package]\nname = \"owned\"\nversion.workspace = true\n",
            );
            fixture.write(
                "engine/Cargo.lock",
                "[[package]]\nname = \"owned\"\nversion = \"1.2.3\"\n",
            );
            fixture.write(
                "engine/crates/legion-runtime/src/wf_port/u03/version.rs",
                "release/version.json",
            );
            fixture.write(
                "engine/bins/legion/src/cli.rs",
                "env!(\"CARGO_PKG_VERSION\")",
            );
            fixture
        }
        fn write(&self, path: &str, source: &str) {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
        fn workspace(&self, members: &str) {
            self.write("engine/Cargo.toml", &format!("[workspace]\nresolver = \"2\"\nmembers = [{members}]\n[workspace.package]\nversion = \"1.2.3\"\n"));
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn independent_nested_fixture_is_outside_workspace_release_parity() {
        let f = Fixture::new();
        f.write(
            "engine/crates/owned/tests/fixtures/upstream/Cargo.toml",
            "[package]\nname = \"official-upstream\"\nversion = \"0.1.0\"\n",
        );
        assert_eq!(report(&f.0, false).status, "pass");
        // A fixture-like name never hides an explicitly declared real member.
        f.workspace(r#""crates/owned", "crates/owned/tests/fixtures/upstream""#);
        let result = report(&f.0, false);
        assert!(result
            .issues
            .iter()
            .any(|issue| issue.path.ends_with("fixtures/upstream/Cargo.toml")
                && issue.reason.contains("inherit")));
        assert!(result.issues.iter().any(|issue| issue
            .reason
            .contains("official-upstream workspace lock block")));
    }

    #[test]
    fn owned_member_inheritance_and_lock_parity_still_fail_closed() {
        let f = Fixture::new();
        f.write(
            "engine/crates/owned/Cargo.toml",
            "[package]\nname = \"owned\"\nversion = \"1.2.3\"\n",
        );
        assert!(report(&f.0, false)
            .issues
            .iter()
            .any(|issue| issue.reason.contains("inherit")));
        f.write(
            "engine/crates/owned/Cargo.toml",
            "[package]\nname = \"owned\"\nversion.workspace = true\n",
        );
        f.write(
            "engine/Cargo.lock",
            "[[package]]\nname = \"owned\"\nversion = \"9.9.9\"\n",
        );
        assert!(report(&f.0, false)
            .issues
            .iter()
            .any(|issue| issue.reason.contains("owned lock version 9.9.9 differs")));
        f.write("engine/Cargo.lock", "");
        assert!(report(&f.0, false)
            .issues
            .iter()
            .any(|issue| issue.reason.contains("owned workspace lock block")));
    }

    #[test]
    fn implicit_in_tree_dependencies_are_owned_on_every_dependency_surface() {
        let f = Fixture::new();
        f.write(
            "engine/crates/implicit/Cargo.toml",
            "[package]\nname = \"implicit\"\nversion = \"0.1.0\"\n",
        );
        for table in [
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
            "target.'cfg(windows)'.dependencies",
        ] {
            f.write("engine/crates/owned/Cargo.toml", &format!("[package]\nname = \"owned\"\nversion.workspace = true\n[{table}]\nimplicit = {{ path = \"../implicit\" }}\n"));
            let result = report(&f.0, false);
            assert!(
                result
                    .issues
                    .iter()
                    .any(|issue| issue.path.ends_with("implicit/Cargo.toml")
                        && issue.reason.contains("inherit")),
                "{table}"
            );
            assert!(
                result
                    .issues
                    .iter()
                    .any(|issue| issue.reason.contains("implicit workspace lock block")),
                "{table}"
            );
        }
        // Inherited paths are relative to workspace root, not member directory.
        let mut workspace = fs::read_to_string(f.0.join("engine/Cargo.toml")).unwrap();
        workspace.push_str("[workspace.dependencies]\nimplicit = { path = \"crates/implicit\" }\nregistry = \"1\"\n");
        f.write("engine/Cargo.toml", &workspace);
        f.write("engine/crates/owned/Cargo.toml", "[package]\nname = \"owned\"\nversion.workspace = true\n[dependencies]\nimplicit.workspace = true\nregistry.workspace = true\n");
        assert!(report(&f.0, false)
            .issues
            .iter()
            .any(|issue| issue.reason.contains("implicit workspace lock block")));
        // Recursion discovers another implicit member via the first dependency.
        f.write("engine/crates/implicit/Cargo.toml", "[package]\nname = \"implicit\"\nversion.workspace = true\n[dependencies]\nleaf = { path = \"../leaf\" }\n");
        f.write(
            "engine/crates/leaf/Cargo.toml",
            "[package]\nname = \"leaf\"\nversion = \"0.1.0\"\n",
        );
        assert!(report(&f.0, false)
            .issues
            .iter()
            .any(|issue| issue.reason.contains("leaf workspace lock block")));
    }

    #[test]
    fn external_path_dependencies_are_not_workspace_release_members() {
        let f = Fixture::new();
        f.write(
            "outside/Cargo.toml",
            "[package]\nname = \"external\"\nversion = \"9.9.9\"\n[workspace]\n",
        );
        f.write("engine/crates/owned/Cargo.toml", "[package]\nname = \"owned\"\nversion.workspace = true\n[dependencies]\nexternal = { path = \"../../../outside\" }\n");
        assert_eq!(report(&f.0, false).status, "pass");
        f.write("engine/crates/owned/Cargo.toml", "[package]\nname = \"owned\"\nversion.workspace = true\nworkspace = \"../../../outside\"\n");
        assert!(cargo_manifests(&f.0).is_err());
        f.write(
            "engine/crates/owned/Cargo.toml",
            "[package]\nname = \"owned\"\nversion.workspace = true\n[workspace]\n",
        );
        assert!(cargo_manifests(&f.0).is_err());
    }

    #[test]
    fn missing_unsafe_duplicate_or_unsupported_membership_cannot_pass() {
        let f = Fixture::new();
        for members in [
            "",
            r#""crates/*""#,
            r#""../outside""#,
            r#""crates/missing""#,
            r#""crates/owned", "crates/owned""#,
        ] {
            f.workspace(members);
            assert!(cargo_manifests(&f.0).is_err(), "{members}");
            assert_eq!(report(&f.0, false).status, "fail");
        }
        f.write("engine/Cargo.toml", "[workspace]\nresolver = \"2\"\n");
        assert!(cargo_manifests(&f.0).is_err());
    }
}
