//! Port of `src/adapters/ecosystem-manifests.mjs` (packet P5c).
//!
//! Regex/text-based dependency extraction across a dozen ecosystem manifest
//! formats. Every parser below mirrors its JS counterpart's regex and
//! control flow field for field; `enrichProjectionWithEcosystems` (the
//! projection-merging half of the JS file) is not ported here because this
//! packet does not own the `projection` shape it merges into — only
//! `read_ecosystem_manifests`, the pure parsing entry point, is in scope.
//! Flag `enrichProjectionWithEcosystems` for whichever packet owns the audit
//! projection pipeline.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use std::sync::LazyLock;

use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcosystemManifest {
    pub path: String,
    pub ecosystem: String,
    pub dependencies: Vec<String>,
    pub scripts: Vec<String>,
    pub package_manager: Option<String>,
    pub parse_error: Option<String>,
}

fn read(root: &Path, path: &str) -> String {
    fs::read_to_string(root.join(path)).unwrap_or_default()
}

fn unique(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let set: BTreeSet<String> = values
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    set.into_iter().collect()
}

fn record(path: &str, ecosystem: &str, dependencies: Vec<String>) -> EcosystemManifest {
    EcosystemManifest {
        path: path.to_string(),
        ecosystem: ecosystem.to_string(),
        dependencies: unique(dependencies),
        scripts: Vec::new(),
        package_manager: None,
        parse_error: None,
    }
}

fn python_name(value: &str) -> String {
    static SPLIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[<>=!~;\s\[]").unwrap());
    SPLIT
        .split(value)
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase()
        .replace('_', "-")
}

fn parse_json(root: &Path, path: &str, ecosystem: &str, sections: &[&str]) -> EcosystemManifest {
    let text = read(root, path);
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(parsed) => {
            let mut deps = Vec::new();
            for section in sections {
                if let Some(obj) = parsed.get(section).and_then(|v| v.as_object()) {
                    deps.extend(obj.keys().cloned());
                }
            }
            let scripts = parsed
                .get("scripts")
                .and_then(|v| v.as_object())
                .map(|obj| unique(obj.keys().cloned()))
                .unwrap_or_default();
            let package_manager = parsed
                .get("packageManager")
                .and_then(|v| v.as_str())
                .map(String::from);
            EcosystemManifest {
                scripts,
                package_manager,
                ..record(path, ecosystem, deps)
            }
        }
        Err(error) => EcosystemManifest {
            parse_error: Some(error.to_string()),
            ..record(path, ecosystem, Vec::new())
        },
    }
}

fn parse_pyproject(root: &Path, path: &str) -> EcosystemManifest {
    static DEPS_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?m)(?:^|\n)\s*dependencies\s*=\s*\[([\s\S]*?)\]").unwrap()
    });
    static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"['"]([^'"]+)['"]"#).unwrap());
    static SECTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*\[([^\]]+)\]\s*$").unwrap());
    static KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*([A-Za-z0-9_.-]+)\s*=").unwrap());

    let text = read(root, path);
    let mut dependencies = Vec::new();
    for capture in DEPS_ARRAY.captures_iter(&text) {
        let block = &capture[1];
        for quoted in QUOTED.captures_iter(block) {
            dependencies.push(python_name(&quoted[1]));
        }
    }
    let mut section = String::new();
    for line in text.split(['\n', '\r']) {
        if let Some(caps) = SECTION.captures(line) {
            section = caps[1].to_string();
        }
        if !(section == "tool.poetry.dependencies" || section == "tool.poetry.group.dev.dependencies") {
            continue;
        }
        if let Some(caps) = KEY.captures(line) {
            let key = &caps[1];
            if key.to_lowercase() != "python" {
                dependencies.push(python_name(key));
            }
        }
    }
    record(path, "python", dependencies)
}

fn parse_requirements(root: &Path, path: &str) -> EcosystemManifest {
    static COMMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+#.*$").unwrap());
    let text = read(root, path);
    let dependencies: Vec<String> = text
        .split(['\n', '\r'])
        .map(|line| COMMENT.replace(line, "").trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('-'))
        .map(|line| python_name(&line))
        .collect();
    record(path, "python", dependencies)
}

fn parse_pom(root: &Path, path: &str) -> EcosystemManifest {
    static DEP: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?s)<(?:dependency|parent)>.*?<groupId>\s*([^<]+)\s*</groupId>.*?<artifactId>\s*([^<]+)\s*</artifactId>.*?</(?:dependency|parent)>",
        )
        .unwrap()
    });
    let text = read(root, path);
    let mut dependencies = Vec::new();
    for caps in DEP.captures_iter(&text) {
        let group = caps[1].trim();
        let artifact = caps[2].trim();
        dependencies.push(format!("{group}:{artifact}"));
        dependencies.push(artifact.to_string());
    }
    record(path, "maven", dependencies)
}

fn parse_gradle(root: &Path, path: &str) -> EcosystemManifest {
    static DEP: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\s*(?:\(|\s)\s*['"]([^'"]+)['"]"#,
        )
        .unwrap()
    });
    static PLUGIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"id\s*(?:\(|\s)\s*['"]([^'"]+)['"]"#).unwrap());
    let text = read(root, path);
    let mut dependencies = Vec::new();
    for caps in DEP.captures_iter(&text) {
        let full = &caps[1];
        dependencies.push(full.to_string());
        let parts: Vec<&str> = full.split(':').collect();
        dependencies.push(parts.iter().take(2).cloned().collect::<Vec<_>>().join(":"));
        if let Some(second) = parts.get(1) {
            dependencies.push((*second).to_string());
        }
    }
    for caps in PLUGIN.captures_iter(&text) {
        dependencies.push(caps[1].to_string());
    }
    record(path, "gradle", dependencies)
}

fn parse_dotnet(root: &Path, path: &str) -> EcosystemManifest {
    static PACKAGE_REF: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"<(?:PackageReference|FrameworkReference)\s+Include=['"]([^'"]+)['"]"#).unwrap()
    });
    static SDK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"<Project\s+Sdk=['"]([^'"]+)['"]"#).unwrap());
    let text = read(root, path);
    let mut dependencies = Vec::new();
    for caps in PACKAGE_REF.captures_iter(&text) {
        dependencies.push(caps[1].to_string());
    }
    for caps in SDK.captures_iter(&text) {
        dependencies.push(caps[1].to_string());
    }
    record(path, "dotnet", dependencies)
}

fn parse_go(root: &Path, path: &str) -> EcosystemManifest {
    static REQUIRE_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^\s*require\s+([^\s(]+)\s+").unwrap());
    static REQUIRE_BLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)require\s*\(([\s\S]*?)\)").unwrap());
    static MODULE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([^\s]+)\s+v").unwrap());
    let text = read(root, path);
    let mut dependencies = Vec::new();
    for caps in REQUIRE_LINE.captures_iter(&text) {
        dependencies.push(caps[1].to_string());
    }
    if let Some(block) = REQUIRE_BLOCK.captures(&text) {
        for line in block[1].split(['\n', '\r']) {
            if let Some(caps) = MODULE.captures(line.trim()) {
                dependencies.push(caps[1].to_string());
            }
        }
    }
    record(path, "go", dependencies)
}

fn parse_keyed(root: &Path, path: &str, ecosystem: &str, pattern: &Regex) -> EcosystemManifest {
    let text = read(root, path);
    let dependencies: Vec<String> = pattern
        .captures_iter(&text)
        .map(|caps| caps[1].to_string())
        .collect();
    record(path, ecosystem, dependencies)
}

fn parse_pubspec(root: &Path, path: &str) -> EcosystemManifest {
    static TOP_LEVEL_DEPS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(dependencies|dev_dependencies):\s*$").unwrap());
    static OTHER_TOP_LEVEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_][^:]*:\s*$").unwrap());
    static NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s{2}([A-Za-z0-9_.-]+):").unwrap());
    let text = read(root, path);
    let mut dependencies = Vec::new();
    let mut active = false;
    for line in text.split(['\n', '\r']) {
        if TOP_LEVEL_DEPS.is_match(line) {
            active = true;
            continue;
        }
        if OTHER_TOP_LEVEL.is_match(line) {
            active = false;
            continue;
        }
        let name = if active {
            NAME.captures(line).map(|c| c[1].to_string())
        } else {
            None
        };
        if let Some(name) = name {
            if name != "sdk" {
                dependencies.push(name);
            }
        }
    }
    record(path, "dart", dependencies)
}

fn parse_cargo(root: &Path, path: &str) -> EcosystemManifest {
    static SECTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*\[([^\]]+)\]").unwrap());
    static NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*([A-Za-z0-9_-]+)\s*=").unwrap());
    let text = read(root, path);
    let mut dependencies = Vec::new();
    let mut section = String::new();
    for line in text.split(['\n', '\r']) {
        if let Some(caps) = SECTION.captures(line) {
            section = caps[1].to_string();
        }
        if !section.ends_with("dependencies") {
            continue;
        }
        if let Some(caps) = NAME.captures(line) {
            dependencies.push(caps[1].to_string());
        }
    }
    record(path, "cargo", dependencies)
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Port of `readEcosystemManifests(root, files)`.
pub fn read_ecosystem_manifests(root: &Path, files: &[String]) -> Vec<EcosystemManifest> {
    static REQUIREMENTS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^requirements(?:[-_.].*)?\.txt$").unwrap());
    static GRADLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^build\.gradle(?:\.kts)?$").unwrap());
    static DOTNET_PROJECT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(csproj|fsproj|vbproj)$").unwrap());
    static GEM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^\s*gem\s+['"]([^'"]+)['"]"#).unwrap());
    static MIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\s*:([A-Za-z0-9_]+)\s*,").unwrap());
    static SWIFT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\.product\s*\(\s*name:\s*['"]([^'"]+)['"]"#).unwrap());

    let mut records = Vec::new();
    for path in files {
        let base = basename(path);
        let manifest = if base == "package.json" {
            Some(parse_json(
                root,
                path,
                "node",
                &["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"],
            ))
        } else if base == "composer.json" {
            Some(parse_json(root, path, "composer", &["require", "require-dev"]))
        } else if base == "pyproject.toml" {
            Some(parse_pyproject(root, path))
        } else if REQUIREMENTS.is_match(base) {
            Some(parse_requirements(root, path))
        } else if base == "pom.xml" {
            Some(parse_pom(root, path))
        } else if GRADLE.is_match(base) {
            Some(parse_gradle(root, path))
        } else if DOTNET_PROJECT.is_match(base) {
            Some(parse_dotnet(root, path))
        } else if base == "go.mod" {
            Some(parse_go(root, path))
        } else if base == "Gemfile" {
            Some(parse_keyed(root, path, "ruby", &GEM))
        } else if base == "pubspec.yaml" {
            Some(parse_pubspec(root, path))
        } else if base == "mix.exs" {
            Some(parse_keyed(root, path, "elixir", &MIX))
        } else if base == "Cargo.toml" {
            Some(parse_cargo(root, path))
        } else if base == "Package.swift" {
            Some(parse_keyed(root, path, "swift", &SWIFT))
        } else {
            None
        };
        if let Some(manifest) = manifest {
            records.push(manifest);
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Minimal self-cleaning temp dir so this test module needs no extra
    /// crate dependency; unique per test via an in-process counter plus the
    /// process id.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "legion-p5c-ecosystem-manifests-{}-{}",
                std::process::id(),
                n
            ));
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tempfile_dir() -> TempDir {
        TempDir::new()
    }

    fn write(root: &Path, path: &str, contents: &str) {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::File::create(full).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
    }

    #[test]
    fn parses_package_json_dependency_sections() {
        let dir = tempfile_dir();
        write(
            dir.path(),
            "package.json",
            r#"{"dependencies": {"left-pad": "^1.0.0"}, "devDependencies": {"vitest": "^1.0.0"}, "scripts": {"test": "vitest"}, "packageManager": "pnpm@9.0.0"}"#,
        );
        let manifests = read_ecosystem_manifests(dir.path(), &["package.json".to_string()]);
        assert_eq!(manifests.len(), 1);
        let manifest = &manifests[0];
        assert_eq!(manifest.ecosystem, "node");
        assert_eq!(manifest.dependencies, vec!["left-pad", "vitest"]);
        assert_eq!(manifest.scripts, vec!["test"]);
        assert_eq!(manifest.package_manager.as_deref(), Some("pnpm@9.0.0"));
    }

    #[test]
    fn parses_cargo_toml_dependency_sections_only() {
        let dir = tempfile_dir();
        write(
            dir.path(),
            "Cargo.toml",
            "[package]\nname = \"x\"\n[dependencies]\nserde = \"1\"\n[dev-dependencies]\ntempfile = \"3\"\n",
        );
        let manifests = read_ecosystem_manifests(dir.path(), &["Cargo.toml".to_string()]);
        assert_eq!(manifests[0].dependencies, vec!["serde", "tempfile"]);
    }

    #[test]
    fn parses_requirements_txt_and_strips_comments() {
        let dir = tempfile_dir();
        write(dir.path(), "requirements.txt", "Flask==2.0  # web\n-e .\nrequests>=2\n");
        let manifests = read_ecosystem_manifests(dir.path(), &["requirements.txt".to_string()]);
        assert_eq!(manifests[0].dependencies, vec!["flask", "requests"]);
    }

    #[test]
    fn unrecognized_file_produces_no_record() {
        let dir = tempfile_dir();
        let manifests = read_ecosystem_manifests(dir.path(), &["README.md".to_string()]);
        assert!(manifests.is_empty());
    }
}
