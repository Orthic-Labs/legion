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
    Regex::new(r"-dev\.").unwrap().is_match(version)
}

fn cargo_manifests(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(&root.join("engine"), &mut out);
    out
}

fn walk(cursor: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(cursor) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name == "target" {
            continue;
        }
        let path = entry.path();
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            walk(&path, out);
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
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

fn cargo_workspace_package_names(root: &Path) -> Vec<String> {
    let engine_toml = root.join("engine").join("Cargo.toml");
    cargo_manifests(root)
        .into_iter()
        .filter(|p| p != &engine_toml)
        .filter_map(|p| fs::read_to_string(&p).ok())
        .filter_map(|s| cargo_package_name(&s))
        .collect()
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

    let release = read_json(&root.join("release/version.json"))
        .unwrap_or_else(|_| serde_json::json!({}));
    let expected = release
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let schema_version_ok = release.get("schemaVersion").and_then(|v| v.as_i64()) == Some(1);
    let kind_ok =
        release.get("kind").and_then(|v| v.as_str()) == Some("legion-release-version");
    let version_is_string = release.get("version").map(|v| v.is_string()).unwrap_or(false);
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

    let engine_toml = root.join("engine").join("Cargo.toml");
    let inherits_re = Regex::new(r"(?m)^version\.workspace\s*=\s*true$").unwrap();
    for path in cargo_manifests(root) {
        if path == engine_toml {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap_or_default();
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
    for name in cargo_workspace_package_names(root) {
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
            reason: "library version does not consume canonical release version record"
                .to_string(),
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
