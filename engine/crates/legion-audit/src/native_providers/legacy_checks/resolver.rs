//! Resolution of frozen legacy-check commands to sealed, argv-only launches.
//!
//! Registry entries intentionally contain stable tool names rather than host
//! paths.  This module is the small host-side bridge: it consults repository
//! package metadata, then bounded local-bin/PATH lookup, and seals the bytes
//! of the selected executable before it reaches `legion-effects`.

use super::attested_runs::AttestedRunsEnrollment;
use super::contracts::CommandShape;
use crate::inventory::InventoryEnvelope;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedCommand {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub digest: String,
    pub cwd: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveError {
    MissingExecutable(String),
    /// The project declares nothing to run (no build script, linter, type
    /// checker or package manager). Nothing is broken; the check has no input.
    NotConfigured(String),
    Unavailable(String),
}

impl ResolveError {
    pub fn message(&self) -> String {
        match self {
            Self::MissingExecutable(value) => format!("missing executable: {value}"),
            Self::NotConfigured(value) | Self::Unavailable(value) => value.clone(),
        }
    }
}

/// Resolve every non-native command in the frozen legacy registry.
pub fn resolve_command(
    root: &Path,
    command: CommandShape,
) -> Result<ResolvedCommand, ResolveError> {
    let (executable, args) = match command {
        CommandShape::Native { .. } => {
            return Err(ResolveError::Unavailable(
                "native command has no external executable".into(),
            ));
        }
        CommandShape::Fixed { executable, args } => (
            resolve_named_path(root, executable)?,
            args.iter().map(|item| (*item).to_owned()).collect(),
        ),
        CommandShape::Named { tool, args } => resolve_named_command(root, tool, args)?,
    };
    seal(root, executable, args)
}

/// Resolve a host request whose command name and argv came from a legacy
/// registry request. This is used by the production effect adapter after the
/// injected provider seam has been constructed.
pub fn resolve_request(
    root: &Path,
    executable: &str,
    args: &[String],
) -> Result<ResolvedCommand, ResolveError> {
    let (path, resolved_args) = match executable {
        "project-build" => project_script_dynamic(root, "build", args, true)?,
        // `project-test` is resolved only through `resolve_test_command`, which
        // first validates runner metadata against the frozen inventory.
        "project-test" => {
            return Err(ResolveError::Unavailable(
                "project-test requires frozen inventory metadata".into(),
            ));
        }
        "project-lint" => project_lint_dynamic(root, args)?,
        "project-types" => project_types_dynamic(root, args)?,
        "package-audit" => package_manager_operation_dynamic(root, "audit", args)?,
        "package-outdated" => package_manager_operation_dynamic(root, "outdated", args)?,
        RUNTIME_CAPTURE_TOOL => (current_legion_executable()?, args.to_vec()),
        // A cargo subcommand binary run directly (not through `cargo`) takes
        // its own name as the first argument.
        "cargo-outdated" => (resolve_named_path(root, executable)?, {
            let mut values = vec!["outdated".to_owned()];
            values.extend(args.iter().cloned());
            values
        }),
        _ => (resolve_named_path(root, executable)?, args.to_vec()),
    };
    let cwd = if uses_cargo_working_directory(executable) && !root.join("Cargo.toml").is_file() {
        if root.join("src-tauri/Cargo.toml").is_file() {
            root.join("src-tauri")
        } else if is_cargo_analysis_tool(executable) {
            // Analysis tools only read manifests and lockfiles, so a repository
            // whose single Cargo workspace lives in a subdirectory (for
            // example `engine/`) is analyzed there. Build and lint never
            // discover a nested workspace: that would start a full compile.
            nested_cargo_dir(root).unwrap_or_else(|| root.to_path_buf())
        } else {
            root.to_path_buf()
        }
    } else {
        root.to_path_buf()
    };
    seal(&cwd, path, resolved_args)
}

/// Resolve only explicitly declared test runners whose input metadata still
/// matches the frozen Audit inventory. This prevents a changed package script
/// from silently falling back to a different family after plan compilation.
pub fn resolve_test_command(
    root: &Path,
    inventory: &InventoryEnvelope,
) -> Result<(ResolvedCommand, Value), ResolveError> {
    resolve_test_command_with_enrollment(root, inventory, None)
}

pub fn resolve_test_command_with_enrollment(
    root: &Path,
    inventory: &InventoryEnvelope,
    enrollment: Option<&AttestedRunsEnrollment>,
) -> Result<(ResolvedCommand, Value), ResolveError> {
    if let Some(enrollment) = enrollment {
        enrollment.validate().map_err(|error| {
            ResolveError::Unavailable(format!("test-enrollment-invalid:{error}"))
        })?;
    }
    let root = fs::canonicalize(root).map_err(|error| {
        ResolveError::Unavailable(format!("test-source-root-unavailable: {error}"))
    })?;
    let mut sources = Vec::new();
    let package = frozen_source_file(&root, inventory, "package.json")?;
    if let Some((bytes, digest)) = package {
        let package_json: Value = serde_json::from_slice(&bytes).map_err(|error| {
            ResolveError::Unavailable(format!("test-source-package-invalid: {error}"))
        })?;
        sources.push(json!({"path":"package.json","digest":digest}));
        let has_test = package_json
            .get("scripts")
            .and_then(Value::as_object)
            .is_some_and(|scripts| scripts.contains_key("test"));
        if has_test {
            let (manager, required_version) =
                if let Some(value) = package_json.get("packageManager").and_then(Value::as_str) {
                    let (manager, version) = value.split_once('@').ok_or_else(|| {
                        ResolveError::Unavailable("test-package-manager-pin-invalid".into())
                    })?;
                    if version.is_empty() {
                        return Err(ResolveError::Unavailable(
                            "test-package-manager-pin-invalid".into(),
                        ));
                    }
                    if !is_exact_semver_pin(version) {
                        return Err(ResolveError::Unavailable(
                            "test-package-manager-pin-invalid".into(),
                        ));
                    }
                    (manager.to_ascii_lowercase(), Some(version.to_owned()))
                } else {
                    let mut selected = None;
                    for (path, manager) in [
                        ("pnpm-lock.yaml", "pnpm"),
                        ("yarn.lock", "yarn"),
                        ("package-lock.json", "npm"),
                        ("bun.lockb", "bun"),
                    ] {
                        if let Some((_, digest)) = frozen_source_file(&root, inventory, path)? {
                            sources.push(json!({"path":path,"digest":digest}));
                            if selected.is_none() {
                                selected = Some(manager);
                            }
                        }
                    }
                    (
                        selected
                            .ok_or_else(|| {
                                ResolveError::NotConfigured(
                                    "test package script has no pinned package manager or lockfile"
                                        .into(),
                                )
                            })?
                            .to_owned(),
                        None,
                    )
                };
            if !matches!(manager.as_str(), "npm" | "pnpm" | "yarn" | "bun") {
                return Err(ResolveError::NotConfigured(managed_runner_gap(&manager)));
            }
            let (resolved, runner_source) = resolve_frozen_test_runner(
                &root,
                inventory,
                &manager,
                frozen_package_test_argv(&manager),
                "package.json",
                &[],
                enrollment,
                required_version.as_deref(),
            )?;
            sources.extend(
                runner_source["sources"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
            );
            let mut source = runner_source;
            source["inventoryDigest"] = json!(inventory.digest);
            source["packageMetadata"] = json!(sources);
            return Ok((resolved, source));
        }
    }

    let cargo_manifest = ["Cargo.toml", "src-tauri/Cargo.toml"]
        .into_iter()
        .find_map(|path| match frozen_source_file(&root, inventory, path) {
            Ok(Some(_)) => Some(Ok(path)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .transpose()?;
    if let Some(cargo_manifest) = cargo_manifest {
        let (_, manifest_digest) = frozen_source_file(&root, inventory, cargo_manifest)?
            .ok_or_else(|| ResolveError::Unavailable("frozen Cargo manifest disappeared".into()))?;
        sources.push(json!({"path":cargo_manifest,"digest":manifest_digest}));
        let cargo_lock = cargo_manifest
            .strip_suffix("Cargo.toml")
            .unwrap_or_default()
            .to_owned()
            + "Cargo.lock";
        if let Some((_, digest)) = frozen_source_file(&root, inventory, &cargo_lock)? {
            sources.push(json!({"path":cargo_lock,"digest":digest}));
        }
        let cwd = if cargo_manifest == "src-tauri/Cargo.toml" {
            root.join("src-tauri")
        } else {
            root.clone()
        };
        let executable = resolve_attestation_cli(&root, enrollment)?;
        let client_digest = enrollment
            .map(|enrollment| enrollment.client_digest.as_str())
            .ok_or_else(|| {
                ResolveError::NotConfigured("managed-test-trust-not-configured".into())
            })?;
        let args = vec!["cargo".into(), "test".into()];
        let resolved = ResolvedCommand {
            executable,
            args,
            digest: format!("sha256:{client_digest}"),
            cwd: cwd.clone(),
        };
        let source = json!({
            "family":"rust-rightkit",
            "inventoryDigest":inventory.digest,
            "sources":sources,
            "executable":resolved.executable.to_string_lossy(),
            "executableDigest":resolved.digest,
            "argv":resolved.args,
            "cwd":resolved.cwd.to_string_lossy(),
            "workspaceRoot":cwd.to_string_lossy(),
        });
        return Ok((resolved, source));
    }

    if let Some((runner, args, manifest, companion_paths)) = native_test_spec(&root, inventory)? {
        return resolve_frozen_test_runner(
            &root,
            inventory,
            &runner,
            args,
            &manifest,
            &companion_paths,
            enrollment,
            None,
        );
    }
    Err(ResolveError::NotConfigured(
        "test runner is not configured".into(),
    ))
}

type NativeTestSpec = (String, Vec<String>, String, Vec<String>);

fn native_test_spec(
    root: &Path,
    inventory: &InventoryEnvelope,
) -> Result<Option<NativeTestSpec>, ResolveError> {
    let has = |path: &str| -> Result<bool, ResolveError> {
        frozen_source_file(root, inventory, path).map(|value| value.is_some())
    };
    let python_declaration = ["pyproject.toml", "pytest.ini", "tox.ini", "setup.cfg"]
        .into_iter()
        .find_map(|path| match frozen_source_file(root, inventory, path) {
            Ok(Some((bytes, _))) => Some(Ok((path, bytes))),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .transpose()?;
    let has_python_tests = inventory.entries.iter().any(|entry| {
        let path = entry.path.as_str();
        (path.starts_with("tests/") || path.starts_with("test/"))
            && (path.ends_with(".py") || path.ends_with(".pyi"))
            || (path.starts_with("test_") && path.ends_with(".py"))
    });
    let python_declaration = python_declaration.or_else(|| {
        inventory
            .entries
            .iter()
            .find(|entry| {
                ((entry.path.starts_with("tests/") || entry.path.starts_with("test/"))
                    && (entry.path.ends_with(".py") || entry.path.ends_with(".pyi")))
                    || (entry.path.starts_with("test_") && entry.path.ends_with(".py"))
            })
            .map(|entry| (entry.path.as_str(), Vec::new()))
    });
    if let Some((declaration, bytes)) = python_declaration {
        let text = String::from_utf8_lossy(&bytes);
        if has_python_tests || text.contains("pytest") {
            return Ok(Some((
                "pytest".into(),
                Vec::new(),
                declaration.into(),
                Vec::new(),
            )));
        }
    }
    let dotnet_solutions = inventory
        .entries
        .iter()
        .filter(|entry| entry.path.ends_with(".sln"))
        .map(|entry| entry.path.as_str())
        .collect::<Vec<_>>();
    let dotnet_projects = inventory
        .entries
        .iter()
        .filter(|entry| {
            [".csproj", ".fsproj", ".vbproj"]
                .iter()
                .any(|suffix| entry.path.ends_with(suffix))
        })
        .map(|entry| entry.path.as_str())
        .collect::<Vec<_>>();
    let dotnet_declaration = if dotnet_solutions.len() == 1 {
        Some(dotnet_solutions[0])
    } else if dotnet_solutions.len() > 1 {
        return Err(ResolveError::NotConfigured(
            "dotnet-test-solution-scope-ambiguous".into(),
        ));
    } else if dotnet_projects.len() == 1 {
        Some(dotnet_projects[0])
    } else if dotnet_projects.len() > 1 {
        return Err(ResolveError::NotConfigured(
            "dotnet-test-solution-required-for-multiple-projects".into(),
        ));
    } else {
        None
    };
    let selected = if has("Package.swift")? {
        Some(("swift", vec!["test".into()], "Package.swift", vec![]))
    } else if has("pom.xml")? {
        Some(("mvn", vec!["test".into()], "pom.xml", vec![]))
    } else if has("build.gradle")? || has("build.gradle.kts")? {
        let manifest = if has("build.gradle")? {
            "build.gradle"
        } else {
            "build.gradle.kts"
        };
        Some((
            "gradle",
            vec!["test".into()],
            manifest,
            vec!["gradle.lockfile"],
        ))
    } else if let Some(path) = dotnet_declaration {
        Some(("dotnet", vec!["test".into(), path.into()], path, vec![]))
    } else if has("go.mod")? {
        Some((
            "go",
            vec!["test".into(), "./...".into()],
            "go.mod",
            vec!["go.sum"],
        ))
    } else if has("Gemfile")? {
        let has_rspec_tests = inventory
            .entries
            .iter()
            .any(|entry| entry.path.starts_with("spec/") && entry.path.ends_with("_spec.rb"));
        let has_ruby_unit_tests = inventory.entries.iter().any(|entry| {
            entry.path.starts_with("test/")
                && (entry.path.ends_with("_test.rb") || entry.path.ends_with("_tests.rb"))
        });
        if has_rspec_tests {
            Some((
                "bundle",
                vec!["exec".into(), "rspec".into()],
                "Gemfile",
                vec!["Gemfile.lock"],
            ))
        } else if has_ruby_unit_tests && has("Rakefile")? {
            Some((
                "bundle",
                vec!["exec".into(), "rake".into(), "test".into()],
                "Gemfile",
                vec!["Gemfile.lock", "Rakefile"],
            ))
        } else {
            None
        }
    } else if has("pubspec.yaml")? {
        let pubspec =
            frozen_source_file(root, inventory, "pubspec.yaml")?.expect("checked frozen pubspec");
        let text = String::from_utf8_lossy(&pubspec.0);
        let (runner, args) = if text.lines().any(|line| line.trim() == "flutter:") {
            ("flutter", vec!["test".into()])
        } else {
            ("dart", vec!["test".into()])
        };
        Some((runner, args, "pubspec.yaml", vec!["pubspec.lock"]))
    } else if has("mix.exs")? {
        Some(("mix", vec!["test".into()], "mix.exs", vec!["mix.lock"]))
    } else {
        None
    };
    Ok(selected.map(|(runner, args, manifest, companions)| {
        (
            runner.to_owned(),
            args,
            manifest.to_owned(),
            companions.into_iter().map(str::to_owned).collect(),
        )
    }))
}

fn is_exact_semver_pin(value: &str) -> bool {
    let (version, build) = match value.split_once('+') {
        Some((version, build)) if !build.is_empty() && !build.contains('+') => {
            (version, Some(build))
        }
        Some(_) => return false,
        None => (value, None),
    };
    let (core, prerelease) = version
        .split_once('-')
        .map_or((version, None), |(core, prerelease)| {
            (core, Some(prerelease))
        });
    let parts = core.split('.').collect::<Vec<_>>();
    let numeric = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'))
    };
    if parts.len() != 3 || !parts.iter().all(|part| numeric(part)) {
        return false;
    }
    let valid_identifiers = |value: &str, leading_zero_rule: bool| {
        !value.is_empty()
            && value.split('.').all(|identifier| {
                !identifier.is_empty()
                    && identifier
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    && (!leading_zero_rule
                        || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                        || identifier == "0"
                        || !identifier.starts_with('0'))
            })
    };
    prerelease.map_or(true, |value| valid_identifiers(value, true))
        && build.map_or(true, |value| valid_identifiers(value, false))
}

fn resolve_frozen_test_runner(
    root: &Path,
    inventory: &InventoryEnvelope,
    runner: &str,
    args: Vec<String>,
    declaration: &str,
    companions: &[String],
    enrollment: Option<&AttestedRunsEnrollment>,
    required_version: Option<&str>,
) -> Result<(ResolvedCommand, Value), ResolveError> {
    let executable = resolve_attestation_cli(root, enrollment)?;
    let client_digest = enrollment
        .map(|enrollment| enrollment.client_digest.as_str())
        .ok_or_else(|| ResolveError::NotConfigured("managed-test-trust-not-configured".into()))?;
    let mut invocation = vec![runner.to_owned()];
    invocation.extend(args);
    let resolved = ResolvedCommand {
        executable,
        args: invocation.clone(),
        digest: format!("sha256:{client_digest}"),
        cwd: root.to_path_buf(),
    };
    let mut sources = vec![
        json!({"path":declaration,"digest":frozen_source_file(root, inventory, declaration)?.map(|(_,digest)|digest)}),
    ];
    for path in companions {
        if let Some((_, digest)) = frozen_source_file(root, inventory, path)? {
            sources.push(json!({"path":path,"digest":digest}));
        }
    }
    let source = json!({
        "family":"registered-adapter",
        "runner":runner,
        "inventoryDigest":inventory.digest,
        "sources":sources,
        "argv":invocation,
        "executable":resolved.executable.to_string_lossy(),
        "executableDigest":resolved.digest,
        "cwd":resolved.cwd.to_string_lossy(),
        "testDeclarationPath":declaration,
        "requiredRunnerVersion":required_version,
        "workspaceRoot":root.to_string_lossy(),
    });
    Ok((resolved, source))
}

fn resolve_attestation_cli(
    _root: &Path,
    enrollment: Option<&AttestedRunsEnrollment>,
) -> Result<PathBuf, ResolveError> {
    let Some(enrollment) = enrollment else {
        return Err(ResolveError::NotConfigured(
            "managed-test-trust-not-configured".into(),
        ));
    };
    let path = &enrollment.client_executable;
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ResolveError::NotConfigured("managed-test-attestation-cli-unavailable".into())
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ResolveError::NotConfigured(
            "managed-test-attestation-cli-unavailable".into(),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|_| {
        ResolveError::NotConfigured("managed-test-attestation-cli-unavailable".into())
    })?;
    let digest = digest_file(&canonical)?;
    if digest != format!("sha256:{}", enrollment.client_digest) {
        return Err(ResolveError::NotConfigured(
            "managed-test-attestation-cli-unavailable".into(),
        ));
    }
    Ok(canonical)
}

fn managed_runner_gap(runner: &str) -> String {
    format!("managed-test-runner-not-registered:{runner}")
}

fn frozen_package_test_argv(manager: &str) -> Vec<String> {
    if manager == "npm" {
        vec!["run".into(), "test".into()]
    } else {
        vec!["test".into()]
    }
}

fn frozen_source_file(
    root: &Path,
    inventory: &InventoryEnvelope,
    relative: &str,
) -> Result<Option<(Vec<u8>, String)>, ResolveError> {
    let entry = inventory
        .entries
        .iter()
        .find(|entry| entry.path == relative);
    let path = root.join(relative);
    let exists = path.exists();
    let Some(entry) = entry else {
        return if exists {
            Err(ResolveError::Unavailable(format!(
                "test-source-input-not-in-inventory:{relative}"
            )))
        } else {
            Ok(None)
        };
    };
    if !exists {
        return Err(ResolveError::Unavailable(format!(
            "test-source-input-missing:{relative}"
        )));
    }
    let expected = entry.digest.as_deref().ok_or_else(|| {
        ResolveError::Unavailable(format!("test-source-input-digest-missing:{relative}"))
    })?;
    let mut current = root.to_path_buf();
    for part in Path::new(relative).components() {
        current.push(part);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            ResolveError::Unavailable(format!("test-source-input-unreadable:{relative}:{error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() && current == path {
            return Err(ResolveError::Unavailable(format!(
                "test-source-input-not-regular:{relative}"
            )));
        }
    }
    let metadata = fs::metadata(&path).map_err(|error| {
        ResolveError::Unavailable(format!("test-source-input-unreadable:{relative}:{error}"))
    })?;
    const MAX_TEST_METADATA_BYTES: u64 = 1_048_576;
    if metadata.len() > MAX_TEST_METADATA_BYTES {
        return Err(ResolveError::Unavailable(format!(
            "test-source-input-too-large:{relative}"
        )));
    }
    let bytes = fs::read(&path).map_err(|error| {
        ResolveError::Unavailable(format!("test-source-input-unreadable:{relative}:{error}"))
    })?;
    let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    if actual != expected {
        return Err(ResolveError::Unavailable(format!(
            "test-source-input-drift:{relative}"
        )));
    }
    Ok(Some((bytes, actual)))
}

fn resolve_named_command(
    root: &Path,
    tool: &str,
    args: &[&str],
) -> Result<(PathBuf, Vec<String>), ResolveError> {
    match tool {
        "project-build" => project_script(root, "build", args, true),
        "project-lint" => project_lint(root, args),
        "project-types" => project_types(root, args),
        "package-audit" => package_manager_operation(root, "audit", args),
        "package-outdated" => package_manager_operation(root, "outdated", args),
        RUNTIME_CAPTURE_TOOL => Ok((
            current_legion_executable()?,
            args.iter().map(|item| (*item).to_owned()).collect(),
        )),
        _ => Ok((
            resolve_named_path(root, tool)?,
            args.iter().map(|item| (*item).to_owned()).collect(),
        )),
    }
}

fn project_script(
    root: &Path,
    script: &str,
    extra: &[&str],
    allow_cargo: bool,
) -> Result<(PathBuf, Vec<String>), ResolveError> {
    let package = package_json(root);
    if package
        .as_ref()
        .and_then(|value| value.get("scripts"))
        .and_then(Value::as_object)
        .is_some_and(|scripts| scripts.contains_key(script))
    {
        return package_manager_script(root, script, extra);
    }
    if allow_cargo
        && (root.join("Cargo.toml").is_file() || root.join("src-tauri/Cargo.toml").is_file())
    {
        return Ok((resolve_named_path(root, "cargo")?, {
            let mut values = vec!["build".to_owned()];
            values.extend(extra.iter().map(|item| (*item).to_owned()));
            values
        }));
    }
    Err(ResolveError::NotConfigured(format!(
        "project script `{script}` is not configured"
    )))
}

fn project_script_dynamic(
    root: &Path,
    script: &str,
    extra: &[String],
    allow_cargo: bool,
) -> Result<(PathBuf, Vec<String>), ResolveError> {
    let package = package_json(root);
    if package
        .as_ref()
        .and_then(|value| value.get("scripts"))
        .and_then(Value::as_object)
        .is_some_and(|scripts| scripts.contains_key(script))
    {
        return package_manager_script_dynamic(root, script, extra);
    }
    if allow_cargo
        && (root.join("Cargo.toml").is_file() || root.join("src-tauri/Cargo.toml").is_file())
    {
        let mut values = vec!["build".to_owned()];
        values.extend(extra.iter().cloned());
        return Ok((resolve_named_path(root, "cargo")?, values));
    }
    Err(ResolveError::NotConfigured(format!(
        "project script `{script}` is not configured"
    )))
}

fn project_lint_dynamic(
    root: &Path,
    _extra: &[String],
) -> Result<(PathBuf, Vec<String>), ResolveError> {
    for candidate in lint_candidates(root) {
        if let Ok(path) = resolve_named_path(root, candidate) {
            let values = match candidate {
                "biome" => vec![
                    "lint".into(),
                    ".".into(),
                    "--reporter=json".into(),
                    "--max-diagnostics=1000".into(),
                ],
                "eslint" => vec![".".into(), "-f".into(), "json".into()],
                "ruff" => vec!["check".into(), "--output-format".into(), "json".into()],
                _ => vec![
                    "clippy".into(),
                    "--all-targets".into(),
                    "--message-format=json".into(),
                    "--".into(),
                    "-D".into(),
                    "warnings".into(),
                ],
            };
            return Ok((path, values));
        }
    }
    Err(ResolveError::NotConfigured(
        "no configured project linter was found".into(),
    ))
}

fn project_types_dynamic(
    root: &Path,
    _extra: &[String],
) -> Result<(PathBuf, Vec<String>), ResolveError> {
    for candidate in type_candidates(root) {
        if let Ok(path) = resolve_named_path(root, candidate) {
            let values = match candidate {
                "tsc" => vec!["--noEmit".into()],
                "basedpyright" => vec!["--outputjson".into()],
                _ => vec![".".into()],
            };
            return Ok((path, values));
        }
    }
    Err(ResolveError::NotConfigured(
        "no configured project type checker was found".into(),
    ))
}

fn project_lint(root: &Path, _extra: &[&str]) -> Result<(PathBuf, Vec<String>), ResolveError> {
    for candidate in lint_candidates(root) {
        if let Ok(path) = resolve_named_path(root, candidate) {
            let values = match candidate {
                "biome" => vec![
                    "lint".into(),
                    ".".into(),
                    "--reporter=json".into(),
                    "--max-diagnostics=1000".into(),
                ],
                "eslint" => vec![".".into(), "-f".into(), "json".into()],
                "ruff" => vec!["check".into(), "--output-format".into(), "json".into()],
                _ => vec![
                    "clippy".into(),
                    "--all-targets".into(),
                    "--message-format=json".into(),
                    "--".into(),
                    "-D".into(),
                    "warnings".into(),
                ],
            };
            return Ok((path, values));
        }
    }
    Err(ResolveError::NotConfigured(
        "no configured project linter was found".into(),
    ))
}

fn project_types(root: &Path, _extra: &[&str]) -> Result<(PathBuf, Vec<String>), ResolveError> {
    for candidate in type_candidates(root) {
        if let Ok(path) = resolve_named_path(root, candidate) {
            let values = match candidate {
                "tsc" => vec!["--noEmit".into()],
                "basedpyright" => vec!["--outputjson".into()],
                _ => vec![".".into()],
            };
            return Ok((path, values));
        }
    }
    Err(ResolveError::NotConfigured(
        "no configured project type checker was found".into(),
    ))
}

fn package_manager_operation(
    root: &Path,
    operation: &str,
    extra: &[&str],
) -> Result<(PathBuf, Vec<String>), ResolveError> {
    let manager = package_manager(root).ok_or_else(|| {
        ResolveError::NotConfigured("package manager metadata is unavailable".into())
    })?;
    let path = resolve_named_path(root, &manager)?;
    let mut values = vec![operation.to_owned()];
    values.extend(extra.iter().map(|item| (*item).to_owned()));
    Ok((path, values))
}

fn package_manager_operation_dynamic(
    root: &Path,
    operation: &str,
    extra: &[String],
) -> Result<(PathBuf, Vec<String>), ResolveError> {
    let manager = package_manager(root).ok_or_else(|| {
        ResolveError::NotConfigured("package manager metadata is unavailable".into())
    })?;
    let path = resolve_named_path(root, &manager)?;
    let mut values = vec![operation.to_owned()];
    values.extend(extra.iter().cloned());
    Ok((path, values))
}

fn package_manager_script(
    root: &Path,
    script: &str,
    extra: &[&str],
) -> Result<(PathBuf, Vec<String>), ResolveError> {
    let manager = package_manager(root).ok_or_else(|| {
        ResolveError::NotConfigured("package manager metadata is unavailable".into())
    })?;
    let path = resolve_named_path(root, &manager)?;
    Ok((
        path,
        package_script_argv(
            &manager,
            script,
            extra.iter().map(|item| (*item).to_owned()),
        ),
    ))
}

fn package_manager_script_dynamic(
    root: &Path,
    script: &str,
    extra: &[String],
) -> Result<(PathBuf, Vec<String>), ResolveError> {
    let manager = package_manager(root).ok_or_else(|| {
        ResolveError::NotConfigured("package manager metadata is unavailable".into())
    })?;
    let path = resolve_named_path(root, &manager)?;
    Ok((
        path,
        package_script_argv(&manager, script, extra.iter().cloned()),
    ))
}

fn package_script_argv(
    manager: &str,
    script: &str,
    extra: impl IntoIterator<Item = String>,
) -> Vec<String> {
    let mut values = Vec::new();
    if manager == "pnpm" {
        values.push("--config.verify-deps-before-run=false".into());
    }
    if manager == "yarn" {
        values.push(script.to_owned());
    } else {
        values.extend(["run".into(), script.to_owned()]);
    }
    let extra = extra.into_iter().collect::<Vec<_>>();
    if !extra.is_empty() {
        values.push("--".into());
        values.extend(extra);
    }
    values
}

/// Symbolic tool name for the runtime capture check. It is never looked up on
/// PATH: it resolves to the running Legion executable, whose own browser route
/// (`script qa/qa-functional`) performs the capture.
pub(super) const RUNTIME_CAPTURE_TOOL: &str = "legion-qa-shot";

/// The executable currently running this Audit, canonicalized. Runtime capture
/// is host-owned: never invoke Node or a checked-out script as a fallback.
fn current_legion_executable() -> Result<PathBuf, ResolveError> {
    let path = env::current_exe().map_err(|error| {
        ResolveError::Unavailable(format!("current-executable-unavailable: {error}"))
    })?;
    Ok(fs::canonicalize(&path).unwrap_or(path))
}

fn package_json(root: &Path) -> Option<Value> {
    serde_json::from_slice(&fs::read(root.join("package.json")).ok()?).ok()
}

fn lint_candidates(root: &Path) -> Vec<&'static str> {
    let package = package_json(root);
    let has_dep = |name: &str| {
        ["dependencies", "devDependencies", "peerDependencies"]
            .iter()
            .any(|key| {
                package
                    .as_ref()
                    .and_then(|value| value.get(key))
                    .and_then(Value::as_object)
                    .is_some_and(|deps| deps.contains_key(name))
            })
    };
    if (root.join("biome.json").is_file() || root.join("biome.jsonc").is_file())
        && has_dep("@biomejs/biome")
    {
        return vec!["biome"];
    }
    let eslint_configured = [
        ".eslintrc",
        ".eslintrc.js",
        ".eslintrc.cjs",
        ".eslintrc.json",
        ".eslintrc.yml",
        "eslint.config.js",
        "eslint.config.mjs",
        "eslint.config.cjs",
    ]
    .iter()
    .any(|path| root.join(path).is_file())
        || package
            .as_ref()
            .and_then(|value| value.get("eslintConfig"))
            .is_some();
    if eslint_configured && has_dep("eslint") {
        return vec!["eslint"];
    }
    if root.join("Cargo.toml").is_file() || root.join("src-tauri/Cargo.toml").is_file() {
        return vec!["cargo"];
    }
    if root.join("pyproject.toml").is_file()
        || root.join("setup.py").is_file()
        || root.join("requirements.txt").is_file()
    {
        return vec!["ruff"];
    }
    Vec::new()
}

fn type_candidates(root: &Path) -> Vec<&'static str> {
    if root.join("tsconfig.json").is_file() {
        return vec!["tsc"];
    }
    if root.join("pyproject.toml").is_file()
        || root.join("setup.py").is_file()
        || root.join("requirements.txt").is_file()
    {
        return vec!["basedpyright", "mypy"];
    }
    Vec::new()
}

fn package_manager(root: &Path) -> Option<String> {
    if let Some(package) = package_json(root) {
        if let Some(value) = package.get("packageManager").and_then(Value::as_str) {
            let manager = value.split('@').next()?.to_ascii_lowercase();
            if matches!(manager.as_str(), "npm" | "pnpm" | "yarn" | "bun") {
                return Some(manager);
            }
        }
    }
    [
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("package-lock.json", "npm"),
        ("bun.lockb", "bun"),
    ]
    .iter()
    .find(|(file, _)| root.join(file).is_file())
    .map(|(_, manager)| (*manager).into())
    .or_else(|| root.join("package.json").is_file().then_some("npm".into()))
}

fn resolve_named_path(root: &Path, name: &str) -> Result<PathBuf, ResolveError> {
    let input = Path::new(name);
    if input.is_absolute() {
        return existing_file(input).ok_or_else(|| ResolveError::MissingExecutable(name.into()));
    }
    let local = root.join("node_modules/.bin").join(name);
    if let Some(path) = existing_file_with_platform_extensions(&local) {
        return Ok(path);
    }
    let path_var = env::var_os("PATH").unwrap_or_default();
    for directory in env::split_paths(&path_var) {
        let candidate = directory.join(name);
        if let Some(path) = existing_file_with_platform_extensions(&candidate) {
            return Ok(path);
        }
    }
    Err(ResolveError::MissingExecutable(name.into()))
}

fn existing_file(path: &Path) -> Option<PathBuf> {
    path.is_file()
        .then(|| fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()))
}

fn existing_file_with_platform_extensions(path: &Path) -> Option<PathBuf> {
    existing_file(path).or_else(|| {
        #[cfg(windows)]
        {
            for extension in [".exe", ".cmd", ".bat", ".com"] {
                if let Some(value) =
                    existing_file(&path.with_extension(extension.trim_start_matches('.')))
                {
                    return Some(value);
                }
            }
        }
        None
    })
}

fn is_cargo_analysis_tool(tool: &str) -> bool {
    matches!(
        tool,
        "cargo-audit" | "cargo-deny" | "cargo-geiger" | "cargo-machete" | "cargo-outdated"
    )
}

/// The one first-level directory holding a `Cargo.toml`, if exactly one does.
fn nested_cargo_dir(root: &Path) -> Option<PathBuf> {
    let mut found = fs::read_dir(root)
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            !name.starts_with('.') && !matches!(name.as_ref(), "node_modules" | "target" | "vendor")
        })
        .map(|entry| entry.path())
        .filter(|path| path.join("Cargo.toml").is_file());
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

fn uses_cargo_working_directory(tool: &str) -> bool {
    matches!(
        tool,
        "project-build"
            | "project-lint"
            | "cargo-audit"
            | "cargo-deny"
            | "cargo-geiger"
            | "cargo-machete"
            | "cargo-outdated"
    )
}

fn seal(
    cwd: &Path,
    executable: PathBuf,
    args: Vec<String>,
) -> Result<ResolvedCommand, ResolveError> {
    let digest = digest_file(&executable)?;
    Ok(ResolvedCommand {
        executable,
        args,
        digest,
        cwd: cwd.to_path_buf(),
    })
}

fn digest_file(path: &Path) -> Result<String, ResolveError> {
    let bytes = fs::read(path).map_err(|error| {
        ResolveError::Unavailable(format!(
            "could not read executable {}: {error}",
            path.display()
        ))
    })?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(test)]
mod test_command_resolution_tests {
    use super::*;
    use crate::inventory::{FilesystemInventorySource, InventorySource};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_root() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "legion-test-command-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    fn make_inventory(root: &Path) -> InventoryEnvelope {
        FilesystemInventorySource::new(root)
            .unwrap()
            .inventory("fixture")
            .unwrap()
    }

    #[test]
    fn package_manager_pin_requires_exact_semver_shape() {
        assert!(is_exact_semver_pin("9.1.0"));
        assert!(is_exact_semver_pin("9.1.0-rc.1"));
        assert!(is_exact_semver_pin("9.1.0+sha224.abc123"));
        assert!(!is_exact_semver_pin("9.1.0-"));
        assert!(!is_exact_semver_pin("09.1.0"));
        assert!(!is_exact_semver_pin("9.1.0+"));
        assert!(!is_exact_semver_pin("9.1.0-rc..1"));
    }

    #[test]
    fn unregistered_or_unbound_managed_test_runners_stay_typed_gaps() {
        for runner in [
            "pytest", "mvn", "gradle", "dotnet", "go", "bundle", "flutter", "dart", "mix", "yarn",
            "bun",
        ] {
            assert_eq!(
                managed_runner_gap(runner),
                format!("managed-test-runner-not-registered:{runner}")
            );
        }
    }

    #[test]
    fn native_test_families_have_frozen_fixed_argv_fixtures() {
        let fixtures: &[(&str, &[(&str, &str)], &str, &[&str])] = &[
            (
                "pytest",
                &[
                    ("pyproject.toml", "[tool.pytest.ini_options]\n"),
                    ("tests/test_app.py", "def test_ok(): pass\n"),
                ],
                "pyproject.toml",
                &[],
            ),
            (
                "swift",
                &[("Package.swift", "// swift-tools-version: 5.9\n")],
                "Package.swift",
                &["test"],
            ),
            ("mvn", &[("pom.xml", "<project/>\n")], "pom.xml", &["test"]),
            (
                "gradle",
                &[("build.gradle.kts", "plugins {}\n")],
                "build.gradle.kts",
                &["test"],
            ),
            (
                "dotnet",
                &[("tests/App.Tests.csproj", "<Project/>\n")],
                "tests/App.Tests.csproj",
                &["test", "tests/App.Tests.csproj"],
            ),
            (
                "go",
                &[
                    ("go.mod", "module fixture\n"),
                    ("app_test.go", "package app\n"),
                ],
                "go.mod",
                &["test", "./..."],
            ),
            (
                "bundle",
                &[
                    ("Gemfile", "source 'https://example.invalid'\n"),
                    ("Rakefile", "task :test\n"),
                    ("test/app_test.rb", "class AppTest; end\n"),
                ],
                "Gemfile",
                &["exec", "rake", "test"],
            ),
            (
                "dart",
                &[
                    ("pubspec.yaml", "name: fixture\n"),
                    ("test/app_test.dart", "void main() {}\n"),
                ],
                "pubspec.yaml",
                &["test"],
            ),
            (
                "flutter",
                &[
                    (
                        "pubspec.yaml",
                        "name: fixture\ndependencies:\n  flutter:\n    sdk: flutter\n",
                    ),
                    ("test/app_test.dart", "void main() {}\n"),
                ],
                "pubspec.yaml",
                &["test"],
            ),
            (
                "mix",
                &[("mix.exs", "defmodule Fixture.MixProject do end\n")],
                "mix.exs",
                &["test"],
            ),
        ];
        for (expected_runner, files, expected_declaration, expected_args) in fixtures {
            let root = fixture_root();
            for (relative, contents) in *files {
                let path = root.join(relative);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, contents).unwrap();
            }
            let inventory = make_inventory(&root);
            let (runner, args, declaration, _) =
                native_test_spec(&root, &inventory).unwrap().unwrap();
            assert_eq!(&runner, expected_runner);
            assert_eq!(&declaration, expected_declaration);
            assert_eq!(
                args.iter().map(String::as_str).collect::<Vec<_>>(),
                *expected_args
            );
            let resolution = resolve_frozen_test_runner(
                &root,
                &inventory,
                expected_runner,
                args.clone(),
                &declaration,
                &[],
                None,
                None,
            );
            match resolution {
                Ok((resolved, source)) => {
                    let expected_argv = std::iter::once(*expected_runner)
                        .chain(expected_args.iter().copied())
                        .map(str::to_owned)
                        .collect::<Vec<_>>();
                    assert_eq!(resolved.args, expected_argv);
                    assert_eq!(source["family"], "registered-adapter");
                }
                Err(ResolveError::NotConfigured(reason)) => {
                    assert_eq!(reason, "managed-test-trust-not-configured")
                }
                Err(error) => panic!("unexpected frozen runner resolution error: {error:?}"),
            }
            fs::remove_dir_all(root).unwrap();
        }

        let root = fixture_root();
        fs::write(root.join("Gemfile"), "source 'https://example.invalid'\n").unwrap();
        fs::create_dir_all(root.join("spec")).unwrap();
        fs::write(root.join("spec/app_spec.rb"), "describe 'app' do end\n").unwrap();
        let inventory = make_inventory(&root);
        let (runner, args, declaration, _) = native_test_spec(&root, &inventory).unwrap().unwrap();
        assert_eq!(runner, "bundle");
        assert_eq!(declaration, "Gemfile");
        assert_eq!(args, ["exec", "rspec"]);
        fs::remove_dir_all(root).unwrap();

        let root = fixture_root();
        for path in ["App.sln", "src/App.csproj", "tests/App.Tests.csproj"] {
            let file = root.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, "fixture\n").unwrap();
        }
        let inventory = make_inventory(&root);
        let (runner, args, declaration, _) = native_test_spec(&root, &inventory).unwrap().unwrap();
        assert_eq!(runner, "dotnet");
        assert_eq!(declaration, "App.sln");
        assert_eq!(args, ["test", "App.sln"]);
        fs::remove_dir_all(root).unwrap();

        let root = fixture_root();
        for path in ["src/App.csproj", "tests/App.Tests.csproj"] {
            let file = root.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, "fixture\n").unwrap();
        }
        let inventory = make_inventory(&root);
        let error = native_test_spec(&root, &inventory).unwrap_err();
        assert!(error
            .message()
            .contains("dotnet-test-solution-required-for-multiple-projects"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_test_manifest_drift_is_not_reselected() {
        let root = fixture_root();
        fs::write(root.join("go.mod"), "module frozen\n").unwrap();
        let inventory = make_inventory(&root);
        fs::write(root.join("go.mod"), "module changed\n").unwrap();
        let error = native_test_spec(&root, &inventory).unwrap_err();
        assert!(error.message().contains("test-source-input-drift:go.mod"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn package_script_requires_authenticated_registered_runner_identity() {
        let root = fixture_root();
        fs::write(
            root.join("package.json"),
            r#"{"packageManager":"pnpm@9.1.0","scripts":{"test":"vitest"}}"#,
        )
        .unwrap();
        fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
        fs::write(root.join("node_modules/.bin/pnpm"), "fixture pnpm").unwrap();
        fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
        let inventory = make_inventory(&root);
        let error = resolve_test_command(&root, &inventory).unwrap_err();
        match error {
            ResolveError::NotConfigured(reason) => {
                assert_eq!(reason, "managed-test-trust-not-configured")
            }
            other => panic!("unexpected package runner resolution error: {other:?}"),
        }

        fs::write(
            root.join("package.json"),
            r#"{"packageManager":"npm@10.0.0","scripts":{"test":"node test.js"}}"#,
        )
        .unwrap();
        let npm_inventory = make_inventory(&root);
        let npm_error = resolve_test_command(&root, &npm_inventory).unwrap_err();
        match npm_error {
            ResolveError::NotConfigured(reason) => {
                assert_eq!(reason, "managed-test-trust-not-configured")
            }
            other => panic!("unexpected npm runner resolution error: {other:?}"),
        }

        fs::write(
            root.join("package.json"),
            r#"{"packageManager":"unsupported@1.2.3","scripts":{"test":"node test.js"}}"#,
        )
        .unwrap();
        let unsupported_inventory = make_inventory(&root);
        assert_eq!(
            resolve_test_command(&root, &unsupported_inventory).unwrap_err(),
            ResolveError::NotConfigured("managed-test-runner-not-registered:unsupported".into())
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn frozen_npm_test_argv_matches_registered_adapter_request_contract() {
        let root = fixture_root();
        fs::write(
            root.join("package.json"),
            r#"{"packageManager":"npm@11.19.0","scripts":{"test":"node test.js"}}"#,
        )
        .unwrap();
        fs::write(root.join("test.js"), "process.exit(0);\n").unwrap();
        let enrolled_client = root.join("trusted-bin/rightkit");
        fs::create_dir_all(enrolled_client.parent().unwrap()).unwrap();
        fs::write(&enrolled_client, "fixture rightkit").unwrap();
        let public_key = "04".to_owned() + &"b".repeat(128);
        let enrollment = AttestedRunsEnrollment {
            schema_version: 1,
            host: "fixture-host".into(),
            key_id: hex::encode(Sha256::digest(hex::decode(&public_key).unwrap())),
            public_key,
            broker_digest: "c".repeat(64),
            client_executable: fs::canonicalize(&enrolled_client).unwrap(),
            client_digest: hex::encode(Sha256::digest(b"fixture rightkit")),
            adapters: std::collections::BTreeMap::from([(
                "npm".into(),
                super::super::AdapterEnrollment {
                    broker_adapter_id: "legion-npm-test".into(),
                    qualified_version: Some("11.19.0".into()),
                },
            )]),
        };
        let inventory = make_inventory(&root);
        let (resolved, source) =
            resolve_test_command_with_enrollment(&root, &inventory, Some(&enrollment)).unwrap();

        assert_eq!(resolved.args, ["npm", "run", "test"]);
        assert_eq!(source["argv"], json!(["npm", "run", "test"]));
        assert_eq!(source["requiredRunnerVersion"], "11.19.0");
        let requested_argv = resolved.args.iter().skip(1).cloned().collect::<Vec<_>>();
        let broker_core = json!({
            "adapter":"legion-npm-test",
            "requestedArgv":requested_argv,
            "shim":"adapter"
        });
        assert_eq!(
            broker_core,
            json!({
                "adapter":"legion-npm-test",
                "requestedArgv":["run", "test"],
                "shim":"adapter"
            })
        );
        let client_argv = ["run", "legion-npm-test", "--"]
            .into_iter()
            .chain(requested_argv.iter().map(String::as_str))
            .collect::<Vec<_>>();
        assert_eq!(client_argv, ["run", "legion-npm-test", "--", "run", "test"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_public_enrollment_is_rejected_before_root_resolution() {
        let root = fixture_root();
        let inventory = make_inventory(&root);
        let enrollment = AttestedRunsEnrollment {
            schema_version: 2,
            host: "fixture-host".into(),
            key_id: "a".repeat(64),
            public_key: "04".to_owned() + &"b".repeat(128),
            broker_digest: "c".repeat(64),
            client_executable: PathBuf::from("relative-rightkit"),
            client_digest: "d".repeat(64),
            adapters: std::collections::BTreeMap::new(),
        };
        let error = resolve_test_command_with_enrollment(
            &root.join("missing-root"),
            &inventory,
            Some(&enrollment),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ResolveError::Unavailable(reason)
                if reason.starts_with("test-enrollment-invalid:")
                    && reason.contains("unsupported schemaVersion")
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn package_script_argv_adds_pnpm_preflight_override_for_build_and_test_only() {
        assert_eq!(frozen_package_test_argv("npm"), ["run", "test"]);
        for manager in ["pnpm", "yarn", "bun"] {
            assert_eq!(frozen_package_test_argv(manager), ["test"]);
        }
        for script in ["build", "test"] {
            assert_eq!(
                package_script_argv("pnpm", script, std::iter::empty()),
                ["--config.verify-deps-before-run=false", "run", script]
            );
            assert_eq!(
                package_script_argv("npm", script, std::iter::empty()),
                ["run", script]
            );
            assert_eq!(
                package_script_argv("yarn", script, std::iter::empty()),
                [script]
            );
        }
    }

    #[test]
    fn static_and_dynamic_package_build_resolvers_use_pnpm_preflight_override() {
        let root = fixture_root();
        fs::write(
            root.join("package.json"),
            r#"{"packageManager":"pnpm@11.24.0","scripts":{"build":"build"}}"#,
        )
        .unwrap();
        fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
        fs::write(root.join("node_modules/.bin/pnpm"), "fixture pnpm").unwrap();

        let frozen = resolve_command(
            &root,
            CommandShape::Named {
                tool: "project-build",
                args: &[],
            },
        )
        .unwrap();
        let dynamic = resolve_request(&root, "project-build", &[]).unwrap();
        let expected = ["--config.verify-deps-before-run=false", "run", "build"];
        assert_eq!(frozen.args, expected);
        assert_eq!(dynamic.args, expected);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_drift_does_not_fall_back_to_cargo() {
        let root = fixture_root();
        fs::write(
            root.join("package.json"),
            r#"{"packageManager":"pnpm@9.1.0","scripts":{"test":"vitest"}}"#,
        )
        .unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\nname='fixture'\n").unwrap();
        fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
        fs::write(root.join("node_modules/.bin/pnpm"), "fixture pnpm").unwrap();
        fs::write(root.join("node_modules/.bin/rightkit"), "fixture rightkit").unwrap();
        let inventory = make_inventory(&root);
        fs::write(root.join("package.json"), r#"{"scripts":{}}"#).unwrap();
        let error = resolve_test_command(&root, &inventory).unwrap_err();
        assert!(error
            .message()
            .contains("test-source-input-drift:package.json"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rust_test_command_is_routed_through_rightkit() {
        let root = fixture_root();
        fs::create_dir_all(root.join("src-tauri")).unwrap();
        fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
        fs::create_dir_all(root.join("trusted-bin")).unwrap();
        fs::write(
            root.join("src-tauri/Cargo.toml"),
            "[package]\nname='fixture'\n",
        )
        .unwrap();
        fs::write(root.join("src-tauri/Cargo.lock"), "# fixture\n").unwrap();
        fs::write(
            root.join("node_modules/.bin/rightkit"),
            "untrusted local cli",
        )
        .unwrap();
        let enrolled_client = root.join("trusted-bin/rightkit");
        fs::write(&enrolled_client, "fixture rightkit").unwrap();
        let public_key = "04".to_owned() + &"b".repeat(128);
        let key_id = hex::encode(Sha256::digest(hex::decode(&public_key).unwrap()));
        let enrollment = AttestedRunsEnrollment {
            schema_version: 1,
            host: "fixture-host".into(),
            key_id,
            public_key,
            broker_digest: "c".repeat(64),
            client_executable: fs::canonicalize(&enrolled_client).unwrap(),
            client_digest: hex::encode(Sha256::digest(b"fixture rightkit")),
            adapters: std::collections::BTreeMap::new(),
        };
        let inventory = make_inventory(&root);
        let (resolved, source) =
            resolve_test_command_with_enrollment(&root, &inventory, Some(&enrollment)).unwrap();
        assert_eq!(resolved.args, ["cargo", "test"]);
        assert_eq!(
            resolved.executable,
            fs::canonicalize(enrolled_client).unwrap()
        );
        assert_eq!(
            resolved.cwd,
            fs::canonicalize(root.join("src-tauri")).unwrap()
        );
        assert_eq!(source["family"], "rust-rightkit");
        assert_eq!(
            source["workspaceRoot"],
            fs::canonicalize(root.join("src-tauri"))
                .unwrap()
                .to_string_lossy()
                .as_ref()
        );
        assert_eq!(source["sources"][0]["path"], "src-tauri/Cargo.toml");
        fs::remove_dir_all(root).unwrap();
    }
}
