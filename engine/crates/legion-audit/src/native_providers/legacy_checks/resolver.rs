//! Resolution of frozen legacy-check commands to sealed, argv-only launches.
//!
//! Registry entries intentionally contain stable tool names rather than host
//! paths.  This module is the small host-side bridge: it consults repository
//! package metadata, then bounded local-bin/PATH lookup, and seals the bytes
//! of the selected executable before it reaches `legion-effects`.

use super::contracts::CommandShape;
use serde_json::Value;
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
    Unavailable(String),
}

impl ResolveError {
    pub fn message(&self) -> String {
        match self {
            Self::MissingExecutable(value) => format!("missing executable: {value}"),
            Self::Unavailable(value) => value.clone(),
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
            ))
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
        "project-lint" => project_lint_dynamic(root, args)?,
        "project-types" => project_types_dynamic(root, args)?,
        "package-audit" => package_manager_operation_dynamic(root, "audit", args)?,
        "package-outdated" => package_manager_operation_dynamic(root, "outdated", args)?,
        "audit-runtime" => (resolve_named_path(root, "audit-runtime")?, args.to_vec()),
        _ => (resolve_named_path(root, executable)?, args.to_vec()),
    };
    let cwd = if uses_cargo_working_directory(executable)
        && !root.join("Cargo.toml").is_file()
        && root.join("src-tauri/Cargo.toml").is_file()
    {
        root.join("src-tauri")
    } else {
        root.to_path_buf()
    };
    seal(&cwd, path, resolved_args)
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
        "audit-runtime" => audit_runtime(root, args),
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
    Err(ResolveError::Unavailable(format!(
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
    Err(ResolveError::Unavailable(format!(
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
    Err(ResolveError::Unavailable(
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
    Err(ResolveError::Unavailable(
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
    Err(ResolveError::Unavailable(
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
    Err(ResolveError::Unavailable(
        "no configured project type checker was found".into(),
    ))
}

fn package_manager_operation(
    root: &Path,
    operation: &str,
    extra: &[&str],
) -> Result<(PathBuf, Vec<String>), ResolveError> {
    let manager = package_manager(root).ok_or_else(|| {
        ResolveError::Unavailable("package manager metadata is unavailable".into())
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
        ResolveError::Unavailable("package manager metadata is unavailable".into())
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
        ResolveError::Unavailable("package manager metadata is unavailable".into())
    })?;
    let path = resolve_named_path(root, &manager)?;
    let mut values = if manager == "yarn" {
        vec![script.to_owned()]
    } else {
        vec!["run".into(), script.to_owned()]
    };
    if !extra.is_empty() {
        values.push("--".into());
        values.extend(extra.iter().map(|item| (*item).to_owned()));
    }
    Ok((path, values))
}

fn package_manager_script_dynamic(
    root: &Path,
    script: &str,
    extra: &[String],
) -> Result<(PathBuf, Vec<String>), ResolveError> {
    let manager = package_manager(root).ok_or_else(|| {
        ResolveError::Unavailable("package manager metadata is unavailable".into())
    })?;
    let path = resolve_named_path(root, &manager)?;
    let mut values = if manager == "yarn" {
        vec![script.to_owned()]
    } else {
        vec!["run".into(), script.to_owned()]
    };
    if !extra.is_empty() {
        values.push("--".into());
        values.extend(extra.iter().cloned());
    }
    Ok((path, values))
}

fn audit_runtime(root: &Path, extra: &[&str]) -> Result<(PathBuf, Vec<String>), ResolveError> {
    // Runtime execution is host-owned. Never invoke Node or a checked-out
    // script as an implicit fallback from native Audit.
    let path = resolve_named_path(root, "audit-runtime")?;
    Ok((path, extra.iter().map(|item| (*item).to_owned()).collect()))
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
    let bytes = fs::read(&executable).map_err(|error| {
        ResolveError::Unavailable(format!(
            "could not read executable {}: {error}",
            executable.display()
        ))
    })?;
    Ok(ResolvedCommand {
        executable,
        args,
        digest: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
        cwd: cwd.to_path_buf(),
    })
}
