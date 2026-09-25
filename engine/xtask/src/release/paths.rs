//! Shared path-safety, digest, JSON and subprocess helpers ported from the
//! small duplicated prelude at the top of every `scripts/release/**/*.mjs`
//! file (`fail`, `assertFile`/`assertDirectory`/`inside`/`pathFrom`, `sha256`,
//! `json`, `run`/`runJson`). Consolidated once here rather than re-duplicated
//! per Rust module, since the JS duplicated it only because each script was
//! independently `node script.mjs`-executable.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::process_boundary::{self, CommandResult};

pub type ReleaseResult<T> = Result<T, String>;

pub fn sha256_file(path: &Path) -> ReleaseResult<String> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Mirrors `assertFile`: must exist, be a regular file, and not a symlink.
pub fn assert_file(path: &Path, label: &str) -> ReleaseResult<()> {
    let meta = fs::symlink_metadata(path).map_err(|_| format!("{label} is missing: {}", path.display()))?;
    if meta.is_symlink() || !meta.is_file() {
        return Err(format!("{label} is not a regular file: {}", path.display()));
    }
    Ok(())
}

/// Mirrors `assertDirectory`: must exist (or be created when `create`), be a
/// real directory, and not a symlink.
pub fn assert_directory(path: &Path, label: &str, create: bool) -> ReleaseResult<()> {
    if !path.exists() {
        if !create {
            return Err(format!("{label} is missing: {}", path.display()));
        }
        fs::create_dir_all(path).map_err(|e| format!("{label} could not be created: {e}"))?;
    }
    let meta = fs::symlink_metadata(path).map_err(|_| format!("{label} is missing: {}", path.display()))?;
    if meta.is_symlink() || !meta.is_dir() {
        return Err(format!("{label} is not a regular directory: {}", path.display()));
    }
    Ok(())
}

/// Mirrors `inside`: resolves `candidate` and refuses to return it unless it
/// is strictly (or, with `allow_root`, exactly) below `root`.
pub fn inside(root: &Path, candidate: &Path, label: &str, allow_root: bool) -> ReleaseResult<PathBuf> {
    let base = dunce_canonicalize_lenient(root);
    let value = dunce_canonicalize_lenient(candidate);
    match value.strip_prefix(&base) {
        Ok(rel) => {
            if rel.as_os_str().is_empty() && !allow_root {
                return Err(format!("{label} escapes root: {}", candidate.display()));
            }
            Ok(value)
        }
        Err(_) => Err(format!("{label} escapes root: {}", candidate.display())),
    }
}

/// `resolve()`-equivalent that does not require the path to exist (Rust's
/// `canonicalize` does); joins relative paths against CWD and normalizes
/// `.`/`..` lexically, matching Node's `path.resolve` semantics closely
/// enough for the containment checks this module performs.
fn dunce_canonicalize_lenient(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut out = PathBuf::new();
    for component in absolute.components() {
        use std::path::Component;
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub fn path_from(root: &Path, value: &str, label: &str) -> ReleaseResult<PathBuf> {
    if value.is_empty() || value.contains('\0') {
        return Err(format!("{label} path is invalid"));
    }
    let candidate = Path::new(value);
    let joined = if candidate.is_absolute() { candidate.to_path_buf() } else { root.join(candidate) };
    inside(root, &joined, label, false)
}

pub fn read_json(path: &Path, label: &str) -> ReleaseResult<serde_json::Value> {
    assert_file(path, label)?;
    let text = fs::read_to_string(path).map_err(|e| format!("{label} could not be read: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{label} is invalid JSON: {e}"))
}

/// Writes `value` pretty-printed with two-space indent plus a trailing
/// newline, matching `JSON.stringify(value, null, 2) + "\n"` byte-for-byte
/// for values with the same key order (this crate uses `serde_json`'s
/// `preserve_order` feature, so struct/`Map` field order is preserved).
pub fn write_json_pretty(path: &Path, value: &serde_json::Value) -> ReleaseResult<()> {
    let text = serde_json::to_string_pretty(value).map_err(|e| format!("failed to serialize {}: {e}", path.display()))?;
    fs::write(path, format!("{text}\n")).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

/// Options mirroring the subset of Node `spawnSync` options the release
/// scripts pass explicitly (`cwd`, `env`).
#[derive(Default, Clone)]
pub struct CommandOptions {
    pub cwd: Option<PathBuf>,
    pub env: Option<HashMap<String, String>>,
}

/// A pluggable process runner, mirroring the JS scripts' `commandRunner`
/// dependency-injection parameter (default `spawnSync`) that tests replace
/// with a stub. Boxed so callers can pass closures or a real-process runner.
pub type CommandRunner<'a> = &'a dyn Fn(&str, &[String], &CommandOptions) -> CommandResult;

/// The default runner: an actual `std::process::Command` invocation, applying
/// the same timeout/output-capture bounds `releaseSpawnOptions` documents
/// (Rust's `Command` has no built-in timeout, so long-running callers should
/// prefer a purpose-built runner; this default is for short commands).
pub fn spawn_sync(command: &str, args: &[String], options: &CommandOptions) -> CommandResult {
    let mut cmd = Command::new(command);
    cmd.args(args);
    if let Some(cwd) = &options.cwd {
        cmd.current_dir(cwd);
    }
    if let Some(env) = &options.env {
        cmd.env_clear();
        for (k, v) in env {
            cmd.env(k, v);
        }
    }
    match cmd.output() {
        Ok(output) => CommandResult {
            error_message: None,
            status: output.status.code(),
            signal: None,
            stdout: Some(String::from_utf8_lossy(&output.stdout).into_owned()),
            stderr: Some(String::from_utf8_lossy(&output.stderr).into_owned()),
        },
        Err(err) => CommandResult {
            error_message: Some(err.to_string()),
            status: None,
            signal: None,
            stdout: None,
            stderr: None,
        },
    }
}

pub fn run_json(
    runner: CommandRunner,
    command: &str,
    args: &[String],
    options: &CommandOptions,
    label: &str,
) -> ReleaseResult<serde_json::Value> {
    let result = runner(command, args, options);
    if result.error_message.is_some() || result.status != Some(0) {
        return Err(format!("{label} failed: {}", process_boundary::command_diagnostic(&result)));
    }
    let stdout = result.stdout.unwrap_or_default();
    serde_json::from_str(stdout.trim()).map_err(|_| format!("{label} must emit one JSON object"))
}

pub fn run_ok(runner: CommandRunner, command: &str, args: &[String], options: &CommandOptions, label: &str) -> ReleaseResult<CommandResult> {
    let result = runner(command, args, options);
    if result.error_message.is_some() || result.status != Some(0) {
        return Err(format!("{label} failed: {}", process_boundary::command_diagnostic(&result)));
    }
    Ok(result)
}

pub const SHA256_RE_LEN: usize = 64;

pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_RE_LEN && value.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn is_revision_hex(value: &str) -> bool {
    (40..=64).contains(&value.len()) && value.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn is_stable_semver(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|part| !part.is_empty() && (part == &"0" || (!part.starts_with('0') && part.chars().all(|c| c.is_ascii_digit()))))
}
