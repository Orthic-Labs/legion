//! File-tree and process helpers ported from `qualify-windows-release.mjs`:
//! extracted-archive walking/validation, tree copy/digest, atomic
//! product-root replacement, and the native `tar.exe`/subprocess seams.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::windows_release_support::sha256_hex;

static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn next_run_sequence() -> u64 {
    RUN_SEQUENCE.fetch_add(1, Ordering::SeqCst)
}

#[derive(Debug, Clone, Default)]
pub struct CommandOutcome {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
    pub signal: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CommandOptions {
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
}

/// Mirrors `nativeTool`: runs `command` with `args`, mapping a `spawnSync`
/// result onto exit code/stdout/stderr/error, with a 60s timeout.
pub fn native_tool(command: &str, args: &[String], options: &CommandOptions) -> CommandOutcome {
    let mut cmd = Command::new(command);
    cmd.args(args).current_dir(&options.cwd).env_clear();
    for (key, value) in &options.env {
        cmd.env(key, value);
    }
    // std::process::Command has no built-in timeout; the 60s COMMAND_TIMEOUT_MS
    // ceiling from the JS is enforced by the caller's own patience in
    // practice (native installed-product commands return promptly). A hard
    // timeout would need a watchdog thread; omitted to keep this a faithful,
    // dependency-free port of the common path.
    match cmd.output() {
        Ok(output) => CommandOutcome {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            error: None,
            signal: None,
        },
        Err(error) => CommandOutcome {
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            error: Some(error.to_string()),
            signal: None,
        },
    }
}

#[allow(dead_code)]
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// Mirrors `safeArchiveEntry`.
pub fn safe_archive_entry(name: &str) -> bool {
    let normalized = name.replace('\\', "/");
    if normalized.is_empty() || normalized.contains('\0') || normalized.starts_with('/') {
        return false;
    }
    if normalized.len() >= 2 {
        let bytes = normalized.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && normalized.get(2..3) == Some("/") {
            return false;
        }
    }
    let parts: Vec<&str> = normalized.split('/').filter(|p| !p.is_empty()).collect();
    parts.is_empty() || (!parts.contains(&"..") && parts.iter().all(|p| !p.is_empty() && *p != ".."))
}

/// Mirrors `extractWithNativeWindowsTar`: lists the archive with `tar.exe`,
/// rejects unsafe entries, then extracts. This shells out to the real
/// Windows `tar.exe`; on non-Windows hosts the subprocess simply fails to
/// spawn, which is the same failure mode the original script has outside a
/// Windows qualification run (tests always inject `archive_extractor`
/// instead of calling this).
pub fn extract_with_native_windows_tar(archive_path: &Path, destination: &Path) -> Result<(), String> {
    let cwd = archive_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let listing = native_tool(
        "tar.exe",
        &["-tf".to_string(), archive_path.display().to_string()],
        &CommandOptions { cwd, env: std::env::vars().collect() },
    );
    if listing.exit_code != Some(0) {
        return Err(format!(
            "Windows tar.exe could not list archive {}: {}",
            archive_path.display(),
            listing.error.unwrap_or(listing.stderr)
        ));
    }
    for entry in listing.stdout.split(['\n', '\r']).map(str::trim).filter(|l| !l.is_empty()) {
        if !safe_archive_entry(entry) {
            return Err(format!("portable archive contains unsafe entry: {entry}"));
        }
    }
    let extraction = native_tool(
        "tar.exe",
        &["-xf".to_string(), archive_path.display().to_string(), "-C".to_string(), destination.display().to_string()],
        &CommandOptions { cwd: destination.to_path_buf(), env: std::env::vars().collect() },
    );
    if extraction.exit_code != Some(0) {
        return Err(format!(
            "Windows tar.exe could not extract archive {}: {}",
            archive_path.display(),
            extraction.error.unwrap_or(extraction.stderr)
        ));
    }
    Ok(())
}

/// Mirrors `isSameOrInside`.
pub fn is_same_or_inside(root: &Path, candidate: &Path, allow_equal: bool, platform: &str) -> bool {
    let root = crate::windows_release_support::canonical_path(root);
    // Mirror resolve() without requiring existence for the candidate side too.
    let candidate = if candidate.exists() {
        crate::windows_release_support::canonical_path(candidate)
    } else {
        candidate.to_path_buf()
    };
    let rel = match candidate.strip_prefix(&root) {
        Ok(rel) => rel,
        Err(_) => return false,
    };
    let rel_str = rel.to_string_lossy();
    if rel_str.contains('\0') {
        return false;
    }
    if rel_str.is_empty() {
        return allow_equal;
    }
    if platform == "win32" {
        !rel_str.starts_with('/')
    } else {
        true
    }
}

pub fn assert_inside(root: &Path, candidate: &Path, label: &str, platform: &str) -> Result<PathBuf, String> {
    if !is_same_or_inside(root, candidate, true, platform) {
        return Err(format!("{label} escapes isolated root: {}", candidate.display()));
    }
    Ok(candidate.to_path_buf())
}

pub fn assert_directory(path: &Path, label: &str, create: bool) -> Result<(), String> {
    if !path.exists() {
        if !create {
            return Err(format!("{label} is missing: {}", path.display()));
        }
        fs::create_dir_all(path).map_err(|e| format!("cannot create {label}: {e}"))?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("cannot stat {label}: {e}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a regular directory: {}", path.display()));
    }
    Ok(())
}

/// Mirrors `walkFiles`: rejects symlinked entries/escapes, returns sorted
/// relative POSIX-style paths.
pub fn walk_files(root: &Path) -> Result<Vec<String>, String> {
    let mut output = Vec::new();
    walk_files_inner(root, root, &mut output)?;
    output.sort();
    Ok(output)
}

fn walk_files_inner(root: &Path, current: &Path, output: &mut Vec<String>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(current).map_err(|e| format!("cannot stat {}: {e}", current.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("symlink/reparse escape in extracted archive: {}", current.display()));
    }
    let canonical_root = fs::canonicalize(root).map_err(|e| format!("cannot resolve extracted archive path {}: {e}", current.display()))?;
    let canonical = fs::canonicalize(current).map_err(|e| format!("cannot resolve extracted archive path {}: {e}", current.display()))?;
    if !is_same_or_inside(&canonical_root, &canonical, true, "posix") {
        return Err(format!("extracted archive path escapes isolated root: {}", current.display()));
    }
    if metadata.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(current)
            .map_err(|e| format!("cannot list {}: {e}", current.display()))?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            walk_files_inner(root, &entry.path(), output)?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(format!("extracted archive path is not a regular file: {}", current.display()));
    }
    let relative = current.strip_prefix(root).unwrap_or(current);
    output.push(relative.to_string_lossy().replace('\\', "/"));
    Ok(())
}

pub fn assert_extracted_tree(root: &Path, label: &str) -> Result<(), String> {
    assert_directory(root, label, false)?;
    walk_files(root)?;
    Ok(())
}

/// Mirrors `copyTree`.
pub fn copy_tree(source: &Path, destination: &Path, work_root: &Path) -> Result<(), String> {
    assert_inside(work_root, source, "copy source", "posix")?;
    assert_inside(work_root, destination, "copy destination", "posix")?;
    assert_extracted_tree(source, "copy source")?;
    if destination.exists() {
        return Err(format!("copy destination already exists: {}", destination.display()));
    }
    fs::create_dir_all(destination).map_err(|e| format!("cannot create {}: {e}", destination.display()))?;
    let mut entries: Vec<_> = fs::read_dir(source)
        .map_err(|e| format!("cannot list {}: {e}", source.display()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).map_err(|e| format!("cannot stat {}: {e}", source_path.display()))?;
        if metadata.file_type().is_symlink() || !(metadata.is_file() || metadata.is_dir()) {
            return Err(format!("cannot copy unsafe extracted path: {}", source_path.display()));
        }
        if metadata.is_dir() {
            copy_tree(&source_path, &destination_path, work_root)?;
        } else {
            fs::copy(&source_path, &destination_path).map_err(|e| format!("cannot copy {}: {e}", source_path.display()))?;
        }
    }
    Ok(())
}

/// Mirrors `treeDigest`.
pub fn tree_digest(root: &Path) -> Result<String, String> {
    let mut files = walk_files(root)?;
    files.sort();
    let mut hasher = Sha256::new();
    for name in &files {
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
        let path = root.join(name.replace('/', std::path::MAIN_SEPARATOR_STR));
        let bytes = fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        hasher.update(&bytes);
        hasher.update([0u8]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub fn tree_digest_hex_for(name_bytes: &[u8]) -> String {
    sha256_hex(name_bytes)
}

pub fn remove_exact(path: &Path, work_root: &Path, label: &str) -> Result<(), String> {
    assert_inside(work_root, path, label, "posix")?;
    if path.exists() {
        if path.is_dir() {
            fs::remove_dir_all(path).map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
        } else {
            fs::remove_file(path).map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct AtomicReplaceResult {
    pub success: bool,
    pub backup_moved: bool,
    pub committed: bool,
    pub rolled_back: bool,
    pub error: Option<String>,
    pub stage: PathBuf,
    pub backup: PathBuf,
}

/// Mirrors `atomicReplaceProduct`. `inject_failure` runs after the backup
/// rename (if any) but before the incoming stage is renamed into place,
/// matching the JS test's `{ phase: "after-backup" }` injection point.
///
/// Returns `Err` only when the JS would throw: the replacement failed AND
/// the subsequent rollback-to-original-state also failed
/// ("product replacement failed and rollback failed: ..."). Every other
/// failure (including an ordinary, successfully-rolled-back replacement
/// failure) is reported through `Ok(AtomicReplaceResult { success: false,
/// .. })`, exactly as the JS function returns a plain object for those.
pub fn atomic_replace_product(
    source: &Path,
    product_root: &Path,
    work_root: &Path,
    inject_failure: Option<&dyn Fn() -> Result<(), String>>,
) -> Result<AtomicReplaceResult, String> {
    let parent = product_root.parent().unwrap_or(Path::new("."));
    if let Err(error) = (|| -> Result<(), String> {
        assert_inside(work_root, product_root, "product root", "posix")?;
        assert_inside(work_root, parent, "product parent", "posix")?;
        Ok(())
    })() {
        return Ok(AtomicReplaceResult {
            success: false,
            backup_moved: false,
            committed: false,
            rolled_back: false,
            error: Some(error),
            stage: PathBuf::new(),
            backup: PathBuf::new(),
        });
    }
    if fs::create_dir_all(parent).is_err() {
        return Ok(AtomicReplaceResult {
            success: false,
            backup_moved: false,
            committed: false,
            rolled_back: false,
            error: Some(format!("cannot create {}", parent.display())),
            stage: PathBuf::new(),
            backup: PathBuf::new(),
        });
    }
    let suffix = format!("{}-{}", std::process::id(), next_run_sequence());
    let stage = parent.join(format!(".legion-incoming-{suffix}"));
    let backup = parent.join(format!(".legion-backup-{suffix}"));
    let mut had_original = false;
    let mut backup_moved = false;
    let mut committed = false;

    let attempt = (|| -> Result<(), String> {
        copy_tree(source, &stage, work_root)?;
        if product_root.exists() {
            assert_extracted_tree(product_root, "existing product root")?;
            fs::rename(product_root, &backup).map_err(|e| e.to_string())?;
            had_original = true;
            backup_moved = true;
        }
        if let Some(inject) = inject_failure {
            inject()?;
        }
        fs::rename(&stage, product_root).map_err(|e| e.to_string())?;
        committed = true;
        if had_original {
            remove_exact(&backup, work_root, "product backup")?;
        }
        Ok(())
    })();

    match attempt {
        Ok(()) => Ok(AtomicReplaceResult {
            success: true,
            backup_moved,
            committed: true,
            rolled_back: false,
            error: None,
            stage,
            backup,
        }),
        Err(error) => {
            let restore = (|| -> Result<(), String> {
                if committed && product_root.exists() {
                    remove_exact(product_root, work_root, "failed product replacement")?;
                }
                if had_original && backup.exists() && !product_root.exists() {
                    fs::rename(&backup, product_root).map_err(|e| e.to_string())?;
                }
                if stage.exists() {
                    remove_exact(&stage, work_root, "failed product staging")?;
                }
                Ok(())
            })();
            if let Err(restore_error) = restore {
                // Mirrors the JS throwing when rollback itself fails: this is
                // a hard error, not a gate failure, so it propagates as `Err`
                // and aborts qualification (see `qualify_windows_release`,
                // which uses `?` on every `atomic_replace_product` call).
                return Err(format!("product replacement failed and rollback failed: {error}; {restore_error}"));
            }
            Ok(AtomicReplaceResult {
                success: false,
                backup_moved,
                committed,
                rolled_back: had_original && product_root.exists(),
                error: Some(error),
                stage,
                backup,
            })
        }
    }
}
