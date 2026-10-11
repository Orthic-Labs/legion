pub mod authority_parity;
pub mod authority_replay;
pub mod blueprint_config;
pub mod canonical_names;
pub mod dependency_closure;
pub mod distribution_contract;
pub mod native_cli_surface;
pub mod packed_import_closure;
pub mod portability;
pub mod publication_policy;
pub mod publication_surface;
pub mod release_obligations;
pub mod retirements;
pub mod run_skill_evals;
pub mod skill_evals;
pub mod skill_references;
pub mod version_parity;

use std::fs;
use std::path::Path;

/// Files/directories every recursive or `git ls-files` walk in the Node
/// scripts implicitly excludes.
pub const SKIP_DIRS: &[&str] = &[".git", ".audit", "node_modules", "target"];

/// Tracked files under `root`, preferring `git ls-files -z` (matching the
/// Node scripts) and falling back to a plain recursive walk when git is
/// unavailable, skipping `SKIP_DIRS`. Returns paths relative to `root` with
/// forward slashes.
///
/// An empty file set is an error: a scan of zero files must never report a
/// clean result, whether git listed nothing or the walk found nothing.
pub fn tracked_files(root: &Path) -> Result<Vec<String>, String> {
    let files = match git_ls_files(root)? {
        Some(files) => files,
        None => recursive_files(root)?,
    };
    if files.is_empty() {
        return Err(format!(
            "no tracked files found under {}; refusing to report a clean scan of nothing",
            root.display()
        ));
    }
    Ok(files)
}

/// `Ok(Some)` when `git ls-files` ran successfully (its empty output is
/// returned as-is and rejected by the caller); `Ok(None)` when git is
/// unusable, which selects the recursive walk. A listed path that is not
/// valid UTF-8 is an error rather than a silently dropped file.
fn git_ls_files(root: &Path) -> Result<Option<Vec<String>>, String> {
    let output = match std::process::Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
    {
        Ok(output) => output,
        Err(_) => return Ok(None),
    };
    if !output.status.success() {
        return Ok(None);
    }
    let mut files = Vec::new();
    for raw in output.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let path = std::str::from_utf8(raw).map_err(|e| {
            format!(
                "git ls-files returned a non-UTF-8 path under {}: {e}",
                root.display()
            )
        })?;
        if root.join(path).is_file() {
            files.push(path.to_string());
        }
    }
    Ok(Some(files))
}

fn recursive_files(root: &Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

/// Recursive walk. An unreadable directory or entry is an error: a scan must
/// not report clean over files it could not enumerate.
fn walk(root: &Path, cursor: &Path, out: &mut Vec<String>) -> Result<(), String> {
    let entries = fs::read_dir(cursor).map_err(|e| format!("{}: {e}", cursor.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", cursor.display()))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if SKIP_DIRS.contains(&name_str.as_ref()) {
            continue;
        }
        let path = entry.path();
        let meta = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.is_dir() {
            walk(root, &path, out)?;
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}

/// Reads a file's bytes and decodes as UTF-8, returning `None` for binary
/// content (a NUL byte anywhere, or invalid UTF-8) — matching the Node
/// scripts' `text()` helper (the byte-level variant, without the naming
/// script's extra control-character heuristic).
pub fn read_text(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    if bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

pub fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}
