pub mod authority_parity;
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
pub fn tracked_files(root: &Path) -> Vec<String> {
    if let Ok(output) = std::process::Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
    {
        if output.status.success() {
            let files: Vec<String> = output
                .stdout
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .filter_map(|s| std::str::from_utf8(s).ok())
                .map(|s| s.to_string())
                .filter(|p| {
                    let abs = root.join(p);
                    abs.is_file()
                })
                .collect();
            if !files.is_empty() || is_empty_repo(root) {
                return files;
            }
        }
    }
    recursive_files(root)
}

fn is_empty_repo(_root: &Path) -> bool {
    // `git ls-files` legitimately returning zero entries is indistinguishable
    // from "git failed silently" here; prefer trusting git's success status.
    true
}

fn recursive_files(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn walk(root: &Path, cursor: &Path, out: &mut Vec<String>) {
    let entries = match fs::read_dir(cursor) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if SKIP_DIRS.contains(&name_str.as_ref()) {
            continue;
        }
        let path = entry.path();
        let meta = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk(root, &path, out);
        } else if meta.is_file() {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
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
