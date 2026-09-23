//! Pure path/scope primitives ported from `validate-dispatch.py`.
//!
//! Every function here is a direct, faithful port of its Python
//! counterpart (same name in a `snake_case` -> already-`snake_case`
//! mapping; see the module docs). Path "resolution" below is a **lexical**
//! reimplementation of `pathlib.Path(...).resolve(strict=False)`: it
//! anchors a relative path at the current working directory and collapses
//! `.`/`..` components without touching the filesystem, which matches
//! Python's behaviour for every path the validator actually receives
//! (declared dispatch/receipt/authority paths that may not exist yet). It
//! does not resolve symlinks, which CPython's `resolve()` does for the
//! portion of the path that exists on disk; none of the ported call sites
//! depend on symlink resolution.

use std::env;
use std::path::{Component, Path, PathBuf};

/// Port of `clean_path_value`.
pub fn clean_path_value(value: &str) -> String {
    let trimmed = value.trim();
    let trimmed = trimmed.trim_matches('`');
    let trimmed = trimmed.trim_matches('"');
    trimmed.trim_matches('\'').to_string()
}

/// Port of `is_absolute_path`.
pub fn is_absolute_path(value: &str) -> bool {
    let raw = clean_path_value(value).replace('\\', "/");
    is_windows_drive_absolute(&raw) || raw.starts_with('/')
}

fn is_windows_drive_absolute(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'/'
}

/// Expand a leading `~` or `~/...` to the user's home directory, mirroring
/// `Path.expanduser()`. Any other path is returned unchanged.
fn expanduser(raw: &str) -> String {
    if raw == "~" || raw.starts_with("~/") {
        if let Ok(home) = env::var("HOME") {
            let home = home.trim_end_matches('/');
            return if raw == "~" {
                home.to_string()
            } else {
                format!("{home}/{}", &raw["~/".len()..])
            };
        }
    }
    raw.to_string()
}

/// Lexically anchor `raw` at `cwd` (if relative) and collapse `.`/`..`
/// components, mirroring `Path(...).resolve(strict=False)` without
/// filesystem access.
fn lexical_resolve(raw: &str, cwd: &Path) -> PathBuf {
    let expanded = expanduser(raw);
    let candidate = Path::new(&expanded);
    let anchored: PathBuf = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        cwd.join(candidate)
    };

    let mut out: Vec<Component> = Vec::new();
    for component in anchored.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                match out.last() {
                    Some(Component::Normal(_)) => {
                        out.pop();
                    }
                    Some(Component::RootDir) | None => {
                        // Cannot go above root; Python silently keeps root.
                    }
                    _ => out.push(component),
                }
            }
            other => out.push(other),
        }
    }
    out.into_iter().collect()
}

/// Resolve a path the way this validator resolves every path it is handed:
/// lexically, anchored at the process current working directory.
pub fn resolve(raw: &str) -> PathBuf {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    lexical_resolve(raw, &cwd)
}

fn resolve_at(raw: &str, cwd: &Path) -> PathBuf {
    lexical_resolve(raw, cwd)
}

/// Port of `in_platform_temp_dir`.
pub fn in_platform_temp_dir(path: &Path) -> bool {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let temp_root = resolve_at(&env::temp_dir().to_string_lossy(), &cwd);
    let resolved = resolve_at(&path.to_string_lossy(), &cwd);
    if resolved == temp_root {
        return true;
    }
    resolved
        .ancestors()
        .skip(1)
        .any(|ancestor| ancestor == temp_root.as_path())
}

/// Port of `repository_root`: walk from `path` (or its parent, if `path`
/// is not itself a directory) upward looking for a `.git` entry.
pub fn repository_root(path: &Path) -> Option<PathBuf> {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let resolved = resolve_at(&path.to_string_lossy(), &cwd);
    let start = if resolved.is_dir() {
        resolved
    } else {
        resolved.parent().map(Path::to_path_buf).unwrap_or(resolved)
    };
    std::iter::once(start.clone())
        .chain(start.ancestors().skip(1).map(Path::to_path_buf))
        .find(|candidate| candidate.join(".git").exists())
}

/// Port of `canonical_locator`.
pub fn canonical_locator(path: &Path) -> String {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let resolved = resolve_at(&path.to_string_lossy(), &cwd);
    match repository_root(&resolved) {
        None => resolved.to_string_lossy().to_string(),
        Some(root) => match resolved.strip_prefix(&root) {
            Ok(relative) => relative.to_string_lossy().replace('\\', "/"),
            Err(_) => resolved.to_string_lossy().to_string(),
        },
    }
}

/// Port of `resolve_declared_path`.
pub fn resolve_declared_path(value: &str, artifact: &Path) -> PathBuf {
    let raw = clean_path_value(value).replace('\\', "/");
    if is_absolute_path(&raw) {
        return resolve(&raw);
    }
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let artifact_resolved = resolve_at(&artifact.to_string_lossy(), &cwd);
    let base = repository_root(&artifact_resolved).unwrap_or_else(|| {
        artifact_resolved
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or(artifact_resolved.clone())
    });
    resolve_at(&base.join(&raw).to_string_lossy(), &cwd)
}

/// Port of `normalized_path`. `platform_name` mirrors the Python
/// function's optional override of `os.name` (pass `Some("nt")` to force
/// Windows case-folding).
pub fn normalized_path(value: &str, platform_name: Option<&str>) -> String {
    let raw = clean_path_value(value).replace('\\', "/");
    let normalized = if is_windows_drive_absolute(&raw) {
        raw.trim_end_matches('/').to_string()
    } else {
        resolve(&raw)
            .to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_string()
    };
    let is_windows = platform_name.unwrap_or(if cfg!(windows) { "nt" } else { "posix" }) == "nt";
    if is_windows {
        normalized.to_lowercase()
    } else {
        normalized
    }
}

/// Port of `posixpath.normpath` (the subset used by `direct_scope_path`):
/// collapse redundant separators and resolve `.`/`..` segments purely
/// lexically, POSIX-style (no drive letters, no filesystem access).
fn posix_normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let leading_slashes = path.chars().take_while(|&c| c == '/').count();
    // POSIX: exactly two leading slashes is preserved; 1 or 3+ collapse to 1.
    let prefix = match leading_slashes {
        0 => "",
        2 => "//",
        _ => "/",
    };

    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                let can_pop = matches!(out.last(), Some(&p) if p != "..");
                if !prefix.is_empty() && out.is_empty() {
                    // leading ".." above an absolute root is a no-op.
                } else if can_pop {
                    out.pop();
                } else if prefix.is_empty() {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }

    let joined = out.join("/");
    let result = format!("{prefix}{joined}");
    if result.is_empty() {
        ".".to_string()
    } else {
        result
    }
}

/// Port of `direct_scope_path`.
pub fn direct_scope_path(value: &str) -> Option<String> {
    let path = value.trim().replace('\\', "/");
    if path.is_empty() || path.contains('\0') || is_absolute_path(&path) {
        return None;
    }
    let normalized = posix_normpath(&path);
    if normalized == "." || normalized == ".." || normalized.starts_with("../") {
        return None;
    }
    Some(if cfg!(windows) {
        normalized.to_lowercase()
    } else {
        normalized
    })
}

/// Port of `direct_file_allowlist_path`.
pub fn direct_file_allowlist_path(value: &str) -> Option<String> {
    let raw = value.trim().replace('\\', "/");
    let normalized = direct_scope_path(&raw)?;
    if raw.ends_with('/') || raw.chars().any(|c| matches!(c, '*' | '?' | '[')) {
        return None;
    }
    Some(normalized)
}

/// Port of `scope_static_prefix`.
pub fn scope_static_prefix(value: &str) -> String {
    let mut concrete: Vec<&str> = Vec::new();
    for part in value.split('/') {
        if part.chars().any(|c| matches!(c, '*' | '?' | '[')) {
            break;
        }
        concrete.push(part);
    }
    concrete.join("/")
}

/// Port of `scopes_overlap`.
pub fn scopes_overlap(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    let left_prefix = scope_static_prefix(left);
    let right_prefix = scope_static_prefix(right);
    if left_prefix.is_empty() || right_prefix.is_empty() {
        return true;
    }
    left_prefix == right_prefix
        || left_prefix.starts_with(&format!("{right_prefix}/"))
        || right_prefix.starts_with(&format!("{left_prefix}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_path_value_strips_whitespace_backticks_and_quotes() {
        assert_eq!(clean_path_value("  `\"'a/b.md'\"`  "), "a/b.md");
        assert_eq!(clean_path_value("plain/path"), "plain/path");
    }

    #[test]
    fn is_absolute_path_matches_unix_and_windows_forms() {
        assert!(is_absolute_path("/abs/path"));
        assert!(is_absolute_path("C:/abs/path"));
        assert!(is_absolute_path("C:\\abs\\path"));
        assert!(!is_absolute_path("relative/path"));
        assert!(!is_absolute_path("Cabs/path"));
    }

    #[test]
    fn direct_scope_path_rejects_absolute_null_and_escaping_paths() {
        assert_eq!(direct_scope_path("a/b"), Some("a/b".to_string()));
        assert_eq!(direct_scope_path("./a/../b"), Some("b".to_string()));
        assert_eq!(direct_scope_path("a/./b/"), Some("a/b".to_string()));
        assert_eq!(direct_scope_path("/abs"), None);
        assert_eq!(direct_scope_path(""), None);
        assert_eq!(direct_scope_path("."), None);
        assert_eq!(direct_scope_path(".."), None);
        assert_eq!(direct_scope_path("../escape"), None);
        assert_eq!(direct_scope_path("a\0b"), None);
    }

    #[test]
    fn direct_file_allowlist_path_forbids_globs_and_directories() {
        assert_eq!(
            direct_file_allowlist_path("engine/src/lib.rs"),
            Some("engine/src/lib.rs".to_string())
        );
        assert_eq!(direct_file_allowlist_path("engine/src/"), None);
        assert_eq!(direct_file_allowlist_path("engine/*.rs"), None);
        assert_eq!(direct_file_allowlist_path("engine/[abc].rs"), None);
        assert_eq!(direct_file_allowlist_path("engine/file?.rs"), None);
    }

    #[test]
    fn scope_static_prefix_stops_at_first_glob_token() {
        assert_eq!(scope_static_prefix("a/b/c"), "a/b/c");
        assert_eq!(scope_static_prefix("a/b/*/c"), "a/b");
        assert_eq!(scope_static_prefix("a/*"), "a");
        assert_eq!(scope_static_prefix("*"), "");
    }

    #[test]
    fn scopes_overlap_is_conservative_on_unresolved_globs() {
        assert!(scopes_overlap("a/b", "a/b"));
        assert!(scopes_overlap("a/b", "a/b/c"));
        assert!(scopes_overlap("a/b/c", "a/b"));
        assert!(!scopes_overlap("a/b", "a/c"));
        assert!(scopes_overlap("a/*", "a/b")); // empty-ish prefix side stays conservative
        assert!(scopes_overlap("*", "anything"));
    }

    #[test]
    fn resolve_declared_path_prefers_repository_root_over_artifact_parent() {
        let dir = tempdir();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let artifact = dir.join("sub").join("dispatch.md");
        std::fs::write(&artifact, "x").unwrap();

        let resolved = resolve_declared_path("engine/src/lib.rs", &artifact);
        assert_eq!(resolved, dir.join("engine/src/lib.rs"));

        let abs = dir.join("elsewhere/file.rs");
        let resolved_abs =
            resolve_declared_path(&abs.to_string_lossy(), &artifact);
        assert_eq!(resolved_abs, abs);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn canonical_locator_returns_repo_relative_posix_path() {
        let dir = tempdir();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let nested = dir.join("a").join("b.md");
        std::fs::create_dir_all(nested.parent().unwrap()).unwrap();
        std::fs::write(&nested, "x").unwrap();

        assert_eq!(canonical_locator(&nested), "a/b.md");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn in_platform_temp_dir_detects_process_temp_root_and_descendants() {
        let temp_root = env::temp_dir();
        assert!(in_platform_temp_dir(&temp_root));
        assert!(in_platform_temp_dir(&temp_root.join("nested/file.md")));
        assert!(!in_platform_temp_dir(Path::new("/definitely/not/temp/file.md")));
    }

    fn tempdir() -> PathBuf {
        let dir = env::temp_dir().join(format!(
            "legion-w2_045-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
