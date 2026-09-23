//! Port of the path helpers in `src/lib/dispatch-validator/validate-dispatch.py`
//! (`in_platform_temp_dir`, `clean_path_value`, `repository_root`,
//! `canonical_locator`, `resolve_declared_path`, `normalized_path`,
//! `is_absolute_path`).

use std::path::{Path, PathBuf};

/// Port of `clean_path_value()`: strip whitespace and a matched pair of
/// surrounding backtick/quote characters (Python's `str.strip` on each of
/// `` ` ``, `"`, `'` in turn — applied one character class at a time, not as
/// a single pass over an arbitrary mix).
pub fn clean_path_value(value: &str) -> String {
    let mut out = value.trim().to_string();
    out = out.trim_matches('`').to_string();
    out = out.trim_matches('"').to_string();
    out = out.trim_matches('\'').to_string();
    out
}

/// Port of `is_absolute_path()`.
pub fn is_absolute_path(value: &str) -> bool {
    let raw = clean_path_value(value).replace('\\', "/");
    is_drive_absolute(&raw) || raw.starts_with('/')
}

fn is_drive_absolute(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'/'
}

/// Port of `repository_root()`: walk upward from `path` (resolving to its
/// parent directory first when `path` is not itself a directory) until a
/// `.git` entry is found.
pub fn repository_root(path: &Path) -> Option<PathBuf> {
    let resolved = dunce_resolve(path);
    let mut current = if resolved.is_dir() {
        resolved
    } else {
        resolved.parent()?.to_path_buf()
    };
    loop {
        if current.join(".git").exists() {
            return Some(current);
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => return None,
        }
    }
}

/// Port of `canonical_locator()`.
pub fn canonical_locator(path: &Path) -> String {
    let resolved = dunce_resolve(path);
    match repository_root(&resolved) {
        Some(root) => match resolved.strip_prefix(&root) {
            Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
            Err(_) => resolved.to_string_lossy().replace('\\', "/"),
        },
        None => resolved.to_string_lossy().replace('\\', "/"),
    }
}

/// Port of `resolve_declared_path()`.
pub fn resolve_declared_path(value: &str, artifact: &Path) -> PathBuf {
    let raw = clean_path_value(value).replace('\\', "/");
    if is_absolute_path(&raw) {
        return dunce_resolve(Path::new(&raw));
    }
    let root = repository_root(artifact).unwrap_or_else(|| {
        dunce_resolve(artifact)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    });
    dunce_resolve(&root.join(raw))
}

/// Best-effort port of Python's `Path.resolve()`: normalize `.`/`..`
/// segments without requiring the path to exist (mirrors `resolve(strict=
/// False)`, the default), joined against the current working directory
/// when `path` is relative.
pub fn dunce_resolve(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_path_value_strips_backticks_and_quotes() {
        assert_eq!(clean_path_value(" `foo/bar` "), "foo/bar");
        assert_eq!(clean_path_value("\"foo\""), "foo");
        assert_eq!(clean_path_value("'foo'"), "foo");
    }

    #[test]
    fn is_absolute_path_detects_unix_and_windows_drive_paths() {
        assert!(is_absolute_path("/tmp/x"));
        assert!(is_absolute_path("C:/Users/x"));
        assert!(!is_absolute_path("relative/x"));
    }

    #[test]
    fn repository_root_walks_up_to_dot_git() {
        let dir = std::env::temp_dir().join(format!("w2_044-repo-root-{}", std::process::id()));
        let nested = dir.join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        assert_eq!(repository_root(&nested), Some(dunce_resolve(&dir)));
        std::fs::remove_dir_all(&dir).ok();
    }
}
