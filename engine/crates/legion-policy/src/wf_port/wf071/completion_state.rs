//! Rust port of `src/lib/verification/arcane/completion-state.mjs`.
//!
//! Faithful, 1:1 port: same git subcommands, same hashing composition, same
//! traversal-escape rules, same aggregate-identity ordering rule (duplicate
//! repository cwd -> `None`).
//!
//! `pathMatches`/`normalizePath` are re-implemented here (not imported) from
//! `src/lib/guard/compat/effects/preeffect-gate.mjs` because that module is
//! out of this packet's owned scope; the glob-to-regex translation below is
//! a byte-for-byte port of `pathMatches` there.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn sha256_hex_bytes(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hex::encode(hasher.finalize())
}

fn run_git(cwd: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).current_dir(cwd).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn normalize_path(p: &str) -> String {
    let replaced = p.replace('\\', "/");
    let mut out = String::with_capacity(replaced.len());
    let mut prev_slash = false;
    for c in replaced.chars() {
        if c == '/' {
            if prev_slash {
                continue;
            }
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        out.push(c);
    }
    out
}

/// Faithful port of `pathMatches` (glob pattern -> regex) from
/// `preeffect-gate.mjs`.
pub fn path_matches(pattern: &str, target: &str) -> bool {
    let t = normalize_path(target);
    if t.split('/').any(|seg| seg == "..") {
        return false;
    }
    let mut p = normalize_path(pattern);
    if p.ends_with('/') {
        p.push_str("**");
    }
    let segments: Vec<&str> = p.split('/').collect();
    let mut rx = String::from("^");
    for (index, segment) in segments.iter().enumerate() {
        let separator = if index != 0 && segments[index - 1] != "**" { "/" } else { "" };
        if *segment == "**" {
            rx.push_str(separator);
            if index == segments.len() - 1 {
                rx.push_str(".*");
            } else {
                rx.push_str("(?:[^/]+/)*");
            }
        } else {
            rx.push_str(separator);
            let mut chars = segment.chars().peekable();
            let mut buf = String::new();
            while let Some(ch) = chars.next() {
                if ch == '*' {
                    buf.push_str("[^/]*");
                } else if ".+?^${}()|[]\\".contains(ch) {
                    buf.push('\\');
                    buf.push(ch);
                } else {
                    buf.push(ch);
                }
            }
            rx.push_str(&buf);
        }
    }
    rx.push('$');
    regex::Regex::new(&rx).map(|re| re.is_match(&t)).unwrap_or(false)
}

/// Canonicalizes the longest existing prefix of `target`, preserving any
/// not-yet-created tail (mirrors the JS `canonicalPath`).
fn canonical_path(target: &Path) -> PathBuf {
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut head = target.to_path_buf();
    loop {
        if let Ok(real) = fs::canonicalize(&head) {
            let mut result = real;
            for component in tail.iter().rev() {
                result.push(component);
            }
            return result;
        }
        let parent = match head.parent() {
            Some(p) if p != head => p.to_path_buf(),
            _ => return target.to_path_buf(),
        };
        if let Some(name) = head.file_name() {
            tail.push(name.to_os_string());
        }
        head = parent;
    }
}

/// Minimal `path.relative`-equivalent: both inputs must already be
/// absolute/canonical. Returns `None` only if components cannot be read
/// (never happens for the canonicalized paths this module passes in).
fn relative_to(target: &Path, base: &Path) -> Option<String> {
    let target_components: Vec<_> = target.components().collect();
    let base_components: Vec<_> = base.components().collect();
    let mut common = 0;
    while common < target_components.len()
        && common < base_components.len()
        && target_components[common] == base_components[common]
    {
        common += 1;
    }
    let mut parts: Vec<String> = Vec::new();
    for _ in common..base_components.len() {
        parts.push("..".to_string());
    }
    for component in &target_components[common..] {
        parts.push(component.as_os_str().to_string_lossy().to_string());
    }
    Some(parts.join("/"))
}

/// Converts a host path to its canonical repository-relative
/// representation. Paths that resolve outside `cwd` are deliberately
/// unmatchable (returns `None`).
pub fn repository_relative(target: &str, cwd: &Path) -> Option<String> {
    let value = target.replace('\\', "/");
    let segments: Vec<&str> = value.split('/').collect();
    if segments.contains(&"..") && !value.starts_with('/') {
        return None;
    }
    let root = fs::canonicalize(cwd).ok()?;
    let joined = if Path::new(&value).is_absolute() { PathBuf::from(&value) } else { root.join(&value) };
    let resolved = canonical_path(&joined);
    let local = relative_to(&resolved, &root)?;
    let local = local.replace('\\', "/");
    if local.is_empty() || local == ".." || local.starts_with("../") || local.split('/').any(|s| s == "..") {
        return None;
    }
    Some(local)
}

fn scoped_untracked(cwd: &Path, scope: &[String]) -> String {
    let listing = run_git(cwd, &["ls-files", "--others", "--exclude-standard"]).unwrap_or_default();
    let mut files: Vec<&str> = listing
        .split('\n')
        .filter(|f| !f.is_empty() && scope.iter().any(|pattern| path_matches(pattern, f)))
        .collect();
    files.sort_unstable();
    files
        .iter()
        .filter_map(|file| {
            let bytes = fs::read(cwd.join(file)).ok()?;
            Some(format!("{file}\0{}", sha256_hex_bytes(&bytes)))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

struct RepoState {
    cwd: String,
    state: String,
}

fn repository_state(cwd: &Path, scope: &[String]) -> Option<RepoState> {
    let toplevel = run_git(cwd, &["rev-parse", "--show-toplevel"])?;
    let root = fs::canonicalize(toplevel.trim()).ok()?;
    let tree = run_git(&root, &["rev-parse", "HEAD^{tree}"])?.trim().to_string();
    let diff = run_git(&root, &["diff", "--binary", "HEAD"]).unwrap_or_default();
    let status = run_git(&root, &["status", "--porcelain=v1", "--untracked-files=no"]).unwrap_or_default();
    let untracked = scoped_untracked(&root, scope);
    let composite = format!("{diff}\n{status}\n{untracked}\n");
    Some(RepoState {
        cwd: root.to_string_lossy().replace('\\', "/"),
        state: format!("git:{tree}:{}", sha256_hex(&composite)),
    })
}

/// One repository declaration for the aggregate-identity path:
/// `{ cwd, scope }` in the JS.
#[derive(Debug, Clone)]
pub struct RepositoryScope {
    pub cwd: PathBuf,
    pub scope: Vec<String>,
}

/// Backwards-compatible one-repository completion identity.
pub fn completion_integrated_state(cwd: &Path, scope: &[String]) -> Option<String> {
    repository_state(cwd, scope).map(|s| s.state)
}

/// Aggregate identity for every delivery repository. Order cannot alter it.
/// Duplicate repositories are rejected as an ambiguous delivery declaration
/// (returns `None`).
pub fn completion_integrated_state_for_repositories(repositories: &[RepositoryScope]) -> Option<String> {
    let mut states: Vec<RepoState> = repositories
        .iter()
        .map(|r| repository_state(&r.cwd, &r.scope))
        .collect::<Option<Vec<_>>>()?;
    states.sort_by(|a, b| a.cwd.cmp(&b.cwd));
    for window in states.windows(2) {
        if window[0].cwd == window[1].cwd {
            return None;
        }
    }
    let joined = states
        .iter()
        .map(|s| format!("{}\0{}", s.cwd, s.state))
        .collect::<Vec<_>>()
        .join("\n");
    Some(format!("git-repositories:{}", sha256_hex(&joined)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as StdCommand;

    fn init_repo(dir: &Path) {
        let run = |args: &[&str]| {
            let status = StdCommand::new("git").args(args).current_dir(dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        };
        run(&["init", "-q"]);
        run(&["config", "user.email", "test@example.com"]);
        run(&["config", "user.name", "Test"]);
        fs::write(dir.join("a.txt"), "hello\n").unwrap();
        run(&["add", "a.txt"]);
        run(&["commit", "-q", "-m", "init"]);
    }

    #[test]
    fn path_matches_glob_star() {
        assert!(path_matches("src/**", "src/a/b.rs"));
        assert!(path_matches("*.rs", "a.rs"));
        assert!(!path_matches("*.rs", "a/b.rs"));
        assert!(!path_matches("src/**", "other/a.rs"));
    }

    #[test]
    fn path_matches_rejects_traversal_target() {
        assert!(!path_matches("**", "../escape"));
    }

    #[test]
    fn repository_relative_normal_path() {
        let dir = std::env::temp_dir().join(format!("legion-wf071-{}", std::process::id()));
        fs::create_dir_all(dir.join("nested")).unwrap();
        let local = repository_relative("nested/file.txt", &dir);
        assert_eq!(local.as_deref(), Some("nested/file.txt"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn repository_relative_rejects_escape() {
        let dir = std::env::temp_dir().join(format!("legion-wf071-esc-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let local = repository_relative("../../etc/passwd", &dir);
        assert_eq!(local, None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn completion_integrated_state_stable_for_clean_repo() {
        let dir = std::env::temp_dir().join(format!("legion-wf071-git-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        init_repo(&dir);
        let first = completion_integrated_state(&dir, &[]);
        let second = completion_integrated_state(&dir, &[]);
        assert!(first.is_some());
        assert_eq!(first, second);
        assert!(first.unwrap().starts_with("git:"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn completion_integrated_state_changes_on_dirty_tracked_file() {
        let dir = std::env::temp_dir().join(format!("legion-wf071-dirty-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        init_repo(&dir);
        let clean = completion_integrated_state(&dir, &[]).unwrap();
        fs::write(dir.join("a.txt"), "changed\n").unwrap();
        let dirty = completion_integrated_state(&dir, &[]).unwrap();
        assert_ne!(clean, dirty);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn completion_integrated_state_changes_on_scoped_untracked_file() {
        let dir = std::env::temp_dir().join(format!("legion-wf071-untracked-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        init_repo(&dir);
        let scope = vec!["**".to_string()];
        let before = completion_integrated_state(&dir, &scope).unwrap();
        fs::write(dir.join("new.txt"), "new\n").unwrap();
        let after = completion_integrated_state(&dir, &scope).unwrap();
        assert_ne!(before, after);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn completion_integrated_state_for_repositories_rejects_duplicates() {
        let dir = std::env::temp_dir().join(format!("legion-wf071-dup-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        init_repo(&dir);
        let repos = vec![
            RepositoryScope { cwd: dir.clone(), scope: vec![] },
            RepositoryScope { cwd: dir.clone(), scope: vec![] },
        ];
        assert_eq!(completion_integrated_state_for_repositories(&repos), None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn completion_integrated_state_for_repositories_order_independent() {
        let dir_a = std::env::temp_dir().join(format!("legion-wf071-a-{}", std::process::id()));
        let dir_b = std::env::temp_dir().join(format!("legion-wf071-b-{}", std::process::id()));
        fs::create_dir_all(&dir_a).unwrap();
        fs::create_dir_all(&dir_b).unwrap();
        init_repo(&dir_a);
        init_repo(&dir_b);
        let forward = vec![
            RepositoryScope { cwd: dir_a.clone(), scope: vec![] },
            RepositoryScope { cwd: dir_b.clone(), scope: vec![] },
        ];
        let reverse = vec![
            RepositoryScope { cwd: dir_b.clone(), scope: vec![] },
            RepositoryScope { cwd: dir_a.clone(), scope: vec![] },
        ];
        let a = completion_integrated_state_for_repositories(&forward);
        let b = completion_integrated_state_for_repositories(&reverse);
        assert!(a.is_some());
        assert_eq!(a, b);
        fs::remove_dir_all(&dir_a).ok();
        fs::remove_dir_all(&dir_b).ok();
    }
}
