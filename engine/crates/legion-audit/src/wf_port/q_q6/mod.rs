//! q_q6 — packet Q6 port of the `isMainEntrypoint`/`sameExecutableHref`/
//! `normalizedExecutableHref` direct-entrypoint check shared, byte-for-byte
//! identically, by `tools/audit/audit-run.mjs` and
//! `tools/audit/audit-complete.mjs`. This is the one gap the prior wf064
//! packet's report flagged as real and unverified (`git grep` found no
//! Rust symbol for it).
//!
//! Node behaviour being mirrored:
//! - `normalizedExecutableHref(href, platform)`: parse `href` as a
//!   `file:` URL, resolve it to a filesystem path, call `realpathSync`
//!   (resolves symlinks; requires the path to exist), convert the result
//!   back to a `file:` URL, and on `platform === 'win32'` lowercase the
//!   whole string (Windows paths are case-insensitive; POSIX paths are
//!   not). If `realpathSync` throws (path does not exist, or `href` was
//!   not a valid local file URL), the original `href` string is kept
//!   unchanged instead.
//! - `isMainEntrypoint(importMetaUrl, argvPath, platform)`: `false` if
//!   `argvPath` is empty/undefined; otherwise resolve `argvPath` to an
//!   absolute path, convert it to a `file:` URL, and compare it against
//!   `importMetaUrl` via `sameExecutableHref` (which normalizes both
//!   sides). Any error (e.g. `argvPath` is not resolvable) yields `false`.
//!
//! Scope: only this pure, self-contained comparison is ported. The rest
//! of `audit-run.mjs`/`audit-complete.mjs` (CLI orchestration, dynamic
//! provider loading, bundle preparation) is out of this packet's scope —
//! see `/private/tmp/claude-501/-Volumes-D-claude-heardright/27c99660-46fe-472a-bd29-43596bb3bc77/scratchpad/loss/full-Q6.md`.
//!
//! `file:` URL construction/parsing here is a minimal, dependency-free
//! equivalent of Node's `pathToFileURL`/`fileURLToPath` sufficient for
//! comparing two local paths for entrypoint identity: it percent-encodes
//! the WHATWG URL "path" percent-encode set members most likely to appear
//! in real filesystem paths (space, `%`, `#`, `?`, `[`, `]`, and C0
//! controls) and reverses that same encoding. It intentionally does not
//! claim full RFC 3986 / WHATWG URL compliance — the only requirement for
//! this comparison is a round-trippable, deterministic mapping between an
//! absolute path and its URL form, which it provides.

use std::path::{Path, PathBuf};

/// Percent-encode the subset of bytes Node's `pathToFileURL` encodes in
/// practice for local paths: space, `%`, `#`, `?`, `[`, `]`, backslash (on
/// POSIX, a literal backslash in a path is not a separator and gets
/// encoded), and C0 controls. Everything else (including `/` as the
/// separator and non-ASCII UTF-8 bytes, which Node also percent-encodes,
/// but which this comparison-only helper passes through unchanged for
/// simplicity) is left as-is.
fn percent_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b' ' => out.push_str("%20"),
            b'%' => out.push_str("%25"),
            b'#' => out.push_str("%23"),
            b'?' => out.push_str("%3F"),
            b'[' => out.push_str("%5B"),
            b']' => out.push_str("%5D"),
            b'\\' => out.push_str("%5C"),
            0..=0x1f => out.push_str(&format!("%{byte:02X}")),
            _ => out.push(byte as char),
        }
    }
    out
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    out.push(value);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Convert an absolute filesystem path to a `file://` URL string, mirroring
/// `url.pathToFileURL(path).href` for the POSIX and Windows drive-path
/// cases used by these callers.
fn path_to_file_url(path: &Path) -> Option<String> {
    let raw = path.to_str()?;
    // Windows `canonicalize` yields verbatim `\\?\C:\...` paths.
    let raw = raw.strip_prefix(r"\\?\").unwrap_or(raw);
    if raw.is_empty() {
        return None;
    }
    // Windows drive path, e.g. `C:\foo\bar` or `C:/foo/bar`.
    if raw.len() >= 2 && raw.as_bytes()[1] == b':' && raw.as_bytes()[0].is_ascii_alphabetic() {
        let drive = &raw[..1];
        let rest = raw[2..].replace('\\', "/");
        let rest = rest.trim_start_matches('/');
        return Some(format!(
            "file:///{}:/{}",
            drive.to_string(),
            percent_encode_path(rest)
        ));
    }
    if !raw.starts_with('/') {
        return None;
    }
    Some(format!("file://{}", percent_encode_path(raw)))
}

/// Convert a `file://` URL string back to a filesystem path, mirroring
/// `url.fileURLToPath(href)` for the same two cases.
fn file_url_to_path(href: &str) -> Option<PathBuf> {
    let rest = href.strip_prefix("file://")?;
    // Windows drive form: `file:///C:/foo/bar`.
    if let Some(drive_rest) = rest.strip_prefix('/') {
        let bytes = drive_rest.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            return Some(PathBuf::from(percent_decode(drive_rest)));
        }
    }
    Some(PathBuf::from(percent_decode(rest)))
}

/// Resolve `path` the way Node's `path.resolve(path)` resolves a single
/// relative-or-absolute argument against `process.cwd()`: if already
/// absolute, return it unchanged (lexically, no symlink resolution); if
/// relative, join it onto the current working directory and lexically
/// normalize `.`/`..` segments.
fn resolve_against_cwd(path: &Path) -> Option<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let mut out: Vec<std::path::Component> = Vec::new();
    for component in joined.components() {
        match component {
            std::path::Component::ParentDir => {
                if matches!(out.last(), Some(std::path::Component::Normal(_))) {
                    out.pop();
                }
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    Some(out.into_iter().collect())
}

/// Faithful port of `normalizedExecutableHref`. `platform` matches Node's
/// `process.platform` values; only `"win32"` changes behaviour (case
/// folding).
fn normalized_executable_href(href: &str, platform: &str) -> String {
    let normalized = (|| -> Option<String> {
        let path = file_url_to_path(href)?;
        let real = std::fs::canonicalize(&path).ok()?;
        path_to_file_url(&real)
    })()
    .unwrap_or_else(|| href.to_string());
    if platform == "win32" {
        normalized.to_lowercase()
    } else {
        normalized
    }
}

/// Faithful port of `sameExecutableHref`.
pub fn same_executable_href(left_href: &str, right_href: &str, platform: &str) -> bool {
    normalized_executable_href(left_href, platform) == normalized_executable_href(right_href, platform)
}

/// Faithful port of `isMainEntrypoint`. `argv_path` is `None`/empty for
/// `!argvPath` (JS falsy: `undefined`, `null`, or `""`).
pub fn is_main_entrypoint(import_meta_url: &str, argv_path: Option<&str>, platform: &str) -> bool {
    let argv_path = match argv_path {
        Some(p) if !p.is_empty() => p,
        _ => return false,
    };
    let resolved = match resolve_against_cwd(Path::new(argv_path)) {
        Some(p) => p,
        None => return false,
    };
    let href = match path_to_file_url(&resolved) {
        Some(h) => h,
        None => return false,
    };
    same_executable_href(&href, import_meta_url, platform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn canon(p: &Path) -> std::io::Result<PathBuf> {
        let real = std::fs::canonicalize(p)?;
        let text = real.to_string_lossy();
        Ok(text.strip_prefix(r"\\?\").map(PathBuf::from).unwrap_or(real))
    }

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "q_q6_entrypoint_{}_{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "// test").unwrap();
        path
    }

    #[test]
    fn no_argv_path_is_false() {
        assert!(!is_main_entrypoint("file:///whatever.mjs", None, "darwin"));
        assert!(!is_main_entrypoint("file:///whatever.mjs", Some(""), "darwin"));
    }

    #[test]
    fn matching_direct_invocation_is_true() {
        let dir = temp_dir();
        let script = write_file(&dir, "audit-run.mjs");
        let real = canon(&script).unwrap();
        let import_meta_url = path_to_file_url(&real).unwrap();
        assert!(is_main_entrypoint(
            &import_meta_url,
            Some(script.to_str().unwrap()),
            "darwin"
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn imported_not_directly_run_is_false() {
        let dir = temp_dir();
        let script = write_file(&dir, "audit-run.mjs");
        let other = write_file(&dir, "audit-complete.mjs");
        let real = canon(&other).unwrap();
        let import_meta_url = path_to_file_url(&real).unwrap();
        assert!(!is_main_entrypoint(
            &import_meta_url,
            Some(script.to_str().unwrap()),
            "darwin"
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn win32_comparison_is_case_insensitive() {
        let dir = temp_dir();
        let script = write_file(&dir, "Audit-Run.mjs");
        let real = canon(&script).unwrap();
        let href_lower = path_to_file_url(&real).unwrap().to_lowercase();
        // Simulate a Windows-style argv path whose case differs only in
        // casing from the on-disk file; win32 folding makes them equal.
        assert!(same_executable_href(&href_lower, &path_to_file_url(&real).unwrap(), "win32"));
    }

    #[test]
    fn nonexistent_path_falls_back_to_href_string_and_is_false() {
        // realpathSync throws on a path that does not exist; the original
        // href is kept, so it will not match a genuinely resolved sibling.
        assert!(!is_main_entrypoint(
            "file:///does/not/exist/audit-run.mjs",
            Some("/definitely/not/here/audit-run.mjs"),
            "darwin"
        ));
    }

    #[test]
    fn round_trip_file_url_conversion() {
        let dir = temp_dir();
        let script = write_file(&dir, "a file.mjs");
        let real = canon(&script).unwrap();
        let href = path_to_file_url(&real).unwrap();
        assert!(href.contains("%20"));
        let back = file_url_to_path(&href).unwrap();
        // Compare component-wise, never as raw strings (Windows
        // canonicalize adds a `\\?\` prefix that a string compare would
        // wrongly reject).
        assert_eq!(back.components().collect::<Vec<_>>(), real.components().collect::<Vec<_>>());
        std::fs::remove_dir_all(&dir).ok();
    }
}
