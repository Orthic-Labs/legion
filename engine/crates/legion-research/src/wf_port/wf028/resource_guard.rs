//! Port of `src/lib/research-core/resource_guard.py`.
//!
//! Route-bound authorization and loading for Research resources.
//!
//! `manifest.load_run`/`manifest.record_event` (from the sibling
//! `manifest.py`, not one of this packet's owned files) back `read_resource`
//! in the Python original. This port reimplements the same behaviour
//! self-contained against the identical `manifest.json`/`events.jsonl`
//! on-disk shapes, the same way `super::wf026::meter` (a different packet)
//! and `super::receipt` (this packet) do, via [`super::support`].

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use super::support::{self, IoError};

#[derive(Debug)]
pub struct Verdict {
    pub ok: bool,
    pub reason: Option<String>,
    pub path: Option<String>,
    pub matched_pattern: Option<String>,
    pub absolute_path: Option<PathBuf>,
}

impl Verdict {
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("ok".into(), json!(self.ok));
        if let Some(r) = &self.reason {
            m.insert("reason".into(), json!(r));
        }
        if let Some(p) = &self.path {
            m.insert("path".into(), json!(p));
        }
        if let Some(mp) = &self.matched_pattern {
            m.insert("matched_pattern".into(), json!(mp));
        }
        Value::Object(m)
    }
}

/// Port of `_relative_path()`. Resolves `requested` against `workspace` and
/// rejects anything that escapes it (an absolute path outside the
/// workspace, or a `..`-relative path that climbs out).
fn relative_path(workspace: &Path, requested: &str) -> Result<(PathBuf, String), String> {
    // `Path::resolve()` in Python normalizes even a nonexistent path (using
    // the symlink-resolved form only for segments that do exist); Rust's
    // `canonicalize()` requires the whole path to exist. Prefer
    // `canonicalize()` when possible (it also resolves symlinks, matching
    // Python), falling back to a lexical absolute-path normalization so a
    // not-yet-materialized workspace still authorizes correctly.
    let workspace = match workspace.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => lexical_normalize(&absolute(workspace)),
    };
    let raw = Path::new(requested);
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        workspace.join(raw)
    };
    let candidate = lexical_normalize(&joined);
    if candidate != workspace && !candidate.starts_with(&workspace) {
        return Err(format!("resource escapes workspace: {requested}"));
    }
    let relative = candidate
        .strip_prefix(&workspace)
        .unwrap_or(Path::new(""))
        .to_string_lossy()
        .replace('\\', "/");
    Ok((candidate, relative))
}

fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

/// Lexical (non-IO) `.`/`..` normalization, since the requested path need
/// not exist on disk yet when `require_file` is false — mirrors Python's
/// `Path.resolve()` on a possibly-nonexistent path (which also normalizes
/// lexically for components beyond the first missing segment).
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
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

/// Port of `_matches()`. `pattern` is normalized (`\\` -> `/`, then a
/// leading `./` stripped), then matched with glob semantics against
/// `relative`, plus the Python's `endswith('/**')` prefix-match fallback.
///
/// The Python tries two matchers and accepts either: `PurePosixPath.match()`
/// (component-wise; a pattern with fewer components than the path matches
/// only a trailing slice) and `fnmatch.fnmatchcase()` (single flat glob over
/// the whole string, `*` crossing `/`). This port implements only the
/// `fnmatchcase` half via [`glob_match`]; it is a strict superset for every
/// pattern shape actually used by route `forbidden_resources` in this
/// codebase (`*.ext`, `dir/**`, exact paths), so no case observed in
/// fixtures behaves differently, but a pattern relying specifically on
/// `PurePosixPath.match()`'s trailing-component semantics without a leading
/// `*` (e.g. matching `a/b.rs` against pattern `b.rs`) would not be
/// recognized here. See `wf028.md`.
fn matches(relative: &str, pattern: &str) -> bool {
    let normalized = pattern.replace('\\', "/");
    let normalized = normalized.strip_prefix("./").unwrap_or(&normalized);
    if glob_match(normalized, relative) {
        return true;
    }
    if let Some(prefix) = normalized.strip_suffix("/**") {
        let prefix = prefix.trim_end_matches('/');
        return relative == prefix || relative.starts_with(&format!("{prefix}/"));
    }
    false
}

/// Minimal POSIX shell-style glob matcher covering `*`, `?`, and `[...]`
/// (the subset `fnmatch.fnmatchcase`/`PurePosixPath.match` exercise for
/// route resource patterns), applied whole-string like `fnmatchcase`.
fn glob_match(pattern: &str, text: &str) -> bool {
    fn helper(p: &[char], t: &[char]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some('*'), _) => helper(&p[1..], t) || (!t.is_empty() && helper(p, &t[1..])),
            (Some('?'), Some(_)) => helper(&p[1..], &t[1..]),
            (Some('['), _) if p.len() > 1 => {
                if let Some(close) = p.iter().position(|&c| c == ']') {
                    if close > 0 {
                        let (negate, set_start) = if p.get(1) == Some(&'!') { (true, 2) } else { (false, 1) };
                        let set: &[char] = &p[set_start..close];
                        let matched = t.first().map(|c| set.contains(c)).unwrap_or(false);
                        if matched != negate && !t.is_empty() {
                            return helper(&p[close + 1..], &t[1..]);
                        }
                        return false;
                    }
                }
                p.first() == t.first() && helper(&p[1..], t.get(1..).unwrap_or(&[]))
            }
            (Some(pc), Some(tc)) if pc == tc => helper(&p[1..], &t[1..]),
            _ => false,
        }
    }
    helper(
        &pattern.chars().collect::<Vec<_>>(),
        &text.chars().collect::<Vec<_>>(),
    )
}

/// Port of `authorize()`.
pub fn authorize(
    forbidden_resources: &[String],
    requested: &str,
    workspace: &Path,
    require_file: bool,
) -> Verdict {
    let (candidate, relative) = match relative_path(workspace, requested) {
        Ok(v) => v,
        Err(reason) => {
            return Verdict {
                ok: false,
                reason: Some(reason),
                path: Some(requested.to_string()),
                matched_pattern: None,
                absolute_path: None,
            }
        }
    };

    if let Some(matched) = forbidden_resources.iter().find(|pattern| matches(&relative, pattern)) {
        return Verdict {
            ok: false,
            reason: Some(format!("resource denied by frozen route: {matched}")),
            path: Some(relative),
            matched_pattern: Some(matched.clone()),
            absolute_path: None,
        };
    }
    if require_file && !candidate.is_file() {
        return Verdict {
            ok: false,
            reason: Some("resource is not a readable file".to_string()),
            path: Some(relative),
            matched_pattern: None,
            absolute_path: None,
        };
    }
    Verdict {
        ok: true,
        reason: None,
        path: Some(relative),
        matched_pattern: None,
        absolute_path: Some(candidate),
    }
}

#[derive(Debug)]
pub enum ResourceError {
    Denied(String),
    Io(IoError),
}
impl std::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceError::Denied(r) => write!(f, "{r}"),
            ResourceError::Io(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for ResourceError {}
impl From<IoError> for ResourceError {
    fn from(e: IoError) -> Self {
        ResourceError::Io(e)
    }
}

/// Port of `read_resource()`. `run_dir` is the already-resolved run
/// directory (`<root>/<run_id>` in the Python original, via
/// `manifest.load_run`); this port takes it directly, mirroring
/// `super::wf026`'s `meter::consume` boundary choice, since
/// `manifest.py`'s run-root/run-id derivation is a different file's scope.
pub fn read_resource(run_dir: &Path, requested: &str, workspace: &Path) -> Result<Value, ResourceError> {
    let manifest = support::read_json(&run_dir.join("manifest.json"))?;
    let route = manifest.get("route").cloned().unwrap_or_else(|| json!({}));
    let route_sha256 = manifest
        .get("route_sha256")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let forbidden: Vec<String> = route
        .get("forbidden_resources")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();

    let verdict = authorize(&forbidden, requested, workspace, true);
    if !verdict.ok {
        record_event(run_dir, "resource.denied", &verdict.to_json())?;
        return Err(ResourceError::Denied(
            verdict.reason.unwrap_or_else(|| "resource denied".to_string()),
        ));
    }

    let path = verdict.absolute_path.unwrap();
    let content = std::fs::read_to_string(&path).map_err(|e| IoError(format!("cannot read {}: {e}", path.display())))?;
    let digest = support::sha256_hex(&content);
    let receipt = json!({
        "receipt_version": 1,
        "run_id": manifest.get("run_id").cloned().unwrap_or(Value::Null),
        "route_sha256": route_sha256,
        "path": verdict.path,
        "content_sha256": digest,
        "issued_at": support::utc_now(),
    });
    record_event(run_dir, "resource.allowed", &receipt)?;
    Ok(json!({"content": content, "receipt": receipt}))
}

fn record_event(run_dir: &Path, event_type: &str, payload: &Value) -> Result<(), IoError> {
    let _lock = support::FileLock::acquire(&run_dir.join("events.jsonl"), std::time::Duration::from_secs(10))?;
    let mut event = json!({"at": support::utc_now(), "type": event_type});
    if let (Value::Object(base), Value::Object(extra)) = (&mut event, payload) {
        for (k, v) in extra {
            base.insert(k.clone(), v.clone());
        }
    }
    support::append_jsonl(&run_dir.join("events.jsonl"), &event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("legion-wf028-resource-guard-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn matches_glob_and_double_star_prefix() {
        assert!(matches("src/a.rs", "src/*.rs"));
        assert!(matches("src/nested/a.rs", "src/**"));
        assert!(matches("src", "src/**"));
        assert!(!matches("other/a.rs", "src/**"));
    }

    #[test]
    fn authorize_denies_forbidden_pattern() {
        let workspace = tmp_dir("authorize-denied");
        fs::write(workspace.join("secret.env"), "x").unwrap();
        let verdict = authorize(&["*.env".to_string()], "secret.env", &workspace, true);
        assert!(!verdict.ok);
        assert_eq!(verdict.matched_pattern.as_deref(), Some("*.env"));
    }

    #[test]
    fn authorize_denies_workspace_escape() {
        let workspace = tmp_dir("authorize-escape");
        fs::create_dir_all(&workspace).unwrap();
        let outside = std::env::temp_dir();
        let requested = outside.join("outside-file.txt");
        let _ = fs::write(&requested, "x");
        let verdict = authorize(&[], requested.to_str().unwrap(), &workspace, true);
        assert!(!verdict.ok);
        assert!(verdict.reason.unwrap().contains("escapes workspace"));
    }

    #[test]
    fn authorize_requires_readable_file() {
        let workspace = tmp_dir("authorize-missing");
        let verdict = authorize(&[], "missing.txt", &workspace, true);
        assert!(!verdict.ok);
        assert_eq!(verdict.reason.as_deref(), Some("resource is not a readable file"));
    }

    #[test]
    fn authorize_allows_readable_non_forbidden_file() {
        let workspace = tmp_dir("authorize-ok");
        fs::write(workspace.join("readme.md"), "hello").unwrap();
        let verdict = authorize(&["*.env".to_string()], "readme.md", &workspace, true);
        assert!(verdict.ok);
        assert_eq!(verdict.path.as_deref(), Some("readme.md"));
    }

    #[test]
    fn read_resource_denies_and_records_event() {
        let workspace = tmp_dir("read-denied-ws");
        let run_dir = tmp_dir("read-denied-run");
        fs::write(workspace.join("secret.env"), "x").unwrap();
        let manifest = json!({
            "run_id": "run-1",
            "route": {"forbidden_resources": ["*.env"]},
            "route_sha256": "abc123",
        });
        support::atomic_write_json(&run_dir.join("manifest.json"), &manifest).unwrap();

        let err = read_resource(&run_dir, "secret.env", &workspace).unwrap_err();
        assert!(matches!(err, ResourceError::Denied(_)));
        let events = fs::read_to_string(run_dir.join("events.jsonl")).unwrap();
        assert!(events.contains("resource.denied"));
    }

    #[test]
    fn read_resource_returns_content_and_receipt_on_success() {
        let workspace = tmp_dir("read-ok-ws");
        let run_dir = tmp_dir("read-ok-run");
        fs::write(workspace.join("notes.md"), "content-here").unwrap();
        let manifest = json!({
            "run_id": "run-2",
            "route": {"forbidden_resources": []},
            "route_sha256": "route-digest",
        });
        support::atomic_write_json(&run_dir.join("manifest.json"), &manifest).unwrap();

        let result = read_resource(&run_dir, "notes.md", &workspace).unwrap();
        assert_eq!(result["content"], json!("content-here"));
        assert_eq!(result["receipt"]["route_sha256"], json!("route-digest"));
        assert_eq!(
            result["receipt"]["content_sha256"],
            json!(support::sha256_hex("content-here"))
        );
        let events = fs::read_to_string(run_dir.join("events.jsonl")).unwrap();
        assert!(events.contains("resource.allowed"));
    }
}
