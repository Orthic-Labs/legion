//! Port of `skills/designer/engine/scripts/lib/impeccable-paths.mjs`
//! (chunk w2_016).
//!
//! GAP vs. the JS source: every JS function takes `cwd` and resolves the
//! project root itself via `resolveProjectRoot` from
//! `skills/designer/engine/scripts/context.mjs` — a file outside this
//! chunk's ownership (`w2_016` owns only files under
//! `skills/designer/engine/scripts/lib/`). This port therefore takes the
//! already-resolved project `root: &Path` directly instead of `cwd` +
//! internally calling `resolveProjectRoot`; the caller (wherever
//! `context.mjs`/its Rust port lands) is expected to resolve the root once
//! and pass it in. All path-joining logic below is otherwise a faithful,
//! byte-for-byte mirror of the JS.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const IMPECCABLE_DIR: &str = ".impeccable";
pub const LIVE_DIR: &str = "live";
pub const CRITIQUE_DIR: &str = "critique";

pub fn get_impeccable_dir(root: &Path) -> PathBuf {
    root.join(IMPECCABLE_DIR)
}

pub fn get_design_sidecar_path(root: &Path) -> PathBuf {
    get_impeccable_dir(root).join("design.json")
}

/// Mirrors `getDesignSidecarCandidates(cwd, contextDir)`: the resolved
/// sidecar path, the legacy `DESIGN.json` at the project root, and the
/// legacy `DESIGN.json` in `context_dir` (deduped).
pub fn get_design_sidecar_candidates(root: &Path, context_dir: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![
        get_design_sidecar_path(root),
        root.join("DESIGN.json"),
    ];
    let context_legacy = context_dir.join("DESIGN.json");
    if !candidates.contains(&context_legacy) {
        candidates.push(context_legacy);
    }
    candidates
}

pub fn resolve_design_sidecar_path(root: &Path, context_dir: &Path) -> Option<PathBuf> {
    first_existing(&get_design_sidecar_candidates(root, context_dir))
}

pub fn get_live_dir(root: &Path) -> PathBuf {
    get_impeccable_dir(root).join(LIVE_DIR)
}

pub fn get_live_config_path(root: &Path) -> PathBuf {
    get_live_dir(root).join("config.json")
}

pub fn get_legacy_live_config_path(scripts_dir: &Path) -> PathBuf {
    scripts_dir.join("config.json")
}

/// Mirrors `resolveLiveConfigPath({ cwd, scriptsDir, env, targetPath })`.
/// `cwd` is used only to resolve a relative `IMPECCABLE_LIVE_CONFIG` env
/// value, matching the JS (`path.resolve(cwd, configured)`); it is
/// independent of `root` (the project root used for the default path).
pub fn resolve_live_config_path(
    root: &Path,
    cwd: &Path,
    scripts_dir: Option<&Path>,
    env_live_config: Option<&str>,
) -> PathBuf {
    if let Some(configured) = env_live_config {
        let trimmed = configured.trim();
        if !trimmed.is_empty() {
            let p = Path::new(trimmed);
            return if p.is_absolute() {
                p.to_path_buf()
            } else {
                cwd.join(p)
            };
        }
    }
    let primary = get_live_config_path(root);
    if primary.exists() {
        return primary;
    }
    if let Some(scripts_dir) = scripts_dir {
        let legacy = get_legacy_live_config_path(scripts_dir);
        if legacy.exists() {
            return legacy;
        }
    }
    primary
}

pub fn get_live_server_path(root: &Path) -> PathBuf {
    get_live_dir(root).join("server.json")
}

pub fn get_legacy_live_server_path(root: &Path) -> PathBuf {
    root.join(".impeccable-live.json")
}

#[derive(Debug, Clone)]
pub struct LiveServerInfo {
    pub path: PathBuf,
    pub raw: serde_json::Value,
}

/// Mirrors `readLiveServerInfo(cwd)`: checks the modern then legacy path,
/// treating a stale (unreachable) pid as absent and deleting that file, like
/// the JS `fs.unlinkSync` best-effort cleanup.
pub fn read_live_server_info(root: &Path) -> Option<LiveServerInfo> {
    for file_path in [get_live_server_path(root), get_legacy_live_server_path(root)] {
        let Ok(raw_str) = fs::read_to_string(&file_path) else {
            continue;
        };
        let Ok(info) = serde_json::from_str::<serde_json::Value>(&raw_str) else {
            continue;
        };
        if let Some(pid) = info.get("pid").and_then(|v| v.as_i64()) {
            if !is_live_server_pid_reachable(pid) {
                let _ = fs::remove_file(&file_path);
                continue;
            }
        }
        return Some(LiveServerInfo {
            path: file_path,
            raw: info,
        });
    }
    None
}

/// Mirrors the JS `process.kill(pid, 0)` liveness probe: `ESRCH` (no such
/// process) means unreachable; any other error (notably `EPERM`, process
/// exists but not signalable by this user) is treated as reachable.
#[cfg(unix)]
pub fn is_live_server_pid_reachable(pid: i64) -> bool {
    // Shell out to `kill -0` rather than calling libc's kill() directly:
    // this crate forbids unsafe code, and `kill -0` gives the same
    // ESRCH-vs-everything-else semantics without an FFI declaration.
    match std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .output()
    {
        Ok(output) => output.status.success() || output.status.code() != Some(1),
        // If we can't even spawn `kill`, conservatively assume reachable
        // rather than deleting live server info we can't verify.
        Err(_) => true,
    }
}

#[cfg(not(unix))]
pub fn is_live_server_pid_reachable(_pid: i64) -> bool {
    // No portable signal-0 probe on non-Unix; conservatively assume
    // reachable rather than deleting live server info we can't verify.
    true
}

pub fn write_live_server_info(root: &Path, info: &serde_json::Value) -> io::Result<PathBuf> {
    let file_path = get_live_server_path(root);
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&file_path, serde_json::to_string(info).unwrap())?;
    Ok(file_path)
}

pub fn remove_live_server_info(root: &Path) {
    for file_path in [get_live_server_path(root), get_legacy_live_server_path(root)] {
        let _ = fs::remove_file(&file_path);
    }
}

pub fn get_live_sessions_dir(root: &Path) -> PathBuf {
    get_live_dir(root).join("sessions")
}

pub fn get_legacy_live_sessions_dir(root: &Path) -> PathBuf {
    root.join(".impeccable-live").join("sessions")
}

pub fn get_live_annotations_dir(root: &Path) -> PathBuf {
    get_live_dir(root).join("annotations")
}

pub fn get_critique_dir(root: &Path) -> PathBuf {
    get_impeccable_dir(root).join(CRITIQUE_DIR)
}

pub fn get_legacy_live_annotations_dir(root: &Path) -> PathBuf {
    root.join(".impeccable-live").join("annotations")
}

fn first_existing(paths: &[PathBuf]) -> Option<PathBuf> {
    paths.iter().find(|p| p.exists()).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "w2-016-impeccable-paths-{}-{}",
                std::process::id(),
                n
            ));
            fs::create_dir_all(&path).unwrap();
            TmpDir(path)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn path_layout_matches_js() {
        let root = Path::new("/proj");
        assert_eq!(get_impeccable_dir(root), Path::new("/proj/.impeccable"));
        assert_eq!(
            get_design_sidecar_path(root),
            Path::new("/proj/.impeccable/design.json")
        );
        assert_eq!(get_live_dir(root), Path::new("/proj/.impeccable/live"));
        assert_eq!(
            get_live_config_path(root),
            Path::new("/proj/.impeccable/live/config.json")
        );
        assert_eq!(
            get_live_server_path(root),
            Path::new("/proj/.impeccable/live/server.json")
        );
        assert_eq!(
            get_legacy_live_server_path(root),
            Path::new("/proj/.impeccable-live.json")
        );
        assert_eq!(
            get_live_sessions_dir(root),
            Path::new("/proj/.impeccable/live/sessions")
        );
        assert_eq!(
            get_legacy_live_sessions_dir(root),
            Path::new("/proj/.impeccable-live/sessions")
        );
        assert_eq!(
            get_critique_dir(root),
            Path::new("/proj/.impeccable/critique")
        );
    }

    #[test]
    fn design_sidecar_candidates_dedupe_context_dir() {
        let root = Path::new("/proj");
        let candidates = get_design_sidecar_candidates(root, root);
        // contextDir == cwd == root here, so the context-legacy candidate is
        // identical to the project-root legacy candidate and is deduped away.
        assert_eq!(
            candidates,
            vec![
                Path::new("/proj/.impeccable/design.json").to_path_buf(),
                Path::new("/proj/DESIGN.json").to_path_buf(),
            ]
        );
    }

    #[test]
    fn design_sidecar_candidates_keep_distinct_context_dir() {
        let root = Path::new("/proj");
        let context_dir = Path::new("/proj/sub");
        let candidates = get_design_sidecar_candidates(root, context_dir);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[2], Path::new("/proj/sub/DESIGN.json"));
    }

    #[test]
    fn resolve_design_sidecar_path_prefers_first_existing() {
        let dir = TmpDir::new();
        let root = dir.0.clone();
        fs::write(root.join("DESIGN.json"), "{}").unwrap();
        let resolved = resolve_design_sidecar_path(&root, &root).unwrap();
        assert_eq!(resolved, root.join("DESIGN.json"));
    }

    #[test]
    fn resolve_design_sidecar_path_none_when_nothing_exists() {
        let dir = TmpDir::new();
        assert!(resolve_design_sidecar_path(&dir.0, &dir.0).is_none());
    }

    #[test]
    fn resolve_live_config_path_env_override_wins() {
        let dir = TmpDir::new();
        let resolved =
            resolve_live_config_path(&dir.0, &dir.0, None, Some("custom/live-config.json"));
        assert_eq!(resolved, dir.0.join("custom/live-config.json"));
    }

    #[test]
    fn resolve_live_config_path_prefers_primary_then_legacy_then_default() {
        let dir = TmpDir::new();
        let root = dir.0.clone();
        let scripts_dir = root.join("scripts");
        fs::create_dir_all(&scripts_dir).unwrap();

        // Neither exists: falls back to the primary (default) path.
        let resolved = resolve_live_config_path(&root, &root, Some(&scripts_dir), None);
        assert_eq!(resolved, get_live_config_path(&root));

        // Legacy exists, primary doesn't: use legacy.
        fs::write(scripts_dir.join("config.json"), "{}").unwrap();
        let resolved = resolve_live_config_path(&root, &root, Some(&scripts_dir), None);
        assert_eq!(resolved, scripts_dir.join("config.json"));

        // Primary exists too: primary wins.
        fs::create_dir_all(get_live_dir(&root)).unwrap();
        fs::write(get_live_config_path(&root), "{}").unwrap();
        let resolved = resolve_live_config_path(&root, &root, Some(&scripts_dir), None);
        assert_eq!(resolved, get_live_config_path(&root));
    }

    #[test]
    fn write_read_remove_live_server_info_round_trip() {
        let dir = TmpDir::new();
        let root = dir.0.clone();
        let info = serde_json::json!({ "pid": std::process::id() as i64, "port": 4321 });
        write_live_server_info(&root, &info).unwrap();
        let read = read_live_server_info(&root).unwrap();
        assert_eq!(read.raw.get("port").and_then(|v| v.as_i64()), Some(4321));
        remove_live_server_info(&root);
        assert!(read_live_server_info(&root).is_none());
    }

    #[test]
    fn read_live_server_info_drops_unreachable_pid() {
        let dir = TmpDir::new();
        let root = dir.0.clone();
        // PID 1 is init on Linux/macOS and reachable; use an implausible pid
        // instead to force ESRCH-style "no such process".
        let info = serde_json::json!({ "pid": 999_999_999_i64 });
        write_live_server_info(&root, &info).unwrap();
        assert!(read_live_server_info(&root).is_none());
        // The stale file should have been removed.
        assert!(!get_live_server_path(&root).exists());
    }
}
