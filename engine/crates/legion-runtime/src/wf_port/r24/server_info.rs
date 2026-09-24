//! Port of the `server.json` connection-record lifecycle from
//! `lib/impeccable-paths.mjs`: `readLiveServerInfo`, `writeLiveServerInfo`,
//! `removeLiveServerInfo`, `isLiveServerPidReachable`. Path derivation is
//! reused from the existing `q_q1::paths` port
//! (`get_live_server_path`/`get_legacy_live_server_path`) rather than
//! duplicated, per the packet rule to extend existing coverage instead of
//! re-deriving it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::wf_port::q_q1::paths::{get_legacy_live_server_path, get_live_server_path};

/// `{ pid, port, token }`, the JSON body written to `server.json` /
/// `.impeccable-live.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub pid: u32,
    pub port: u16,
    pub token: String,
}

/// `isLiveServerPidReachable(pid)`: `process.kill(pid, 0)` semantics —
/// signal 0 sends no signal but still validates the pid exists and is
/// signalable. ESRCH => unreachable (dead); EPERM (exists, not ours) =>
/// still reachable/valid, matching the JS `err.code !== 'ESRCH'` check.
#[cfg(unix)]
pub fn is_live_server_pid_reachable(pid: u32) -> bool {
    // SAFETY: `kill(pid, 0)` performs no action beyond existence/permission
    // checking; it does not dereference the pid as a pointer or otherwise
    // touch memory owned by that process.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    errno != libc::ESRCH
}

#[cfg(not(unix))]
pub fn is_live_server_pid_reachable(pid: u32) -> bool {
    // Windows has no ESRCH-equivalent `kill(pid, 0)`; matching the JS
    // fallback would need `OpenProcess`, which is out of scope for this
    // server-plumbing packet (named gap: Windows pid-liveness check).
    // Fail open, same direction as treating an unreachable pid as reachable
    // would (caller then attempts to reach the server over HTTP, which is
    // the real liveness signal `run()` relies on for the "already running"
    // guard).
    let _ = pid;
    true
}

/// `readLiveServerInfo(cwd, options)`: try `server.json`, then the legacy
/// `.impeccable-live.json`, skipping (and deleting) stale records whose pid
/// is no longer reachable. Returns `(info, path_it_was_read_from)`.
pub fn read_live_server_info(project_root: &Path) -> Option<(ServerInfo, PathBuf)> {
    for file_path in [
        get_live_server_path(project_root),
        get_legacy_live_server_path(project_root),
    ] {
        let contents = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let info: ServerInfo = match serde_json::from_str(&contents) {
            Ok(i) => i,
            Err(_) => continue,
        };
        if !is_live_server_pid_reachable(info.pid) {
            let _ = fs::remove_file(&file_path);
            continue;
        }
        return Some((info, file_path));
    }
    None
}

/// `writeLiveServerInfo(cwd, info, options)`.
pub fn write_live_server_info(project_root: &Path, info: &ServerInfo) -> io::Result<PathBuf> {
    let file_path = get_live_server_path(project_root);
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string(info)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(&file_path, body)?;
    Ok(file_path)
}

/// `removeLiveServerInfo(cwd, options)`: best-effort delete of both the
/// current and legacy record paths.
pub fn remove_live_server_info(project_root: &Path) -> io::Result<()> {
    for file_path in [
        get_live_server_path(project_root),
        get_legacy_live_server_path(project_root),
    ] {
        let _ = fs::remove_file(file_path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_project_root() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "r24-server-info-{}-{}-{}",
            std::process::id(),
            nanos,
            n
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_then_read_round_trips() {
        let root = temp_project_root();
        let info = ServerInfo {
            pid: std::process::id(),
            port: 8401,
            token: "tok-abc".to_string(),
        };
        write_live_server_info(&root, &info).unwrap();
        let (read_back, _path) = read_live_server_info(&root).unwrap();
        assert_eq!(read_back, info);
        remove_live_server_info(&root).unwrap();
        assert!(read_live_server_info(&root).is_none());
    }

    #[test]
    fn stale_pid_record_is_dropped_and_deleted() {
        let root = temp_project_root();
        // A pid essentially guaranteed not to be alive right now.
        let info = ServerInfo {
            pid: 1,
            port: 8402,
            token: "tok-def".to_string(),
        };
        // pid 1 (init/launchd) is always reachable on unix, so use an
        // out-of-range-ish pid instead to force ESRCH.
        let dead = ServerInfo { pid: 999_999, ..info };
        write_live_server_info(&root, &dead).unwrap();
        let file_path = get_live_server_path(&root);
        assert!(file_path.exists());
        let result = read_live_server_info(&root);
        #[cfg(unix)]
        {
            assert!(result.is_none(), "unreachable pid should be treated as stale");
            assert!(!file_path.exists(), "stale record should be deleted");
        }
        #[cfg(not(unix))]
        {
            let _ = result;
        }
    }

    #[test]
    fn missing_record_returns_none() {
        let root = temp_project_root();
        assert!(read_live_server_info(&root).is_none());
    }
}
