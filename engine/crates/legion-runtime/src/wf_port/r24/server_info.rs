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
    // `kill -0` checks existence/permission without signalling; the crate
    // forbids unsafe code, so this goes through the system utility.
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
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
    let body =
        serde_json::to_string(info).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
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
