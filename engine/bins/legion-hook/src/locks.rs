//! One writer per file, across sessions (fix plan M6). Check id `locks`.
//!
//! - `observe_edit` (PostToolUse of an edit tool) records
//!   `{path, session_id, t}` in `<state>/locks/index.json`.
//! - `pre_edit` (PreToolUse of an edit tool) denies an edit to a path that
//!   another session edited within the last two hours while that file still
//!   has uncommitted changes (`ARC_FILE_OWNED`), and denies edits inside a
//!   checkout while a `rightkit-gate` run holds it (`ARC_CHECKOUT_BUSY`).
//!
//! Fails open everywhere: an unreadable index, a failing or slow `git`/`ps`,
//! a missing field or an unsupported host allows the edit.

use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    time::Duration,
};

use serde_json::{json, Map, Value};

use crate::protocol::{HookRequest, HookResponse};
use crate::skills_gate::{
    check_disabled, now_secs, session_id, state_dir, str_field, tool_input, tool_name, write_atomic,
};

pub const CHECK: &str = "locks";

const STATE_FOLDER: &str = "locks";
const INDEX_FILE: &str = "index.json";
/// An edit by another session blocks for this long.
const WINDOW_SECS: u64 = 2 * 3600;
/// Older index entries are dropped on the next write.
const RETAIN_SECS: u64 = 12 * 3600;
const MAX_ENTRIES: usize = 4000;
const EDIT_TOOLS: [&str; 5] = ["Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"];
const GIT_TIMEOUT: Duration = Duration::from_secs(3);
const PS_TIMEOUT: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// Index (pure model + thin I/O)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct LockEntry {
    path: String,
    session_id: String,
    t: u64,
}

fn parse_index(bytes: &[u8]) -> Vec<LockEntry> {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    value
        .get("entries")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some(LockEntry {
                        path: item.get("path")?.as_str()?.to_owned(),
                        session_id: item.get("session_id")?.as_str()?.to_owned(),
                        t: item.get("t").and_then(Value::as_u64)?,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn render_index(entries: &[LockEntry]) -> Vec<u8> {
    let value = json!({
        "entries": entries
            .iter()
            .map(|e| json!({"path": e.path, "session_id": e.session_id, "t": e.t}))
            .collect::<Vec<Value>>(),
    });
    let mut bytes = serde_json::to_vec(&value).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// Upsert `(path, session)` at `now`, drop stale entries, cap the size.
fn record(entries: &mut Vec<LockEntry>, path: &str, session: &str, now: u64) {
    entries.retain(|entry| {
        now.saturating_sub(entry.t) <= RETAIN_SECS
            && !(entry.path == path && entry.session_id == session)
    });
    entries.push(LockEntry {
        path: path.to_owned(),
        session_id: session.to_owned(),
        t: now,
    });
    if entries.len() > MAX_ENTRIES {
        let excess = entries.len() - MAX_ENTRIES;
        entries.drain(..excess);
    }
}

/// The most recent edit of `path` by a session other than `session`, inside
/// the two-hour window.
fn other_owner<'a>(
    entries: &'a [LockEntry],
    path: &str,
    session: &str,
    now: u64,
) -> Option<&'a LockEntry> {
    entries
        .iter()
        .filter(|entry| {
            entry.path == path
                && entry.session_id != session
                && now.saturating_sub(entry.t) <= WINDOW_SECS
        })
        .max_by_key(|entry| entry.t)
}

fn index_path() -> Option<PathBuf> {
    Some(state_dir(STATE_FOLDER)?.join(INDEX_FILE))
}

/// Run `body` while holding `<dir>/index.lock` (best effort): the lock is a
/// `create_new` file, a lock older than five seconds is stolen, and after
/// about 300 ms the body runs without it. A lost update only weakens the check.
fn with_index_lock<T>(dir: &Path, body: impl FnOnce() -> T) -> T {
    let lock = dir.join("index.lock");
    let _ = fs::create_dir_all(dir);
    let mut held = false;
    for _ in 0..30 {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
        {
            Ok(_) => {
                held = true;
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let stale = fs::metadata(&lock)
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age >= Duration::from_secs(5));
                if stale {
                    let _ = fs::remove_file(&lock);
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            Err(_) => break,
        }
    }
    let result = body();
    if held {
        let _ = fs::remove_file(&lock);
    }
    result
}

// ---------------------------------------------------------------------------
// Payload: which files does this edit touch
// ---------------------------------------------------------------------------

fn is_edit_tool(tool: &str) -> bool {
    EDIT_TOOLS.contains(&tool)
}

/// `*** Add File: x` / `*** Update File: x` / `*** Delete File: x` /
/// `*** Move to: x` lines of a Codex `apply_patch` body.
fn patch_paths(patch: &str) -> Vec<String> {
    const MARKERS: [&str; 4] = [
        "*** Add File: ",
        "*** Update File: ",
        "*** Delete File: ",
        "*** Move to: ",
    ];
    patch
        .lines()
        .filter_map(|line| {
            MARKERS
                .iter()
                .find_map(|marker| line.trim().strip_prefix(marker))
        })
        .map(|path| path.trim().to_owned())
        .filter(|path| !path.is_empty())
        .collect()
}

fn patch_text(input: &Map<String, Value>) -> Option<String> {
    for key in ["command", "input", "patch"] {
        match input.get(key) {
            Some(Value::String(text)) => return Some(text.clone()),
            Some(Value::Array(parts)) => {
                let joined: Vec<&str> = parts.iter().filter_map(Value::as_str).collect();
                if !joined.is_empty() {
                    return Some(joined.join("\n"));
                }
            }
            _ => {}
        }
    }
    None
}

/// Absolute paths an edit tool call touches (relative paths join `cwd`).
fn edit_paths(tool: &str, payload: &Map<String, Value>) -> Vec<PathBuf> {
    let Some(input) = tool_input(payload) else {
        return Vec::new();
    };
    let raw: Vec<String> = if tool == "apply_patch" {
        patch_text(input)
            .map(|patch| patch_paths(&patch))
            .unwrap_or_default()
    } else {
        str_field(input, &["file_path", "notebook_path", "path"])
            .into_iter()
            .collect()
    };
    let cwd = str_field(payload, &["cwd", "workdir"]).map(PathBuf::from);
    raw.into_iter()
        .map(|path| {
            let path = PathBuf::from(path);
            match (&cwd, path.is_relative()) {
                (Some(cwd), true) => cwd.join(path),
                _ => path,
            }
        })
        .collect()
}

/// A stable key for a path: symlinks in the directory part are resolved even
/// when the file does not exist yet.
fn canonical_key(path: &Path) -> String {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical.to_string_lossy().into_owned();
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        if let Ok(parent) = fs::canonicalize(parent) {
            return parent.join(name).to_string_lossy().into_owned();
        }
    }
    path.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// PostToolUse: record edits
// ---------------------------------------------------------------------------

/// PostToolUse of an edit tool: record the touched paths for this session.
/// Observation only; any failure is ignored.
pub fn observe_edit(request: &HookRequest) {
    if check_disabled(CHECK)
        || !matches!(request.event_type.as_str(), "PostToolUse" | "post-effect")
    {
        return;
    }
    let Some(payload) = request.payload.as_object() else {
        return;
    };
    let Some(tool) = tool_name(payload) else {
        return;
    };
    if !is_edit_tool(&tool) {
        return;
    }
    let Some(session) = session_id(payload) else {
        return;
    };
    let keys: Vec<String> = edit_paths(&tool, payload)
        .iter()
        .map(|path| canonical_key(path))
        .collect();
    if keys.is_empty() {
        return;
    }
    let (Some(dir), Some(index)) = (state_dir(STATE_FOLDER), index_path()) else {
        return;
    };
    let now = now_secs();
    with_index_lock(&dir, || {
        let mut entries = fs::read(&index)
            .map(|bytes| parse_index(&bytes))
            .unwrap_or_default();
        for key in &keys {
            record(&mut entries, key, &session, now);
        }
        let _ = write_atomic(&index, &render_index(&entries));
    });
}

// ---------------------------------------------------------------------------
// Subprocess helpers (fail open)
// ---------------------------------------------------------------------------

/// Run `command` and give up after `limit`. The child may outlive a timeout;
/// the hook process exits right after, and an orphaned `git status` or `ps`
/// finishes on its own.
fn run_with_timeout(mut command: Command, limit: Duration) -> Option<std::process::Output> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(command.output());
    });
    receiver.recv_timeout(limit).ok()?.ok()
}

/// `Some(true)` when `git status --porcelain` lists the file, `Some(false)`
/// when it is clean or ignored, `None` when git could not answer.
fn has_uncommitted_changes(file: &Path) -> Option<bool> {
    let parent = file.parent()?;
    let name = file.file_name()?;
    if !parent.is_dir() {
        return None;
    }
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(parent)
        .args(["status", "--porcelain", "--"])
        .arg(name)
        .env("GIT_OPTIONAL_LOCKS", "0");
    let output = run_with_timeout(command, GIT_TIMEOUT)?;
    if !output.status.success() {
        return None;
    }
    Some(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

fn git_toplevel(dir: &Path) -> Option<PathBuf> {
    if !dir.is_dir() {
        return None;
    }
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .env("GIT_OPTIONAL_LOCKS", "0");
    let output = run_with_timeout(command, GIT_TIMEOUT)?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.trim();
    (!line.is_empty()).then(|| PathBuf::from(line))
}

// ---------------------------------------------------------------------------
// Running gate (pure parsing + thin `ps`)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct GateProcess {
    pid: String,
    command: String,
}

fn is_gate_token(token: &str) -> bool {
    let token = token.trim_matches(|c: char| c == '"' || c == '\'');
    let base = token.rsplit('/').next().unwrap_or(token);
    base == "rightkit-gate" || base.starts_with("rightkit-gate.")
}

/// A gate run: `rightkit-gate` is the program, or one of the first two
/// arguments of an interpreter or shell (`node .../rightkit-gate`,
/// `zsh -c "rightkit-gate ..."`). A long-lived `claude -p "...rightkit-gate..."`
/// whose prompt merely mentions it does not count.
fn is_gate_command(command: &str) -> bool {
    command.split_whitespace().take(3).any(is_gate_token)
}

fn parse_gate_processes(listing: &str) -> Vec<GateProcess> {
    listing
        .lines()
        .filter_map(|line| {
            let (pid, command) = line.trim_start().split_once(char::is_whitespace)?;
            if pid.is_empty() || !pid.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let command = command.trim();
            is_gate_command(command).then(|| GateProcess {
                pid: pid.to_owned(),
                command: command.to_owned(),
            })
        })
        .collect()
}

/// Live `rightkit-gate` processes (macOS only; empty elsewhere or on error).
fn running_gate_processes() -> Vec<GateProcess> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    let mut command = Command::new("ps");
    command.args(["-axo", "pid,command"]);
    let Some(output) = run_with_timeout(command, PS_TIMEOUT) else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    parse_gate_processes(&String::from_utf8_lossy(&output.stdout))
}

/// The path part of one argv token (`--flag=value` yields the value).
fn token_path(token: &str) -> &str {
    let token = token.trim_matches(|c: char| c == '"' || c == '\'');
    let value = token.split_once('=').map(|(_, rest)| rest).unwrap_or(token);
    value.trim_matches(|c: char| c == '"' || c == '\'')
}

/// The gate process that holds `checkout`, if any: one of its argv paths is
/// the checkout itself, or lies inside it and resolves (through
/// `toplevel_of`) to that same checkout. A path inside a nested repository
/// resolves to the nested one, so a gate on `legion` does not hold the
/// workspace repository that merely contains it.
fn gate_holding<'a>(
    processes: &'a [GateProcess],
    checkout: &str,
    toplevel_of: &dyn Fn(&str) -> Option<String>,
) -> Option<&'a GateProcess> {
    let checkout = checkout.trim_end_matches('/');
    if checkout.is_empty() {
        return None;
    }
    processes.iter().find(|process| {
        process.command.split_whitespace().any(|token| {
            let candidate = token_path(token);
            if candidate == checkout {
                return true;
            }
            candidate
                .strip_prefix(checkout)
                .is_some_and(|rest| rest.starts_with('/'))
                && toplevel_of(candidate).as_deref() == Some(checkout)
        })
    })
}

/// The git toplevel of a path (a file resolves through its folder).
fn toplevel_of_path(path: &str) -> Option<String> {
    let path = Path::new(path);
    let dir = if path.is_dir() { path } else { path.parent()? };
    git_toplevel(dir).map(|top| top.to_string_lossy().into_owned())
}

// ---------------------------------------------------------------------------
// PreToolUse: deny
// ---------------------------------------------------------------------------

fn short_session(session: &str) -> String {
    session.chars().take(8).collect()
}

fn owned_denial(event_type: &str, path: &str, owner: &LockEntry, now: u64) -> HookResponse {
    let minutes = now.saturating_sub(owner.t) / 60;
    HookResponse::denied(
        event_type.to_owned(),
        "ARC_FILE_OWNED",
        format!(
            "{path} has uncommitted edits from another session ({}, {minutes} min ago). \
             Wait for that session to commit it, edit a different file, or ask Adrian.",
            short_session(&owner.session_id)
        ),
        "strong",
    )
}

fn busy_denial(event_type: &str, checkout: &str, process: &GateProcess) -> HookResponse {
    HookResponse::denied(
        event_type.to_owned(),
        "ARC_CHECKOUT_BUSY",
        format!(
            "A rightkit-gate run (pid {}) holds {checkout}; edits there wait until it finishes.",
            process.pid
        ),
        "strong",
    )
}

/// PreToolUse of an edit tool: deny a file another live session is editing,
/// or any file in a checkout a gate run holds. Returns `None` to allow.
pub fn pre_edit(request: &HookRequest) -> Option<HookResponse> {
    if check_disabled(CHECK) || !request.is_pre_effect() {
        return None;
    }
    let payload = request.payload.as_object()?;
    let tool = tool_name(payload)?;
    if !is_edit_tool(&tool) {
        return None;
    }
    let session = session_id(payload)?;
    let paths = edit_paths(&tool, payload);
    if paths.is_empty() {
        return None;
    }
    let now = now_secs();
    let entries = index_path()
        .and_then(|path| fs::read(path).ok())
        .map(|bytes| parse_index(&bytes))
        .unwrap_or_default();
    let mut gates: Option<Vec<GateProcess>> = None;
    for path in &paths {
        let key = canonical_key(path);
        if let Some(owner) = other_owner(&entries, &key, &session, now) {
            if has_uncommitted_changes(Path::new(&key)) == Some(true) {
                return Some(owned_denial(&request.event_type, &key, owner, now));
            }
        }
        let processes = gates.get_or_insert_with(running_gate_processes);
        if processes.is_empty() {
            continue;
        }
        let parent = Path::new(&key).parent().map(Path::to_path_buf)?;
        if let Some(checkout) = git_toplevel(&parent) {
            let checkout = checkout.to_string_lossy().into_owned();
            if let Some(process) = gate_holding(processes, &checkout, &toplevel_of_path) {
                return Some(busy_denial(&request.event_type, &checkout, process));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "legion-hook-{tag}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).expect("create test dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn entry(path: &str, session: &str, t: u64) -> LockEntry {
        LockEntry {
            path: path.to_owned(),
            session_id: session.to_owned(),
            t,
        }
    }

    #[test]
    fn index_round_trips_and_tolerates_garbage() {
        let entries = vec![entry("/a/b.rs", "s1", 10), entry("/a/c.rs", "s2", 20)];
        assert_eq!(parse_index(&render_index(&entries)), entries);
        assert!(parse_index(b"not json").is_empty());
        assert!(parse_index(br#"{"entries":[{"path":"/x"}]}"#).is_empty());
    }

    #[test]
    fn record_upserts_one_entry_per_path_and_session() {
        let mut entries = vec![entry("/a", "s1", 10)];
        record(&mut entries, "/a", "s1", 50);
        record(&mut entries, "/a", "s2", 60);
        assert_eq!(entries, vec![entry("/a", "s1", 50), entry("/a", "s2", 60)]);
    }

    #[test]
    fn record_drops_entries_past_the_retention_window() {
        let mut entries = vec![entry("/old", "s1", 0)];
        record(&mut entries, "/new", "s1", RETAIN_SECS + 1);
        assert_eq!(entries, vec![entry("/new", "s1", RETAIN_SECS + 1)]);
    }

    #[test]
    fn other_owner_ignores_self_stale_and_other_paths() {
        let now = 100_000;
        let entries = vec![
            entry("/a", "mine", now - 10),
            entry("/a", "old", now - WINDOW_SECS - 1),
            entry("/b", "other", now - 10),
            entry("/a", "recent", now - 60),
            entry("/a", "recent2", now - 30),
        ];
        let owner = other_owner(&entries, "/a", "mine", now).expect("owner");
        assert_eq!(owner.session_id, "recent2");
        assert!(other_owner(&entries, "/c", "mine", now).is_none());
        assert!(other_owner(&entries[..2], "/a", "mine", now).is_none());
    }

    #[test]
    fn patch_paths_reads_codex_apply_patch_bodies() {
        let patch = "*** Begin Patch\n*** Update File: src/a.rs\n@@\n-x\n+y\n*** Add File: b.txt\n+z\n*** Delete File: c.txt\n*** End Patch";
        assert_eq!(patch_paths(patch), vec!["src/a.rs", "b.txt", "c.txt"]);
    }

    #[test]
    fn edit_paths_join_relative_paths_to_cwd() {
        let payload = json!({
            "cwd": "/repo",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/a.rs"}
        });
        let object = payload.as_object().expect("object");
        assert_eq!(
            edit_paths("Edit", object),
            vec![PathBuf::from("/repo/src/a.rs")]
        );
        let payload = json!({"tool_name": "Write", "tool_input": {"file_path": "/abs/b.rs"}});
        let object = payload.as_object().expect("object");
        assert_eq!(
            edit_paths("Write", object),
            vec![PathBuf::from("/abs/b.rs")]
        );
        let payload = json!({"tool_name": "Edit", "tool_input": {}});
        assert!(edit_paths("Edit", payload.as_object().expect("object")).is_empty());
    }

    #[test]
    fn gate_commands_need_the_gate_as_program_or_early_argument() {
        assert!(is_gate_command(
            "/Users/a/.local/bin/rightkit-gate --to dev -- --platform mac"
        ));
        assert!(is_gate_command(
            "node /opt/rightkit/rightkit-gate.mjs --to dev /Volumes/D/claude/legion"
        ));
        assert!(is_gate_command("/bin/zsh -c rightkit-gate --to dev"));
        assert!(!is_gate_command(
            "claude -p please run rightkit-gate on /Volumes/D/claude/legion"
        ));
        assert!(!is_gate_command(
            "grep -r rightkit-gate-cache /Volumes/D/claude/legion"
        ));
        assert!(!is_gate_command("/usr/bin/vim notes.md"));
    }

    #[test]
    fn ps_listing_yields_only_gate_processes() {
        let listing = "  PID COMMAND\n  101 /sbin/launchd\n 2024 rightkit-gate --to dev /Volumes/D/claude/legion\n 2025 claude -p mention rightkit-gate /Volumes/D/claude/legion\n";
        assert_eq!(
            parse_gate_processes(listing),
            vec![GateProcess {
                pid: "2024".into(),
                command: "rightkit-gate --to dev /Volumes/D/claude/legion".into()
            }]
        );
    }

    #[test]
    fn gate_holds_a_checkout_only_when_its_path_is_in_argv() {
        let legion = "/Volumes/D/claude/legion";
        let resolver = |path: &str| path.starts_with(legion).then(|| legion.to_owned());
        let flagged = vec![GateProcess {
            pid: "9".into(),
            command:
                "rightkit-gate --to dev --repo=/Volumes/D/claude/legion/engine -- --platform mac"
                    .into(),
        }];
        assert!(gate_holding(&flagged, legion, &resolver).is_some());
        assert!(gate_holding(&flagged, "/Volumes/D/claude/legion/", &resolver).is_some());
        // The workspace repo contains legion but is not what the gate builds.
        assert!(gate_holding(&flagged, "/Volumes/D/claude", &resolver).is_none());
        assert!(gate_holding(&flagged, "/Volumes/D/claude/legion2", &resolver).is_none());
        assert!(gate_holding(&flagged, "/Volumes/D/claude/pulse", &resolver).is_none());
        assert!(gate_holding(&[], legion, &resolver).is_none());
        let exact = vec![GateProcess {
            pid: "10".into(),
            command: "rightkit-gate --to dev /Volumes/D/claude/legion".into(),
        }];
        assert!(gate_holding(&exact, legion, &|_: &str| None).is_some());
    }

    #[test]
    fn index_lock_runs_the_body_and_releases() {
        let dir = TestDir::new("lock");
        let value = with_index_lock(dir.path(), || 7);
        assert_eq!(value, 7);
        assert!(!dir.path().join("index.lock").exists());
        // A lock held by someone else delays the body by about 300 ms at most.
        fs::write(dir.path().join("index.lock"), b"").expect("write lock");
        assert_eq!(with_index_lock(dir.path(), || 8), 8);
    }

    #[test]
    fn denial_names_the_other_session() {
        let owner = entry("/repo/a.rs", "abcdef123456", 1000);
        let response = owned_denial("PreToolUse", "/repo/a.rs", &owner, 1000 + 600);
        assert!(!response.allowed);
        assert_eq!(response.code.as_deref(), Some("ARC_FILE_OWNED"));
        assert!(response.reason.contains("abcdef12"));
        assert!(response.reason.contains("10 min ago"));
    }
}
