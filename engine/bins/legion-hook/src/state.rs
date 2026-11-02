//! Shared hook state: state folder, atomic writes, kill switch, mode and payload fields.

use std::env::{var, var_os};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, io::Write};

use serde_json::{Map, Value};

pub type Payload = Map<String, Value>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Off,
    Shadow,
    Enforce,
}

/// `$LEGION_STATE_DIR`, else `$LEGION_STATE_ROOT/hook-state`, else `~/.legion`.
pub fn state_root() -> Option<PathBuf> {
    let env = |name: &str| var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    let home = env("HOME").or_else(|| env("USERPROFILE"));
    let root = env("LEGION_STATE_ROOT").map(|root| root.join("hook-state"));
    let home = home.map(|home| home.join(".legion"));
    env("LEGION_STATE_DIR").or(root).or(home)
}

pub fn state_dir(name: &str) -> Option<PathBuf> {
    Some(state_root()?.join(name))
}

/// Write a temp file beside `path`, then rename it into place.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Option<()> {
    fs::create_dir_all(path.parent()?).ok()?;
    let temp = path.with_extension(format!("tmp{}", std::process::id()));
    fs::write(&temp, bytes).ok()?;
    fs::rename(&temp, path).ok()
}

/// Append one line with a single write, so concurrent hooks do not interleave.
pub fn append_line(path: &Path, line: &str) -> Option<()> {
    fs::create_dir_all(path.parent()?).ok()?;
    let mut options = fs::OpenOptions::new();
    let mut file = options.append(true).create(true).open(path).ok()?;
    file.write_all(format!("{line}\n").as_bytes()).ok()
}

/// True when `LEGION_HOOK_OFF` (a comma list) names the check.
pub fn off(check_id: &str) -> bool {
    let list = var("LEGION_HOOK_OFF").unwrap_or_default();
    list.split(',').any(|id| id.trim() == check_id)
}

/// Mode from an env var: `off`, `enforce` (or `block`, `on`); anything else is shadow.
pub fn mode(env_var: &str) -> Mode {
    match var(env_var).unwrap_or_default().trim() {
        "off" => Mode::Off,
        "enforce" | "block" | "on" => Mode::Enforce,
        _ => Mode::Shadow,
    }
}

pub fn now_secs() -> u64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH);
    since.map_or(0, |elapsed| elapsed.as_secs())
}

pub fn str_field(object: &Payload, keys: &[&str]) -> Option<String> {
    let found = keys.iter().find_map(|key| object.get(*key)?.as_str())?;
    Some(found.trim().to_owned()).filter(|text| !text.is_empty())
}

pub fn session_id(payload: &Payload) -> Option<String> {
    let raw = str_field(payload, &["session_id", "sessionId"])?;
    let safe = |c: &char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_');
    let id: String = raw.chars().filter(safe).take(96).collect();
    (!id.is_empty()).then_some(id)
}

pub fn tool_name(payload: &Payload) -> Option<String> {
    str_field(payload, &["tool_name", "toolName"])
}

pub fn tool_input(payload: &Payload) -> Option<&Payload> {
    let input = payload.get("tool_input").or(payload.get("toolInput"));
    input?.as_object()
}

/// The file an edit tool call writes, made absolute against the payload's cwd.
pub fn edit_path(payload: &Payload) -> Option<PathBuf> {
    let tool = tool_name(payload)?;
    if !["Write", "Edit", "MultiEdit", "NotebookEdit"].contains(&tool.as_str()) {
        return None;
    }
    let keys = ["file_path", "filePath", "notebook_path", "path"];
    let file = str_field(tool_input(payload)?, &keys)?;
    let cwd = str_field(payload, &["cwd", "workdir"]).unwrap_or_default();
    Some(PathBuf::from(cwd).join(file))
}

/// stdout of `git -C dir args`; `None` when git fails or takes over 5 s.
pub fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let mut command = std::process::Command::new("git");
    command.env("GIT_OPTIONAL_LOCKS", "0");
    command.arg("-C").arg(dir).args(args);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || sender.send(command.output()));
    let wait = std::time::Duration::from_secs(5);
    let output = receiver.recv_timeout(wait).ok()?.ok()?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    output.status.success().then_some(text)
}

pub fn ledger(session: &str) -> Vec<Value> {
    let path = state_dir("evidence").map(|dir| dir.join(format!("{session}.jsonl")));
    let text = path.and_then(|path| fs::read_to_string(path).ok());
    let parse = |line: &str| serde_json::from_str(line).ok();
    text.unwrap_or_default().lines().filter_map(parse).collect()
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A fresh empty directory under the system temp folder.
    pub fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = format!("legion-hook-{name}-{}-{nanos}", std::process::id());
        let dir = std::env::temp_dir().join(dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn session_id_keeps_only_file_safe_characters() {
        let payload: Payload = serde_json::from_str(r#"{"session_id":"ab-1/../x y"}"#).unwrap();
        assert_eq!(session_id(&payload).as_deref(), Some("ab-1xy"));
    }

    #[test]
    fn atomic_write_replaces_and_lines_append() {
        let dir = temp_dir("state");
        let file = dir.join("sub").join("a.json");
        write_atomic(&file, b"one").unwrap();
        write_atomic(&file, b"two").unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "two");
        let log = dir.join("log.jsonl");
        append_line(&log, "a").unwrap();
        append_line(&log, "b").unwrap();
        assert_eq!(fs::read_to_string(&log).unwrap(), "a\nb\n");
    }

    #[test]
    fn relative_edit_paths_join_the_cwd() {
        let json = r#"{"cwd":"/r","tool_name":"Edit","tool_input":{"file_path":"src/a.rs"}}"#;
        let payload: Payload = serde_json::from_str(json).unwrap();
        assert_eq!(edit_path(&payload), Some(PathBuf::from("/r/src/a.rs")));
    }
}
