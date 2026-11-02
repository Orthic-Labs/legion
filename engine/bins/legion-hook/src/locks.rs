//! One writer per file across sessions, and no edits in a checkout while a gate run holds it.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::{fs, process::Command};

use crate::protocol::{HookRequest, HookResponse};
use crate::state::{edit_path, git, now_secs, off, session_id, state_dir, write_atomic};

/// Another session's edit holds a file this long.
const WINDOW_SECS: u64 = 2 * 3600;

/// The lock file of a path; it records which session edited the path last, and when.
fn lock_file(path: &Path) -> Option<PathBuf> {
    let mut hasher = DefaultHasher::new();
    fs::canonicalize(path)
        .unwrap_or(path.to_path_buf())
        .hash(&mut hasher);
    Some(state_dir("locks")?.join(format!("{:016x}", hasher.finish())))
}

/// PostToolUse of an edit: remember this session as the file's last editor.
pub fn observe_edit(request: &HookRequest) {
    if off("locks") || !matches!(request.event_type.as_str(), "PostToolUse" | "post-effect") {
        return;
    }
    let Some(payload) = request.payload.as_object() else {
        return;
    };
    if let (Some(path), Some(session)) = (edit_path(payload), session_id(payload)) {
        let note = format!("{session} {}", now_secs());
        lock_file(&path).and_then(|file| write_atomic(&file, note.as_bytes()));
    }
}

/// The pid of a gate process (`rightkit-gate` or `rightkit-host-gate` as argv[0] or argv[1])
/// that names the checkout, in `ps -axo pid,command` output.
fn gate_holding(listing: &str, checkout: &str) -> Option<String> {
    listing.lines().find_map(|line| {
        let (pid, command) = line.trim().split_once(' ')?;
        let words: Vec<&str> = command.split_whitespace().collect();
        let gate = |word: &&str| {
            matches!(
                word.rsplit('/').next(),
                Some("rightkit-gate" | "rightkit-host-gate")
            )
        };
        let inside = |word: &&str| {
            let path = word.split('=').last().unwrap_or("");
            path == checkout || path.starts_with(&format!("{checkout}/"))
        };
        (words.iter().take(2).any(gate) && words.iter().any(inside)).then(|| pid.to_owned())
    })
}

/// A lock file's content: the editing session and the time.
fn parse_lock(text: &str) -> Option<(String, u64)> {
    let (session, time) = text.split_once(' ')?;
    Some((session.to_owned(), time.trim().parse().ok()?))
}

/// PreToolUse of an edit: deny a file another session edited and left uncommitted, or any file in a
/// checkout a gate run holds.
pub fn pre_edit(request: &HookRequest) -> Option<HookResponse> {
    if off("locks") || !request.is_pre_effect() {
        return None;
    }
    let payload = request.payload.as_object()?;
    let (path, session) = (edit_path(payload)?, session_id(payload)?);
    let (parent, name) = (
        path.parent()?,
        path.file_name()?.to_string_lossy().into_owned(),
    );
    let deny = |code: &str, message: String| {
        Some(HookResponse::denied(
            request.event_type.clone(),
            code,
            message,
            "strong",
        ))
    };
    let held = lock_file(&path).and_then(|file| fs::read_to_string(file).ok());
    if let Some((owner, time)) = held.and_then(|text| parse_lock(&text)) {
        let age = now_secs().saturating_sub(time);
        if owner != session && age <= WINDOW_SECS {
            let status = git(parent, &["status", "--porcelain", "--", name.as_str()]);
            if status.is_some_and(|out| !out.trim().is_empty()) {
                let who: String = owner.chars().take(8).collect();
                let message = format!("{name} has uncommitted edits from another session ({who}, {} min ago). Wait for it to commit, edit another file, or ask Adrian.", age / 60);
                return deny("ARC_FILE_OWNED", message);
            }
        }
    }
    let top = git(parent, &["rev-parse", "--show-toplevel"])?;
    let listing = Command::new("ps")
        .args(["-axo", "pid,command"])
        .output()
        .ok()?;
    let pid = gate_holding(&String::from_utf8_lossy(&listing.stdout), top.trim())?;
    deny(
        "ARC_CHECKOUT_BUSY",
        format!(
            "A rightkit-gate run (pid {pid}) holds {}; edits there wait until it finishes.",
            top.trim()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lock_file_names_the_session_and_the_time() {
        assert_eq!(
            parse_lock("abc-1 1700000000"),
            Some(("abc-1".to_owned(), 1_700_000_000))
        );
        assert_eq!(parse_lock("garbage"), None);
    }

    #[test]
    fn a_gate_run_holds_the_checkout_it_names() {
        let listing = "  101 /usr/local/bin/rightkit-gate --to compile /r/legion\n  202 node /opt/rightkit-host-gate check --repo=/r/other\n  303 claude -p rightkit-gate /r/legion\n";
        assert_eq!(gate_holding(listing, "/r/legion").as_deref(), Some("101"));
        assert_eq!(gate_holding(listing, "/r/other").as_deref(), Some("202"));
        assert_eq!(gate_holding(listing, "/r/legio"), None);
        assert_eq!(
            gate_holding("  303 claude -p rightkit-gate /r/legion", "/r/legion"),
            None
        );
    }
}
