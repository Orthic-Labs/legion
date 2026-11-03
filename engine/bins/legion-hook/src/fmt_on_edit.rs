//! Format Rust at edit time: pipe the edited `.rs` file through rustfmt and write it back when it changed.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::{fs, time::Duration};

use crate::protocol::HookRequest;
use crate::state::{edit_path, off, write_atomic};

/// The edition of the nearest `Cargo.toml` that names one in quotes (a workspace edition sits further up).
fn edition(path: &Path) -> String {
    let year = |dir: &Path| {
        let text = fs::read_to_string(dir.join("Cargo.toml")).ok()?;
        let line = text
            .lines()
            .find(|l| l.trim_start().starts_with("edition") && l.contains('"'))?;
        Some(line.split('"').nth(1)?.to_owned())
    };
    path.ancestors()
        .skip(1)
        .find_map(year)
        .unwrap_or("2021".to_owned())
}

/// Fixture paths, and files the nearest `.rightkit/fixture-files.json` names, keep their exact text.
fn is_fixture(path: &Path) -> bool {
    let text = path.to_string_lossy().replace('\\', "/");
    let listed = path.ancestors().skip(1).find_map(|dir| {
        let list = fs::read_to_string(dir.join(".rightkit/fixture-files.json")).ok()?;
        let relative = path
            .strip_prefix(dir)
            .ok()?
            .to_string_lossy()
            .replace('\\', "/");
        Some(list.contains(&format!("\"{relative}\"")))
    });
    ["/tests/fixtures/", "/scripts/ci/fixtures/"]
        .iter()
        .any(|dir| text.contains(dir))
        || listed == Some(true)
}

/// rustfmt's output for `source`; `None` when rustfmt is missing, rejects the text or takes over 5 s.
fn rustfmt(source: &str, edition: &str, dir: &Path) -> Option<String> {
    let mut command = Command::new("rustfmt");
    command.args(["--edition", edition, "--emit", "stdout"]);
    command.stdin(Stdio::piped()).stdout(Stdio::piped());
    command.current_dir(dir);
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut command, 0x0800_0000);
    let mut child = command.spawn().ok()?;
    let mut stdin = child.stdin.take()?;
    let input = source.to_owned();
    std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || sender.send(child.wait_with_output()));
    let output = receiver.recv_timeout(Duration::from_secs(5)).ok()?.ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    output.status.success().then_some(text)
}

/// PostToolUse of an edit to a `.rs` file: format that one file. Returns a one-line note for the agent.
pub fn observe_edit(request: &HookRequest) -> Option<String> {
    if off("fmt-on-edit") || !matches!(request.event_type.as_str(), "PostToolUse" | "post-effect") {
        return None;
    }
    let path = edit_path(request.payload.as_object()?)?;
    if path.extension()? != "rs" || is_fixture(&path) {
        return None;
    }
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > 2 << 20 {
        return None;
    }
    let source = fs::read_to_string(&path).ok()?;
    let name = path.file_name()?.to_string_lossy().into_owned();
    let Some(formatted) = rustfmt(&source, &edition(&path), path.parent()?) else {
        return Some(format!("rustfmt could not format {name}"));
    };
    let unchanged = formatted == source || formatted.trim().is_empty();
    // Write back only when nobody changed the file while rustfmt ran.
    if unchanged || fs::read_to_string(&path).ok()? != source {
        return None;
    }
    write_atomic(&path, formatted.as_bytes())?;
    Some(format!("rustfmt formatted {name}"))
}
