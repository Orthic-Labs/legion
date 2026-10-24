//! SessionStart: when the session opens inside a Legion workspace, verify the
//! RightKit pre-push hook with the workspace's own `setup-workspace.py
//! --check` and put the result in front of the model and the operator.
//!
//! The check is read-only by contract and bounded; it never installs. A
//! missing hook is reported with the command that installs it, because a hook
//! may deny but must not decide to change git configuration on its own.

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use serde_json::Value;

use crate::{
    first_string,
    process::{bounded_output, Unfinished},
    windows_path_from_posix_drive,
};

const SCRIPT: &str = "tools/setup-workspace.py";
const LIMIT: Duration = Duration::from_secs(7);
const MAX_OUTPUT_CHARS: usize = 600;

pub(crate) fn workspace_root(payload: &Value) -> Option<PathBuf> {
    let object = payload.as_object()?;
    // The host's cwd is authoritative; the process cwd only stands in for a
    // host that sends none.
    let start = match first_string(object, &["cwd", "workspace"]) {
        Some(value) => {
            windows_path_from_posix_drive(&value).unwrap_or_else(|| PathBuf::from(value))
        }
        None => std::env::current_dir().ok()?,
    };
    start
        .ancestors()
        .find(|dir| dir.join(SCRIPT).is_file())
        .map(Path::to_path_buf)
}

fn interpreters() -> Vec<(&'static str, Vec<&'static str>)> {
    if cfg!(windows) {
        vec![("py", vec!["-3.11"]), ("python", vec![])]
    } else {
        vec![("python3", vec![]), ("python", vec![])]
    }
}

/// The line(s) to add to the SessionStart context, or `None` outside a
/// workspace.
pub(crate) fn pre_push_hook_notice(payload: &Value) -> Option<String> {
    let root = workspace_root(payload)?;
    let mut last = Unfinished::NotStarted;
    for (program, prefix) in interpreters() {
        let mut command = Command::new(program);
        command
            .args(prefix)
            .arg(SCRIPT)
            .arg("--check")
            .current_dir(&root);
        match bounded_output(command, LIMIT) {
            Ok(finished) => {
                let mut text = String::from_utf8_lossy(&finished.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&finished.stderr));
                let text: String = text.trim().chars().take(MAX_OUTPUT_CHARS).collect();
                return Some(match finished.code {
                    Some(0) => format!(
                        "Workspace gate hook: `{SCRIPT} --check` exited 0; the RightKit pre-push hook is installed.{}",
                        suffix(&text)
                    ),
                    code => format!(
                        "Workspace gate hook: `{SCRIPT} --check` exited {}; the RightKit pre-push hook is missing or unverified. Run `python3 {SCRIPT}` to install it and check again. Until it passes, run `right-release check` yourself before any push.{}",
                        code.map_or_else(|| "without a status".to_owned(), |code| code.to_string()),
                        suffix(&text)
                    ),
                });
            }
            Err(Unfinished::TimedOut) => {
                return Some(format!(
                    "Workspace gate hook: `{SCRIPT} --check` did not finish in {}s; treat the RightKit pre-push hook as unverified and run `right-release check` yourself before any push.",
                    LIMIT.as_secs()
                ));
            }
            Err(not_started) => last = not_started,
        }
    }
    debug_assert_eq!(last, Unfinished::NotStarted);
    Some(format!(
        "Workspace gate hook: no Python interpreter could run `{SCRIPT} --check`; treat the RightKit pre-push hook as unverified and run `right-release check` yourself before any push."
    ))
}

fn suffix(output: &str) -> String {
    if output.is_empty() {
        String::new()
    } else {
        format!("\n{output}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn python_available() -> bool {
        interpreters().iter().any(|(program, prefix)| {
            let mut command = Command::new(program);
            command.args(prefix).arg("-c").arg("pass");
            bounded_output(command, Duration::from_secs(5))
                .is_ok_and(|finished| finished.code == Some(0))
        })
    }

    fn workspace(script: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "legion-workspace-{}-{}",
            std::process::id(),
            crate::unix_nanos()
        ));
        fs::create_dir_all(root.join("tools")).unwrap();
        fs::create_dir_all(root.join("app/src")).unwrap();
        fs::write(root.join(SCRIPT), script).unwrap();
        root
    }

    #[test]
    fn outside_a_workspace_nothing_is_said() {
        let bare = std::env::temp_dir().join(format!(
            "legion-no-workspace-{}-{}",
            std::process::id(),
            crate::unix_nanos()
        ));
        fs::create_dir_all(&bare).unwrap();
        assert!(workspace_root(&json!({"cwd": bare})).is_none());
        assert!(pre_push_hook_notice(&json!({"cwd": bare})).is_none());
        let _ = fs::remove_dir_all(bare);
    }

    #[test]
    fn a_passing_check_is_reported_with_its_output_from_any_subdirectory() {
        if !python_available() {
            return;
        }
        let root = workspace("import sys\nprint('ok: ' + ' '.join(sys.argv[1:]))\n");
        let notice = pre_push_hook_notice(&json!({"cwd": root.join("app/src")}))
            .expect("the workspace is found from a subdirectory");
        assert!(notice.contains("exited 0"), "{notice}");
        assert!(notice.contains("ok: --check"), "{notice}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_failing_check_names_the_installer_and_the_manual_gate() {
        if !python_available() {
            return;
        }
        let root = workspace("import sys\nprint('app: core.hooksPath unset')\nsys.exit(1)\n");
        let notice = pre_push_hook_notice(&json!({"cwd": root})).expect("workspace found");
        assert!(notice.contains("exited 1"), "{notice}");
        assert!(notice.contains("missing or unverified"), "{notice}");
        assert!(notice.contains("setup-workspace.py"), "{notice}");
        assert!(notice.contains("right-release check"), "{notice}");
        assert!(notice.contains("core.hooksPath unset"), "{notice}");
        let _ = fs::remove_dir_all(root);
    }
}
