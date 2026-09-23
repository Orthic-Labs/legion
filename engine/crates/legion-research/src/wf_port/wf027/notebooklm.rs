//! Port of `src/lib/research-core/providers/notebooklm.py`.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use super::support::WfError;

/// Port of `NotebookLMAdapter`.
pub struct NotebookLmAdapter {
    executable: PathBuf,
}

impl NotebookLmAdapter {
    pub const NAME: &'static str = "notebooklm";

    /// Port of `__init__`: resolves `executable` on `PATH` (mirrors
    /// `shutil.which`), erroring like the Python `RuntimeError` when absent.
    pub fn new(executable: &str) -> Result<Self, WfError> {
        let resolved = which(executable)
            .ok_or_else(|| WfError::NotConfigured("notebooklm CLI is not installed".into()))?;
        Ok(Self {
            executable: resolved,
        })
    }

    /// Port of `_run`. Deviation: on timeout this returns `WfError::Timeout`
    /// without killing the child (see `support::command_json` docs for the
    /// same tradeoff).
    fn run(&self, args: &[&str], timeout_s: u64) -> Result<Value, WfError> {
        let mut cmd = Command::new(&self.executable);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = cmd.spawn()?;
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });
        let output = match rx.recv_timeout(Duration::from_secs(timeout_s)) {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => return Err(WfError::from(e)),
            Err(_) => return Err(WfError::Timeout),
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let message = if stderr.is_empty() {
                format!(
                    "notebooklm exited {}",
                    output
                        .status
                        .code()
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "signal".into())
                )
            } else {
                stderr
            };
            return Err(WfError::Provider(message));
        }
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        match serde_json::from_str::<Value>(&text) {
            Ok(v) => Ok(v),
            Err(_) => Ok(json!({"text": text})),
        }
    }

    pub fn status(&self) -> Result<Value, WfError> {
        self.run(&["status"], 180)
    }

    pub fn list_notebooks(&self) -> Result<Value, WfError> {
        self.run(&["list", "--json"], 180)
    }

    /// Port of `ask`: NotebookLM answers remain leads, wrapped with
    /// `evidence_status: "lead"`.
    pub fn ask(&self, notebook_id: &str, question: &str) -> Result<Value, WfError> {
        let result = self.run(&["ask", question, "--notebook", notebook_id, "--json"], 180)?;
        Ok(json!({
            "evidence_status": "lead",
            "provider": Self::NAME,
            "answer": result,
        }))
    }

    pub fn create(&self, title: &str) -> Result<Value, WfError> {
        self.run(&["create", title, "--json"], 180)
    }

    pub fn add_source(&self, notebook_id: &str, source: &str) -> Result<Value, WfError> {
        self.run(&["source", "add", source, "--notebook", notebook_id, "--json"], 180)
    }

    pub fn generate(
        &self,
        notebook_id: &str,
        artifact_type: &str,
        instructions: Option<&str>,
    ) -> Result<Value, WfError> {
        let mut args: Vec<&str> = vec!["generate", artifact_type];
        if let Some(instructions) = instructions {
            args.push(instructions);
        }
        args.push("--notebook");
        args.push(notebook_id);
        args.push("--json");
        self.run(&args, 600)
    }
}

/// Port of `shutil.which`.
fn which(executable: &str) -> Option<PathBuf> {
    let candidate = Path::new(executable);
    if executable.contains('/') {
        return if is_executable(candidate) {
            Some(candidate.to_path_buf())
        } else {
            None
        };
    }
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        let full = dir.join(executable);
        if is_executable(&full) {
            return Some(full);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn new_errors_when_executable_missing() {
        let err = NotebookLmAdapter::new("legion_wf027_definitely_missing_cli_xyz").unwrap_err();
        assert_eq!(err, WfError::NotConfigured("notebooklm CLI is not installed".into()));
    }

    #[cfg(unix)]
    fn write_fake_cli(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("fake_notebooklm.sh");
        let mut f = fs::File::create(&path).unwrap();
        writeln!(f, "#!/bin/sh\n{body}").unwrap();
        drop(f);
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn ask_wraps_answer_as_a_lead() {
        let dir = std::env::temp_dir().join(format!(
            "legion_wf027_notebooklm_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let cli = write_fake_cli(&dir, "echo '{\"answer\": \"42\"}'");
        let adapter = NotebookLmAdapter::new(cli.to_str().unwrap()).unwrap();
        let result = adapter.ask("nb-1", "what is it?").unwrap();
        assert_eq!(result["evidence_status"], json!("lead"));
        assert_eq!(result["provider"], json!("notebooklm"));
        assert_eq!(result["answer"]["answer"], json!("42"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn run_propagates_nonzero_exit_as_provider_error() {
        let dir = std::env::temp_dir().join(format!(
            "legion_wf027_notebooklm_fail_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let cli = write_fake_cli(&dir, "echo 'boom' >&2; exit 3");
        let adapter = NotebookLmAdapter::new(cli.to_str().unwrap()).unwrap();
        let err = adapter.status().unwrap_err();
        match err {
            WfError::Provider(m) => assert!(m.contains("boom")),
            other => panic!("expected Provider error, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn run_falls_back_to_text_when_stdout_is_not_json() {
        let dir = std::env::temp_dir().join(format!(
            "legion_wf027_notebooklm_text_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let cli = write_fake_cli(&dir, "echo 'plain text output'");
        let adapter = NotebookLmAdapter::new(cli.to_str().unwrap()).unwrap();
        let result = adapter.status().unwrap();
        assert_eq!(result["text"], json!("plain text output"));
        let _ = fs::remove_dir_all(&dir);
    }
}
