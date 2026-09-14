use crate::error::MinimizeError;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct GitContext {
    pub cwd: PathBuf,
    pub minimize_base_ref: Option<String>,
}

impl GitContext {
    pub fn new(cwd: PathBuf) -> Self {
        let minimize_base_ref = std::env::var("MINIMIZE_BASE_REF")
            .ok()
            .filter(|value| !value.is_empty());
        Self {
            cwd,
            minimize_base_ref,
        }
    }

    pub fn git(&self, args: &[&str]) -> Result<String, MinimizeError> {
        self.git_at(&self.cwd, args)
    }

    pub fn git_at(&self, cwd: &Path, args: &[&str]) -> Result<String, MinimizeError> {
        let mut command = Command::new("git");
        command.arg("-C").arg(cwd).args(args);
        hide_console(&mut command);
        let output = command.output().map_err(|error| {
            MinimizeError::new(format!("git {} failed: {}", args.join(" "), error))
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr = stderr.trim();
            return Err(MinimizeError::new(
                if stderr.is_empty() {
                    format!("git {} failed", args.join(" "))
                } else {
                    stderr.to_string()
                },
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    pub fn git_optional(&self, args: &[&str]) -> String {
        let mut command = Command::new("git");
        command.args(args);
        hide_console(&mut command);
        let output = command.output().ok();
        let Some(output) = output else {
            return String::new();
        };
        if output.status.code() == Some(0) || output.status.code() == Some(1) {
            String::from_utf8_lossy(&output.stdout).to_string()
        } else {
            String::new()
        }
    }

    pub fn git_optional_at(&self, cwd: &Path, args: &[&str]) -> String {
        let mut command = Command::new("git");
        command.arg("-C").arg(cwd).args(args);
        hide_console(&mut command);
        let output = command.output().ok();
        let Some(output) = output else {
            return String::new();
        };
        if output.status.code() == Some(0) || output.status.code() == Some(1) {
            String::from_utf8_lossy(&output.stdout).to_string()
        } else {
            String::new()
        }
    }
}

fn hide_console(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
}

#[derive(Debug, Clone)]
pub struct StagedChange {
    pub kind: char,
    pub status: String,
    pub source: Option<String>,
    pub path: String,
}

impl GitContext {
    pub fn staged_tree(&self) -> Result<String, MinimizeError> {
        self.git(&["write-tree"])
    }

    pub fn staged_changes(&self) -> Result<Vec<StagedChange>, MinimizeError> {
        let mut args = vec!["diff", "--cached"];
        if let Some(base) = &self.minimize_base_ref {
            args.push(base);
        }
        args.extend([
            "-M",
            "--name-status",
            "-z",
            "--diff-filter=ACMRD",
        ]);
        let raw = self.git_at(&self.cwd, &args)?;
        let mut fields = raw.split('\0').collect::<Vec<_>>();
        if fields.last() == Some(&"") {
            fields.pop();
        }
        let mut changes = Vec::new();
        let mut index = 0;
        while index < fields.len() {
            let status = fields[index];
            index += 1;
            let kind = status.chars().next().ok_or_else(|| {
                MinimizeError::new("git diff returned an invalid staged change record")
            })?;
            if kind == 'R' || kind == 'C' {
                let source = fields.get(index).ok_or_else(|| {
                    MinimizeError::new("git diff returned an incomplete rename record")
                })?;
                index += 1;
                let path = fields.get(index).ok_or_else(|| {
                    MinimizeError::new("git diff returned an incomplete rename record")
                })?;
                index += 1;
                changes.push(StagedChange {
                    kind,
                    status: status.to_string(),
                    source: Some(source.to_string()),
                    path: path.to_string(),
                });
            } else {
                let path = fields.get(index).ok_or_else(|| {
                    MinimizeError::new("git diff returned an incomplete staged change record")
                })?;
                index += 1;
                changes.push(StagedChange {
                    kind,
                    status: status.to_string(),
                    source: None,
                    path: path.to_string(),
                });
            }
        }
        Ok(changes)
    }

    pub fn repository_root(&self) -> Result<String, MinimizeError> {
        self.git_at(&self.cwd, &["rev-parse", "--show-toplevel"])
    }

    pub fn staged_files(&self) -> Result<Vec<String>, MinimizeError> {
        Ok(self
            .staged_changes()?
            .into_iter()
            .filter(|change| change.kind != 'D')
            .map(|change| change.path)
            .collect())
    }

    pub fn staged_added_files(&self) -> Result<Vec<String>, MinimizeError> {
        Ok(self
            .git(&["diff", "--cached", "--name-only", "--diff-filter=A"])?
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect())
    }
}

pub fn canonical_locator(path: &Path) -> PathBuf {
    let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let parent = resolved.parent().unwrap_or_else(|| Path::new("."));
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(parent)
        .args(["rev-parse", "--show-toplevel"]);
    hide_console(&mut command);
    let output = command.output();
    let Ok(output) = output else {
        return resolved;
    };
    if !output.status.success() {
        return resolved;
    }
    let root_stdout = String::from_utf8_lossy(&output.stdout);
    let root = root_stdout.trim();
    let normalized = resolved.to_string_lossy().replace('\\', "/");
    let root_normalized = root.replace('\\', "/");
    if let Some(rest) = normalized.strip_prefix(&format!("{root_normalized}/")) {
        PathBuf::from(rest)
    } else {
        resolved
    }
}
