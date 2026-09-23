use std::path::{Path, PathBuf};

/// Walk up from the current directory until a directory containing both
/// `package.json` and an `engine/` directory is found. Mirrors the Node
/// scripts' `resolve(dirname(fileURLToPath(import.meta.url)), '..')`
/// (repository root, one level above `scripts/`), without depending on the
/// binary's own install location.
pub fn find_root() -> Result<PathBuf, String> {
    let start = std::env::current_dir().map_err(|e| format!("cannot read cwd: {e}"))?;
    let mut cursor: Option<&Path> = Some(start.as_path());
    while let Some(dir) = cursor {
        if dir.join("package.json").is_file() && dir.join("engine").is_dir() {
            return Ok(dir.to_path_buf());
        }
        cursor = dir.parent();
    }
    Err(format!(
        "could not locate repository root (package.json + engine/) above {}",
        start.display()
    ))
}
