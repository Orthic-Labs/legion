//! Rust port of `scripts/prepare-windows-candidate-finalization.mjs`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::prepare_unsigned_candidate::{self, CheckArgs};

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// `path.resolve()`: relative paths resolve against the working directory.
fn normalize_lexical(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut out = PathBuf::new();
    for component in absolute.components() {
        use std::path::Component::*;
        match component {
            ParentDir => {
                out.pop();
            }
            CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn assert_owned_output(path: &Path, repository_root: &Path) -> Result<PathBuf, String> {
    let root = normalize_lexical(&repository_root.join("dist/native"));
    let value = normalize_lexical(path);
    if !value.starts_with(&root) || value == root {
        return Err(format!("candidate extraction output must be below {}", root.display()));
    }
    Ok(value)
}

fn find_release_root(extracted: &Path) -> Result<PathBuf, String> {
    let mut candidates = vec![extracted.to_path_buf()];
    for entry in fs::read_dir(extracted).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if fs::symlink_metadata(entry.path()).map(|m| m.is_dir()).unwrap_or(false) {
            candidates.push(entry.path());
        }
    }
    let matches: Vec<_> = candidates.into_iter().filter(|p| p.join("bin/legion.exe").exists()).collect();
    if matches.len() != 1 {
        return Err("candidate archive must contain exactly one Legion release root".to_string());
    }
    Ok(matches.into_iter().next().unwrap())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        let meta = fs::symlink_metadata(entry.path())?;
        if meta.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

pub struct PrepareArgs {
    pub candidate_root: Option<PathBuf>,
    pub output_root: Option<PathBuf>,
    pub architecture: Option<String>,
    pub source_revision: Option<String>,
    pub version: Option<String>,
    pub receipt_path: Option<PathBuf>,
}

pub fn prepare_windows_candidate_finalization(repository_root: &Path, args: PrepareArgs) -> Result<Value, String> {
    let candidate_root = args.candidate_root.ok_or("LEGION_UNSIGNED_CANDIDATE_ROOT or --candidate is required")?;
    let output_root = args.output_root.ok_or("--output is required")?;
    let output = assert_owned_output(&output_root, repository_root)?;
    let checked = prepare_unsigned_candidate::check_unsigned_candidate(
        repository_root,
        CheckArgs {
            output_root: Some(candidate_root),
            platform: Some("windows".to_string()),
            architecture: args.architecture.clone(),
            source_revision: args.source_revision.clone(),
            version: args.version.clone(),
        },
    )?;
    let archive = PathBuf::from(checked.get("archive").and_then(|v| v.as_str()).unwrap_or_default());

    let pid = std::process::id();
    let staging = PathBuf::from(format!("{}.candidate-extract-{pid}", output.display()));
    let _ = fs::remove_dir_all(&staging);
    let _ = fs::remove_dir_all(&output);
    fs::create_dir_all(&staging).map_err(|e| e.to_string())?;

    let result: Result<(), String> = (|| {
        let command = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Expand-Archive -LiteralPath $env:LEGION_CANDIDATE_ARCHIVE -DestinationPath $env:LEGION_CANDIDATE_STAGING -Force",
            ])
            .current_dir(repository_root)
            .env("LEGION_CANDIDATE_ARCHIVE", &archive)
            .env("LEGION_CANDIDATE_STAGING", &staging)
            .output()
            .map_err(|e| e.to_string())?;
        if !command.status.success() {
            let msg = if !command.stderr.is_empty() { command.stderr } else { command.stdout };
            return Err(format!("candidate extraction failed: {}", String::from_utf8_lossy(&msg).trim()));
        }
        let release_root = find_release_root(&staging)?;
        if output.exists() {
            return Err(format!("candidate extraction output already exists: {}", output.display()));
        }
        copy_dir_recursive(&release_root, &output).map_err(|e| e.to_string())?;
        Ok(())
    })();
    let _ = fs::remove_dir_all(&staging);
    result?;

    let files: Result<Vec<Value>, String> = ["legion.exe", "legion-hook.exe", "legion-mcp.exe"]
        .iter()
        .map(|name| {
            let path = output.join("bin").join(name);
            let meta = fs::metadata(&path).map_err(|_| format!("candidate executable missing: {name}"))?;
            if !meta.is_file() {
                return Err(format!("candidate executable missing: {name}"));
            }
            Ok(json!({ "file": format!("bin/{name}"), "sha256": sha256_file(&path)?, "sizeBytes": meta.len() }))
        })
        .collect();
    let files = files?;

    let mut receipt = json!({
        "schema": 1,
        "kind": "legion-windows-candidate-input",
        "status": "verified",
        "candidateArchive": checked.get("archive"),
        "candidateArchiveSha256": checked.get("archiveSha256"),
        "sourceRevision": checked.get("sourceRevision"),
        "version": checked.get("version"),
        "architecture": checked.get("architecture"),
        "output": output.display().to_string(),
        "files": files,
    });
    if let Some(receipt_path) = &args.receipt_path {
        if let Some(parent) = receipt_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(receipt_path, format!("{}\n", serde_json::to_string_pretty(&receipt).unwrap())).map_err(|e| e.to_string())?;
    }
    receipt["receipt"] = match &args.receipt_path {
        Some(p) => Value::String(p.display().to_string()),
        None => Value::Null,
    };
    Ok(receipt)
}

// Rust port of "Windows finalization expands exact verified candidate bytes
// and records pre-sign identity" (`tests/unsigned-release-candidate.test.mjs`,
// itself gated `{ skip: process.platform !== "win32" }`). No injection seam
// is needed here: unlike the macOS test, the JS test does not mock
// `createArchive`/`commandRunner` either — both `prepareUnsignedCandidate`
// and `prepareWindowsCandidateFinalization` run for real (real zip creation,
// real `Expand-Archive`), so this only compiles and runs on Windows, same as
// the JS test only ran there.
#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use crate::prepare_unsigned_candidate;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_root(prefix: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn windows_finalization_expands_exact_candidate_bytes() {
        let root = temp_root("legion-windows-candidate");
        let repository_root = root.join("repo");
        let input = root.join("install");
        let output_root = root.join("candidate");
        let extracted = repository_root.join("dist/native/windows-x86_64/legion-0.1.0");
        let receipt_path = repository_root.join(".right-release/receipts/candidate.json");
        let source_revision = "b".repeat(40);

        fs::create_dir_all(repository_root.join("release")).unwrap();
        fs::write(
            repository_root.join("release/version.json"),
            serde_json::json!({ "schemaVersion": 1, "kind": "legion-release-version", "version": "0.1.0" }).to_string(),
        )
        .unwrap();
        fs::create_dir_all(input.join("bin")).unwrap();
        for name in ["legion.exe", "legion-hook.exe", "legion-mcp.exe"] {
            fs::write(input.join("bin").join(name), format!("{name}\n")).unwrap();
        }

        let candidate = prepare_unsigned_candidate::prepare_unsigned_candidate(
            &repository_root,
            prepare_unsigned_candidate::PrepareArgs {
                input: Some(input.clone()),
                output_root: Some(output_root.clone()),
                platform: Some("windows".to_string()),
                architecture: Some("x86_64".to_string()),
                source_revision: Some(source_revision.clone()),
                version: None,
                created_at: Some("2026-08-28T00:00:00.000Z".to_string()),
            },
        )
        .unwrap();

        let result = prepare_windows_candidate_finalization(
            &repository_root,
            PrepareArgs {
                candidate_root: Some(output_root.clone()),
                output_root: Some(extracted.clone()),
                architecture: Some("x86_64".to_string()),
                source_revision: Some(source_revision.clone()),
                version: Some("0.1.0".to_string()),
                receipt_path: Some(receipt_path.clone()),
            },
        )
        .unwrap();

        assert_eq!(result["candidateArchiveSha256"], candidate["archiveSha256"]);
        let files: Vec<String> = result["files"].as_array().unwrap().iter().map(|f| f["file"].as_str().unwrap().to_string()).collect();
        assert_eq!(files, vec!["bin/legion.exe", "bin/legion-hook.exe", "bin/legion-mcp.exe"]);
        let receipt: Value = serde_json::from_str(&fs::read_to_string(&receipt_path).unwrap()).unwrap();
        assert_eq!(receipt["candidateArchiveSha256"], candidate["archiveSha256"]);

        let _ = fs::remove_dir_all(&root);
    }
}
