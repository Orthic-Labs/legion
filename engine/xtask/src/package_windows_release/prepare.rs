//! Native port of `prepareWindowsArchive` (package mode) and
//! `createPortableArchive` from `@rightkit/release/direct-bootstrap.mjs`
//! (itself a thin `tar` subprocess wrapper, faithfully reproduced here).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

use crate::windows_release_config::windows_architecture;
use crate::windows_release_support::{assert_regular_file, assert_source_revision, assert_version, digest_matches, read_json, release_generation, sha256_file};

const REQUIRED_BINARIES: [&str; 3] = ["legion.exe", "legion-hook.exe", "legion-mcp.exe"];

pub struct FileRecord {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

impl FileRecord {
    pub fn to_json(&self) -> Value {
        json!({ "name": self.name, "size": self.size, "sha256": self.sha256 })
    }
}

/// Mirrors `fileRecord`.
pub fn file_record(path: &Path) -> Result<FileRecord, String> {
    assert_regular_file(path, "release artifact")?;
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    Ok(FileRecord {
        name: path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        size: metadata.len(),
        sha256: sha256_file(path)?,
    })
}

/// Mirrors `windowsTargetIdentity` / `normalizeWindowsArchitecture` in
/// `package-windows-release.mjs` (identical to the shared config helper).
pub fn windows_target_identity(architecture: &str) -> Result<Value, String> {
    let normalized = crate::windows_release_config::normalize_windows_architecture(architecture)?;
    let configured = windows_architecture(&normalized).ok_or_else(|| format!("unsupported Windows architecture: {architecture}"))?;
    Ok(json!({
        "platform": configured.platform,
        "architecture": configured.architecture,
        "nativeArchitecture": configured.native_architecture,
        "targetTriple": configured.target_triple,
        "executable": "legion.exe",
        "artifactId": configured.artifact_id,
    }))
}

/// Mirrors `releaseVersion`.
pub fn release_version(repository_root: &Path) -> Result<String, String> {
    let record = read_json(&repository_root.join("release").join("version.json"), "release version")?;
    let version = record.get("version").and_then(|v| v.as_str()).unwrap_or_default();
    let ok = record.get("schemaVersion").and_then(|v| v.as_i64()) == Some(1)
        && record.get("kind").and_then(|v| v.as_str()) == Some("legion-release-version")
        && assert_version(Some(version), "release version").is_ok();
    if !ok {
        return Err("release/version.json must declare one stable SemVer".to_string());
    }
    Ok(version.to_string())
}

/// Mirrors `sourceRevision`: uses the supplied value if present, otherwise
/// shells out to `git rev-parse HEAD`.
pub fn source_revision(repository_root: &Path, supplied: Option<&str>) -> Result<String, String> {
    if let Some(supplied) = supplied {
        return assert_source_revision(Some(supplied));
    }
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repository_root)
        .output()
        .map_err(|_| "release source revision is unavailable".to_string())?;
    if !output.status.success() {
        return Err("release source revision is unavailable".to_string());
    }
    let revision = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_source_revision(Some(&revision)).map_err(|_| "release source revision is unavailable".to_string())
}

pub struct AssembledRelease {
    pub identity: Value,
    #[allow(dead_code)]
    pub metadata: Value,
    pub runtime_sha256: String,
    pub generation: String,
}

/// Mirrors `assembledRelease`.
pub fn assembled_release(input_root: &Path, architecture: &str, version: &str) -> Result<AssembledRelease, String> {
    let metadata_check = fs::metadata(input_root).map_err(|_| format!("assembled release root is missing: {}", input_root.display()))?;
    if !metadata_check.is_dir() {
        return Err(format!("assembled release root is missing: {}", input_root.display()));
    }
    let identity = windows_target_identity(architecture)?;
    let metadata = read_json(&resolve_inside(input_root, "share/legion/release.json", "release metadata")?, "assembled release metadata")?;
    let runtime_platform = metadata.pointer("/runtime/platform").and_then(|v| v.as_str());
    let runtime_architecture = metadata.pointer("/runtime/architecture").and_then(|v| v.as_str());
    if metadata.get("releaseVersion").and_then(|v| v.as_str()) != Some(version) || runtime_platform != Some("windows") || runtime_architecture != identity.get("architecture").and_then(|v| v.as_str()) {
        return Err("assembled release identity does not match requested Windows target".to_string());
    }
    let mut binaries = Vec::new();
    for name in REQUIRED_BINARIES {
        let path = resolve_inside(input_root, &format!("bin/{name}"), "release binary")?;
        let ok = fs::symlink_metadata(&path).map(|m| m.is_file() && !m.file_type().is_symlink()).unwrap_or(false);
        if !ok {
            return Err(format!("release binary is missing or unsafe: {}", path.display()));
        }
        binaries.push(path);
    }
    let runtime_sha256 = sha256_file(&binaries[0])?;
    if !digest_matches(metadata.pointer("/runtime/sha256").and_then(|v| v.as_str()), Some(&runtime_sha256)) {
        return Err("assembled release runtime digest mismatch".to_string());
    }
    let generation = release_generation(&metadata, version, &runtime_sha256);
    Ok(AssembledRelease { identity, metadata, runtime_sha256, generation })
}

/// Mirrors `resolveInside`: resolves `relative_path` under `root`'s
/// realpath, rejecting escapes.
fn resolve_inside(root: &Path, relative_path: &str, label: &str) -> Result<PathBuf, String> {
    let base = fs::canonicalize(root).map(crate::windows_release_support::strip_verbatim).map_err(|e| format!("{label} root is unreadable: {e}"))?;
    let candidate = base.join(relative_path.replace('/', &std::path::MAIN_SEPARATOR.to_string()));
    let candidate_resolved = crate::windows_release_support::canonical_path(&candidate);
    if candidate_resolved == base || !candidate_resolved.starts_with(&base) {
        return Err(format!("{label} escapes release root: {relative_path}"));
    }
    Ok(candidate)
}

/// Mirrors `assertReleaseOutputPath`.
fn assert_release_output_path(output_dir: &Path, repository_root: &Path, input_root: &Path) -> Result<(), String> {
    let resolved_output = crate::windows_release_support::canonical_path(output_dir);
    let resolved_input = crate::windows_release_support::canonical_path(input_root);
    let resolved_repo = crate::windows_release_support::canonical_path(repository_root);
    let relative_input = resolved_output.strip_prefix(&resolved_input);
    let ok = resolved_output != resolved_repo
        && match relative_input {
            Ok(rel) => !rel.as_os_str().is_empty(),
            Err(_) => true, // output is not inside input_root at all: fine, matches ".." case in JS intent
        };
    // The JS accepts paths that are NOT inside inputRoot (typical case: dist/releases/...)
    // and rejects the repository root itself; this mirrors that.
    if !ok {
        return Err(format!("unsafe release output path: {}", resolved_output.display()));
    }
    Ok(())
}

/// Mirrors `@rightkit/release/direct-bootstrap.mjs`'s `createPortableArchive`:
/// shells out to `tar` (the Windows System32 `bsdtar` on Windows) to build a
/// zip from `source_dir`.
pub fn create_portable_archive(source_dir: &Path, output_path: &Path) -> Result<(), String> {
    let source = fs::canonicalize(source_dir).map(crate::windows_release_support::strip_verbatim).map_err(|e| e.to_string())?;
    let output_dir = output_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;
    let tar_program = if cfg!(windows) {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        format!("{system_root}\\System32\\tar.exe")
    } else {
        "tar".to_string()
    };
    let output_name = output_path.file_name().ok_or("output path has no file name")?;
    let status = Command::new(&tar_program)
        .args(["-a", "-c", "-f"])
        .arg(output_name)
        .arg("-C")
        .arg(&source)
        .arg(".")
        .current_dir(&output_dir)
        .status()
        .map_err(|e| format!("portable archive failed: {e}"))?;
    if !status.success() {
        return Err("portable archive failed".to_string());
    }
    if !output_path.is_file() {
        return Err(format!("portable archive missing: {}", output_path.display()));
    }
    Ok(())
}

pub struct PrepareOptions<'a> {
    pub input: &'a Path,
    pub output: Option<&'a Path>,
    pub architecture: &'a str,
    pub source_revision: Option<&'a str>,
    pub force: bool,
    pub repository_root: &'a Path,
}

/// Mirrors `prepareWindowsArchive`.
pub fn prepare_windows_archive(options: PrepareOptions) -> Result<Value, String> {
    let input_root = crate::windows_release_support::canonical_path(options.input);
    let version = release_version(options.repository_root)?;
    let revision = source_revision(options.repository_root, options.source_revision)?;
    let assembled = assembled_release(&input_root, options.architecture, &version)?;
    let architecture = assembled.identity.get("architecture").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let output_dir = options
        .output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| options.repository_root.join("dist").join("releases").join("windows").join(&version).join(&architecture));
    assert_release_output_path(&output_dir, options.repository_root, &input_root)?;
    if output_dir.exists() && options.force {
        fs::remove_dir_all(&output_dir).map_err(|e| e.to_string())?;
    }
    fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;
    let archive_path = output_dir.join(format!("legion-{version}-windows-{architecture}.zip"));
    if archive_path.exists() && !options.force {
        return Err(format!("release archive exists: {}; pass --force to replace it", archive_path.display()));
    }
    create_portable_archive(&input_root, &archive_path)?;
    if !archive_path.is_file() {
        return Err(format!("portable archive is missing: {}", archive_path.display()));
    }
    let archive = file_record(&archive_path)?;
    Ok(json!({
        "status": "archive-prepared",
        "outputDir": output_dir,
        "archive": archive_path,
        "archiveSha256": archive.sha256,
        "runtimeSha256": assembled.runtime_sha256,
        "generation": assembled.generation,
        "releaseVersion": version,
        "sourceRevision": revision,
        "targetIdentity": assembled.identity,
    }))
}
