//! Rust port of `scripts/ci/prepare-unsigned-candidate.mjs`.
//!
//! `createPortableArchive` and the CycloneDX/in-toto materialize/validate
//! calls delegate to the external `@rightkit/release` npm package via
//! `rightkit_release_bridge` (see that module's doc comment for why).
//! Everything else — target inference, path safety, candidate.json
//! read/write, the `--check` verification pass, and the assemble+smoke
//! orchestration run when no `--input` is supplied — is a faithful 1:1 port.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::rightkit_release_bridge;

const PRODUCT: &str = "legion";
const SOURCE_REPOSITORY: &str = "https://github.com/Orthic-Labs/legion";
const CANDIDATE_ROOT_NAME: &str = "legion-unsigned-candidate";
const CANDIDATE_FILE: &str = "candidate.json";
const CANDIDATE_KIND: &str = "legion-unsigned-release-candidate";

fn stable_version_re() -> Regex {
    Regex::new(r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$").unwrap()
}
fn source_revision_re() -> Regex {
    Regex::new(r"(?i)^[a-f0-9]{40,64}$").unwrap()
}
fn sha256_re() -> Regex {
    Regex::new(r"(?i)^[a-f0-9]{64}$").unwrap()
}

fn normalize_platform(value: &str) -> Option<String> {
    match value.trim().to_lowercase().as_str() {
        "win32" | "win" | "windows" => Some("windows".to_string()),
        "darwin" | "mac" | "macos" => Some("macos".to_string()),
        _ => None,
    }
}

pub fn normalize_architecture(value: &str) -> Option<String> {
    match value.trim().to_lowercase().as_str() {
        "x64" | "amd64" | "x86_64" => Some("x86_64".to_string()),
        "arm64" | "aarch64" => Some("arm64".to_string()),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub platform: String,
    pub architecture: String,
    pub target: String,
}

pub fn infer_target(platform: Option<&str>, architecture: Option<&str>) -> Result<Option<Identity>, String> {
    let (Some(platform), Some(architecture)) = (platform, architecture) else {
        return Err("unsigned candidate target requires explicit platform and architecture".to_string());
    };
    let Some(normalized_platform) = normalize_platform(platform) else { return Ok(None) };
    let Some(normalized_architecture) = normalize_architecture(architecture) else {
        return Err(format!("unsupported {normalized_platform} architecture: {architecture}"));
    };
    let target = format!("{normalized_platform}-{normalized_architecture}");
    Ok(Some(Identity { platform: normalized_platform, architecture: normalized_architecture, target }))
}

fn read_stable_version(repository_root: &Path, supplied: Option<&str>) -> Result<String, String> {
    let record: Value = serde_json::from_str(
        &fs::read_to_string(repository_root.join("release/version.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if record.get("schemaVersion").and_then(|v| v.as_i64()) != Some(1)
        || record.get("kind").and_then(|v| v.as_str()) != Some("legion-release-version")
    {
        return Err("release/version.json must be the canonical release version record".to_string());
    }
    let version = supplied.map(|s| s.to_string()).unwrap_or_else(|| {
        record.get("version").and_then(|v| v.as_str()).unwrap_or_default().to_string()
    });
    if !stable_version_re().is_match(&version) {
        return Err(format!("release version must be stable SemVer: {version}"));
    }
    Ok(version)
}

fn read_source_revision(repository_root: &Path, supplied: Option<&str>) -> Result<String, String> {
    if let Some(s) = supplied {
        let revision = s.trim().to_lowercase();
        if !source_revision_re().is_match(&revision) {
            return Err("source revision must be a 40-64 character git SHA".to_string());
        }
        return Ok(revision);
    }
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repository_root)
        .output()
        .map_err(|_| "release source revision is unavailable".to_string())?;
    let revision = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
    if !output.status.success() || !source_revision_re().is_match(&revision) {
        return Err("release source revision is unavailable".to_string());
    }
    Ok(revision)
}

fn configured_path(value: Option<&str>, label: &str) -> Result<PathBuf, String> {
    let value = value.unwrap_or("").trim();
    if value.is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(PathBuf::from(value))
}

fn resolve_input_root(input: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(p) = input {
        return Ok(p.to_path_buf());
    }
    let runner_temp = env::var("RUNNER_TEMP").ok();
    configured_path(
        runner_temp.as_deref().map(|t| format!("{t}/legion-install")).as_deref(),
        "assembled install root",
    )
}

pub fn resolve_artifact_root(output_root: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(p) = output_root {
        return Ok(p.to_path_buf());
    }
    if let Ok(v) = env::var("RIGHT_GIT_ARTIFACT_ROOT") {
        if !v.trim().is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    let runner_temp = env::var("RUNNER_TEMP").ok();
    configured_path(
        runner_temp.as_deref().map(|t| format!("{t}/{CANDIDATE_ROOT_NAME}")).as_deref(),
        "RIGHT_GIT_ARTIFACT_ROOT or RUNNER_TEMP",
    )
}

fn assert_directory(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_dir() {
        return Err(format!("{label} is missing: {}", path.display()));
    }
    Ok(())
}

fn assert_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| format!("{label} is missing or unsafe: {}", path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(format!("{label} is missing or unsafe: {}", path.display()));
    }
    Ok(())
}

/// Lexical `..`/`.` resolution without requiring existence.
fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
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

/// Forward-slash relative path from `root` to `target` (mirrors Node's
/// `path.relative`, lexically, without requiring the paths to exist).
fn relative_lexical(root: &Path, target: &Path) -> String {
    let root = normalize_lexical(root);
    let target = normalize_lexical(target);
    let root_components: Vec<_> = root.components().collect();
    let target_components: Vec<_> = target.components().collect();
    let common = root_components.iter().zip(target_components.iter()).take_while(|(a, b)| a == b).count();
    let mut parts: Vec<String> = Vec::new();
    for _ in common..root_components.len() {
        parts.push("..".to_string());
    }
    for component in &target_components[common..] {
        parts.push(component.as_os_str().to_string_lossy().to_string());
    }
    parts.join("/")
}

fn assert_outside(source_root: &Path, destination_root: &Path) -> Result<(), String> {
    let rel = relative_lexical(source_root, destination_root);
    let bad = rel.is_empty() || (rel != ".." && !rel.starts_with("../"));
    if bad {
        return Err(format!("candidate artifacts must be outside assembled install root: {}", destination_root.display()));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn file_record(path: &Path) -> Result<Value, String> {
    Ok(json!({
        "name": path.file_name().map(|n| n.to_string_lossy().to_string()),
        "size": fs::metadata(path).map_err(|e| e.to_string())?.len(),
        "sha256": sha256_file(path)?,
    }))
}

fn timestamp(value: Option<&str>) -> String {
    if let Some(v) = value {
        return v.to_string();
    }
    if let Ok(epoch) = env::var("SOURCE_DATE_EPOCH") {
        if let Ok(secs) = epoch.parse::<i64>() {
            if secs >= 0 {
                return iso8601_utc_millis(secs, 0);
            }
        }
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    iso8601_utc_millis(now.as_secs() as i64, now.subsec_millis())
}

/// Formats an epoch-seconds + milliseconds pair as `YYYY-MM-DDTHH:MM:SS.mmmZ`
/// (matches `Date#toISOString()`), without a chrono/time dependency (neither
/// is declared in this crate's workspace deps).
pub(crate) fn iso8601_utc_millis(epoch_secs: i64, millis: u32) -> String {
    let days = epoch_secs.div_euclid(86_400);
    let secs_of_day = epoch_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Howard Hinnant's civil_from_days algorithm (proleptic Gregorian, days
/// since 1970-01-01) — public-domain algorithm, reimplemented here.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn property<'a>(properties: &'a Value, name: &str) -> Option<&'a Value> {
    properties.as_array()?.iter().find(|entry| entry.get("name").and_then(|v| v.as_str()) == Some(name)).and_then(|e| e.get("value"))
}

pub struct PrepareArgs {
    pub input: Option<PathBuf>,
    pub output_root: Option<PathBuf>,
    pub platform: Option<String>,
    pub architecture: Option<String>,
    pub source_revision: Option<String>,
    pub version: Option<String>,
    pub created_at: Option<String>,
}

fn run_inherit(command: &str, args: &[&str], cwd: &Path, extra_env: &[(String, String)], label: &str) -> Result<(), String> {
    // pnpm is a .cmd shim on Windows, which CreateProcess cannot launch directly.
    let mut cmd = if cfg!(windows) && command == "pnpm" {
        let mut c = Command::new("cmd");
        c.args(["/C", "pnpm"]);
        c
    } else {
        Command::new(command)
    };
    cmd.args(args).current_dir(cwd);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let status = cmd.status().map_err(|e| format!("{label} failed: {e}"))?;
    if !status.success() {
        return Err(format!("{label} failed: exit={}", status.code().unwrap_or(-1)));
    }
    Ok(())
}

fn assemble_and_smoke(repository_root: &Path, input_root: &Path, identity: &Identity) -> Result<(), String> {
    let target_triple = match (identity.platform.as_str(), identity.architecture.as_str()) {
        ("windows", "arm64") => "aarch64-pc-windows-msvc",
        ("windows", _) => "x86_64-pc-windows-msvc",
        (_, "arm64") => "aarch64-apple-darwin",
        _ => "x86_64-apple-darwin",
    };
    run_inherit("pnpm", &["legion:check"], repository_root, &[], "Legion consistency gate")?;
    let engine_dir = repository_root.join("engine");
    run_inherit("cargo", &["check", "--workspace", "--all-targets", "--locked"], &engine_dir, &[], "Cargo check")?;
    run_inherit("cargo", &["test", "--locked"], &engine_dir, &[], "Cargo tests")?;
    run_inherit(
        "cargo",
        &["build", "--locked", "--release", "--bins", "--target", target_triple],
        &engine_dir,
        &[],
        "cargo build",
    )?;
    let input_root_str = input_root.to_string_lossy().to_string();
    run_inherit(
        "pnpm",
        &[
            "native:assemble",
            "--",
            "--profile",
            "release",
            "--platform",
            &identity.platform,
            "--architecture",
            &identity.architecture,
            "--target",
            target_triple,
            "--out",
            &input_root_str,
            "--force",
        ],
        repository_root,
        &[],
        "native assembly",
    )?;
    let smoke_script = repository_root.join("scripts/ci/native-installed-smoke.mjs").to_string_lossy().to_string();
    run_inherit("node", &[smoke_script.as_str(), &input_root_str], repository_root, &[], "installed-product smoke")?;
    let bin_name = if identity.platform == "windows" { "legion.exe" } else { "legion" };
    let native_cli_path = input_root.join("bin").join(bin_name).to_string_lossy().to_string();
    run_inherit(
        "pnpm",
        &["test"],
        repository_root,
        &[("LEGION_TEST_NATIVE_CLI_PATH".to_string(), native_cli_path)],
        "Node tests",
    )?;
    Ok(())
}

/// Minimal seam over the one external call this function makes
/// (`createPortableArchive`), so tests can point it at a fake archive writer
/// instead of the real `@rightkit/release` subprocess bridge — mirroring the
/// JS test's `createArchive` override in
/// `tests/unsigned-release-candidate.test.mjs`. Everything else in this
/// function (SBOM/provenance materialization, path safety, candidate.json)
/// is exercised for real, same as the JS test.
pub struct PrepareDeps<'a> {
    pub create_archive: Box<dyn Fn(&Path, &Path, &Path) -> Result<Value, String> + 'a>,
}

impl<'a> Default for PrepareDeps<'a> {
    fn default() -> Self {
        Self { create_archive: Box::new(|root, src, out| rightkit_release_bridge::create_portable_archive(root, src, out)) }
    }
}

pub fn prepare_unsigned_candidate(repository_root: &Path, args: PrepareArgs) -> Result<Value, String> {
    prepare_unsigned_candidate_with(repository_root, args, &PrepareDeps::default())
}

pub fn prepare_unsigned_candidate_with(repository_root: &Path, args: PrepareArgs, deps: &PrepareDeps) -> Result<Value, String> {
    let platform = args
        .platform
        .clone()
        .or_else(|| env::var("RIGHT_GIT_RELEASE_PLATFORM").ok())
        .or_else(|| env::var("LEGION_RELEASE_PLATFORM").ok());
    let architecture = args
        .architecture
        .clone()
        .or_else(|| env::var("RIGHT_GIT_RELEASE_ARCHITECTURE").ok())
        .or_else(|| env::var("LEGION_RELEASE_ARCHITECTURE").ok());
    let identity = infer_target(platform.as_deref(), architecture.as_deref())?
        .ok_or_else(|| format!("unsigned public candidates require Windows or macOS: {}", platform.unwrap_or_default()))?;

    let input_root = resolve_input_root(args.input.as_deref())?;
    let artifact_root = resolve_artifact_root(args.output_root.as_deref())?;
    assert_outside(&input_root, &artifact_root)?;
    if args.input.is_none() && !input_root.exists() {
        assemble_and_smoke(repository_root, &input_root, &identity)?;
    }
    assert_directory(&input_root, "assembled install root")?;
    fs::create_dir_all(&artifact_root).map_err(|e| e.to_string())?;

    let release_version = read_stable_version(repository_root, args.version.as_deref())?;
    let revision = read_source_revision(repository_root, args.source_revision.as_deref())?;
    let target = identity.target.clone();
    let stem = format!("{PRODUCT}-{release_version}-{target}");
    let archive_ext = if identity.platform == "macos" { ".tar.gz" } else { ".zip" };
    let archive_path = artifact_root.join(format!("{stem}{archive_ext}"));
    let sbom_path = artifact_root.join(format!("{stem}.cdx.json"));
    let provenance_path = artifact_root.join(format!("{stem}.intoto.jsonl"));

    let archive_result = (deps.create_archive)(repository_root, &input_root, &archive_path)?;
    assert_regular_file(&archive_path, "portable archive")?;
    let archive_size = fs::metadata(&archive_path).map_err(|e| e.to_string())?.len();
    if archive_size < 1 {
        return Err(format!("portable archive is empty: {}", archive_path.display()));
    }
    let archive_sha256 = sha256_file(&archive_path)?;
    if let Some(reported) = archive_result.get("sha256").and_then(|v| v.as_str()) {
        let normalized = reported.trim_start_matches("sha256:").trim_start_matches("SHA256:").to_lowercase();
        if !normalized.is_empty() && normalized != archive_sha256 {
            return Err(format!("portable archive digest changed during preparation: {}", archive_path.display()));
        }
    }
    let archive = json!({
        "name": archive_path.file_name().unwrap().to_string_lossy(),
        "size": archive_size,
        "sha256": archive_sha256,
    });
    let evidence_timestamp = timestamp(args.created_at.as_deref());

    rightkit_release_bridge::materialize_cyclonedx_sbom(
        repository_root,
        &json!({
            "outputPath": sbom_path.to_string_lossy(),
            "product": PRODUCT,
            "version": release_version,
            "target": target,
            "sourceCommit": revision,
            "files": [archive],
            "createdAt": evidence_timestamp,
        }),
    )?;
    rightkit_release_bridge::materialize_in_toto_slsa_provenance(
        repository_root,
        &json!({
            "outputPath": provenance_path.to_string_lossy(),
            "product": PRODUCT,
            "version": release_version,
            "target": target,
            "sourceCommit": revision,
            "sourceRepository": SOURCE_REPOSITORY,
            "subjects": [archive],
            "startedAt": evidence_timestamp,
            "finishedAt": evidence_timestamp,
        }),
    )?;

    let candidate = json!({
        "schemaVersion": 1,
        "kind": CANDIDATE_KIND,
        "product": PRODUCT,
        "version": release_version,
        "target": target,
        "sourceRevision": revision,
        "files": {
            "archive": file_record(&archive_path)?,
            "sbom": file_record(&sbom_path)?,
            "provenance": file_record(&provenance_path)?,
        }
    });
    let candidate_path = artifact_root.join(CANDIDATE_FILE);
    fs::write(&candidate_path, format!("{}\n", serde_json::to_string_pretty(&candidate).unwrap())).map_err(|e| e.to_string())?;

    Ok(json!({
        "status": "complete",
        "product": PRODUCT,
        "version": release_version,
        "target": target,
        "platform": identity.platform,
        "architecture": identity.architecture,
        "sourceRevision": revision,
        "inputRoot": input_root.display().to_string(),
        "outputRoot": artifact_root.display().to_string(),
        "archive": archive_path.display().to_string(),
        "archiveSha256": archive_sha256,
        "sbom": sbom_path.display().to_string(),
        "provenance": provenance_path.display().to_string(),
        "candidate": candidate_path.display().to_string(),
    }))
}

pub struct CheckArgs {
    pub output_root: Option<PathBuf>,
    pub platform: Option<String>,
    pub architecture: Option<String>,
    pub source_revision: Option<String>,
    pub version: Option<String>,
}

pub fn check_unsigned_candidate(repository_root: &Path, args: CheckArgs) -> Result<Value, String> {
    let platform = args
        .platform
        .clone()
        .or_else(|| env::var("RIGHT_GIT_RELEASE_PLATFORM").ok())
        .or_else(|| env::var("LEGION_RELEASE_PLATFORM").ok());
    let architecture = args
        .architecture
        .clone()
        .or_else(|| env::var("RIGHT_GIT_RELEASE_ARCHITECTURE").ok())
        .or_else(|| env::var("LEGION_RELEASE_ARCHITECTURE").ok());
    let identity = infer_target(platform.as_deref(), architecture.as_deref())?
        .ok_or_else(|| format!("unsigned public candidates require Windows or macOS: {}", platform.unwrap_or_default()))?;

    let artifact_root = resolve_artifact_root(args.output_root.as_deref())?;
    let release_version = read_stable_version(repository_root, args.version.as_deref())?;
    let revision = read_source_revision(repository_root, args.source_revision.as_deref())?;
    let target = identity.target.clone();
    let stem = format!("{PRODUCT}-{release_version}-{target}");
    let archive_ext = if identity.platform == "macos" { ".tar.gz" } else { ".zip" };
    let archive_path = artifact_root.join(format!("{stem}{archive_ext}"));
    let sbom_path = artifact_root.join(format!("{stem}.cdx.json"));
    let provenance_path = artifact_root.join(format!("{stem}.intoto.jsonl"));
    let candidate_path = artifact_root.join(CANDIDATE_FILE);
    if !artifact_root.is_dir() {
        return Err(format!("candidate artifact root is missing: {}", artifact_root.display()));
    }

    let expected_names: std::collections::HashSet<String> = [
        CANDIDATE_FILE.to_string(),
        archive_path.file_name().unwrap().to_string_lossy().to_string(),
        sbom_path.file_name().unwrap().to_string_lossy().to_string(),
        provenance_path.file_name().unwrap().to_string_lossy().to_string(),
    ]
    .into_iter()
    .collect();
    let entries: Vec<_> = fs::read_dir(&artifact_root).map_err(|e| e.to_string())?.filter_map(|e| e.ok()).collect();
    if entries.len() != expected_names.len()
        || entries.iter().any(|e| !expected_names.contains(&e.file_name().to_string_lossy().to_string()))
    {
        return Err("candidate artifact root must contain exactly candidate.json, archive, SBOM, and provenance".to_string());
    }
    for (path, label) in [
        (&candidate_path, CANDIDATE_FILE),
        (&archive_path, "portable archive"),
        (&sbom_path, "CycloneDX SBOM"),
        (&provenance_path, "in-toto provenance"),
    ] {
        assert_regular_file(path, label)?;
    }

    let candidate: Value = serde_json::from_str(&fs::read_to_string(&candidate_path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut candidate_keys: Vec<String> = candidate.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
    candidate_keys.sort();
    if candidate_keys.join(",") != "files,kind,product,schemaVersion,sourceRevision,target,version" {
        return Err("candidate.json schema is invalid".to_string());
    }
    if candidate.get("schemaVersion").and_then(|v| v.as_i64()) != Some(1)
        || candidate.get("kind").and_then(|v| v.as_str()) != Some(CANDIDATE_KIND)
        || candidate.get("product").and_then(|v| v.as_str()) != Some(PRODUCT)
        || candidate.get("version").and_then(|v| v.as_str()) != Some(release_version.as_str())
        || candidate.get("target").and_then(|v| v.as_str()) != Some(target.as_str())
        || candidate.get("sourceRevision").and_then(|v| v.as_str()) != Some(revision.as_str())
    {
        return Err("candidate.json identity does not match unsigned candidate".to_string());
    }
    let files = candidate.get("files").cloned().unwrap_or(Value::Null);
    let mut file_roles: Vec<String> = files.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
    file_roles.sort();
    if !files.is_object() || file_roles.join(",") != "archive,provenance,sbom" {
        return Err("candidate.json files must contain exactly archive, sbom, and provenance".to_string());
    }

    let archive_size = fs::metadata(&archive_path).map_err(|e| e.to_string())?.len();
    if archive_size < 1 {
        return Err(format!("portable archive is empty: {}", archive_path.display()));
    }
    let archive = json!({
        "name": archive_path.file_name().unwrap().to_string_lossy(),
        "size": archive_size,
        "sha256": sha256_file(&archive_path)?,
    });
    for (role, path) in [("archive", &archive_path), ("sbom", &sbom_path), ("provenance", &provenance_path)] {
        let expected = files.get(role).cloned().unwrap_or(Value::Null);
        let observed = file_record(path)?;
        let mut expected_keys: Vec<String> = expected.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        expected_keys.sort();
        let ok = expected.is_object()
            && expected_keys.join(",") == "name,sha256,size"
            && expected.get("name") == observed.get("name")
            && expected.get("size") == observed.get("size")
            && expected.get("sha256").and_then(|v| v.as_str()).map(|s| sha256_re().is_match(s)).unwrap_or(false)
            && expected.get("sha256") == observed.get("sha256");
        if !ok {
            return Err(format!("candidate file digest or size mismatch: {role}"));
        }
    }

    let sbom = rightkit_release_bridge::validate_cyclonedx_sbom(repository_root, &sbom_path, &archive)?;
    let component = sbom.get("metadata").and_then(|m| m.get("component")).cloned().unwrap_or(Value::Null);
    let properties = component.get("properties").cloned().unwrap_or(Value::Null);
    if component.get("name").and_then(|v| v.as_str()) != Some(PRODUCT)
        || component.get("version").and_then(|v| v.as_str()) != Some(release_version.as_str())
        || property(&properties, "rightkit:target").and_then(|v| v.as_str()) != Some(target.as_str())
        || property(&properties, "rightkit:sourceCommit").and_then(|v| v.as_str()) != Some(revision.as_str())
    {
        return Err("CycloneDX identity does not match unsigned candidate".to_string());
    }

    let expected_subject = json!({ "name": archive.get("name"), "sha256": archive.get("sha256") });
    let provenance =
        rightkit_release_bridge::validate_in_toto_slsa_provenance(repository_root, &provenance_path, &expected_subject)?;
    let build_definition = provenance.get("predicate").and_then(|p| p.get("buildDefinition")).cloned().unwrap_or(Value::Null);
    let dependency = build_definition
        .get("resolvedDependencies")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .cloned()
        .unwrap_or(Value::Null);
    let external_parameters = build_definition.get("externalParameters").cloned().unwrap_or(Value::Null);
    let expected_uri = format!("git+{SOURCE_REPOSITORY}@{revision}");
    if external_parameters.get("product").and_then(|v| v.as_str()) != Some(PRODUCT)
        || external_parameters.get("version").and_then(|v| v.as_str()) != Some(release_version.as_str())
        || external_parameters.get("target").and_then(|v| v.as_str()) != Some(target.as_str())
        || dependency.get("digest").and_then(|d| d.get("gitCommit")).and_then(|v| v.as_str()) != Some(revision.as_str())
        || dependency.get("uri").and_then(|v| v.as_str()) != Some(expected_uri.as_str())
    {
        return Err("in-toto identity does not match unsigned candidate".to_string());
    }

    Ok(json!({
        "status": "verified",
        "product": PRODUCT,
        "version": release_version,
        "target": target,
        "platform": identity.platform,
        "architecture": identity.architecture,
        "sourceRevision": revision,
        "outputRoot": artifact_root.display().to_string(),
        "archive": archive_path.display().to_string(),
        "archiveSha256": archive.get("sha256"),
        "sbom": sbom_path.display().to_string(),
        "provenance": provenance_path.display().to_string(),
        "candidate": candidate_path.display().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rust port of the JS test "unsigned candidates require explicit
    /// platform and architecture" (`tests/unsigned-release-candidate.test.mjs`).
    #[test]
    fn infer_target_normalizes_platform_and_architecture() {
        let identity = infer_target(Some("win32"), Some("x64")).unwrap().unwrap();
        assert_eq!(identity.platform, "windows");
        assert_eq!(identity.architecture, "x86_64");
        assert_eq!(identity.target, "windows-x86_64");
    }

    #[test]
    fn infer_target_requires_explicit_platform_and_architecture() {
        let err = infer_target(None, None).unwrap_err();
        assert!(err.contains("explicit platform and architecture"));
    }

    #[test]
    fn assert_outside_rejects_nested_output_root() {
        let source = PathBuf::from("/tmp/legion-test/install");
        let nested = PathBuf::from("/tmp/legion-test/install/nested-artifacts");
        let err = assert_outside(&source, &nested).unwrap_err();
        assert!(err.contains("must be outside assembled install root"));
    }

    #[test]
    fn assert_outside_accepts_sibling_output_root() {
        let source = PathBuf::from("/tmp/legion-test/install");
        let sibling = PathBuf::from("/tmp/legion-test/artifacts");
        assert!(assert_outside(&source, &sibling).is_ok());
    }

    #[test]
    fn iso8601_matches_expected_format() {
        // 2026-08-28T00:00:00.000Z
        let secs = 1787875200; // 2026-08-28T00:00:00Z (verified independently)
        let formatted = iso8601_utc_millis(secs, 0);
        assert!(formatted.ends_with("T00:00:00.000Z"));
        assert!(formatted.starts_with("2026-08-28"));
    }

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn temp_root(prefix: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn fake_create_archive<'a>() -> PrepareDeps<'a> {
        PrepareDeps {
            create_archive: Box::new(|_root, _src, out| {
                fs::create_dir_all(out.parent().unwrap()).map_err(|e| e.to_string())?;
                fs::write(out, "portable archive\n").map_err(|e| e.to_string())?;
                Ok(json!({ "path": out.to_string_lossy() }))
            }),
        }
    }

    fn first_jsonl_object(path: &Path) -> Value {
        let text = fs::read_to_string(path).unwrap();
        let line = text.lines().find(|l| !l.trim().is_empty()).unwrap();
        serde_json::from_str(line).unwrap()
    }

    /// Rust port of "unsigned candidate binds portable archive to CycloneDX
    /// 1.6 and SLSA v1 evidence" (`tests/unsigned-release-candidate.test.mjs`).
    /// `createArchive` is stubbed (mirroring the JS test); SBOM/provenance
    /// materialization and validation run for real against the external
    /// `@rightkit/release` package, same as the JS test.
    #[test]
    fn prepare_and_check_unsigned_candidate_end_to_end() {
        let root = temp_root("legion-unsigned-candidate");
        let repository_root = root.join("repo");
        let input = root.join("install");
        let output_root = root.join("artifacts");
        fs::create_dir_all(repository_root.join("release")).unwrap();
        fs::write(
            repository_root.join("release/version.json"),
            json!({ "schemaVersion": 1, "kind": "legion-release-version", "version": "0.1.0" }).to_string(),
        )
        .unwrap();
        fs::create_dir_all(input.join("bin")).unwrap();
        fs::write(input.join("bin/legion"), "candidate runtime\n").unwrap();

        let source_revision = "a".repeat(40);
        let result = prepare_unsigned_candidate_with(
            &repository_root,
            PrepareArgs {
                input: Some(input.clone()),
                output_root: Some(output_root.clone()),
                platform: Some("darwin".to_string()),
                architecture: Some("arm64".to_string()),
                source_revision: Some(source_revision.clone()),
                version: None,
                created_at: Some("2026-08-28T00:00:00.000Z".to_string()),
            },
            &fake_create_archive(),
        )
        .unwrap();

        assert_eq!(result["status"], "complete");
        assert_eq!(result["target"], "macos-arm64");
        assert_eq!(result["version"], "0.1.0");
        assert_eq!(result["sourceRevision"], source_revision);
        assert!(result["archive"].as_str().unwrap().ends_with("legion-0.1.0-macos-arm64.tar.gz"));
        assert!(result["candidate"].as_str().unwrap().ends_with("candidate.json"));

        let candidate_path = PathBuf::from(result["candidate"].as_str().unwrap());
        let candidate: Value = serde_json::from_str(&fs::read_to_string(&candidate_path).unwrap()).unwrap();
        let mut file_keys: Vec<String> = candidate["files"].as_object().unwrap().keys().cloned().collect();
        file_keys.sort();
        assert_eq!(file_keys, vec!["archive", "provenance", "sbom"]);

        let sbom_path = PathBuf::from(result["sbom"].as_str().unwrap());
        let sbom: Value = serde_json::from_str(&fs::read_to_string(&sbom_path).unwrap()).unwrap();
        assert_eq!(sbom["specVersion"], "1.6");
        assert_eq!(sbom["components"][0]["name"], "legion-0.1.0-macos-arm64.tar.gz");

        let provenance_path = PathBuf::from(result["provenance"].as_str().unwrap());
        let provenance = first_jsonl_object(&provenance_path);
        assert_eq!(provenance["predicateType"], "https://slsa.dev/provenance/v1");
        assert_eq!(provenance["subject"][0]["digest"]["sha256"], result["archiveSha256"]);

        let checked = check_unsigned_candidate(
            &repository_root,
            CheckArgs {
                output_root: Some(output_root.clone()),
                platform: Some("darwin".to_string()),
                architecture: Some("arm64".to_string()),
                source_revision: Some(source_revision.clone()),
                version: None,
            },
        )
        .unwrap();
        assert_eq!(checked["status"], "verified");

        let original_sbom = fs::read(&sbom_path).unwrap();
        let mut tampered = original_sbom.clone();
        tampered.extend_from_slice(b"tampered\n");
        fs::write(&sbom_path, &tampered).unwrap();
        let err = check_unsigned_candidate(
            &repository_root,
            CheckArgs {
                output_root: Some(output_root.clone()),
                platform: Some("darwin".to_string()),
                architecture: Some("arm64".to_string()),
                source_revision: Some(source_revision.clone()),
                version: None,
            },
        )
        .unwrap_err();
        assert!(err.contains("candidate file digest or size mismatch"), "{err}");
        fs::write(&sbom_path, &original_sbom).unwrap();

        fs::write(output_root.join("extra.txt"), "unexpected\n").unwrap();
        let err = check_unsigned_candidate(
            &repository_root,
            CheckArgs {
                output_root: Some(output_root.clone()),
                platform: Some("darwin".to_string()),
                architecture: Some("arm64".to_string()),
                source_revision: Some(source_revision.clone()),
                version: None,
            },
        )
        .unwrap_err();
        assert!(err.contains("exactly candidate.json, archive, SBOM, and provenance"), "{err}");

        let err = prepare_unsigned_candidate_with(
            &repository_root,
            PrepareArgs {
                input: Some(input.clone()),
                output_root: Some(input.join("nested-artifacts")),
                platform: Some("darwin".to_string()),
                architecture: Some("arm64".to_string()),
                source_revision: Some(source_revision.clone()),
                version: None,
                created_at: None,
            },
            &PrepareDeps {
                create_archive: Box::new(|_, _, _| panic!("archive should not be created")),
            },
        )
        .unwrap_err();
        assert!(err.contains("candidate artifacts must be outside assembled install root"), "{err}");

        let _ = fs::remove_dir_all(&root);
    }
}
