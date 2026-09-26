//! Rust port of `scripts/release/installer-release-chain.mjs`: the one
//! deliberately narrow seam between RightRelease portable candidates and
//! Legion's platform installer finalizers. It never guesses artifacts: every
//! hand-off is a digest-bound manifest owned by its producing platform.
//!
//! `admission`/`stage-summary`/`evidence-verification` are re-exports of
//! `admission.rs` (already wired to `xtask release-*` subcommands).
//! `finalize-windows`/`finalize-macos` call the Rust `windows_finalize`/
//! `macos_finalize` modules in-process instead of spawning a `node` worker
//! (both are now Rust). `right-release` and `gh` remain external subprocess
//! calls with exactly the arguments the JS used, per the porting brief.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Value};

use super::macos_finalize::{finalize_macos as run_finalize_macos, FinalizeMacosInput};
use super::paths::{inside, is_revision_hex, is_stable_semver, read_json, sha256_file, write_json_pretty, CommandOptions, CommandRunner, ReleaseResult};
use super::windows_finalize::{finalize_windows as run_finalize_windows, FinalizeWindowsInput};
use super::windows_qualify_installed::{qualify_installed_windows, QualifyInstalledWindowsInput};
use crate::process_boundary::command_diagnostic;

const PRODUCT: &str = "legion";
const REPOSITORY: &str = "Orthic-Labs/legion";

fn fail(message: impl Into<String>) -> String {
    message.into()
}

fn required<'a>(env: &'a HashMap<String, String>, name: &str) -> ReleaseResult<&'a str> {
    match env.get(name).map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(v) => Ok(v),
        None => Err(fail(format!("{name} is required"))),
    }
}

fn stable_version(value: &str, label: &str) -> ReleaseResult<String> {
    if !is_stable_semver(value) {
        return Err(fail(format!("{label} is invalid: {value}")));
    }
    Ok(value.to_string())
}

fn source_revision_norm(value: &str) -> ReleaseResult<String> {
    if !is_revision_hex(value) {
        return Err(fail(format!("source revision is invalid: {value}")));
    }
    Ok(value.to_lowercase())
}

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub role: String,
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// Mirrors `entryRecord`: validates a manifest-declared record against the
/// real file on disk (path containment, digest, size, role presence).
fn entry_record(root: &Path, value: &Value, label: &str) -> ReleaseResult<Record> {
    if !value.is_object() {
        return Err(fail(format!("{label} record is invalid")));
    }
    let raw_path = value.get("path").and_then(Value::as_str).unwrap_or("");
    let candidate = Path::new(raw_path);
    let joined = if candidate.is_absolute() { candidate.to_path_buf() } else { root.join(candidate) };
    let path = inside(root, &joined, label, false)?;
    if !path.is_file() {
        return Err(fail(format!("{label} is missing: {}", path.display())));
    }
    let observed_sha256 = sha256_file(&path)?;
    let observed_size = fs::metadata(&path).map_err(|e| fail(e.to_string()))?.len();
    let declared_sha256 = value.get("sha256").and_then(Value::as_str).unwrap_or("");
    if declared_sha256.len() != 64 || !declared_sha256.chars().all(|c| c.is_ascii_hexdigit()) || observed_sha256 != declared_sha256.to_lowercase() {
        return Err(fail(format!("{label} digest mismatch")));
    }
    let declared_size = value.get("size").and_then(Value::as_u64);
    if declared_size != Some(observed_size) {
        return Err(fail(format!("{label} size mismatch")));
    }
    let role = value.get("role").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| fail(format!("{label} role is missing")))?;
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    Ok(Record { role: role.to_string(), path, name, size: observed_size, sha256: observed_sha256 })
}

/// Mirrors `copyRecord`: copies a validated staged record into the final
/// output root at its visible basename (GitHub artifact transfer excludes
/// dot-prefixed directories, so publish names are basenames, not the
/// finalizer's private staging layout).
fn copy_record(from_root: &Path, to_root: &Path, record: &Record) -> ReleaseResult<Record> {
    inside(from_root, &record.path, "finalizer artifact", false)?;
    let target = inside(to_root, &to_root.join(&record.name), "finalized output", false)?;
    fs::create_dir_all(target.parent().unwrap()).map_err(|e| fail(e.to_string()))?;
    if target.exists() {
        return Err(fail(format!("finalized output already exists: {}", target.display())));
    }
    fs::copy(&record.path, &target).map_err(|e| fail(e.to_string()))?;
    if sha256_file(&target)? != record.sha256 {
        return Err(fail(format!("copied artifact digest mismatch: {}", record.name)));
    }
    Ok(Record { role: record.role.clone(), name: record.name.clone(), path: target, size: record.size, sha256: record.sha256.clone() })
}

fn record_from_value(size: u64, sha256: String, path: PathBuf, role: String) -> Record {
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    Record { role, path, name, size, sha256 }
}

fn right_release_cli(repository_root: &Path) -> PathBuf {
    repository_root.join("node_modules").join("@rightkit").join("release").join("cli").join("right-release.mjs")
}

fn run_command(runner: CommandRunner, command: &str, args: &[String], options: &CommandOptions, label: &str) -> ReleaseResult<crate::process_boundary::CommandResult> {
    let result = runner(command, args, options);
    if result.error_message.is_some() || result.status != Some(0) {
        // The diagnostic keeps only the head of stderr; the failing step's own
        // error is at the tail, so surface the full stream in the job log.
        if let Some(stderr) = result.stderr.as_deref().filter(|s| !s.trim().is_empty()) {
            eprintln!("--- {label} stderr ---\n{stderr}\n--- end {label} stderr ---");
        }
        return Err(fail(format!("{label} failed: {}", command_diagnostic(&result))));
    }
    Ok(result)
}

fn run_json(runner: CommandRunner, command: &str, args: &[String], options: &CommandOptions, label: &str) -> ReleaseResult<Value> {
    let result = run_command(runner, command, args, options, label)?;
    let stdout = result.stdout.unwrap_or_default();
    serde_json::from_str(stdout.trim()).map_err(|_| fail(format!("{label} must emit one JSON object")))
}

struct RightReleaseEnvironment {
    source_revision: String,
    unsigned_candidate_root: PathBuf,
    architecture: String,
    env: HashMap<String, String>,
}

fn right_release_environment(env: &HashMap<String, String>, platform: &str) -> ReleaseResult<RightReleaseEnvironment> {
    let source = source_revision_norm(required(env, "RIGHT_GIT_SOURCE_REVISION")?)?;
    let candidate = required(env, "RIGHT_GIT_UNSIGNED_CANDIDATE_ROOT")?.to_string();
    let architecture = required(env, "RIGHT_GIT_RELEASE_ARCHITECTURE")?.to_string();
    let declared_platform = required(env, "RIGHT_GIT_RELEASE_PLATFORM")?;
    if declared_platform != platform {
        return Err(fail(format!("RIGHT_GIT_RELEASE_PLATFORM must be {platform}")));
    }
    let candidate_root = std::env::current_dir().unwrap_or_default().join(&candidate);
    let candidate_root = if Path::new(&candidate).is_absolute() { PathBuf::from(&candidate) } else { candidate_root };
    let mut merged = env.clone();
    merged.insert("LEGION_SOURCE_REVISION".to_string(), source.clone());
    merged.insert("LEGION_UNSIGNED_CANDIDATE_ROOT".to_string(), candidate_root.to_string_lossy().to_string());
    merged.insert("RIGHT_GIT_SOURCE_REVISION".to_string(), source.clone());
    merged.insert("RIGHT_GIT_RELEASE_PLATFORM".to_string(), platform.to_string());
    merged.insert("RIGHT_GIT_RELEASE_ARCHITECTURE".to_string(), architecture.clone());
    Ok(RightReleaseEnvironment { source_revision: source, unsigned_candidate_root: candidate_root, architecture, env: merged })
}

struct CandidateEvidence {
    sbom: PathBuf,
    provenance: PathBuf,
}

fn candidate_evidence(candidate_root: &Path, platform: &str, architecture: &str, version: &str, source_revision: &str) -> ReleaseResult<CandidateEvidence> {
    let candidate = read_json(&candidate_root.join("candidate.json"), "unsigned candidate receipt")?;
    let ok = candidate.get("schemaVersion").and_then(Value::as_i64) == Some(1)
        && candidate.get("kind").and_then(Value::as_str) == Some("legion-unsigned-release-candidate")
        && candidate.get("product").and_then(Value::as_str) == Some(PRODUCT)
        && candidate.get("version").and_then(Value::as_str) == Some(version)
        && candidate.get("target").and_then(Value::as_str) == Some(format!("{platform}-{architecture}").as_str())
        && candidate.get("sourceRevision").and_then(Value::as_str).map(|s| s.to_lowercase()) == Some(source_revision.to_string());
    if !ok {
        return Err(fail("unsigned candidate receipt identity is invalid"));
    }
    let record = |key: &str, suffix: &str| -> ReleaseResult<PathBuf> {
        let value = candidate.get("files").and_then(|f| f.get(key));
        let Some(value) = value else { return Err(fail(format!("unsigned candidate {key} record is invalid"))) };
        let name = value.get("name").and_then(Value::as_str).unwrap_or("");
        let size = value.get("size").and_then(Value::as_u64);
        let sha256 = value.get("sha256").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() || !name.ends_with(suffix) || size.is_none() || sha256.len() != 64 {
            return Err(fail(format!("unsigned candidate {key} record is invalid")));
        }
        let candidate_path = candidate_root.join(name);
        let path = inside(candidate_root, &candidate_path, &format!("unsigned candidate {key}"), false)?;
        if !path.is_file() {
            return Err(fail(format!("unsigned candidate {key} is missing: {}", path.display())));
        }
        if fs::metadata(&path).map_err(|e| fail(e.to_string()))?.len() != size.unwrap() || sha256_file(&path)? != sha256.to_lowercase() {
            return Err(fail(format!("unsigned candidate {key} digest mismatch")));
        }
        Ok(path)
    };
    Ok(CandidateEvidence { sbom: record("sbom", ".cdx.json")?, provenance: record("provenance", ".intoto.jsonl")? })
}

/// Mirrors `signedPortableEvidenceRoot`: stages the signed RightRelease
/// portable archive plus its SBOM/provenance into a fresh temp directory the
/// platform finalizer reads from (and this function's caller removes when done).
fn signed_portable_evidence_root(portable_root: &Path, candidate_root: &Path, platform: &str, architecture: &str, version: &str, source_revision: &str) -> ReleaseResult<PathBuf> {
    let extension = if platform == "windows" { ".zip" } else { ".tar.gz" };
    let entries: Vec<_> = fs::read_dir(portable_root).map_err(|e| fail(e.to_string()))?.filter_map(|e| e.ok()).collect();
    let archives: Vec<_> = entries
        .iter()
        .filter(|e| {
            let meta = fs::symlink_metadata(e.path()).ok();
            meta.map(|m| m.is_file() && !m.is_symlink()).unwrap_or(false) && e.file_name().to_string_lossy().ends_with(extension)
        })
        .collect();
    if archives.len() != 1 {
        return Err(fail("RightRelease portable output must contain exactly one signed archive"));
    }
    let root = std::env::temp_dir().join(format!("legion-installer-evidence-{}-{}", std::process::id(), rand_suffix()));
    fs::create_dir_all(&root).map_err(|e| fail(e.to_string()))?;
    let archive_name = archives[0].file_name();
    fs::copy(portable_root.join(&archive_name), root.join(&archive_name)).map_err(|e| fail(e.to_string()))?;
    let evidence = candidate_evidence(candidate_root, platform, architecture, version, source_revision)?;
    fs::copy(&evidence.sbom, root.join(evidence.sbom.file_name().unwrap())).map_err(|e| fail(e.to_string()))?;
    fs::copy(&evidence.provenance, root.join(evidence.provenance.file_name().unwrap())).map_err(|e| fail(e.to_string()))?;
    Ok(root)
}

fn rand_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub struct FinalizationManifestOptions<'a> {
    pub env: &'a HashMap<String, String>,
    pub runner: CommandRunner<'a>,
    pub repository_root: &'a Path,
    pub inno_template: &'a str,
    pub activation_script: &'a Path,
    pub swift_source: &'a Path,
    pub developer_id: Option<&'a str>,
    pub api_key_path: Option<&'a str>,
    pub api_key: Option<&'a str>,
    pub api_issuer: Option<&'a str>,
    pub now: &'a dyn Fn() -> String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FinalizationManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: &'static str,
    pub product: &'static str,
    pub platform: String,
    pub version: String,
    #[serde(rename = "sourceRevision")]
    pub source_revision: String,
    pub architecture: String,
    pub assets: Vec<Record>,
    pub evidence: Vec<Record>,
    pub manifest: PathBuf,
    pub digest: String,
}

/// Mirrors `finalizationManifest`, shared by `finalize-windows`/`finalize-macos`.
/// RightRelease is the exact signer/notarizer; no platform finalizer runs
/// until `right-release build --skip-checks` succeeds (`--skip-checks` only
/// skips package checks already run by candidate CI).
pub fn finalization_manifest(platform: &str, options: FinalizationManifestOptions) -> ReleaseResult<FinalizationManifest> {
    let mapped = right_release_environment(options.env, platform)?;
    let version = stable_version(
        read_json(&options.repository_root.join("release").join("version.json"), "release version")?.get("version").and_then(Value::as_str).unwrap_or(""),
        "version",
    )?;
    let final_root_name = if platform == "windows" { "RIGHT_GIT_FINALIZED_WINDOWS_ROOT" } else { "RIGHT_GIT_FINALIZED_MACOS_ROOT" };
    let final_root = PathBuf::from(required(options.env, final_root_name)?);
    fs::create_dir_all(&final_root).map_err(|e| fail(e.to_string()))?;
    if fs::read_dir(&final_root).map_err(|e| fail(e.to_string()))?.next().is_some() {
        return Err(fail(format!("{final_root_name} must be empty")));
    }
    let platform_dir = if platform == "windows" { "windows" } else { "mac" };
    let portable_root = options.repository_root.join("dist").join("releases").join(platform_dir).join(&version).join(&mapped.architecture);
    if !mapped.unsigned_candidate_root.is_dir() {
        return Err(fail("unsigned candidate root is missing or unsafe"));
    }

    let cli = right_release_cli(options.repository_root);
    let build_platform = if platform == "windows" { "win" } else { "mac" };
    let build_options = CommandOptions { cwd: Some(options.repository_root.to_path_buf()), env: Some(mapped.env.clone()) };
    run_command(options.runner, "node", &[cli.to_string_lossy().to_string(), "build".to_string(), "--platform".to_string(), build_platform.to_string(), "--skip-checks".to_string()], &build_options, &format!("RightRelease {platform} finalization"))?;
    if !portable_root.is_dir() {
        return Err(fail("RightRelease portable output is missing or unsafe"));
    }

    let staged = final_root.join(".staging");
    fs::create_dir_all(&staged).map_err(|e| fail(e.to_string()))?;
    let evidence_root = signed_portable_evidence_root(&portable_root, &mapped.unsigned_candidate_root, platform, &mapped.architecture, &version, &mapped.source_revision)?;

    let finalize_result = if platform == "windows" {
        run_finalize_windows(
            options.runner,
            options.repository_root,
            options.inno_template,
            options.activation_script,
            FinalizeWindowsInput { portable_root: Some(evidence_root.clone()), output_root: Some(staged.clone()), source_revision: mapped.source_revision.clone(), version: version.clone(), architecture: mapped.architecture.clone() },
        )
        .map(|r| (r.assets.into_iter().map(|a| record_from_value(a.size, a.sha256, a.path, a.role.to_string())).collect::<Vec<_>>(), r.evidence.into_iter().map(|e| record_from_value(e.size, e.sha256, e.path, e.role.to_string())).collect::<Vec<_>>()))
    } else {
        run_finalize_macos(
            options.runner,
            options.swift_source,
            FinalizeMacosInput { portable_root: Some(evidence_root.clone()), output_root: Some(staged.clone()), source_revision: mapped.source_revision.clone(), version: version.clone(), architecture: mapped.architecture.clone() },
            options.developer_id,
            options.api_key_path,
            options.api_key,
            options.api_issuer,
            options.now,
        )
        .map(|r| (r.assets.into_iter().map(|a| record_from_value(a.size, a.sha256, a.path, a.role.to_string())).collect::<Vec<_>>(), r.evidence.into_iter().map(|e| record_from_value(e.size, e.sha256, e.path, e.role.to_string())).collect::<Vec<_>>()))
    };
    let _ = fs::remove_dir_all(&evidence_root);
    let (response_assets, response_evidence) = finalize_result?;

    if response_assets.is_empty() || response_evidence.is_empty() {
        return Err(fail(format!("{platform} finalizer must declare installer assets & portable evidence")));
    }
    let all: Vec<Record> = response_assets.iter().cloned().chain(response_evidence.iter().cloned()).collect();
    let mut names = std::collections::HashSet::new();
    for record in &all {
        if !names.insert(record.name.to_lowercase()) {
            return Err(fail(format!("{platform} finalizer contains duplicate records")));
        }
    }
    let setup_count = all.iter().filter(|r| r.role == "installer").count();
    if setup_count != 1 {
        return Err(fail(format!("{} finalizer must declare exactly one installer", if platform == "windows" { "Windows" } else { "macOS" })));
    }
    let copied: Vec<Record> = all.iter().map(|r| copy_record(&staged, &final_root, r)).collect::<ReleaseResult<Vec<_>>>()?;
    let _ = fs::remove_dir_all(&staged);

    let asset_names: std::collections::HashSet<String> = response_assets.iter().map(|r| r.name.clone()).collect();
    let evidence_names: std::collections::HashSet<String> = response_evidence.iter().map(|r| r.name.clone()).collect();
    let assets: Vec<Record> = copied.iter().filter(|r| asset_names.contains(&r.name)).cloned().collect();
    let evidence: Vec<Record> = copied.iter().filter(|r| evidence_names.contains(&r.name)).cloned().collect();

    let manifest_value = json!({
        "schemaVersion": 1, "kind": "legion-installer-finalization", "product": PRODUCT, "platform": platform,
        "version": version, "sourceRevision": mapped.source_revision, "architecture": mapped.architecture,
        "assets": assets.iter().map(|r| json!({"role": r.role, "path": r.name, "name": r.name, "size": r.size, "sha256": r.sha256})).collect::<Vec<_>>(),
        "evidence": evidence.iter().map(|r| json!({"role": r.role, "path": r.name, "name": r.name, "size": r.size, "sha256": r.sha256})).collect::<Vec<_>>(),
    });
    let manifest_path = final_root.join("installer-finalization.json");
    write_json_pretty(&manifest_path, &manifest_value)?;
    let digest = sha256_file(&manifest_path)?;

    Ok(FinalizationManifest {
        schema_version: 1,
        kind: "legion-installer-finalization",
        product: PRODUCT,
        platform: platform.to_string(),
        version,
        source_revision: mapped.source_revision,
        architecture: mapped.architecture,
        assets,
        evidence,
        manifest: manifest_path,
        digest,
    })
}

pub struct ReadFinalization {
    pub schema_version: u32,
    pub platform: String,
    pub version: String,
    pub source_revision: String,
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    pub digest: String,
    pub records: Vec<Record>,
}

/// Mirrors `readFinalization`.
pub fn read_finalization(root: &Path, platform: &str) -> ReleaseResult<ReadFinalization> {
    let manifest_path = root.join("installer-finalization.json");
    let manifest = read_json(&manifest_path, &format!("{platform} finalization manifest"))?;
    let version = manifest.get("version").and_then(Value::as_str).unwrap_or("").to_string();
    let source_revision = manifest.get("sourceRevision").and_then(Value::as_str).unwrap_or("").to_string();
    let ok = manifest.get("schemaVersion").and_then(Value::as_i64) == Some(1)
        && manifest.get("kind").and_then(Value::as_str) == Some("legion-installer-finalization")
        && manifest.get("product").and_then(Value::as_str) == Some(PRODUCT)
        && manifest.get("platform").and_then(Value::as_str) == Some(platform)
        && is_stable_semver(&version)
        && is_revision_hex(&source_revision)
        && manifest.get("assets").and_then(Value::as_array).is_some()
        && manifest.get("evidence").and_then(Value::as_array).is_some();
    if !ok {
        return Err(fail(format!("{platform} finalization manifest is invalid")));
    }
    let mut all: Vec<Value> = vec![];
    all.extend(manifest.get("assets").and_then(Value::as_array).cloned().unwrap_or_default());
    all.extend(manifest.get("evidence").and_then(Value::as_array).cloned().unwrap_or_default());
    let mut records = vec![];
    for (i, item) in all.iter().enumerate() {
        records.push(entry_record(root, item, &format!("{platform} manifest record {i}"))?);
    }
    let mut names = std::collections::HashSet::new();
    for r in &records {
        if !names.insert(r.name.to_lowercase()) {
            return Err(fail(format!("{platform} finalization has duplicate paths")));
        }
    }
    Ok(ReadFinalization { schema_version: 1, platform: platform.to_string(), version, source_revision, digest: sha256_file(&manifest_path)?, root: root.to_path_buf(), manifest_path, records })
}

/// Mirrors `qualifyInstalled`.
pub fn qualify_installed(runner: CommandRunner, env: &HashMap<String, String>, is_windows: bool) -> ReleaseResult<Value> {
    if !is_windows {
        return Err(fail("installed qualification requires Windows"));
    }
    let finalization = read_finalization(Path::new(required(env, "RIGHT_GIT_FINALIZED_WINDOWS_ROOT")?), "windows")?;
    let evidence_root = PathBuf::from(required(env, "RIGHT_GIT_QUALIFICATION_EVIDENCE_ROOT")?);
    fs::create_dir_all(&evidence_root).map_err(|e| fail(e.to_string()))?;
    if fs::read_dir(&evidence_root).map_err(|e| fail(e.to_string()))?.next().is_some() {
        return Err(fail("RIGHT_GIT_QUALIFICATION_EVIDENCE_ROOT must be empty"));
    }
    let installers: Vec<&Record> = finalization.records.iter().filter(|r| r.role == "installer" && r.name.to_lowercase().ends_with(".exe")).collect();
    if installers.len() != 1 {
        return Err(fail("Windows finalization must contain exactly one setup EXE"));
    }
    let response = qualify_installed_windows(
        runner,
        QualifyInstalledWindowsInput {
            setup: Some(installers[0].path.clone()),
            output_root: Some(evidence_root.clone()),
            finalization_path: Some(finalization.manifest_path.clone()),
            source_revision: finalization.source_revision.clone(),
            version: finalization.version.clone(),
            platform_is_windows: is_windows,
        },
    )?;
    let windows_finalization_sha256 = response.get("windowsFinalizationSha256").and_then(Value::as_str).unwrap_or("").to_lowercase();
    if windows_finalization_sha256 != finalization.digest {
        return Err(fail("Windows qualification does not bind exact finalization"));
    }
    let evidence_value = response.get("evidence").cloned().ok_or_else(|| fail("Windows qualification evidence is missing"))?;
    let evidence = entry_record(&evidence_root, &evidence_value, "Windows qualification evidence")?;
    let mut result = response;
    result["evidence"] = json!({"role": evidence.role, "path": evidence.name, "name": evidence.name, "size": evidence.size, "sha256": evidence.sha256});
    result["finalizationDigest"] = json!(finalization.digest);
    Ok(result)
}

fn gh(runner: CommandRunner, args: &[String], options: &CommandOptions) -> crate::process_boundary::CommandResult {
    runner("gh", args, options)
}

fn gh_json(runner: CommandRunner, args: &[String], options: &CommandOptions, label: &str) -> ReleaseResult<Value> {
    let result = gh(runner, args, options);
    if result.error_message.is_some() || result.status != Some(0) {
        // The diagnostic keeps only the head of stderr; the failing step's own
        // error is at the tail, so surface the full stream in the job log.
        if let Some(stderr) = result.stderr.as_deref().filter(|s| !s.trim().is_empty()) {
            eprintln!("--- {label} stderr ---\n{stderr}\n--- end {label} stderr ---");
        }
        return Err(fail(format!("{label} failed: {}", command_diagnostic(&result))));
    }
    serde_json::from_str(&result.stdout.unwrap_or_default()).map_err(|_| fail(format!("{label} returned invalid JSON")))
}

pub struct PublishQualifiedOptions<'a> {
    pub env: &'a HashMap<String, String>,
    pub runner: CommandRunner<'a>,
    pub repository_root: &'a Path,
    pub download_root: Option<&'a Path>,
}

/// Mirrors `publishQualified`: verifies the Windows+macOS finalizations and
/// Windows qualification are mutually consistent, creates (or reuses) the
/// GitHub release for the tag, uploads every asset/evidence/qualification
/// file, then re-downloads each one and checks its digest against the
/// manifest before returning.
pub fn publish_qualified(options: PublishQualifiedOptions) -> ReleaseResult<Value> {
    let token = required(options.env, "GH_TOKEN")?.to_string();
    let windows = read_finalization(Path::new(required(options.env, "RIGHT_GIT_FINALIZED_WINDOWS_ROOT")?), "windows")?;
    let macos = read_finalization(Path::new(required(options.env, "RIGHT_GIT_FINALIZED_MACOS_ROOT")?), "macos")?;
    if windows.version != macos.version || windows.source_revision != macos.source_revision {
        return Err(fail("platform finalizations have mismatched source/version"));
    }
    let qualification_root = PathBuf::from(required(options.env, "RIGHT_GIT_QUALIFICATION_EVIDENCE_ROOT")?);
    let qualification_files: Vec<PathBuf> = fs::read_dir(&qualification_root)
        .map_err(|e| fail(e.to_string()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|ext| ext == "json").unwrap_or(false))
        .collect();
    if qualification_files.len() != 1 {
        return Err(fail("qualification evidence root must contain exactly one JSON evidence file"));
    }
    let qualification_path = qualification_files[0].clone();
    let qualification = read_json(&qualification_path, "qualification evidence")?;
    let q_sha256 = qualification.get("windowsFinalizationSha256").and_then(Value::as_str).unwrap_or("").to_lowercase();
    let ok = qualification.get("schemaVersion").and_then(Value::as_i64) == Some(1)
        && qualification.get("kind").and_then(Value::as_str) == Some("legion-windows-installed-installer-qualification")
        && qualification.get("status").and_then(Value::as_str) == Some("qualified")
        && qualification.get("product").and_then(Value::as_str) == Some(PRODUCT)
        && qualification.get("version").and_then(Value::as_str) == Some(windows.version.as_str())
        && qualification.get("sourceRevision").and_then(Value::as_str).map(|s| s.to_lowercase()) == Some(windows.source_revision.clone())
        && q_sha256 == windows.digest;
    if !ok {
        return Err(fail("qualification does not match Windows finalization"));
    }

    let tag = format!("v{}", windows.version);
    let mut release_env = options.env.clone();
    release_env.insert("GH_TOKEN".to_string(), token);
    let release_options = CommandOptions { cwd: Some(options.repository_root.to_path_buf()), env: Some(release_env.clone()) };

    let mut release = gh(options.runner, &["release".into(), "view".into(), tag.clone(), "--repo".into(), REPOSITORY.into(), "--json".into(), "tagName,isDraft,isPrerelease,assets".into()], &release_options);
    if release.status != Some(0) {
        release = gh(
            options.runner,
            &[
                "release".into(), "create".into(), tag.clone(), "--repo".into(), REPOSITORY.into(),
                "--target".into(), windows.source_revision.clone(),
                "--title".into(), format!("Legion {tag}"),
                "--notes".into(), format!("Qualified installers for {}.", windows.source_revision),
            ],
            &release_options,
        );
        if release.error_message.is_some() || release.status != Some(0) {
            return Err(fail(format!("GitHub release create failed: {}", command_diagnostic(&release))));
        }
    }

    let qualification_record = entry_record(
        &qualification_root,
        &json!({ "role": "qualification", "path": qualification_path, "size": fs::metadata(&qualification_path).map_err(|e| fail(e.to_string()))?.len(), "sha256": sha256_file(&qualification_path)? }),
        "qualification evidence",
    )?;
    let mut records: Vec<Record> = vec![];
    records.extend(windows.records.iter().cloned());
    records.extend(macos.records.iter().cloned());
    records.push(qualification_record);

    let mut names = std::collections::HashSet::new();
    for record in &records {
        let lower = record.name.to_lowercase();
        if !names.insert(lower) {
            return Err(fail(format!("release asset name is duplicated: {}", record.name)));
        }
        let source = if record.role == "qualification" { qualification_path.clone() } else { record.path.clone() };
        let upload = gh(options.runner, &["release".into(), "upload".into(), tag.clone(), source.to_string_lossy().to_string(), "--repo".into(), REPOSITORY.into()], &release_options);
        let already_exists = upload.stderr.as_deref().map(|s| s.to_lowercase()).map(|s| s.contains("already exists") || s.contains("already been taken")).unwrap_or(false);
        if (upload.error_message.is_some() || upload.status != Some(0)) && !already_exists {
            return Err(fail(format!("GitHub release upload failed for {}: {}", record.name, command_diagnostic(&upload))));
        }
    }

    let verified = gh_json(options.runner, &["release".into(), "view".into(), tag.clone(), "--repo".into(), REPOSITORY.into(), "--json".into(), "tagName,assets".into()], &release_options, "GitHub release verify")?;
    if verified.get("tagName").and_then(Value::as_str) != Some(tag.as_str()) || verified.get("assets").and_then(Value::as_array).is_none() {
        return Err(fail("GitHub release identity is invalid"));
    }
    let verified_assets = verified.get("assets").and_then(Value::as_array).cloned().unwrap_or_default();

    let root = options.download_root.map(|p| p.to_path_buf()).unwrap_or_else(|| options.repository_root.join(".right-release").join("downloads").join(&tag));
    fs::create_dir_all(&root).map_err(|e| fail(e.to_string()))?;
    for record in &records {
        let matches: Vec<&Value> = verified_assets.iter().filter(|a| a.get("name").and_then(Value::as_str) == Some(record.name.as_str())).collect();
        if matches.len() != 1 || matches[0].get("size").and_then(Value::as_u64) != Some(record.size) {
            return Err(fail(format!("GitHub release asset is missing or mismatched: {}", record.name)));
        }
        let destination = root.join(&record.name);
        if destination.exists() {
            let _ = fs::remove_file(&destination);
        }
        let download = gh(options.runner, &["release".into(), "download".into(), tag.clone(), "--repo".into(), REPOSITORY.into(), "--pattern".into(), record.name.clone(), "--dir".into(), root.to_string_lossy().to_string()], &release_options);
        if download.error_message.is_some() || download.status != Some(0) {
            return Err(fail(format!("GitHub release download failed for {}: {}", record.name, command_diagnostic(&download))));
        }
        if sha256_file(&destination)? != record.sha256 {
            return Err(fail(format!("GitHub release download digest mismatch: {}", record.name)));
        }
    }

    Ok(json!({
        "status": "published", "tag": tag, "version": windows.version, "sourceRevision": windows.source_revision,
        "windowsFinalizationSha256": windows.digest, "macosFinalizationSha256": macos.digest,
        "qualificationSha256": sha256_file(&qualification_path)?,
    }))
}
