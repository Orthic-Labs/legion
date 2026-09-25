//! Rust port of `scripts/release/windows/finalize.mjs`: extracts the signed
//! RightRelease portable `.zip`, copies its SBOM/provenance evidence, and
//! invokes the Windows installer worker (`windows_finalize_installer`,
//! in-process here rather than as a `node` child process, now that both are
//! Rust) to produce the finalized installer + evidence manifest.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::paths::{is_revision_hex, is_stable_semver, sha256_file, CommandOptions, CommandRunner, ReleaseResult};
use super::windows_finalize_installer::{finalize_windows_installer, FinalizeWindowsInstallerInput};
use crate::process_boundary::command_diagnostic;

fn fail(message: impl Into<String>) -> String {
    format!("windows-finalize-adapter: {}", message.into())
}

fn is_architecture(value: &str) -> bool {
    value == "x86_64" || value == "arm64"
}

#[derive(Debug, Clone, Serialize)]
pub struct FinalizeRecord {
    pub path: PathBuf,
    pub role: &'static str,
    pub size: u64,
    pub sha256: String,
}

fn record(path: &Path, role: &'static str) -> ReleaseResult<FinalizeRecord> {
    Ok(FinalizeRecord { size: fs::metadata(path).map_err(|e| fail(e.to_string()))?.len(), sha256: sha256_file(path)?, path: path.to_path_buf(), role })
}

struct PortableEvidencePaths {
    archive: PathBuf,
    sbom: PathBuf,
    provenance: PathBuf,
}

fn portable_evidence(root: &Path, extension: &str) -> ReleaseResult<PortableEvidencePaths> {
    let entries: Vec<_> = fs::read_dir(root).map_err(|e| fail(e.to_string()))?.filter_map(|e| e.ok()).collect();
    for entry in &entries {
        let meta = fs::symlink_metadata(entry.path()).map_err(|e| fail(e.to_string()))?;
        if meta.is_symlink() || !meta.is_file() {
            return Err(fail("portable root contains unsafe nested entry"));
        }
    }
    let one = |suffix: &str, label: &str| -> ReleaseResult<PathBuf> {
        let matches: Vec<_> = entries.iter().filter(|e| e.file_name().to_string_lossy().ends_with(suffix)).collect();
        if matches.len() != 1 {
            return Err(fail(format!("portable root must contain exactly one {label}")));
        }
        Ok(matches[0].path())
    };
    Ok(PortableEvidencePaths { archive: one(extension, "portable archive")?, sbom: one(".cdx.json", "SBOM")?, provenance: one(".intoto.jsonl", "provenance")? })
}

fn extract(runner: CommandRunner, archive: &Path, destination: &Path) -> ReleaseResult<()> {
    fs::create_dir_all(destination).map_err(|e| fail(e.to_string()))?;
    let options = CommandOptions::default();
    let result = runner("tar", &["-xf".to_string(), archive.to_string_lossy().to_string(), "-C".to_string(), destination.to_string_lossy().to_string()], &options);
    if result.error_message.is_some() || result.status != Some(0) {
        return Err(fail(format!("portable extraction failed: {}", command_diagnostic(&result))));
    }
    for name in ["bin", "plugin", "share"] {
        let path = destination.join(name);
        if !path.is_dir() {
            return Err(fail(format!("extracted {name} is missing or unsafe")));
        }
    }
    Ok(())
}

fn copy_evidence(input: &PortableEvidencePaths, output: &Path) -> ReleaseResult<PortableEvidencePaths> {
    let root = output.join("evidence");
    fs::create_dir_all(&root).map_err(|e| fail(e.to_string()))?;
    let copy = |path: &Path| -> ReleaseResult<PathBuf> {
        let target = root.join(path.file_name().unwrap());
        fs::copy(path, &target).map_err(|e| fail(e.to_string()))?;
        if sha256_file(&target)? != sha256_file(path)? {
            return Err(fail(format!("portable evidence copy mismatch: {}", path.file_name().unwrap().to_string_lossy())));
        }
        Ok(target)
    };
    Ok(PortableEvidencePaths { archive: copy(&input.archive)?, sbom: copy(&input.sbom)?, provenance: copy(&input.provenance)? })
}

#[derive(Default)]
pub struct FinalizeWindowsInput {
    pub portable_root: Option<PathBuf>,
    pub output_root: Option<PathBuf>,
    pub source_revision: String,
    pub version: String,
    pub architecture: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FinalizeWindowsResult {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: &'static str,
    pub status: &'static str,
    pub product: &'static str,
    pub version: String,
    #[serde(rename = "sourceRevision")]
    pub source_revision: String,
    pub architecture: String,
    pub assets: Vec<FinalizeRecord>,
    pub evidence: Vec<FinalizeRecord>,
}

pub fn finalize_windows(runner: CommandRunner, repository_root: &Path, inno_template: &str, activation_script: &Path, input: FinalizeWindowsInput) -> ReleaseResult<FinalizeWindowsResult> {
    if !is_stable_semver(&input.version) {
        return Err(fail("stable version is required"));
    }
    if !is_revision_hex(&input.source_revision) {
        return Err(fail("source revision is invalid"));
    }
    if !is_architecture(&input.architecture) {
        return Err(fail("architecture must be x86_64 or arm64"));
    }
    let portable = input.portable_root.clone().ok_or_else(|| fail("--portable-root is required"))?;
    let output = input.output_root.clone().ok_or_else(|| fail("--output-root is required"))?;
    if !portable.is_dir() {
        return Err(fail("portable root is missing or unsafe"));
    }
    fs::create_dir_all(&output).map_err(|e| fail(e.to_string()))?;
    if fs::read_dir(&output).map_err(|e| fail(e.to_string()))?.next().is_some() {
        return Err(fail("output root must be empty"));
    }
    let portable_input = portable_evidence(&portable, ".zip")?;
    let evidence = copy_evidence(&portable_input, &output)?;
    let payload = output.join(".payload");
    extract(runner, &portable_input.archive, &payload)?;
    let installer_output = output.join(".installer");
    let receipt = installer_output.join("installer-signing.json");
    let response = finalize_windows_installer(
        runner,
        repository_root,
        inno_template,
        activation_script,
        FinalizeWindowsInstallerInput {
            input_root: Some(payload),
            output_root: Some(installer_output.clone()),
            version: input.version.clone(),
            architecture: input.architecture.clone(),
            receipt_path: Some(receipt),
            rendered_script_path: None,
            unsigned: false,
            inno_setup_path: None,
        },
    )
    .map_err(|e| fail(format!("Windows installer worker failed: {e}")))?;
    if response.status != "signed" || response.identity.version != input.version || response.identity.architecture != input.architecture {
        return Err(fail("Windows installer worker response is invalid"));
    }
    let Some(signing_receipt) = response.receipt.clone() else {
        return Err(fail("Windows installer worker did not return a signing receipt"));
    };
    Ok(FinalizeWindowsResult {
        schema_version: 1,
        kind: "legion-windows-installer-finalization",
        status: "finalized",
        product: "legion",
        version: input.version,
        source_revision: input.source_revision.to_lowercase(),
        architecture: input.architecture,
        assets: vec![record(&response.installer, "installer")?],
        evidence: vec![
            record(&evidence.archive, "portable-archive")?,
            record(&evidence.sbom, "sbom")?,
            record(&evidence.provenance, "provenance")?,
            record(&signing_receipt, "installer-signing-receipt")?,
        ],
    })
}
