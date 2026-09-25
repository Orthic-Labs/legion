//! Native orchestration of `finalizeWindowsDirectRelease`. All pure
//! verification (signature/provenance/qualification evidence, publication
//! policy, output-path safety) runs in `evidence.rs`/native code here.
//! `checkUnsignedCandidate` (`scripts/ci/prepare-unsigned-candidate.mjs`) is
//! already ported natively (`crate::prepare_unsigned_candidate`, T4 packet)
//! and is called directly, in-process. The handful of calls that genuinely
//! need `@rightkit/release` (Azure-signed release-manifest materialization,
//! PowerShell bootstrap rendering/validation, CycloneDX/in-toto
//! materialization, GitHub Releases publication) go through
//! `crate::rightkit_release_bridge`, the shared T4 subprocess bridge into
//! that external package.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::prepare_unsigned_candidate::{check_unsigned_candidate, CheckArgs};
use crate::rightkit_release_bridge::call_module_function;
use crate::windows_release_support::{assert_source_revision, digest_matches, read_json, sha256_file};

use super::evidence::{assert_publication_policy, candidate_signature_evidence, finalization_provenance_evidence, qualification_evidence, CandidateSignatureArgs, QualificationEvidenceArgs};
use super::prepare::{file_record, release_version, source_revision, windows_target_identity};

fn call_node_function(repository_root: &Path, module_path: &str, function_name: &str, args: &Value) -> Result<Value, String> {
    call_module_function(repository_root, module_path, function_name, args)
}

const PRODUCT: &str = "legion";
const GITHUB_REPOSITORY: &str = "Orthic-Labs/legion";
const SOURCE_REPOSITORY: &str = "https://github.com/Orthic-Labs/legion";

pub struct FinalizeOptions<'a> {
    pub input: &'a Path,
    pub output: Option<&'a Path>,
    pub architecture: &'a str,
    pub source_revision: Option<&'a str>,
    pub signature_receipt: Option<&'a Path>,
    pub candidate_receipt: Option<&'a Path>,
    pub qualification: Option<&'a Path>,
    pub provenance: Option<&'a Path>,
    pub publish_github: bool,
    pub dry_run: bool,
    pub repository_root: &'a Path,
    pub created_at: String,
}

/// Mirrors `finalizeWindowsDirectRelease`.
pub fn finalize_windows_direct_release(options: FinalizeOptions) -> Result<Value, String> {
    let input_root = crate::windows_release_support::canonical_path(options.input);
    let version = release_version(options.repository_root)?;
    let is_candidate = input_root.join("candidate.json").exists();
    if !is_candidate {
        return Err("protected Windows finalization requires an exact unsigned candidate root".to_string());
    }
    let supplied_revision = options.source_revision.ok_or_else(|| "--source-revision is required when consuming an exact unsigned candidate".to_string())?;
    let revision = assert_source_revision(Some(supplied_revision))?;

    // checkUnsignedCandidate: native in-process call (T4 packet port), no
    // subprocess needed.
    let checked = check_unsigned_candidate(
        options.repository_root,
        CheckArgs {
            output_root: Some(input_root.clone()),
            platform: Some("windows".to_string()),
            architecture: Some(options.architecture.to_string()),
            source_revision: Some(revision.clone()),
            version: Some(version.clone()),
        },
    )?;
    let identity = windows_target_identity(options.architecture)?;
    let archive_path_for_candidate = checked.get("archive").and_then(|v| v.as_str()).ok_or("checkUnsignedCandidate result has no archive path")?;
    let candidate_archive = file_record(Path::new(archive_path_for_candidate))?;
    let sbom_path_for_candidate = checked.get("sbom").and_then(|v| v.as_str()).map(PathBuf::from);
    let provenance_path_for_candidate = checked.get("provenance").and_then(|v| v.as_str()).map(PathBuf::from);

    let architecture = identity.get("architecture").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let output_dir = options
        .output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| options.repository_root.join("dist").join("releases").join("windows").join(&version).join(&architecture));
    let archive_name = format!("legion-{version}-windows-{architecture}.zip");
    let archive_path = output_dir.join(&archive_name);

    let signed_provenance = finalization_provenance_evidence(
        options.provenance.map(|p| options.repository_root.join(p)).as_deref(),
        &version,
        &identity,
        options.repository_root,
    )
    .unwrap_or_else(|e| json!({ "status": "invalid", "reason": e }));
    if signed_provenance.get("status").and_then(|v| v.as_str()) != Some("verified") {
        return Err(format!(
            "RightRelease provenance is not verified: {}",
            signed_provenance.get("reason").and_then(|v| v.as_str()).unwrap_or_default()
        ));
    }
    fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;
    let signed_archive_path = signed_provenance.get("archivePath").and_then(|v| v.as_str()).ok_or("finalization provenance has no archive path")?;
    fs::copy(signed_archive_path, &archive_path).map_err(|e| e.to_string())?;
    if !digest_matches(Some(&sha256_file(Path::new(signed_archive_path))?), Some(&sha256_file(&archive_path)?)) {
        return Err("signed final archive bytes changed during product packaging".to_string());
    }
    let archive = file_record(&archive_path)?;

    let effective_signature = candidate_signature_evidence(CandidateSignatureArgs {
        receipt_path: options.signature_receipt.map(|p| options.repository_root.join(p)).as_deref(),
        candidate_receipt_path: options.candidate_receipt.map(|p| options.repository_root.join(p)).as_deref(),
        candidate_archive_sha256: &candidate_archive.sha256,
        final_archive_sha256: &archive.sha256,
        finalization_archive_sha256: signed_provenance.pointer("/source/archiveSha256").and_then(|v| v.as_str()),
        finalization_signed_artifacts: signed_provenance.pointer("/source/signedArtifacts").unwrap_or(&Value::Null),
    });
    if effective_signature.get("status").and_then(|v| v.as_str()) != Some("verified") {
        return Err(format!(
            "Windows release signing is not verified: {}",
            effective_signature.get("reason").and_then(|v| v.as_str()).unwrap_or_default()
        ));
    }

    let qualification_path = options
        .qualification
        .map(|p| options.repository_root.join(p))
        .unwrap_or_else(|| options.repository_root.join(".right-release").join("receipts").join(format!("windows-{architecture}-qualification.json")));
    let qualification_value = if qualification_path.exists() { read_json(&qualification_path, "Windows qualification evidence").ok() } else { None };
    let runtime_sha256 = qualification_value.as_ref().and_then(|v| v.get("runtimeSha256")).and_then(|v| v.as_str()).map(str::to_string);
    let generation = qualification_value.as_ref().and_then(|v| v.get("generation")).and_then(|v| v.as_str()).map(str::to_string);
    let qualification_record = qualification_evidence(QualificationEvidenceArgs {
        evidence_path: &qualification_path,
        archive_digest: &archive.sha256,
        runtime_digest: runtime_sha256.as_deref(),
        identity: &identity,
        release_version: &version,
        source_revision: &revision,
        generation: generation.as_deref(),
    });
    if qualification_record.get("status").and_then(|v| v.as_str()) != Some("verified") {
        return Err(format!(
            "Windows release qualification is not verified: {}",
            qualification_record.get("reason").and_then(|v| v.as_str()).unwrap_or_default()
        ));
    }

    let evidence_stem = format!("legion-{version}-windows-{architecture}");
    let sbom_path = output_dir.join(format!("{evidence_stem}.cdx.json"));
    let provenance_path = output_dir.join(format!("{evidence_stem}.intoto.jsonl"));
    let candidate_sbom_path = output_dir.join(format!("{evidence_stem}.candidate.cdx.json"));
    let candidate_provenance_path = output_dir.join(format!("{evidence_stem}.candidate.intoto.jsonl"));
    if let Some(sbom) = &sbom_path_for_candidate {
        fs::copy(sbom, &candidate_sbom_path).map_err(|e| e.to_string())?;
    }
    if let Some(provenance) = &provenance_path_for_candidate {
        fs::copy(provenance, &candidate_provenance_path).map_err(|e| e.to_string())?;
    }

    // materializeCycloneDxSbom / materializeInTotoSlsaProvenance: pure
    // generators in @rightkit/release/supply-chain-evidence.mjs.
    call_node_function(
        options.repository_root,
        "@rightkit/release/supply-chain-evidence.mjs",
        "materializeCycloneDxSbom",
        &json!({ "outputPath": sbom_path, "product": PRODUCT, "version": version, "target": format!("windows-{architecture}"), "sourceCommit": revision, "files": [archive.to_json()], "createdAt": options.created_at }),
    )?;
    call_node_function(
        options.repository_root,
        "@rightkit/release/supply-chain-evidence.mjs",
        "materializeInTotoSlsaProvenance",
        &json!({ "outputPath": provenance_path, "product": PRODUCT, "version": version, "target": format!("windows-{architecture}"), "sourceCommit": revision, "sourceRepository": SOURCE_REPOSITORY, "subjects": [archive.to_json()], "startedAt": options.created_at, "finishedAt": options.created_at }),
    )?;

    let release_base = format!("https://github.com/{GITHUB_REPOSITORY}/releases/download/v{version}");
    let asset = call_node_function(
        options.repository_root,
        "@rightkit/release/direct-bootstrap.mjs",
        "collectReleaseAsset",
        &json!({
            "target": format!("windows-{architecture}"),
            "name": archive.name,
            "url": format!("{release_base}/{}", archive.name),
            "archivePath": archive_path,
            "executablePath": "bin/legion.exe",
            "nativeSignaturePolicy": "authenticode-valid",
            "provenancePath": provenance_path,
            "sbomPath": sbom_path,
        }),
    )?;

    let direct = call_node_function(
        options.repository_root,
        "@rightkit/release/direct-bootstrap.mjs",
        "materializeDirectRelease",
        &json!({
            "outputDir": output_dir,
            "manifestInput": { "product": PRODUCT, "version": version, "sourceCommit": revision, "minimumBootstrapVersion": version, "assets": [asset] },
        }),
    )?;
    let checksums_path = output_dir.join("checksums.json");
    let signer = direct.pointer("/signing/signer").cloned().unwrap_or(Value::Null);
    let bootstrap = call_node_function(
        options.repository_root,
        "@rightkit/release/direct-bootstrap.mjs",
        "renderPowerShellBootstrap",
        &json!({
            "product": PRODUCT,
            "repository": GITHUB_REPOSITORY,
            "bootstrapVersion": version,
            "acceptedManifestSigners": [signer],
            "installRootSubdir": "Orthic Labs/Legion",
            "executablePath": "bin/legion.exe",
            "activationArgs": ["--json", "setup", "repair", "--confirm"],
            "statusArgs": ["--json", "setup", "status"],
        }),
    )?
    .as_str()
    .unwrap_or_default()
    .to_string();
    let bootstrap_path = output_dir.join("install.ps1");
    fs::write(&bootstrap_path, &bootstrap).map_err(|e| e.to_string())?;
    let bootstrap_validation = call_node_function(
        options.repository_root,
        "@rightkit/release/direct-bootstrap.mjs",
        "validatePowerShellBootstrap",
        &json!({ "bootstrap": bootstrap, "options": { "product": PRODUCT, "acceptedSignerIds": [direct.pointer("/signing/signer/id")] } }),
    )?;
    if bootstrap_validation.get("valid").and_then(|v| v.as_bool()) != Some(true) {
        return Err("generated bootstrap is invalid".to_string());
    }

    if options.publish_github {
        assert_publication_policy(
            options.repository_root,
            &json!({
                "platform-artifacts": true,
                "platform-signatures": effective_signature.get("status").and_then(|v| v.as_str()) == Some("verified"),
                "provenance-attestations": true,
                "signed-release-manifest": direct.get("signaturePath").is_some(),
                "bootstrap-transaction": true,
                "rollback-transaction": qualification_record.get("status").and_then(|v| v.as_str()) == Some("verified"),
                "client-integration-health": qualification_record.get("status").and_then(|v| v.as_str()) == Some("verified"),
                "channel-authorization": true,
            }),
        )?;
    }

    let github_plan = call_node_function(
        options.repository_root,
        "@rightkit/release/github-release.mjs",
        "prepareGitHubDirectRelease",
        &json!({
            "repoRoot": options.repository_root,
            "repo": GITHUB_REPOSITORY,
            "product": PRODUCT,
            "version": version,
            "manifestPath": direct.get("manifestPath"),
            "signaturePath": direct.get("signaturePath"),
            "checksumsPath": checksums_path,
            "archivePaths": [archive_path],
            "provenancePaths": [provenance_path],
            "sbomPaths": [sbom_path],
            "signing": direct.get("signing"),
            "assets": [bootstrap_path],
        }),
    )?;
    let github = if options.publish_github {
        call_node_function(
            options.repository_root,
            "@rightkit/release/github-release.mjs",
            "publishGitHubRelease",
            &json!({ "plan": github_plan, "options": { "repo": GITHUB_REPOSITORY, "dryRun": options.dry_run } }),
        )?
    } else {
        json!({ "status": "prepared", "tag": github_plan.get("tag") })
    };

    Ok(json!({
        "status": "qualified",
        "outputDir": output_dir,
        "archive": archive_path,
        "manifest": direct.get("manifestPath"),
        "signature": direct.get("signaturePath"),
        "checksums": checksums_path,
        "provenance": provenance_path,
        "sbom": sbom_path,
        "candidateSbom": candidate_sbom_path,
        "candidateProvenance": candidate_provenance_path,
        "rightkitFinalizationReceipt": signed_provenance.get("receipt"),
        "bootstrap": bootstrap_path,
        "releaseVersion": version,
        "sourceRevision": revision,
        "targetIdentity": identity,
        "archiveSha256": archive.sha256,
        "runtimeSha256": runtime_sha256,
        "github": github,
    }))
}

#[allow(dead_code)]
fn resolve_source_revision_default(repository_root: &Path) -> Result<String, String> {
    source_revision(repository_root, None)
}
