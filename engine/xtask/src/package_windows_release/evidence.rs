//! Native port of `package-windows-release.mjs`'s pure evidence-verification
//! helpers: `qualificationEvidence`, `candidateSignatureEvidence`, and
//! `assertPublicationPolicy`. These never touch `@rightkit/release`; they
//! only read/compare JSON receipts already on disk, so they are fully
//! native. `finalizationProvenanceEvidence` additionally needs
//! `@rightkit/release`'s `readNativeFinalizationOutput`/
//! `validateNativeFinalizationOutput`, so its non-JSON-shape validation runs
//! through `node_shim`.

use std::path::Path;

use serde_json::{json, Value};

use crate::windows_release_config::WindowsInstallContract;
use crate::windows_release_support::{bare_digest, digest_matches, has_forbidden_binding_segment, paths_equal, path_inside, read_json, version_root_matches};

const REQUIRED_BINARIES: [&str; 3] = ["legion.exe", "legion-hook.exe", "legion-mcp.exe"];
const REQUIRED_QUALIFICATION_GATES: [&str; 6] = ["installed-product", "command-resolution", "client-integration", "update", "rollback", "uninstall"];

fn qualification_target_identity_matches(observed: &Value, expected: &Value) -> bool {
    let keys = ["platform", "architecture", "nativeArchitecture", "targetTriple", "executable", "artifactId"];
    observed.is_object()
        && observed.as_object().map(|o| o.len()) == Some(keys.len())
        && keys.iter().all(|key| observed.get(*key) == expected.get(*key))
}

fn qualification_gates_pass(value: &Value) -> bool {
    let gates = match value.get("gates") {
        Some(g) if g.is_object() => g,
        _ => return false,
    };
    let entries = gates.as_object().unwrap();
    if entries.len() != REQUIRED_QUALIFICATION_GATES.len() {
        return false;
    }
    REQUIRED_QUALIFICATION_GATES.iter().all(|name| {
        entries
            .get(*name)
            .map(|gate| gate.get("name").and_then(|v| v.as_str()) == Some(*name) && gate.get("status").and_then(|v| v.as_str()) == Some("pass"))
            .unwrap_or(false)
    })
}

pub struct QualificationEvidenceArgs<'a> {
    pub evidence_path: &'a Path,
    pub archive_digest: &'a str,
    pub runtime_digest: Option<&'a str>,
    pub identity: &'a Value,
    pub release_version: &'a str,
    pub source_revision: &'a str,
    pub generation: Option<&'a str>,
}

/// Mirrors `qualificationEvidence`.
pub fn qualification_evidence(args: QualificationEvidenceArgs) -> Value {
    if !args.evidence_path.exists() {
        return json!({ "status": "missing", "reason": "native installed-product qualification is required" });
    }
    let value = match read_json(args.evidence_path, "Windows qualification evidence") {
        Ok(v) => v,
        Err(e) => return json!({ "status": "invalid", "reason": e }),
    };
    if !value.is_object() {
        return json!({ "status": "invalid", "reason": "qualification evidence must be a JSON object" });
    }
    if crate::windows_release_support::assert_source_revision(Some(args.source_revision)).is_err() {
        return json!({ "status": "invalid", "reason": "qualification source revision is missing or invalid" });
    }
    let expected_generation = args
        .generation
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}:{}", args.release_version, bare_digest(args.runtime_digest.unwrap_or(""))));
    let runner_architecture = if args.identity.get("architecture").and_then(|v| v.as_str()) == Some("x86_64") { "x64" } else { "arm64" };

    let install = value.get("install");
    let install_root = install.and_then(|i| i.get("root")).and_then(|v| v.as_str());
    let executable = install.and_then(|i| i.get("executable")).and_then(|v| v.as_str());
    let current_version_root = install.and_then(|i| i.get("currentVersionRoot")).and_then(|v| v.as_str());
    let versions_root = install.and_then(|i| i.get("versionsRoot")).and_then(|v| v.as_str());
    let integration_journal_path = install.and_then(|i| i.get("integrationJournal")).and_then(|v| v.as_str());
    let expected_versions_root = install_root.map(|r| format!("{r}/versions"));

    let stable_binding_ok = |binding: Option<&Value>| -> bool {
        let install = match binding {
            Some(b) if b.is_object() => b,
            _ => return false,
        };
        let install_root = install.get("root").or_else(|| install.get("installRoot")).and_then(|v| v.as_str());
        let current_path = install.get("currentPath").and_then(|v| v.as_str());
        let exe = install.get("executable").and_then(|v| v.as_str());
        install.get("origin").and_then(|v| v.as_str()) == Some(WindowsInstallContract::ORIGIN)
            && install_root.is_some()
            && current_path.is_some()
            && exe.is_some()
            && install_root.map(|p| Path::new(p).is_absolute()).unwrap_or(false)
            && current_path.map(|p| Path::new(p).is_absolute()).unwrap_or(false)
            && exe.map(|p| Path::new(p).is_absolute()).unwrap_or(false)
            && paths_equal(current_path, install_root.map(|r| format!("{r}/{}", WindowsInstallContract::STABLE_CURRENT_NAME)).as_deref())
            && paths_equal(exe, current_path.map(|c| format!("{c}/{}", WindowsInstallContract::EXECUTABLE_PATH)).as_deref())
            && install.get("generation").and_then(|v| v.as_str()) == Some(expected_generation.as_str())
            && !has_forbidden_binding_segment(install_root.unwrap_or_default())
            && !has_forbidden_binding_segment(current_path.unwrap_or_default())
            && !has_forbidden_binding_segment(exe.unwrap_or_default())
    };

    let valid = value.get("schemaVersion").and_then(|v| v.as_i64()) == Some(1)
        && value.get("kind").and_then(|v| v.as_str()) == Some("legion-windows-installed-product-qualification")
        && value.get("status").and_then(|v| v.as_str()) == Some("qualified")
        && value.get("nativeExecution").and_then(|v| v.as_bool()) == Some(true)
        && value.get("executionMode").and_then(|v| v.as_str()) == Some("native")
        && qualification_target_identity_matches(value.get("targetIdentity").unwrap_or(&Value::Null), args.identity)
        && value.get("releaseVersion").and_then(|v| v.as_str()) == Some(args.release_version)
        && value.get("sourceRevision").and_then(|v| v.as_str()).map(|s| s.to_lowercase()) == Some(args.source_revision.to_lowercase())
        && value.pointer("/runner/os").and_then(|v| v.as_str()) == Some("win32")
        && value.pointer("/runner/architecture").and_then(|v| v.as_str()) == Some(runner_architecture)
        && value.pointer("/runner/simulated").and_then(|v| v.as_bool()) == Some(false)
        && value.get("origin").and_then(|v| v.as_str()) == Some(WindowsInstallContract::ORIGIN)
        && paths_equal(value.get("installRoot").and_then(|v| v.as_str()), install_root)
        && paths_equal(value.get("executable").and_then(|v| v.as_str()), executable)
        && value.get("generation").and_then(|v| v.as_str()) == Some(expected_generation.as_str())
        && stable_binding_ok(install)
        && stable_binding_ok(value.get("binding"))
        && paths_equal(value.pointer("/binding/resolvedVersionRoot").and_then(|v| v.as_str()), current_version_root)
        && current_version_root.map(|p| Path::new(p).is_absolute()).unwrap_or(false)
        && path_inside(versions_root, current_version_root)
        && version_root_matches(current_version_root, Some(args.release_version), Some(args.archive_digest))
        && !has_forbidden_binding_segment(current_version_root.unwrap_or_default())
        && paths_equal(versions_root, expected_versions_root.as_deref())
        && paths_equal(integration_journal_path, install_root.map(|r| format!("{r}/{}", WindowsInstallContract::INTEGRATION_JOURNAL_NAME)).as_deref())
        && value.pointer("/integrationJournal/kind").and_then(|v| v.as_str()) == Some("legion-integration-journal")
        && value.pointer("/integrationJournal/origin").and_then(|v| v.as_str()) == Some(WindowsInstallContract::ORIGIN)
        && paths_equal(value.pointer("/integrationJournal/installRoot").and_then(|v| v.as_str()), install_root)
        && paths_equal(value.pointer("/integrationJournal/executable").and_then(|v| v.as_str()), executable)
        && value.pointer("/integrationJournal/generation").and_then(|v| v.as_str()) == Some(expected_generation.as_str())
        && paths_equal(value.pointer("/integrationJournal/activeVersionRoot").and_then(|v| v.as_str()), current_version_root)
        && paths_equal(
            value.pointer("/integrationJournal/binding/resolvedVersionRoot").and_then(|v| v.as_str()),
            current_version_root,
        )
        && digest_matches(value.get("archiveSha256").and_then(|v| v.as_str()), Some(args.archive_digest))
        && digest_matches(value.get("runtimeSha256").and_then(|v| v.as_str()), args.runtime_digest)
        && qualification_gates_pass(&value);

    if valid {
        json!({ "status": "verified", "source": value })
    } else {
        json!({ "status": "invalid", "reason": "qualification is not exact native target/version/source/digest-bound evidence" })
    }
}

pub struct CandidateSignatureArgs<'a> {
    pub receipt_path: Option<&'a Path>,
    pub candidate_receipt_path: Option<&'a Path>,
    pub candidate_archive_sha256: &'a str,
    pub final_archive_sha256: &'a str,
    pub finalization_archive_sha256: Option<&'a str>,
    pub finalization_signed_artifacts: &'a Value,
}

/// Mirrors `candidateSignatureEvidence`.
pub fn candidate_signature_evidence(args: CandidateSignatureArgs) -> Value {
    let receipt_path = match args.receipt_path.filter(|p| p.exists()) {
        Some(p) => p,
        None => return json!({ "status": "missing", "reason": "RightRelease archive signing receipt is required" }),
    };
    let receipt = match read_json(receipt_path, "RightRelease archive signing receipt") {
        Ok(v) => v,
        Err(e) => return json!({ "status": "invalid", "reason": e }),
    };
    let candidate_receipt_path = match args.candidate_receipt_path.filter(|p| p.exists()) {
        Some(p) => p,
        None => return json!({ "status": "missing", "reason": "verified candidate-input receipt is required" }),
    };
    let candidate_receipt = match read_json(candidate_receipt_path, "candidate-input receipt") {
        Ok(v) => v,
        Err(e) => return json!({ "status": "invalid", "reason": e }),
    };
    if candidate_receipt.get("schema").and_then(|v| v.as_i64()) != Some(1)
        || candidate_receipt.get("kind").and_then(|v| v.as_str()) != Some("legion-windows-candidate-input")
        || candidate_receipt.get("status").and_then(|v| v.as_str()) != Some("verified")
        || !digest_matches(candidate_receipt.get("candidateArchiveSha256").and_then(|v| v.as_str()), Some(args.candidate_archive_sha256))
    {
        return json!({ "status": "invalid", "reason": "candidate-input receipt does not bind exact CI archive bytes" });
    }
    if !digest_matches(args.finalization_archive_sha256, Some(args.final_archive_sha256)) {
        return json!({ "status": "invalid", "reason": "RightRelease finalization does not bind final archive bytes" });
    }
    let files = receipt.get("files").and_then(|v| v.as_array());
    let candidate_files = candidate_receipt.get("files").and_then(|v| v.as_array());
    let signed_artifacts = args.finalization_signed_artifacts.as_array();
    let (files, candidate_files, signed_artifacts) = match (files, candidate_files, signed_artifacts) {
        (Some(f), Some(c), Some(s)) if f.len() == REQUIRED_BINARIES.len() => (f, c, s),
        _ => return json!({ "status": "invalid", "reason": "receipt does not enumerate every signed Legion executable" }),
    };
    for name in REQUIRED_BINARIES {
        let entry = files.iter().find(|item| file_basename(item, "file").as_deref() == Some(name) || file_basename(item, "path").as_deref() == Some(name));
        let input = candidate_files.iter().find(|item| file_basename(item, "file").as_deref() == Some(name));
        let signed = signed_artifacts.iter().find(|item| file_basename(item, "path").as_deref() == Some(name));
        let ok = match (entry, input, signed) {
            (Some(entry), Some(input), Some(signed)) => {
                digest_matches(entry.pointer("/before/sha256").and_then(|v| v.as_str()), input.get("sha256").and_then(|v| v.as_str()))
                    && digest_matches(entry.pointer("/after/sha256").and_then(|v| v.as_str()), signed.get("sha256").and_then(|v| v.as_str()))
                    && entry.get("authenticode").and_then(|v| v.as_str()) == Some("Valid")
                    && entry.get("subject").and_then(|v| v.as_str()) == Some("CN=Damned Ventures LLC")
                    && entry.get("timestampPresent").and_then(|v| v.as_bool()) == Some(true)
            }
            _ => false,
        };
        if !ok {
            return json!({ "status": "invalid", "reason": format!("receipt does not prove Authenticode final bytes for {name}") });
        }
    }
    json!({ "status": "verified", "receipt": receipt_path, "root": Value::Null })
}

fn file_basename(item: &Value, key: &str) -> Option<String> {
    item.get(key).and_then(|v| v.as_str()).map(|s| Path::new(s).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| s.to_string()))
}

/// Mirrors `assertPublicationPolicy`.
pub fn assert_publication_policy(repository_root: &Path, evidence: &Value) -> Result<(), String> {
    let contract = read_json(&repository_root.join("release").join("distribution-contract.json"), "distribution contract")?;
    let policy = read_json(&repository_root.join("release").join("publication-policy.json"), "publication policy")?;
    let channel_name = contract.pointer("/nativeRelease/channel").and_then(|v| v.as_str()).unwrap_or("direct-bootstrap");
    let channel = policy.pointer(&format!("/channels/{channel_name}"));
    let channel_allowed = channel.and_then(|c| c.get("allowed")).and_then(|v| v.as_bool()) == Some(true);
    if contract.pointer("/nativeRelease/status").and_then(|v| v.as_str()) != Some("available") || !channel_allowed {
        let reason = channel.and_then(|c| c.get("reason")).and_then(|v| v.as_str()).unwrap_or("native release is not authorized");
        return Err(format!("publication blocked by release/publication-policy.json: {reason}"));
    }
    let channel = channel.unwrap();
    if policy.get("publisher").and_then(|v| v.as_str()) != Some("rightkit-release")
        || channel.get("payloadAuthority").and_then(|v| v.as_str()) != Some("immutable-github-release")
        || channel.get("bootstrapProvider").and_then(|v| v.as_str()) != Some("rightkit-worker-r2")
    {
        return Err("publication blocked: checked-in publication authority is invalid".to_string());
    }
    if channel.get("approvedBy").is_none() || channel.get("approvedAt").is_none() || channel.get("policyDigest").is_none() {
        return Err("publication blocked: channel authorization evidence is incomplete".to_string());
    }
    let required = contract.pointer("/nativeRelease/requiredEvidence").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let missing: Vec<String> = required
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|name| evidence.get(*name).and_then(|v| v.as_bool()) != Some(true))
        .map(str::to_string)
        .collect();
    if !missing.is_empty() {
        return Err(format!("publication blocked: required evidence is incomplete ({})", missing.join(", ")));
    }
    Ok(())
}
