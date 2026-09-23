//! Rust port of `scripts/verify-release.mjs`.
//!
//! Faithful port of `verifyReleaseManifestObject` (the schema/digest/path
//! validation core) plus a `sha256_file` helper matching
//! `src/lib/distribution/release-manifest.mjs`'s `fileDigest`. The CLI entry
//! point (`verifyReleaseManifest` reading a manifest path) is exposed as
//! `verify_release_manifest`.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn sha256_file(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(hex::encode(hasher.finalize()))
}

#[derive(Debug, Serialize, Clone)]
pub struct Issue {
    pub artifact: Value,
    pub issue: &'static str,
}

#[derive(Debug, Serialize)]
pub struct VerificationResult {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: &'static str,
    pub manifest: Option<String>,
    pub valid: bool,
    pub issues: Vec<Issue>,
}

/// Resolves `path` under `root`, rejecting empty/NUL/escaping paths. Mirrors
/// `resolvedArtifact`.
fn resolved_artifact(root: &Path, path: &str) -> Option<PathBuf> {
    if path.is_empty() || path.contains('\0') {
        return None;
    }
    let absolute = root.join(path);
    let normalized = normalize(&absolute);
    let root_normalized = normalize(root);
    if normalized.starts_with(&root_normalized) && normalized != root_normalized {
        Some(absolute)
    } else if normalized == root_normalized {
        // relative resolves to root itself ("" case) -> treat like JS: rel === ''
        None
    } else {
        None
    }
}

/// Lexical normalization (no filesystem access), matching Node's
/// `path.relative` resolving `..` segments without requiring existence.
fn normalize(path: &Path) -> PathBuf {
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

fn entry_path(entry: &Value) -> Option<String> {
    match entry {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map.get("path").and_then(|v| v.as_str()).map(|s| s.to_string()),
        _ => None,
    }
}

fn entry_digest(entry: &Value) -> Option<String> {
    match entry {
        Value::Object(map) => map.get("digest").and_then(|v| v.as_str()).map(|s| s.to_string()),
        _ => None,
    }
}

fn verify_referenced(root: &Path, entries: &[Value], issues: &mut Vec<Issue>) {
    for entry in entries {
        let path_str = entry_path(entry);
        let resolved = path_str.as_deref().and_then(|p| resolved_artifact(root, p));
        let artifact_value = path_str
            .clone()
            .map(Value::String)
            .unwrap_or(Value::Null);
        match resolved {
            None => issues.push(Issue { artifact: artifact_value, issue: "missing" }),
            Some(path) if !path.exists() => {
                issues.push(Issue { artifact: artifact_value, issue: "missing" })
            }
            Some(path) => {
                let digest = entry_digest(entry);
                match digest {
                    None => issues.push(Issue { artifact: artifact_value, issue: "digest-missing" }),
                    Some(expected) => {
                        if sha256_file(&path).as_deref() != Some(expected.as_str()) {
                            issues.push(Issue { artifact: artifact_value, issue: "digest-mismatch" });
                        }
                    }
                }
            }
        }
    }
}

fn array_field<'a>(manifest: &'a Value, field: &str) -> &'a [Value] {
    manifest
        .get(field)
        .and_then(|v| v.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

pub fn verify_release_manifest_object(
    manifest: &Value,
    root: &Path,
    manifest_path: Option<&str>,
) -> Result<VerificationResult, String> {
    let schema_ok = manifest.get("schemaVersion").and_then(|v| v.as_i64()) == Some(1)
        && manifest.get("kind").and_then(|v| v.as_str()) == Some("legion-release-manifest");
    if !schema_ok {
        return Err("release manifest must be legion-release-manifest schemaVersion=1".to_string());
    }

    let dir = normalize(root);
    let mut issues: Vec<Issue> = Vec::new();

    for entry in array_field(manifest, "artifacts") {
        let path_str = entry_path(entry);
        let artifact_value = path_str.clone().map(Value::String).unwrap_or(Value::Null);
        let resolved = path_str.as_deref().and_then(|p| resolved_artifact(&dir, p));
        let resolved = match resolved {
            None => {
                issues.push(Issue { artifact: artifact_value, issue: "path-escape" });
                continue;
            }
            Some(p) => p,
        };
        let observed = sha256_file(&resolved);
        match observed {
            None => issues.push(Issue { artifact: artifact_value, issue: "missing" }),
            Some(observed) => match entry_digest(entry) {
                None => issues.push(Issue { artifact: artifact_value, issue: "digest-missing" }),
                Some(expected) if expected != observed => {
                    issues.push(Issue { artifact: artifact_value, issue: "digest-mismatch" })
                }
                _ => {}
            },
        }
    }

    for (field, label) in [
        ("checksums", "SHA256SUMS"),
        ("sboms", "SBOM"),
        ("notices", "THIRD_PARTY_NOTICES"),
        ("signatures", "signature"),
        ("notarization", "notarization"),
        ("qualificationArtifacts", "qualification"),
    ] {
        let entries = array_field(manifest, field);
        if entries.is_empty() {
            issues.push(Issue { artifact: Value::String(label.to_string()), issue: "missing" });
        } else {
            verify_referenced(&dir, entries, &mut issues);
        }
    }

    for entry in array_field(manifest, "sboms") {
        let path_str = entry_path(entry);
        if let Some(resolved) = path_str.as_deref().and_then(|p| resolved_artifact(&dir, p)) {
            if resolved.exists() {
                let artifact_value = path_str.clone().map(Value::String).unwrap_or(Value::Null);
                match fs::read_to_string(&resolved).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
                    Some(value) => {
                        let components = value
                            .get("components")
                            .or_else(|| value.get("packages"))
                            .and_then(|v| v.as_array())
                            .map(|v| v.is_empty())
                            .unwrap_or(true);
                        if components {
                            issues.push(Issue { artifact: artifact_value, issue: "empty-sbom" });
                        }
                    }
                    None => issues.push(Issue { artifact: artifact_value, issue: "invalid-sbom" }),
                }
            }
        }
    }

    for signature in array_field(manifest, "signatures") {
        let artifact_value = entry_path(signature)
            .map(Value::String)
            .unwrap_or_else(|| Value::String("signature".to_string()));
        if entry_digest(signature).is_none() {
            issues.push(Issue { artifact: artifact_value.clone(), issue: "signature-digest-missing" });
        }
        let status = signature.get("status").and_then(|v| v.as_str());
        if status.is_none() || status == Some("placeholder") || status == Some("missing") {
            issues.push(Issue { artifact: artifact_value, issue: "placeholder-signature" });
        }
    }

    for entry in array_field(manifest, "notarization") {
        let artifact_value = entry_path(entry)
            .map(Value::String)
            .unwrap_or_else(|| Value::String("notarization".to_string()));
        if entry_digest(entry).is_none() {
            issues.push(Issue { artifact: artifact_value.clone(), issue: "notarization-digest-missing" });
        }
        let status = entry.get("status").and_then(|v| v.as_str());
        if status.is_none() || status == Some("placeholder") || status == Some("missing") {
            issues.push(Issue { artifact: artifact_value, issue: "notarization-status-unresolved" });
        }
    }

    for artifact in array_field(manifest, "artifacts") {
        let artifact_value = entry_path(artifact).map(Value::String).unwrap_or(Value::Null);
        let is_native = artifact.get("type").and_then(|v| v.as_str()) == Some("native");
        if is_native && artifact.get("platform").is_none() {
            issues.push(Issue { artifact: artifact_value.clone(), issue: "platform-missing" });
        }
        if artifact.get("semanticEquivalent").and_then(|v| v.as_bool()) == Some(false) {
            issues.push(Issue { artifact: artifact_value, issue: "semantic-equivalence-failed" });
        }
    }

    let artifacts_len = array_field(manifest, "artifacts").len();
    for channel in array_field(manifest, "channels") {
        let channel_artifacts_len = channel
            .get("artifacts")
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or(0);
        if channel_artifacts_len != artifacts_len {
            let id = channel
                .get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "channel".to_string());
            issues.push(Issue { artifact: Value::String(id), issue: "artifact-decision-missing" });
        }
    }

    let has_version = manifest.get("version").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
    let has_source_revision = manifest
        .get("sourceRevision")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if !has_version || !has_source_revision {
        issues.push(Issue { artifact: Value::String("manifest".to_string()), issue: "identity-missing" });
    }

    Ok(VerificationResult {
        schema_version: 1,
        kind: "legion-release-verification",
        manifest: manifest_path.map(|p| p.to_string()),
        valid: issues.is_empty(),
        issues,
    })
}

pub fn verify_release_manifest(manifest_path: &Path, dist_dir: Option<&Path>) -> Result<VerificationResult, String> {
    let raw = fs::read_to_string(manifest_path).map_err(|e| e.to_string())?;
    let manifest: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let root = match dist_dir {
        Some(d) => d.to_path_buf(),
        None => manifest_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".")),
    };
    verify_release_manifest_object(&manifest, &root, manifest_path.to_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_wrong_schema() {
        let manifest = json!({ "schemaVersion": 2 });
        let err = verify_release_manifest_object(&manifest, Path::new("/tmp"), None).unwrap_err();
        assert!(err.contains("schemaVersion=1"));
    }

    #[test]
    fn flags_missing_required_groups() {
        let manifest = json!({
            "schemaVersion": 1,
            "kind": "legion-release-manifest",
            "version": "1.0.0",
            "sourceRevision": "abc123",
            "artifacts": [],
        });
        let result = verify_release_manifest_object(&manifest, Path::new("/tmp"), None).unwrap();
        assert!(!result.valid);
        let labels: Vec<_> = result.issues.iter().map(|i| i.artifact.as_str().unwrap_or_default().to_string()).collect();
        assert!(labels.contains(&"SHA256SUMS".to_string()));
        assert!(labels.contains(&"SBOM".to_string()));
    }

    #[test]
    fn flags_path_escape() {
        let manifest = json!({
            "schemaVersion": 1,
            "kind": "legion-release-manifest",
            "version": "1.0.0",
            "sourceRevision": "abc123",
            "artifacts": [{ "path": "../escape.bin" }],
        });
        let result = verify_release_manifest_object(&manifest, Path::new("/tmp/dist"), None).unwrap();
        assert!(result.issues.iter().any(|i| i.issue == "path-escape"));
    }
}
