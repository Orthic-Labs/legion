//! Port of `src/lib/distribution/release-manifest.mjs`.
//!
//! Release manifests bind every distributable byte to a version and source
//! revision. They intentionally model absent channels as BLOCKED evidence.

use crate::l4_platform::contracts::sha256_bytes;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub fn sha256(bytes: &[u8]) -> String {
    sha256_bytes(bytes)
}

/// `fileDigest(path)`.
pub fn file_digest(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|bytes| sha256(&bytes))
}

/// `safeRelativePath(root, path)`: rejects paths that escape `root`.
/// Panics like the JS `throw` on an escaping path.
pub fn safe_relative_path(root: &Path, path: &str) -> String {
    let resolved = normalize_join(root, path);
    let relative = pathdiff(&resolved, root);
    if relative.is_empty() || relative == ".." || relative.starts_with("../") || relative.contains('\0') {
        panic!("release artifact path escapes distribution root: {path}");
    }
    relative
}

fn normalize_join(root: &Path, path: &str) -> PathBuf {
    let candidate = if Path::new(path).is_absolute() { PathBuf::from(path) } else { root.join(path) };
    normalize_path(&candidate)
}

/// Lexical path normalization (no filesystem access), resolving `.`/`..`
/// components, mirroring `node:path.resolve` behaviour closely enough for
/// this bounded, string-based use.
fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    let mut has_root = false;
    for component in path.components() {
        match component {
            Component::ParentDir => {
                let can_pop = matches!(out.last(), Some(last) if last != "..");
                if can_pop {
                    out.pop();
                } else if !has_root {
                    out.push("..".into());
                }
            }
            Component::CurDir => {}
            Component::Normal(part) => out.push(part.to_os_string()),
            Component::RootDir | Component::Prefix(_) => {
                has_root = true;
                out.push(component.as_os_str().to_os_string());
            }
        }
    }
    let mut result = PathBuf::new();
    for part in out {
        result.push(part);
    }
    result
}

fn pathdiff(target: &Path, root: &Path) -> String {
    let root = normalize_path(root);
    let target = normalize_path(target);
    match target.strip_prefix(&root) {
        Ok(rest) => rest.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"),
        Err(_) => {
            // target does not live under root: emulate `path.relative`
            // producing a `..`-prefixed path.
            let root_str = root.to_string_lossy();
            let target_str = target.to_string_lossy();
            if target_str.starts_with(root_str.as_ref()) {
                target_str.trim_start_matches(root_str.as_ref()).trim_start_matches('/').to_string()
            } else {
                "..".to_string()
            }
        }
    }
}

fn bind_records(root: &Path, records: &[Value]) -> Vec<Value> {
    records
        .iter()
        .map(|record| {
            let raw_path = record.get("path").and_then(Value::as_str).unwrap_or("");
            let path = safe_relative_path(root, raw_path);
            let digest = record
                .get("digest")
                .filter(|d| !d.is_null())
                .cloned()
                .or_else(|| file_digest(&root.join(&path)).map(Value::String))
                .unwrap_or(Value::Null);
            let mut obj: Map<String, Value> = record.as_object().cloned().unwrap_or_default();
            obj.insert("path".to_string(), Value::String(path));
            obj.insert("digest".to_string(), digest);
            Value::Object(obj)
        })
        .collect()
}

pub struct ReleaseManifestInput<'a> {
    pub root: &'a Path,
    pub version: &'a str,
    pub source_revision: &'a str,
    pub artifacts: Vec<Value>,
    pub channels: Vec<Value>,
    pub checksums: Vec<Value>,
    pub sboms: Vec<Value>,
    pub notices: Vec<Value>,
    pub signatures: Vec<Value>,
    pub notarization: Vec<Value>,
    pub qualification_artifacts: Vec<Value>,
}

/// `buildReleaseManifest(input)`. Panics if `root`/`version`/`sourceRevision`
/// are absent, or if a listed artifact is missing on disk with no digest
/// supplied — matching the JS `throw` fail-closed behaviour.
pub fn build_release_manifest(input: ReleaseManifestInput) -> Value {
    let normalized: Vec<Value> = input
        .artifacts
        .iter()
        .map(|artifact| {
            let raw_path = artifact.get("path").and_then(Value::as_str).unwrap_or("");
            let path = safe_relative_path(input.root, raw_path);
            let digest = artifact
                .get("digest")
                .filter(|d| !d.is_null())
                .cloned()
                .or_else(|| file_digest(&input.root.join(&path)).map(Value::String));
            let digest = match digest {
                Some(d) if !d.is_null() => d,
                _ => panic!("release artifact is missing: {path}"),
            };
            let mut obj: Map<String, Value> = artifact.as_object().cloned().unwrap_or_default();
            obj.insert("path".to_string(), Value::String(path));
            obj.insert("digest".to_string(), digest);
            Value::Object(obj)
        })
        .collect();

    let channels: Vec<Value> = input
        .channels
        .iter()
        .map(|channel| {
            let decision = channel.get("decision").and_then(Value::as_str).unwrap_or("BLOCKED").to_string();
            let artifact_decisions = channel.get("artifactDecisions").cloned().unwrap_or_else(|| json!({}));
            let artifacts: Vec<Value> = normalized
                .iter()
                .map(|artifact| {
                    let path = artifact.get("path").cloned().unwrap_or(Value::Null);
                    let path_str = path.as_str().unwrap_or("");
                    let artifact_decision = artifact_decisions
                        .get(path_str)
                        .and_then(Value::as_str)
                        .unwrap_or(&decision)
                        .to_string();
                    json!({"path": path, "decision": artifact_decision})
                })
                .collect();
            let mut obj: Map<String, Value> = channel.as_object().cloned().unwrap_or_default();
            obj.insert("decision".to_string(), Value::String(decision));
            obj.insert("artifacts".to_string(), Value::Array(artifacts));
            Value::Object(obj)
        })
        .collect();

    json!({
        "schemaVersion": 1,
        "kind": "legion-release-manifest",
        "version": input.version,
        "sourceRevision": input.source_revision,
        "artifacts": normalized,
        "checksums": bind_records(input.root, &input.checksums),
        "sboms": bind_records(input.root, &input.sboms),
        "notices": bind_records(input.root, &input.notices),
        "signatures": bind_records(input.root, &input.signatures),
        "notarization": bind_records(input.root, &input.notarization),
        "qualificationArtifacts": bind_records(input.root, &input.qualification_artifacts),
        "channels": channels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn safe_relative_path_rejects_escape() {
        let root = std::env::temp_dir().join("legion-l4-release-manifest-test");
        let result = std::panic::catch_unwind(|| safe_relative_path(&root, "../outside"));
        assert!(result.is_err());
    }

    #[test]
    fn builds_manifest_with_digests() {
        let dir = std::env::temp_dir().join(format!("legion-l4-release-{}", std::process::id()));
        let _ = fs::create_dir_all(dir.join("dist"));
        fs::write(dir.join("dist/pkg.tgz"), b"final-bytes").unwrap();
        let manifest = build_release_manifest(ReleaseManifestInput {
            root: &dir,
            version: "1.0.0",
            source_revision: "abc1234",
            artifacts: vec![json!({"path": "dist/pkg.tgz", "type": "package"})],
            channels: vec![json!({"id": "internal"})],
            checksums: vec![],
            sboms: vec![],
            notices: vec![],
            signatures: vec![],
            notarization: vec![],
            qualification_artifacts: vec![],
        });
        assert!(manifest["artifacts"][0]["digest"].as_str().unwrap().starts_with("sha256:"));
        assert_eq!(manifest["channels"][0]["artifacts"][0]["decision"], "BLOCKED");
        let _ = fs::remove_dir_all(dir);
    }
}
