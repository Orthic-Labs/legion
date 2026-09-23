//! Packaged-skill loading.
//!
//! Ported from `src/lib/skills/loader.mjs`. The JS original is `async`
//! because it runs inside an async host (`fs/promises`); the port performs
//! the same synchronous-in-effect filesystem read with `std::fs`, since
//! there is no concurrency in this function to preserve.

use super::verify::verify_skill_bytes;
use crate::l5_skills::contracts::validate_skill_bundle;
use crate::l5_skills::profile::project_skill_text;
use crate::l5_skills::uri::parse_skill_uri;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderError(pub String);

impl std::fmt::Display for LoaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for LoaderError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoadedSkillCapabilities {
    pub mutation: bool,
    pub publish: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadedSkill {
    /// Port of `{ state: 'forbidden-profile', bundle, path }`.
    ForbiddenProfile { bundle: String, path: String },
    /// Port of `{ state: 'missing', bundle, path }` (record not declared).
    Missing { bundle: String, path: String },
    /// Port of `{ state: 'ready', text, record, capabilities }`.
    Ready { text: String, record: Value, capabilities: LoadedSkillCapabilities },
    /// Port of `{ state: 'corrupt', ok, digest, expectedDigest, record }`
    /// (digest mismatch) or `{ state: 'corrupt', error, record }` (read
    /// error other than ENOENT).
    Corrupt { detail: String, record: Value },
    /// Port of the catch branch's `{ state: 'missing', error, record }`
    /// (ENOENT while reading the file after the record was already found).
    MissingOnRead { error: String, record: Value },
}

/// Port of `loadSkill`.
///
/// `manifests` maps bundle id to its raw manifest JSON, mirroring the JS
/// `manifests[parsed.bundle]` lookup; `validateSkillBundle` is applied to
/// the looked-up value exactly as the JS does.
pub fn load_skill(
    uri: &str,
    package_root: &Path,
    manifests: &BTreeMap<String, Value>,
    profile: &str,
) -> Result<LoadedSkill, LoaderError> {
    let parsed = parse_skill_uri(uri).map_err(LoaderError)?;
    let raw_manifest = manifests
        .get(&parsed.bundle)
        .ok_or_else(|| LoaderError(format!("no manifest for bundle {}", parsed.bundle)))?;
    let manifest = validate_skill_bundle(raw_manifest).map_err(LoaderError)?;

    let profile_contract = manifest.get("profiles").and_then(|p| p.get(profile));
    let forbidden = match profile_contract {
        None => true,
        Some(Value::Null) => true,
        Some(contract) => contract.get("externalOnly").and_then(Value::as_bool).unwrap_or(false),
    };
    if forbidden {
        return Ok(LoadedSkill::ForbiddenProfile { bundle: parsed.bundle, path: parsed.path });
    }

    let files = manifest.get("files").and_then(Value::as_array).cloned().unwrap_or_default();
    let Some(record) = files.iter().find(|item| item.get("path").and_then(Value::as_str) == Some(parsed.path.as_str())) else {
        return Ok(LoadedSkill::Missing { bundle: parsed.bundle, path: parsed.path });
    };
    let record = record.clone();

    let file_path = package_root.join("skills").join(&parsed.bundle).join(&parsed.path);
    match std::fs::read(&file_path) {
        Ok(bytes) => {
            let expected_digest = record.get("digest").and_then(Value::as_str).unwrap_or("");
            let (ok, digest) = verify_skill_bytes(&bytes, expected_digest);
            if !ok {
                return Ok(LoadedSkill::Corrupt {
                    detail: format!("digest mismatch: expected {expected_digest}, got {digest}"),
                    record,
                });
            }
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let projected = project_skill_text(&text, &parsed.bundle, &parsed.path, profile);
            Ok(LoadedSkill::Ready {
                text: projected,
                record,
                capabilities: LoadedSkillCapabilities { mutation: false, publish: false },
            })
        }
        Err(error) => {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(LoadedSkill::MissingOnRead { error: error.to_string(), record })
            } else {
                Ok(LoadedSkill::Corrupt { detail: error.to_string(), record })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::w2_056::test_support::TempDir;
    use serde_json::json;
    use std::fs;

    fn manifest(profiles: Value, files: Value) -> Value {
        json!({
            "schemaVersion": 1, "id": "demo", "version": "1.0.0", "entry": "SKILL.md",
            "provenance": {}, "licenseState": "public-domain",
            "profiles": profiles, "files": files,
        })
    }

    #[test]
    fn ready_projects_text_and_strips_capabilities() {
        let dir = TempDir::new();
        fs::create_dir_all(dir.path().join("skills/demo")).unwrap();
        fs::write(dir.path().join("skills/demo/SKILL.md"), "hello\n").unwrap();
        let (_, digest) = verify_skill_bytes(b"hello\n", "");
        let m = manifest(
            json!({"audit": {}}),
            json!([{"path": "SKILL.md", "digest": digest}]),
        );
        let mut manifests = BTreeMap::new();
        manifests.insert("demo".to_string(), m);

        let result = load_skill("legion-skill://demo/SKILL.md", dir.path(), &manifests, "audit").unwrap();
        match result {
            LoadedSkill::Ready { text, capabilities, .. } => {
                assert_eq!(text, "hello\n");
                assert!(!capabilities.mutation);
                assert!(!capabilities.publish);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn forbidden_profile_when_missing_or_external_only() {
        let dir = TempDir::new();
        fs::create_dir_all(dir.path().join("skills/demo")).unwrap();
        let m = manifest(json!({"audit": {"externalOnly": true}}), json!([]));
        let mut manifests = BTreeMap::new();
        manifests.insert("demo".to_string(), m);

        let result = load_skill("legion-skill://demo/SKILL.md", dir.path(), &manifests, "audit").unwrap();
        assert_eq!(
            result,
            LoadedSkill::ForbiddenProfile { bundle: "demo".to_string(), path: "SKILL.md".to_string() }
        );

        let result2 = load_skill("legion-skill://demo/SKILL.md", dir.path(), &manifests, "authoring").unwrap();
        assert_eq!(
            result2,
            LoadedSkill::ForbiddenProfile { bundle: "demo".to_string(), path: "SKILL.md".to_string() }
        );
    }

    #[test]
    fn missing_when_record_not_declared() {
        let dir = TempDir::new();
        let m = manifest(json!({"audit": {}}), json!([]));
        let mut manifests = BTreeMap::new();
        manifests.insert("demo".to_string(), m);

        let result = load_skill("legion-skill://demo/SKILL.md", dir.path(), &manifests, "audit").unwrap();
        assert_eq!(
            result,
            LoadedSkill::Missing { bundle: "demo".to_string(), path: "SKILL.md".to_string() }
        );
    }

    #[test]
    fn missing_on_read_when_file_absent_from_disk() {
        let dir = TempDir::new();
        let m = manifest(
            json!({"audit": {}}),
            json!([{"path": "SKILL.md", "digest": "sha256:deadbeef"}]),
        );
        let mut manifests = BTreeMap::new();
        manifests.insert("demo".to_string(), m);

        let result = load_skill("legion-skill://demo/SKILL.md", dir.path(), &manifests, "audit").unwrap();
        match result {
            LoadedSkill::MissingOnRead { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn corrupt_on_digest_mismatch() {
        let dir = TempDir::new();
        fs::create_dir_all(dir.path().join("skills/demo")).unwrap();
        fs::write(dir.path().join("skills/demo/SKILL.md"), "hello\n").unwrap();
        let m = manifest(
            json!({"audit": {}}),
            json!([{"path": "SKILL.md", "digest": "sha256:deadbeef"}]),
        );
        let mut manifests = BTreeMap::new();
        manifests.insert("demo".to_string(), m);

        let result = load_skill("legion-skill://demo/SKILL.md", dir.path(), &manifests, "audit").unwrap();
        match result {
            LoadedSkill::Corrupt { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}
