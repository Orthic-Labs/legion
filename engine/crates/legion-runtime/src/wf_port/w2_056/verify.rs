//! Packaged-skill verification.
//!
//! Ported from `src/lib/skills/verify.mjs`. Legion is the canonical source
//! for the skills it ships. There is no upstream to diff against, so a
//! packaged file is verified against one digest and the manifest that
//! declares it — not against a transform of some other copy living
//! elsewhere.

use crate::p6_inventory::artifacts::digest_bytes;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static PACKAGE_URI: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"legion-skill://[a-z0-9-]+/[^\s)`"']+"#).unwrap());

/// Port of `verifySkillBytes`.
pub fn verify_skill_bytes(bytes: &[u8], expected_digest: &str) -> (bool, String) {
    let digest = digest_bytes(bytes);
    (digest == expected_digest, digest)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyFinding {
    pub code: &'static str,
    pub bundle_id: String,
    pub path: Option<String>,
    pub detail: String,
    pub expected_digest: Option<String>,
    pub actual_digest: Option<String>,
}

fn finding(
    code: &'static str,
    bundle_id: &str,
    path: Option<&str>,
    detail: String,
    digests: Option<(String, String)>,
) -> VerifyFinding {
    VerifyFinding {
        code,
        bundle_id: bundle_id.to_string(),
        path: path.map(String::from),
        detail,
        expected_digest: digests.as_ref().map(|(expected, _)| expected.clone()),
        actual_digest: digests.map(|(_, actual)| actual),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub ok: bool,
    pub findings: Vec<VerifyFinding>,
}

/// Safe-join `path` under `root`, rejecting escapes. Mirrors the JS
/// `safePath` helper (`resolve` + startsWith check).
fn safe_path(root: &Path, path: &str) -> Option<PathBuf> {
    let base_clean = normalize(root);
    let target_clean = normalize(&base_clean.join(path));
    if target_clean.starts_with(&base_clean) && target_clean != base_clean {
        Some(target_clean)
    } else {
        None
    }
}

/// Lexical normalization (resolve `.`/`..`) without touching the filesystem,
/// mirroring Node's `path.resolve` semantics closely enough for containment
/// checks.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Port of `verifySkillCatalog`.
pub fn verify_skill_catalog(
    package_root: &Path,
    manifests: &[Value],
    publication: bool,
) -> VerifyResult {
    let mut findings = Vec::new();
    let mut declared_uris: BTreeSet<String> = BTreeSet::new();
    for manifest in manifests {
        if let Some(files) = manifest.get("files").and_then(Value::as_array) {
            for record in files {
                if let Some(uri) = record.get("uri").and_then(Value::as_str) {
                    declared_uris.insert(uri.to_string());
                }
            }
        }
    }

    for manifest in manifests {
        let bundle_id = manifest.get("id").and_then(Value::as_str).unwrap_or("");
        let mut declared: BTreeSet<PathBuf> = BTreeSet::new();

        if publication && manifest.get("licenseState").and_then(Value::as_str) == Some("unresolved")
        {
            findings.push(finding(
                "rights-unresolved",
                bundle_id,
                None,
                "publication rejects unresolved rights".to_string(),
                None,
            ));
        }

        let files = manifest.get("files").and_then(Value::as_array).cloned().unwrap_or_default();
        for record in &files {
            let record_path = record.get("path").and_then(Value::as_str).unwrap_or("");
            let relative = Path::new("skills").join(bundle_id).join(record_path);
            let Some(output_path) = safe_path(package_root, &relative.to_string_lossy()) else {
                findings.push(finding(
                    "invalid-path",
                    bundle_id,
                    Some(record_path),
                    "output path escapes package root".to_string(),
                    None,
                ));
                continue;
            };
            declared.insert(output_path.clone());
            verify_file(bundle_id, record, record_path, &output_path, &declared_uris, &mut findings);
        }

        find_unexpected(package_root, bundle_id, &declared, &mut findings);
    }

    let ok = findings.is_empty();
    VerifyResult { ok, findings }
}

fn verify_file(
    bundle_id: &str,
    record: &Value,
    record_path: &str,
    output_path: &Path,
    declared_uris: &BTreeSet<String>,
    findings: &mut Vec<VerifyFinding>,
) {
    if !output_path.exists() {
        findings.push(finding(
            "missing",
            bundle_id,
            Some(record_path),
            "declared file is missing".to_string(),
            None,
        ));
        return;
    }
    let Ok(bytes) = std::fs::read(output_path) else {
        findings.push(finding(
            "missing",
            bundle_id,
            Some(record_path),
            "declared file is missing".to_string(),
            None,
        ));
        return;
    };
    let expected_digest = record.get("digest").and_then(Value::as_str).unwrap_or("").to_string();
    let (ok, digest) = verify_skill_bytes(&bytes, &expected_digest);
    if !ok {
        findings.push(finding(
            "digest-drift",
            bundle_id,
            Some(record_path),
            "file digest differs from manifest".to_string(),
            Some((expected_digest, digest)),
        ));
    }

    let lower = record_path.to_ascii_lowercase();
    if !(lower.ends_with(".md") || lower.ends_with(".mdx") || lower.ends_with(".txt")) {
        return;
    }
    let text = String::from_utf8_lossy(&bytes);
    for capture in PACKAGE_URI.find_iter(&text) {
        let matched = capture.as_str();
        let uri = matched.split('#').next().unwrap_or(matched);
        if !declared_uris.contains(uri) {
            findings.push(finding(
                "broken-link",
                bundle_id,
                Some(record_path),
                format!("packaged link is not declared: {uri}"),
                None,
            ));
        }
    }
}

fn find_unexpected(
    package_root: &Path,
    bundle_id: &str,
    declared: &BTreeSet<PathBuf>,
    findings: &mut Vec<VerifyFinding>,
) {
    let bundle_root = package_root.join("skills").join(bundle_id);
    if !bundle_root.exists() {
        return;
    }
    for path in all_files(&bundle_root) {
        let normalized = normalize(&path);
        if !declared.contains(&normalized) {
            let relative = path
                .strip_prefix(&bundle_root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            findings.push(finding(
                "unexpected",
                bundle_id,
                Some(&relative),
                "file is absent from manifest".to_string(),
                None,
            ));
        }
    }
}

fn all_files(directory: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else { return out };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(name.as_ref(), "__pycache__" | ".audit" | ".cache") {
                continue;
            }
            out.extend(all_files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::w2_056::test_support::TempDir;
    use serde_json::json;
    use std::fs;

    fn write(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    #[test]
    fn verify_skill_bytes_matches_digest() {
        let (ok, digest) = verify_skill_bytes(b"hello", "wrong");
        assert!(!ok);
        assert_ne!(digest, "wrong");
        let (ok2, _) = verify_skill_bytes(b"hello", &digest);
        assert!(ok2);
    }

    #[test]
    fn detects_missing_digest_drift_and_unexpected_files() {
        let dir = TempDir::new();
        write(dir.path(), "skills/demo/SKILL.md", "hello world");
        write(dir.path(), "skills/demo/extra.md", "unexpected");

        let (_, good_digest) = verify_skill_bytes(b"hello world", "");
        let manifest = json!({
            "id": "demo",
            "files": [
                {"path": "SKILL.md", "digest": good_digest, "uri": "legion-skill://demo/SKILL.md"},
                {"path": "missing.md", "digest": "sha256:deadbeef", "uri": "legion-skill://demo/missing.md"},
            ]
        });

        let result = verify_skill_catalog(dir.path(), &[manifest], false);
        assert!(!result.ok);
        let codes: Vec<&str> = result.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&"missing"));
        assert!(codes.contains(&"unexpected"));
        assert!(!codes.contains(&"digest-drift"));
    }

    #[test]
    fn digest_drift_when_bytes_differ() {
        let dir = TempDir::new();
        write(dir.path(), "skills/demo/SKILL.md", "changed content");
        let manifest = json!({
            "id": "demo",
            "files": [
                {"path": "SKILL.md", "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000", "uri": "legion-skill://demo/SKILL.md"},
            ]
        });
        let result = verify_skill_catalog(dir.path(), &[manifest], false);
        assert!(result.findings.iter().any(|f| f.code == "digest-drift"));
    }

    #[test]
    fn rejects_path_escape() {
        let dir = TempDir::new();
        write(dir.path(), "skills/demo/SKILL.md", "x");
        // The output path is joined as `skills/demo/<record.path>`: two `..`
        // only walks back up to `package_root` itself (still contained), so
        // a third `..` is required to actually escape it (mirrors
        // `classify_resource`'s `PACKAGE_INTERNAL` escape math in
        // dependency_closure.rs, verified against verify.mjs's `safePath`).
        let manifest = json!({
            "id": "demo",
            "files": [
                {"path": "../../../etc/passwd", "digest": "sha256:x", "uri": "legion-skill://demo/x"},
            ]
        });
        let result = verify_skill_catalog(dir.path(), &[manifest], false);
        assert!(result.findings.iter().any(|f| f.code == "invalid-path"));
    }

    #[test]
    fn broken_link_when_uri_not_declared() {
        let dir = TempDir::new();
        write(dir.path(), "skills/demo/SKILL.md", "see legion-skill://demo/other.md for detail");
        let (_, digest) = verify_skill_bytes(
            b"see legion-skill://demo/other.md for detail",
            "",
        );
        let manifest = json!({
            "id": "demo",
            "files": [
                {"path": "SKILL.md", "digest": digest, "uri": "legion-skill://demo/SKILL.md"},
            ]
        });
        let result = verify_skill_catalog(dir.path(), &[manifest], false);
        assert!(result.findings.iter().any(|f| f.code == "broken-link"));
    }

    #[test]
    fn publication_rejects_unresolved_rights() {
        let dir = TempDir::new();
        write(dir.path(), "skills/demo/SKILL.md", "x");
        let (_, digest) = verify_skill_bytes(b"x", "");
        let manifest = json!({
            "id": "demo",
            "licenseState": "unresolved",
            "files": [
                {"path": "SKILL.md", "digest": digest, "uri": "legion-skill://demo/SKILL.md"},
            ]
        });
        let result = verify_skill_catalog(dir.path(), &[manifest.clone()], true);
        assert!(result.findings.iter().any(|f| f.code == "rights-unresolved"));
        let result_no_pub = verify_skill_catalog(dir.path(), &[manifest], false);
        assert!(!result_no_pub.findings.iter().any(|f| f.code == "rights-unresolved"));
    }
}
