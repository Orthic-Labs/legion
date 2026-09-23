//! Skill bundle manifest contract validation.
//!
//! Ported from `src/lib/skills/contracts.mjs`.

use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::LazyLock;

static URI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^legion-skill://([a-z0-9-]+)/(.*)$").unwrap());
static SHA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^sha256:[a-f0-9]{64}$").unwrap());
static LICENSES: &[&str] = &["unresolved", "user-owned-supplied", "licensed", "public-domain"];

/// Validate a packaged skill bundle manifest, returning the same value on success.
///
/// Mirrors `validateSkillBundle` in `src/lib/skills/contracts.mjs` field for field.
pub fn validate_skill_bundle(bundle: &Value) -> Result<&Value, String> {
    let schema_version = bundle.get("schemaVersion");
    if schema_version != Some(&Value::from(1)) {
        return Err(format!(
            "skill bundle unsupported schema version: {}",
            schema_version.map(|v| v.to_string()).unwrap_or_else(|| "undefined".into())
        ));
    }
    let id = bundle.get("id").and_then(Value::as_str);
    let version = bundle.get("version");
    let entry = bundle.get("entry").and_then(Value::as_str);
    let provenance = bundle.get("provenance");
    if id.is_none()
        || id == Some("")
        || version.is_none()
        || version.map(Value::is_null).unwrap_or(true)
        || entry.is_none()
        || entry == Some("")
        || provenance.is_none()
        || provenance.map(Value::is_null).unwrap_or(true)
    {
        return Err("skill bundle requires id version entry and provenance".to_string());
    }
    let id = id.unwrap();
    let entry = entry.unwrap();

    let license_state = bundle.get("licenseState").and_then(Value::as_str).unwrap_or("");
    if !LICENSES.contains(&license_state) {
        return Err("skill bundle license state is invalid".to_string());
    }
    // Mirrors JS `bundle.rightsReceipt !== null`: missing (undefined) counts as not-null.
    let rights_receipt = bundle.get("rightsReceipt");
    let receipt_is_null = rights_receipt == Some(&Value::Null);
    if license_state == "unresolved" && !receipt_is_null {
        return Err("unresolved skill rights cannot have a receipt".to_string());
    }
    // Mirrors JS falsy check on `!bundle.rightsReceipt`.
    let receipt_is_falsy = matches!(
        rights_receipt,
        None | Some(&Value::Null) | Some(&Value::Bool(false))
    ) || rights_receipt == Some(&Value::from(0))
        || rights_receipt == Some(&Value::String(String::new()));
    if license_state != "unresolved" && receipt_is_falsy {
        return Err("resolved skill rights require a receipt".to_string());
    }

    let root = format!("legion-skill://{id}/");
    if bundle.get("rootUri").and_then(Value::as_str) != Some(root.as_str()) {
        return Err("skill root must match bundle-owned legion-skill URI".to_string());
    }

    let profiles = bundle.get("profiles");
    let audit = profiles.and_then(|p| p.get("audit"));
    let authoring = profiles.and_then(|p| p.get("authoring"));
    if audit.map(Value::is_null).unwrap_or(true) || authoring.map(Value::is_null).unwrap_or(true) {
        return Err("skill bundle requires audit and authoring profiles".to_string());
    }
    let audit = audit.unwrap();
    if audit.get("mutation") != Some(&Value::Bool(false)) || audit.get("publish") != Some(&Value::Bool(false)) {
        return Err("audit profile cannot grant mutation or publish".to_string());
    }

    let mut paths: HashSet<String> = HashSet::new();
    let mut uris: HashSet<String> = HashSet::new();
    let files = bundle.get("files").and_then(Value::as_array).cloned().unwrap_or_default();
    for file in &files {
        let path = file.get("path").and_then(Value::as_str).unwrap_or("");
        if path.is_empty() || path.starts_with('/') || path.split('/').any(|s| s == "..") {
            return Err("skill file outside root".to_string());
        }
        if paths.contains(path) {
            return Err(format!("duplicate skill file: {path}"));
        }
        paths.insert(path.to_string());
        let uri = file.get("uri").and_then(Value::as_str).unwrap_or("");
        let captures = URI.captures(uri);
        let matches = captures
            .as_ref()
            .map(|c| &c[1] == id && &c[2] == path)
            .unwrap_or(false);
        if !matches {
            return Err(format!("skill URI must match bundle path: {uri}"));
        }
        if uris.contains(uri) {
            return Err(format!("duplicate skill URI: {uri}"));
        }
        uris.insert(uri.to_string());
        let digest = file.get("digest").and_then(Value::as_str).unwrap_or("");
        if !SHA.is_match(digest) {
            return Err(format!("skill digest missing: {path}"));
        }
    }
    if !paths.contains(entry) {
        return Err(format!("skill entry missing: {entry}"));
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_bundle() -> Value {
        json!({
            "schemaVersion": 1,
            "id": "qa",
            "version": "1.0.0",
            "entry": "SKILL.md",
            "provenance": { "author": "legion" },
            "licenseState": "public-domain",
            "rightsReceipt": { "kind": "public-domain" },
            "rootUri": "legion-skill://qa/",
            "profiles": {
                "audit": { "mutation": false, "publish": false },
                "authoring": { "mutation": true, "publish": true },
            },
            "files": [
                { "path": "SKILL.md", "uri": "legion-skill://qa/SKILL.md", "digest": format!("sha256:{}", "a".repeat(64)) },
            ],
        })
    }

    #[test]
    fn accepts_valid_bundle() {
        let bundle = valid_bundle();
        assert!(validate_skill_bundle(&bundle).is_ok());
    }

    #[test]
    fn rejects_bad_schema_version() {
        let mut bundle = valid_bundle();
        bundle["schemaVersion"] = json!(2);
        assert!(validate_skill_bundle(&bundle).is_err());
    }

    #[test]
    fn rejects_unresolved_with_receipt() {
        let mut bundle = valid_bundle();
        bundle["licenseState"] = json!("unresolved");
        assert!(validate_skill_bundle(&bundle).is_err());
    }

    #[test]
    fn rejects_mismatched_root_uri() {
        let mut bundle = valid_bundle();
        bundle["rootUri"] = json!("legion-skill://other/");
        assert!(validate_skill_bundle(&bundle).is_err());
    }

    #[test]
    fn rejects_audit_profile_granting_mutation() {
        let mut bundle = valid_bundle();
        bundle["profiles"]["audit"]["mutation"] = json!(true);
        assert!(validate_skill_bundle(&bundle).is_err());
    }

    #[test]
    fn rejects_file_outside_root() {
        let mut bundle = valid_bundle();
        bundle["files"][0]["path"] = json!("../escape.md");
        assert!(validate_skill_bundle(&bundle).is_err());
    }

    #[test]
    fn rejects_missing_entry_file() {
        let mut bundle = valid_bundle();
        bundle["entry"] = json!("MISSING.md");
        assert!(validate_skill_bundle(&bundle).is_err());
    }

    #[test]
    fn rejects_bad_digest() {
        let mut bundle = valid_bundle();
        bundle["files"][0]["digest"] = json!("md5:abc");
        assert!(validate_skill_bundle(&bundle).is_err());
    }
}
