//! Authenticated, run- and draft-bound receipts for native Research patch steps.
//!
//! These receipts express integrity for the ambient CLI flow. They do not
//! attest that a hook ran or grant host-level authority.

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

pub const ISSUER: &str = "legion.research.patch-guard";
pub const ASSURANCE: &str = "ambient-cli";
pub const DEFAULT_MAX_HUNKS: u32 = 8;
pub const DEFAULT_MAX_HUNK_BYTES: u32 = 4096;
const RECEIPT_VERSION: u64 = 3;

#[derive(Debug)]
pub struct PatchGuardError(pub String);

impl fmt::Display for PatchGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PatchGuardError {}

fn error(message: impl Into<String>) -> PatchGuardError {
    PatchGuardError(message.into())
}

pub fn canonical_draft_path(path: &Path) -> Result<PathBuf, PatchGuardError> {
    fs::canonicalize(path).map_err(|e| error(format!("cannot resolve draft path: {e}")))
}

pub fn path_text(path: &Path) -> Result<String, PatchGuardError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| error("draft path is not valid UTF-8"))
}

/// Resolve an output to an absolute path without following its final component.
/// Its parent must already exist, so an output step cannot create unrelated
/// directory trees as a side effect.
pub fn canonical_output_path(path: &Path) -> Result<PathBuf, PatchGuardError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|e| error(format!("cannot resolve output directory: {e}")))?;
    let name = path
        .file_name()
        .ok_or_else(|| error("output path must name a file"))?;
    let candidate = canonical_parent.join(name);
    if candidate.exists() {
        fs::canonicalize(&candidate).map_err(|e| error(format!("cannot resolve output path: {e}")))
    } else {
        Ok(candidate)
    }
}

pub fn read_key(path: &Path) -> Result<Vec<u8>, PatchGuardError> {
    let key = fs::read(path).map_err(|e| error(format!("cannot read --key-file: {e}")))?;
    if key.len() < 32 {
        return Err(error("patch key must contain at least 32 raw bytes"));
    }
    Ok(key)
}

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Canonical compact JSON with recursively sorted object keys, excluding the
/// signature field. This makes receipt verification independent of whitespace.
pub fn canonical_payload(receipt: &Value) -> Vec<u8> {
    let mut body = receipt.clone();
    if let Some(object) = body.as_object_mut() {
        object.remove("signature");
    }
    canonical_json(&body).into_bytes()
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort();
            let entries = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        canonical_json(object.get(key).expect("collected object key exists"))
                    )
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", entries.join(","))
        }
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn signature(receipt: &Value, key: &[u8]) -> Result<String, PatchGuardError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| error("invalid patch key"))?;
    mac.update(&canonical_payload(receipt));
    Ok(format!(
        "hmac-sha256:{}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

pub fn issue_receipt(
    draft: &Path,
    run_id: &str,
    key_file: &Path,
) -> Result<Value, PatchGuardError> {
    validate_run_id(run_id)?;
    let canonical_path = canonical_draft_path(draft)?;
    let draft_bytes =
        fs::read(&canonical_path).map_err(|e| error(format!("cannot read draft: {e}")))?;
    std::str::from_utf8(&draft_bytes).map_err(|_| error("draft must be UTF-8 text"))?;
    let key = read_key(key_file)?;
    if fs::canonicalize(key_file).map_err(|e| error(format!("cannot resolve --key-file: {e}")))?
        == canonical_path
    {
        return Err(error("--draft and --key-file must be distinct files"));
    }
    let mut receipt = json!({
        "receipt_version": RECEIPT_VERSION,
        "issued_by": ISSUER,
        "assurance": ASSURANCE,
        "issued_at": super::utc_now(),
        "run_id": run_id,
        "stage": "patch",
        "allowed_tools": ["Read", "Edit"],
        "sourced_draft_path": path_text(&canonical_path)?,
        "sourced_draft_sha256": sha256(&draft_bytes),
        "max_hunks": DEFAULT_MAX_HUNKS,
        "max_hunk_bytes": DEFAULT_MAX_HUNK_BYTES,
    });
    receipt["signature"] = json!(signature(&receipt, &key)?);
    Ok(receipt)
}

pub fn validate_run_id(run_id: &str) -> Result<(), PatchGuardError> {
    if run_id.trim().is_empty() || run_id.len() > 256 {
        return Err(error("--run-id must contain 1 to 256 non-whitespace bytes"));
    }
    Ok(())
}

/// Validate schema, exact run/path/draft binding, bounded grants, and HMAC.
pub fn validate_receipt(
    receipt: &Value,
    run_id: &str,
    draft_path: &Path,
    source_bytes: &[u8],
    key: &[u8],
) -> Result<(u32, u32), PatchGuardError> {
    validate_run_id(run_id)?;
    let object = receipt
        .as_object()
        .ok_or_else(|| error("patch receipt must be a JSON object"))?;
    let expected_keys = [
        "allowed_tools",
        "assurance",
        "issued_at",
        "issued_by",
        "max_hunk_bytes",
        "max_hunks",
        "receipt_version",
        "run_id",
        "signature",
        "sourced_draft_path",
        "sourced_draft_sha256",
        "stage",
    ];
    if object.len() != expected_keys.len()
        || expected_keys.iter().any(|key| !object.contains_key(*key))
    {
        return Err(error("patch receipt has missing or unknown fields"));
    }
    if receipt["receipt_version"] != json!(RECEIPT_VERSION)
        || receipt["issued_by"] != json!(ISSUER)
        || receipt["assurance"] != json!(ASSURANCE)
        || receipt["stage"] != json!("patch")
    {
        return Err(error("receipt must be a native Research patch receipt v3"));
    }
    if receipt["issued_at"].as_str().map_or(true, str::is_empty) {
        return Err(error("patch receipt issued_at must be a nonempty string"));
    }
    if receipt["run_id"].as_str() != Some(run_id) {
        return Err(error("patch receipt run_id does not match --run-id"));
    }
    if receipt["allowed_tools"] != json!(["Read", "Edit"]) {
        return Err(error("patch receipt tools must be exactly [Read, Edit]"));
    }
    let canonical_path = path_text(draft_path)?;
    if receipt["sourced_draft_path"].as_str() != Some(canonical_path.as_str()) {
        return Err(error(
            "patch receipt path does not match canonical --draft path",
        ));
    }
    let bound_hash = receipt["sourced_draft_sha256"]
        .as_str()
        .ok_or_else(|| error("patch receipt must bind a draft sha256"))?;
    if bound_hash.len() != 64 || !bound_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(error("patch receipt draft sha256 is malformed"));
    }
    if bound_hash != sha256(source_bytes) {
        return Err(error(
            "patch receipt draft hash does not match source bytes",
        ));
    }
    let max_hunks = receipt["max_hunks"]
        .as_u64()
        .filter(|value| (1..=DEFAULT_MAX_HUNKS as u64).contains(value))
        .ok_or_else(|| error("patch receipt max_hunks must be between 1 and 8"))?
        as u32;
    let max_hunk_bytes = receipt["max_hunk_bytes"]
        .as_u64()
        .filter(|value| (1..=DEFAULT_MAX_HUNK_BYTES as u64).contains(value))
        .ok_or_else(|| error("patch receipt max_hunk_bytes must be between 1 and 4096"))?
        as u32;
    let supplied = receipt["signature"]
        .as_str()
        .and_then(|value| value.strip_prefix("hmac-sha256:"))
        .and_then(|value| hex::decode(value).ok())
        .ok_or_else(|| error("patch receipt signature is malformed"))?;
    if supplied.len() != 32 {
        return Err(error("patch receipt signature is malformed"));
    }
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| error("invalid patch key"))?;
    mac.update(&canonical_payload(receipt));
    mac.verify_slice(&supplied)
        .map_err(|_| error("patch receipt signature mismatch"))?;
    Ok((max_hunks, max_hunk_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "legion-research-patch-guard-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn receipt_binds_path_hash_run_and_exact_grant() {
        let dir = fixture("bind");
        let draft = dir.join("draft.md");
        let key_file = dir.join("key");
        fs::write(&draft, b"draft\n").unwrap();
        fs::write(&key_file, [7u8; 32]).unwrap();
        let receipt = issue_receipt(&draft, "run-1", &key_file).unwrap();
        let key = read_key(&key_file).unwrap();
        let path = canonical_draft_path(&draft).unwrap();
        let other_draft = dir.join("other.md");
        fs::write(&other_draft, b"draft\n").unwrap();
        let other_path = canonical_draft_path(&other_draft).unwrap();

        assert_eq!(receipt["receipt_version"], json!(3));
        assert_eq!(receipt["issued_by"], json!(ISSUER));
        assert_eq!(receipt["assurance"], json!(ASSURANCE));
        assert_eq!(receipt["allowed_tools"], json!(["Read", "Edit"]));
        assert_eq!(
            validate_receipt(&receipt, "run-1", &path, b"draft\n", &key).unwrap(),
            (8, 4096)
        );
        assert!(validate_receipt(&receipt, "run-2", &path, b"draft\n", &key).is_err());
        assert!(validate_receipt(&receipt, "run-1", &other_path, b"draft\n", &key).is_err());
        assert!(validate_receipt(&receipt, "run-1", &path, b"changed\n", &key).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn short_key_and_tampered_receipt_are_rejected() {
        let dir = fixture("tamper");
        let draft = dir.join("draft.md");
        let key_file = dir.join("key");
        fs::write(&draft, b"draft\n").unwrap();
        fs::write(&key_file, b"short").unwrap();
        assert!(issue_receipt(&draft, "run-1", &key_file).is_err());
        fs::write(&key_file, [9u8; 32]).unwrap();
        let key = read_key(&key_file).unwrap();
        let mut receipt = issue_receipt(&draft, "run-1", &key_file).unwrap();
        receipt["max_hunks"] = json!(1);
        let path = canonical_draft_path(&draft).unwrap();
        assert!(validate_receipt(&receipt, "run-1", &path, b"draft\n", &key).is_err());
        let _ = fs::remove_dir_all(dir);
    }
}
