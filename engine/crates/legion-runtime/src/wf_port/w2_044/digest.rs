//! Port of the digest/reference helpers in
//! `src/lib/dispatch-validator/validate-dispatch.py` (`digest_path`,
//! `content_reference`).

use super::paths::{canonical_locator, resolve_declared_path};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// A `{path, sha256}` reference, mirroring the dicts `validate-dispatch.py`
/// appends to its `references` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub path: String,
    pub sha256: String,
}

/// Port of `hashlib.sha256(...).hexdigest()`, prefixed `sha256:`, as used
/// throughout `validate-dispatch.py`.
pub fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn is_sha256_digest(value: &str) -> bool {
    match value.strip_prefix("sha256:") {
        Some(hex) => {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        }
        None => false,
    }
}

/// Port of `digest_path()`: `value` must be a JSON object with a string
/// `path` and a `sha256:<64 lowercase hex>` `digest`; the referenced file's
/// actual digest must match.
pub fn digest_path(
    value: &serde_json::Value,
    packet: &Path,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<PathBuf> {
    let path_str = value.get("path").and_then(|v| v.as_str());
    let digest_str = value
        .get("digest")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if path_str.is_none() || !is_sha256_digest(digest_str) {
        errors.push(format!("{label} requires path and sha256 digest"));
        return None;
    }
    let candidate = resolve_declared_path(path_str.unwrap(), packet);
    let bytes = match std::fs::read(&candidate) {
        Ok(bytes) => bytes,
        Err(_) => {
            errors.push(format!("{label} artifact is missing"));
            return None;
        }
    };
    let actual = sha256_digest(&bytes);
    if digest_str != actual {
        errors.push(format!("{label} digest mismatch"));
    }
    Some(candidate)
}

/// Port of `content_reference()`.
pub fn content_reference(
    value: Option<&str>,
    packet: &Path,
    label: &str,
    errors: &mut Vec<String>,
    references: &mut Vec<Reference>,
) -> Option<PathBuf> {
    let value = match value {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            errors.push(format!("{label} requires an artifact path"));
            return None;
        }
    };
    let path = resolve_declared_path(value, packet);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => {
            errors.push(format!("{label} artifact is missing"));
            return None;
        }
    };
    let digest = sha256_digest(&bytes);
    references.push(Reference {
        path: canonical_locator(&path),
        sha256: digest,
    });
    Some(path)
}
