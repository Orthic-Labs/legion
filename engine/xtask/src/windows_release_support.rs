//! Digest and path helpers shared by `qualify-windows-release.mjs` and
//! `package-windows-release.mjs`'s ports. Both scripts define near-identical
//! copies of these functions (`bareDigest`, `digestMatches`, `pathsEqual`,
//! `hasForbiddenBindingSegment`, `releaseGeneration`, ...); this module is
//! the single Rust source of truth for them.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::windows_release_config::forbidden_binding_segments;

/// Mirrors `sha256File` from `@rightkit/release/direct-bootstrap.mjs`: a bare
/// lowercase hex digest, no `sha256:` prefix.
pub fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Mirrors `qualify-windows-release.mjs`'s `sha256()`: `sha256:<hex>`.
pub fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// Mirrors `bareDigest`.
pub fn bare_digest(value: &str) -> String {
    let lower = value.to_lowercase();
    lower.strip_prefix("sha256:").unwrap_or(&lower).to_string()
}

pub fn bare_digest_opt(value: Option<&str>) -> String {
    bare_digest(value.unwrap_or(""))
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Mirrors `digestMatches`.
pub fn digest_matches(observed: Option<&str>, expected: Option<&str>) -> bool {
    let left = bare_digest_opt(observed);
    let right = bare_digest_opt(expected);
    is_hex64(&left) && is_hex64(&right) && left == right
}

pub fn is_hex_digest(value: Option<&str>) -> bool {
    is_hex64(&bare_digest_opt(value))
}

pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub fn is_nonempty_digest(value: Option<&str>) -> bool {
    let digest = bare_digest_opt(value);
    is_hex64(&digest) && digest != EMPTY_SHA256
}

/// Mirrors `releaseGeneration` (identical in both scripts): explicit
/// generation wins, then declarative-assets digest, then `version:runtime`.
pub fn release_generation(metadata: &Value, version: &str, runtime_sha256: &str) -> String {
    let explicit = metadata
        .get("generation")
        .or_else(|| metadata.get("installGeneration"))
        .or_else(|| metadata.pointer("/runtime/generation"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(explicit) = explicit {
        return explicit.to_string();
    }
    let assets_digest = metadata
        .get("declarativeAssetsSha256")
        .or_else(|| metadata.get("declarative_assets_sha256"))
        .and_then(|v| v.as_str());
    if let Some(assets_digest) = assets_digest {
        let bare = bare_digest(assets_digest);
        if is_hex64(&bare) {
            return format!("{version}:{bare}");
        }
    }
    format!("{version}:{}", bare_digest(runtime_sha256))
}

/// Mirrors `hasForbiddenBindingSegment`.
pub fn has_forbidden_binding_segment(value: &str) -> bool {
    let normalized = value.replace('\\', "/").to_lowercase();
    normalized
        .split('/')
        .any(|segment| forbidden_binding_segments().contains(&segment))
}

/// Best-effort canonicalization mirroring `realpathSync` with a fallback to
/// lexical `resolve`.
pub fn canonical_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| lexical_resolve(path))
}

fn lexical_resolve(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut out = PathBuf::new();
    for component in absolute.components() {
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

fn normalized_slashes_lower(path: &Path) -> String {
    lexical_resolve(path).to_string_lossy().replace('\\', "/").to_lowercase()
}

/// Mirrors `pathsEqual` in `package-windows-release.mjs` (lexical, not
/// canonical): both values must be absolute-ish resolvable paths whose
/// normalized forms match.
pub fn paths_equal(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(l), Some(r)) => normalized_slashes_lower(Path::new(l)) == normalized_slashes_lower(Path::new(r)),
        _ => false,
    }
}

/// Mirrors `canonicalPathsEqual`.
pub fn canonical_paths_equal(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(l), Some(r)) => {
            let cl = canonical_path(Path::new(l)).to_string_lossy().replace('\\', "/").to_lowercase();
            let cr = canonical_path(Path::new(r)).to_string_lossy().replace('\\', "/").to_lowercase();
            cl == cr
        }
        _ => false,
    }
}

/// Mirrors `pathInside` (lexical relative-path containment check via the
/// canonical form of both sides).
pub fn path_inside(root: Option<&str>, candidate: Option<&str>) -> bool {
    let (root, candidate) = match (root, candidate) {
        (Some(r), Some(c)) => (r, c),
        _ => return false,
    };
    let root_canon = canonical_path(Path::new(root));
    let candidate_canon = canonical_path(Path::new(candidate));
    match candidate_canon.strip_prefix(&root_canon) {
        Ok(rel) => rel.as_os_str().len() > 0,
        Err(_) => false,
    }
}

/// Mirrors `versionRootMatches`.
pub fn version_root_matches(root: Option<&str>, version: Option<&str>, archive_digest: Option<&str>) -> bool {
    let (root, version) = match (root, version) {
        (Some(r), Some(v)) => (r, v),
        _ => return false,
    };
    let prefix = format!(
        "{version}-{}",
        &bare_digest_opt(archive_digest).chars().take(12).collect::<String>()
    )
    .to_lowercase();
    let name = Path::new(&root.replace('\\', "/"))
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    name == prefix || name.starts_with(&format!("{prefix}-"))
}

pub fn assert_regular_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| format!("{label} is missing: {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a regular file: {}", path.display()));
    }
    Ok(())
}

pub fn read_json(path: &Path, label: &str) -> Result<Value, String> {
    assert_regular_file(path, label)?;
    let raw = fs::read_to_string(path).map_err(|e| format!("{label} could not be read: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("{label} is invalid JSON: {e}"))
}

pub fn assert_version(value: Option<&str>, label: &str) -> Result<String, String> {
    let value = value.unwrap_or_default();
    let valid = !value.is_empty()
        && value.split('.').count() == 3
        && value.split('.').all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()) && (part == "0" || !part.starts_with('0')));
    if !valid {
        return Err(format!("invalid {label}: {value}"));
    }
    Ok(value.to_string())
}

/// Mirrors `SOURCE_REVISION`/`assertSourceRevision`: a 40-64 char hex git SHA.
pub fn assert_source_revision(value: Option<&str>) -> Result<String, String> {
    let value = value.unwrap_or_default().trim();
    let ok = (40..=64).contains(&value.len()) && value.chars().all(|c| c.is_ascii_hexdigit());
    if !ok {
        return Err("source revision must be a 40-64 character git SHA".to_string());
    }
    Ok(value.to_lowercase())
}
