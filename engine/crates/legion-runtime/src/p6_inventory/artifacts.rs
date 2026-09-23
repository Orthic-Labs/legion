//! Port of `src/lib/artifacts/digests.mjs` and `src/lib/artifacts/paths.mjs`.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

/// Port of `digestBytes` in `src/lib/artifacts/digests.mjs`:
/// `` `sha256:${createHash('sha256').update(bytes).digest('hex')}` ``.
pub fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Port of the `TypeError` cases thrown by `safeArtifactPath` in
/// `src/lib/artifacts/paths.mjs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactPathError {
    AbsoluteChild,
    Traversal,
    OutsideRun,
}

impl fmt::Display for ArtifactPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            ArtifactPathError::AbsoluteChild => "artifact path escape: absolute child",
            ArtifactPathError::Traversal => "artifact path escape: traversal",
            ArtifactPathError::OutsideRun => "artifact path escape: outside run",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ArtifactPathError {}

fn looks_like_windows_drive_absolute(child: &str) -> bool {
    // Mirrors the JS check `/^[A-Za-z]:[\\/]/.test(child)`.
    let bytes = child.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

/// Port of `safeArtifactPath` in `src/lib/artifacts/paths.mjs`: resolves
/// `child` against `root` and rejects any path that would escape `root`,
/// whether via an absolute child, a `..` traversal segment, or (after
/// normalization) a resolved target outside `root`.
pub fn safe_artifact_path(root: &Path, child: &str) -> Result<PathBuf, ArtifactPathError> {
    if child.is_empty() || Path::new(child).is_absolute() || looks_like_windows_drive_absolute(child)
    {
        return Err(ArtifactPathError::AbsoluteChild);
    }

    let normalized = child.replace('\\', "/");
    if normalized.split('/').any(|segment| segment == "..") {
        return Err(ArtifactPathError::Traversal);
    }

    let root_resolved = normalize(root);
    let target = normalize(&root_resolved.join(&normalized));

    let rel = target
        .strip_prefix(&root_resolved)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| PathBuf::from(".."));

    if rel == Path::new("..") || rel.starts_with("..") {
        return Err(ArtifactPathError::OutsideRun);
    }

    Ok(target)
}

/// Lexical normalization equivalent to Node's `path.resolve` for the
/// purposes of this check: collapses `.`/`..` without touching the
/// filesystem.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}
