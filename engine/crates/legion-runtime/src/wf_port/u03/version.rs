//! Port of `src/lib/version.mjs`.
//!
//! Canonical product version comes from `release/version.json`. Release
//! tooling verifies every shipped manifest & native crate against this one
//! value (see `engine/bins/legion-dev/src/checks/version_parity.rs`, a
//! different, already-ported file that *checks* parity rather than
//! *defining* the canonical constants this module exposes).

use serde_json::Value;

pub const LEGION_PACKAGE: &str = "@orthic-labs/legion";
pub const LEGION_REPOSITORY: &str = "https://github.com/Orthic-Labs/legion";

/// Port of `export const LEGION_VERSION = releaseIdentity.version`. Reads
/// `release/version.json` relative to the given repository root, mirroring
/// the JS module's `readFileSync(new URL('../../release/version.json', ...))`
/// resolution (JS resolves relative to `src/lib/`, i.e. two levels up from
/// the repo root).
pub fn legion_version(repo_root: &std::path::Path) -> Result<String, String> {
    let path = repo_root.join("release/version.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|cause| format!("failed to read {}: {cause}", path.display()))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|cause| format!("failed to parse {}: {cause}", path.display()))?;
    value
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("{} has no string `version` field", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "legion-u03-version-{}-{}-{}",
            std::process::id(),
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn reads_version_from_release_manifest() {
        let root = temp_dir();
        fs::create_dir_all(root.join("release")).unwrap();
        fs::write(
            root.join("release/version.json"),
            r#"{"schemaVersion":1,"kind":"legion-release-version","version":"1.2.3"}"#,
        )
        .unwrap();
        assert_eq!(legion_version(&root).unwrap(), "1.2.3");
    }

    #[test]
    fn errors_when_manifest_missing() {
        let root = temp_dir();
        assert!(legion_version(&root).is_err());
    }

    #[test]
    fn constants_match_js_literals() {
        assert_eq!(LEGION_PACKAGE, "@orthic-labs/legion");
        assert_eq!(LEGION_REPOSITORY, "https://github.com/Orthic-Labs/legion");
    }
}
