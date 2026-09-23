//! Port of `src/lib/distribution/native-manifest.mjs`.

use super::release_manifest::file_digest;
use serde_json::{json, Value};
use std::path::Path;

#[cfg(unix)]
fn file_mode(meta: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::PermissionsExt;
    (meta.permissions().mode() & 0o777) as i64
}

#[cfg(not(unix))]
fn file_mode(_meta: &std::fs::Metadata) -> i64 {
    // Windows has no POSIX mode bits; report a fixed non-executable-aware
    // placeholder. Tracked as part of the general Windows parity gap noted
    // in docs/DESKTOP_PASTE_AND_MEDIA_SPEC.md section 5.
    0o644
}

pub struct NativeBuildInput<'a> {
    pub platform: &'a str,
    pub architecture: &'a str,
    pub node_binary: &'a str,
    pub node_version: &'a str,
    pub sea_config_digest: Value,
    pub package_digest: Value,
    pub assets: Value,
    pub executable: Option<&'a str>,
    pub source_revision: Value,
}

/// `nativeBuildManifest(input)`.
pub fn native_build_manifest(input: NativeBuildInput) -> Value {
    let executable_path = input.executable.filter(|p| !p.is_empty());
    let executable_present = executable_path.map(|p| Path::new(p).exists()).unwrap_or(false);
    let mode = executable_present
        .then(|| executable_path.and_then(|p| std::fs::metadata(p).ok()))
        .flatten()
        .map(|meta| file_mode(&meta));

    json!({
        "schemaVersion": 1,
        "kind": "legion-native-build",
        "platform": input.platform,
        "architecture": input.architecture,
        "nodeBinary": input.node_binary,
        "nodeVersion": input.node_version,
        "sourceRevision": input.source_revision,
        "seaConfigDigest": input.sea_config_digest,
        "packageDigest": input.package_digest,
        "assets": input.assets,
        "executable": if executable_present { Value::String(executable_path.unwrap().to_string()) } else { Value::Null },
        "executableDigest": if executable_present { file_digest(Path::new(executable_path.unwrap())).map(Value::String).unwrap_or(Value::Null) } else { Value::Null },
        "executableMode": mode,
        "rustCrate": false,
        "blobInjected": executable_present,
        "decision": if executable_present { "QUALIFIED" } else { "BLOCKED" },
        "blockers": if executable_present { json!([]) } else {
            json!([{"kind": "native-executable-absent", "required": "postject injection tool and successful executable build"}])
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_when_executable_absent() {
        let manifest = native_build_manifest(NativeBuildInput {
            platform: "darwin",
            architecture: "arm64",
            node_binary: "node",
            node_version: "20.0.0",
            sea_config_digest: Value::Null,
            package_digest: Value::Null,
            assets: json!([]),
            executable: Some("/nonexistent/legion-native"),
            source_revision: Value::Null,
        });
        assert_eq!(manifest["decision"], "BLOCKED");
        assert_eq!(manifest["blockers"][0]["kind"], "native-executable-absent");
    }

    #[test]
    fn qualified_when_executable_present() {
        let path = std::env::temp_dir().join(format!("legion-native-{}", std::process::id()));
        std::fs::write(&path, b"binary").unwrap();
        let path_str = path.to_string_lossy().into_owned();
        let manifest = native_build_manifest(NativeBuildInput {
            platform: "darwin",
            architecture: "arm64",
            node_binary: "node",
            node_version: "20.0.0",
            sea_config_digest: Value::Null,
            package_digest: Value::Null,
            assets: json!([]),
            executable: Some(&path_str),
            source_revision: Value::Null,
        });
        assert_eq!(manifest["decision"], "QUALIFIED");
        assert!(manifest["executableDigest"].as_str().unwrap().starts_with("sha256:"));
        let _ = std::fs::remove_file(&path);
    }
}
