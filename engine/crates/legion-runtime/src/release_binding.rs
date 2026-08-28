//! Fail-closed verification of the complete installed Legion release identity.

use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use legion_catalog::json;
use serde::{Deserialize, Serialize};

/// The sole remediation for a mixed or otherwise invalid installed identity.
pub const REPAIR_COMMAND: &str = "legion setup repair --confirm";
pub const CANONICAL_RELEASE_MANIFEST: &str = "share/legion/release.json";
pub const RIGHTKIT_AX_VERSION: &str = "0.2.0";
pub const RIGHTKIT_AX_SOURCE_COMMIT: &str = "01f52555202da3dffc6b649ca44e803b55238081";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseManifest {
    pub release_version: String,
    pub runtime: RuntimeIdentity,
    pub capability_catalog_sha256: String,
    pub mcp_tool_schema_sha256: String,
    pub declarative_assets_sha256: String,
    pub state_schema_version: u32,
    pub rightkit_ax: RightkitAxIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeIdentity {
    pub platform: String,
    pub architecture: String,
    pub sha256: String,
    pub provenance: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RightkitAxIdentity {
    pub version: String,
    pub source_commit: String,
}

/// Local values that must exactly reconcile with one `release.json` manifest.
#[derive(Clone, Debug)]
pub struct ReleaseBindingInputs {
    pub release_version: String,
    pub runtime_path: PathBuf,
    pub runtime_platform: String,
    pub runtime_architecture: String,
    pub runtime_provenance: String,
    pub catalog_path: PathBuf,
    pub mcp_tool_schema_path: PathBuf,
    pub declarative_assets: DeclarativeAssets,
    pub state_schema_version: u32,
    pub rightkit_ax: RightkitAxIdentity,
}

#[derive(Clone, Debug)]
pub enum DeclarativeAssets {
    File(PathBuf),
    Directory(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReleaseBinding {
    manifest: ReleaseManifest,
}

/// The release identity discovered from the running installed executable.
/// Product commands must use this source rather than caller-supplied paths or
/// developer-environment configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledRelease {
    pub manifest: ReleaseManifest,
    pub manifest_path: PathBuf,
    pub executable_path: PathBuf,
}

impl VerifiedReleaseBinding {
    pub fn manifest(&self) -> &ReleaseManifest {
        &self.manifest
    }

    pub fn release_version(&self) -> &str {
        &self.manifest.release_version
    }
}

#[derive(Debug)]
pub enum ReleaseBindingError {
    InvalidManifest {
        path: PathBuf,
        reason: String,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Mismatch {
        component: &'static str,
        expected: String,
        actual: String,
        remediation: &'static str,
    },
}

impl fmt::Display for ReleaseBindingError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest { path, reason } => {
                write!(out, "invalid release manifest at {}: {reason}", path.display())
            }
            Self::Io { path, source } => write!(out, "I/O at {}: {source}", path.display()),
            Self::Mismatch { component, expected, actual, remediation } => write!(
                out,
                "release binding mismatch for {component}: expected {expected}, got {actual}; run {remediation}"
            ),
        }
    }
}

impl std::error::Error for ReleaseBindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl ReleaseManifest {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ReleaseBindingError> {
        load_release_manifest(path)
    }

    pub fn verify(
        &self,
        inputs: &ReleaseBindingInputs,
    ) -> Result<VerifiedReleaseBinding, ReleaseBindingError> {
        verify_release_binding(self, inputs)
    }

    fn validate(&self, path: &Path) -> Result<(), ReleaseBindingError> {
        let version_core = self
            .release_version
            .split(['-', '+'])
            .next()
            .unwrap_or_default();
        if version_core.split('.').count() != 3
            || !version_core
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return invalid(
                path,
                "releaseVersion must be semantic version major.minor.patch",
            );
        }
        require(path, "runtime.platform", &self.runtime.platform)?;
        require(path, "runtime.architecture", &self.runtime.architecture)?;
        require(path, "runtime.provenance", &self.runtime.provenance)?;
        digest_field(path, "runtime.sha256", &self.runtime.sha256)?;
        digest_field(
            path,
            "capabilityCatalogSha256",
            &self.capability_catalog_sha256,
        )?;
        digest_field(path, "mcpToolSchemaSha256", &self.mcp_tool_schema_sha256)?;
        digest_field(
            path,
            "declarativeAssetsSha256",
            &self.declarative_assets_sha256,
        )?;
        require(path, "rightkitAx.version", &self.rightkit_ax.version)?;
        if self.rightkit_ax.source_commit.len() != 40
            || !self
                .rightkit_ax
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return invalid(
                path,
                "rightkitAx.sourceCommit must be a 40-character git SHA",
            );
        }
        Ok(())
    }
}

/// Load a typed release manifest. Unknown fields are rejected to prevent partial bindings.
pub fn load_release_manifest(
    path: impl AsRef<Path>,
) -> Result<ReleaseManifest, ReleaseBindingError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|source| ReleaseBindingError::Io {
        path: path.into(),
        source,
    })?;
    let manifest = json::from_slice::<ReleaseManifest>(&bytes).map_err(|error| {
        ReleaseBindingError::InvalidManifest {
            path: path.into(),
            reason: error.to_string(),
        }
    })?;
    manifest.validate(path)?;
    validate_frozen_rightkit(path, &manifest)?;
    Ok(manifest)
}

/// Locate the canonical installed manifest relative to the running executable.
/// No environment, source checkout, or caller-selected fallback is consulted.
pub fn load_installed_release() -> Result<InstalledRelease, ReleaseBindingError> {
    let executable =
        fs::canonicalize(
            std::env::current_exe().map_err(|source| ReleaseBindingError::Io {
                path: PathBuf::from("<current_exe>"),
                source,
            })?,
        )
        .map_err(|source| ReleaseBindingError::Io {
            path: PathBuf::from("<current_exe>"),
            source,
        })?;
    let executable_directory =
        executable
            .parent()
            .ok_or_else(|| ReleaseBindingError::InvalidManifest {
                path: executable.clone(),
                reason: "installed executable has no parent directory".into(),
            })?;
    let mut roots = vec![executable_directory];
    if executable_directory
        .file_name()
        .is_some_and(|name| name == "bin")
    {
        if let Some(parent) = executable_directory.parent() {
            roots.push(parent);
        }
    }
    let manifest_path = roots
        .into_iter()
        .map(|root| root.join(CANONICAL_RELEASE_MANIFEST))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| ReleaseBindingError::InvalidManifest {
            path: executable.clone(),
            reason: "installed release manifest share/legion/release.json was not found".into(),
        })?;
    let manifest_path =
        fs::canonicalize(manifest_path.clone()).map_err(|source| ReleaseBindingError::Io {
            path: manifest_path,
            source,
        })?;
    let manifest = load_release_manifest(&manifest_path)?;
    exact(
        "runtime platform",
        &manifest.runtime.platform,
        std::env::consts::OS,
    )?;
    exact(
        "runtime architecture",
        &manifest.runtime.architecture,
        std::env::consts::ARCH,
    )?;
    check_file("runtime digest", &manifest.runtime.sha256, &executable)?;
    Ok(InstalledRelease {
        manifest,
        manifest_path,
        executable_path: executable,
    })
}

/// Verify all required runtime, catalog, schema, asset, state, and RightKit identities.
pub fn verify_release_binding(
    manifest: &ReleaseManifest,
    inputs: &ReleaseBindingInputs,
) -> Result<VerifiedReleaseBinding, ReleaseBindingError> {
    manifest.validate(Path::new("release.json"))?;
    exact(
        "RightKit AX version",
        RIGHTKIT_AX_VERSION,
        &manifest.rightkit_ax.version,
    )?;
    exact(
        "RightKit AX source commit",
        RIGHTKIT_AX_SOURCE_COMMIT,
        &manifest.rightkit_ax.source_commit,
    )?;
    exact(
        "RightKit AX version",
        RIGHTKIT_AX_VERSION,
        &inputs.rightkit_ax.version,
    )?;
    exact(
        "RightKit AX source commit",
        RIGHTKIT_AX_SOURCE_COMMIT,
        &inputs.rightkit_ax.source_commit,
    )?;
    exact(
        "release version",
        &manifest.release_version,
        &inputs.release_version,
    )?;
    exact(
        "runtime platform",
        &manifest.runtime.platform,
        &inputs.runtime_platform,
    )?;
    exact(
        "runtime architecture",
        &manifest.runtime.architecture,
        &inputs.runtime_architecture,
    )?;
    exact(
        "runtime provenance",
        &manifest.runtime.provenance,
        &inputs.runtime_provenance,
    )?;
    check_file(
        "runtime digest",
        &manifest.runtime.sha256,
        &inputs.runtime_path,
    )?;
    check_file(
        "capability catalog digest",
        &manifest.capability_catalog_sha256,
        &inputs.catalog_path,
    )?;
    check_file(
        "MCP tool schema digest",
        &manifest.mcp_tool_schema_sha256,
        &inputs.mcp_tool_schema_path,
    )?;
    let assets = match &inputs.declarative_assets {
        DeclarativeAssets::File(path) => file_digest(path)?,
        DeclarativeAssets::Directory(path) => directory_digest(path)?,
    };
    digest_equal(
        "declarative assets digest",
        &manifest.declarative_assets_sha256,
        &assets,
    )?;
    exact(
        "state schema version",
        &manifest.state_schema_version.to_string(),
        &inputs.state_schema_version.to_string(),
    )?;
    exact(
        "RightKit AX version",
        &manifest.rightkit_ax.version,
        &inputs.rightkit_ax.version,
    )?;
    exact(
        "RightKit AX source commit",
        &manifest.rightkit_ax.source_commit,
        &inputs.rightkit_ax.source_commit,
    )?;
    Ok(VerifiedReleaseBinding {
        manifest: manifest.clone(),
    })
}

fn invalid<T>(path: &Path, reason: impl Into<String>) -> Result<T, ReleaseBindingError> {
    Err(ReleaseBindingError::InvalidManifest {
        path: path.into(),
        reason: reason.into(),
    })
}

fn validate_frozen_rightkit(
    path: &Path,
    manifest: &ReleaseManifest,
) -> Result<(), ReleaseBindingError> {
    if manifest.rightkit_ax.version != RIGHTKIT_AX_VERSION {
        return invalid(
            path,
            format!("rightkitAx.version must equal frozen version {RIGHTKIT_AX_VERSION}"),
        );
    }
    if manifest.rightkit_ax.source_commit != RIGHTKIT_AX_SOURCE_COMMIT {
        return invalid(
            path,
            format!(
                "rightkitAx.sourceCommit must equal frozen source commit {RIGHTKIT_AX_SOURCE_COMMIT}"
            ),
        );
    }
    Ok(())
}

fn require(path: &Path, field: &str, value: &str) -> Result<(), ReleaseBindingError> {
    if value.trim().is_empty() {
        invalid(path, format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn digest_field(path: &Path, field: &str, value: &str) -> Result<(), ReleaseBindingError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        invalid(path, format!("{field} must be a SHA-256 hex digest"))
    } else {
        Ok(())
    }
}

fn exact(component: &'static str, expected: &str, actual: &str) -> Result<(), ReleaseBindingError> {
    if expected == actual {
        Ok(())
    } else {
        Err(ReleaseBindingError::Mismatch {
            component,
            expected: expected.into(),
            actual: actual.into(),
            remediation: REPAIR_COMMAND,
        })
    }
}

/// SHA-256 is hexadecimal data; its casing has no semantic meaning. All other
/// release identity fields intentionally use [`exact`] instead.
fn digest_equal(
    component: &'static str,
    expected: &str,
    actual: &str,
) -> Result<(), ReleaseBindingError> {
    if expected.eq_ignore_ascii_case(actual) {
        Ok(())
    } else {
        Err(ReleaseBindingError::Mismatch {
            component,
            expected: expected.into(),
            actual: actual.into(),
            remediation: REPAIR_COMMAND,
        })
    }
}

fn check_file(
    component: &'static str,
    expected: &str,
    path: &Path,
) -> Result<(), ReleaseBindingError> {
    digest_equal(component, expected, &file_digest(path)?)
}

fn file_digest(path: &Path) -> Result<String, ReleaseBindingError> {
    fs::read(path)
        .map(|bytes| digest(&bytes))
        .map_err(|source| ReleaseBindingError::Io {
            path: path.into(),
            source,
        })
}

/// Deterministic tree digest: sorted relative name, NUL separator, length, then bytes.
fn directory_digest(root: &Path) -> Result<String, ReleaseBindingError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|source| ReleaseBindingError::Io {
        path: root.into(),
        source,
    })?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return invalid(root, "declarative assets must be a non-symlink directory");
    }
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    paths.sort();
    let mut canonical = Vec::new();
    for relative in paths {
        let path = root.join(&relative);
        let bytes = fs::read(&path).map_err(|source| ReleaseBindingError::Io { path, source })?;
        canonical.extend_from_slice(relative.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        canonical.extend_from_slice(&bytes);
    }
    Ok(digest(&canonical))
}

fn collect_files(
    root: &Path,
    directory: &Path,
    paths: &mut Vec<String>,
) -> Result<(), ReleaseBindingError> {
    for entry in fs::read_dir(directory).map_err(|source| ReleaseBindingError::Io {
        path: directory.into(),
        source,
    })? {
        let entry = entry.map_err(|source| ReleaseBindingError::Io {
            path: directory.into(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| ReleaseBindingError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return invalid(&path, "declarative assets may not contain symlinks");
        }
        if metadata.is_dir() {
            collect_files(root, &path, paths)?;
        } else if metadata.is_file() {
            paths.push(
                path.strip_prefix(root)
                    .expect("descendant path")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    legion_catalog::hex_digest(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    fn root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "legion-binding-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("assets/nested")).expect("directory");
        fs::write(root.join("runtime"), b"runtime").expect("runtime");
        fs::write(root.join("catalog"), b"catalog").expect("catalog");
        fs::write(root.join("schema"), b"schema").expect("schema");
        fs::write(root.join("assets/nested/a"), b"a").expect("asset");
        root
    }

    fn manifest(root: &Path) -> ReleaseManifest {
        ReleaseManifest {
            release_version: "1.2.3".into(),
            runtime: RuntimeIdentity {
                platform: "macos".into(),
                architecture: "aarch64".into(),
                sha256: file_digest(&root.join("runtime")).expect("digest"),
                provenance: "rightkit-release://42".into(),
            },
            capability_catalog_sha256: file_digest(&root.join("catalog")).expect("digest"),
            mcp_tool_schema_sha256: file_digest(&root.join("schema")).expect("digest"),
            declarative_assets_sha256: directory_digest(&root.join("assets")).expect("digest"),
            state_schema_version: 2,
            rightkit_ax: RightkitAxIdentity {
                version: "0.2.0".into(),
                source_commit: "01f52555202da3dffc6b649ca44e803b55238081".into(),
            },
        }
    }

    fn inputs(root: &Path) -> ReleaseBindingInputs {
        ReleaseBindingInputs {
            release_version: "1.2.3".into(),
            runtime_path: root.join("runtime"),
            runtime_platform: "macos".into(),
            runtime_architecture: "aarch64".into(),
            runtime_provenance: "rightkit-release://42".into(),
            catalog_path: root.join("catalog"),
            mcp_tool_schema_path: root.join("schema"),
            declarative_assets: DeclarativeAssets::Directory(root.join("assets")),
            state_schema_version: 2,
            rightkit_ax: RightkitAxIdentity {
                version: "0.2.0".into(),
                source_commit: "01f52555202da3dffc6b649ca44e803b55238081".into(),
            },
        }
    }

    #[test]
    fn verifies_every_identity_with_deterministic_asset_digest() {
        let root = root();
        let manifest = manifest(&root);
        assert_eq!(
            directory_digest(&root.join("assets")).expect("repeat"),
            manifest.declarative_assets_sha256
        );
        assert_eq!(
            verify_release_binding(&manifest, &inputs(&root))
                .expect("valid")
                .release_version(),
            "1.2.3"
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn mismatch_is_typed_and_has_exact_repair_text() {
        let root = root();
        let manifest = manifest(&root);
        let mut inputs = inputs(&root);
        inputs.state_schema_version = 3;
        match verify_release_binding(&manifest, &inputs).expect_err("must reject") {
            ReleaseBindingError::Mismatch {
                component,
                remediation,
                ..
            } => {
                assert_eq!(component, "state schema version");
                assert_eq!(remediation, "legion setup repair --confirm");
            }
            error => panic!("wrong error: {error:?}"),
        }
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn every_bound_identity_is_checked() {
        let root = root();
        let manifest = manifest(&root);
        let inputs = inputs(&root);
        let assert_component =
            |manifest: &ReleaseManifest, inputs: &ReleaseBindingInputs, component: &str| {
                match verify_release_binding(manifest, inputs) {
                    Err(ReleaseBindingError::Mismatch {
                        component: actual, ..
                    }) => assert_eq!(actual, component),
                    other => panic!("expected {component} mismatch, got {other:?}"),
                }
            };

        let mut different_inputs = inputs.clone();
        different_inputs.release_version = "1.2.4".into();
        assert_component(&manifest, &different_inputs, "release version");
        different_inputs = inputs.clone();
        different_inputs.runtime_platform = "windows".into();
        assert_component(&manifest, &different_inputs, "runtime platform");
        different_inputs = inputs.clone();
        different_inputs.runtime_architecture = "x86_64".into();
        assert_component(&manifest, &different_inputs, "runtime architecture");
        different_inputs = inputs.clone();
        different_inputs.runtime_provenance = "rightkit-release://other".into();
        assert_component(&manifest, &different_inputs, "runtime provenance");
        different_inputs = inputs.clone();
        different_inputs.state_schema_version = 3;
        assert_component(&manifest, &different_inputs, "state schema version");
        different_inputs = inputs.clone();
        different_inputs.rightkit_ax.version = "0.2.1".into();
        assert_component(&manifest, &different_inputs, "RightKit AX version");
        different_inputs = inputs.clone();
        different_inputs.rightkit_ax.source_commit =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
        assert_component(&manifest, &different_inputs, "RightKit AX source commit");

        let mut different_manifest = manifest.clone();
        different_manifest.runtime.sha256 = "0".repeat(64);
        assert_component(&different_manifest, &inputs, "runtime digest");
        different_manifest = manifest.clone();
        different_manifest.capability_catalog_sha256 = "0".repeat(64);
        assert_component(&different_manifest, &inputs, "capability catalog digest");
        different_manifest = manifest.clone();
        different_manifest.mcp_tool_schema_sha256 = "0".repeat(64);
        assert_component(&different_manifest, &inputs, "MCP tool schema digest");
        different_manifest = manifest.clone();
        different_manifest.declarative_assets_sha256 = "0".repeat(64);
        assert_component(&different_manifest, &inputs, "declarative assets digest");
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn case_only_identity_variants_fail_but_hex_digest_casing_is_accepted() {
        let root = root();
        let mut manifest = manifest(&root);
        let mut inputs = inputs(&root);
        let assert_component =
            |manifest: &ReleaseManifest, inputs: &ReleaseBindingInputs, component: &str| {
                match verify_release_binding(manifest, inputs) {
                    Err(ReleaseBindingError::Mismatch {
                        component: actual, ..
                    }) => assert_eq!(actual, component),
                    other => panic!("expected {component} mismatch, got {other:?}"),
                }
            };

        manifest.release_version = "1.2.3-rc".into();
        inputs.release_version = "1.2.3-RC".into();
        assert_component(&manifest, &inputs, "release version");
        inputs.release_version = manifest.release_version.clone();
        inputs.runtime_provenance = "RIGHTKIT-RELEASE://42".into();
        assert_component(&manifest, &inputs, "runtime provenance");
        inputs.runtime_provenance = manifest.runtime.provenance.clone();
        inputs.rightkit_ax.version = "0.2.0-RC".into();
        assert_component(&manifest, &inputs, "RightKit AX version");
        inputs.rightkit_ax.version = RIGHTKIT_AX_VERSION.into();
        inputs.rightkit_ax.source_commit = manifest.rightkit_ax.source_commit.to_uppercase();
        assert_component(&manifest, &inputs, "RightKit AX source commit");

        inputs.rightkit_ax.source_commit = manifest.rightkit_ax.source_commit.clone();
        manifest.runtime.sha256 = manifest.runtime.sha256.to_uppercase();
        assert!(verify_release_binding(&manifest, &inputs).is_ok());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
