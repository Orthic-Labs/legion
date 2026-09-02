//! Fail-closed verification of the complete installed Legion release identity.

use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
};

use legion_catalog::json;
use serde::{Deserialize, Serialize};

/// The sole remediation for a mixed or otherwise invalid installed identity.
pub const REPAIR_COMMAND: &str = "legion setup repair --confirm";
pub const CANONICAL_RELEASE_MANIFEST: &str = "share/legion/release.json";
pub const STABLE_INSTALL_PRODUCT_ROOT: &str = "Orthic Labs/Legion";
pub const ORIGIN_INSTALLED: &str = "installed";
pub const ORIGIN_DEVELOPMENT: &str = "development";
pub const RIGHTKIT_AX_VERSION: &str = "0.2.1";
pub const RIGHTKIT_AX_SOURCE_COMMIT: &str = "4c1a414269d8ffdb95b4b1e685440bd34784b41b";

/// Explicit repository execution context. It is never synthesized for an
/// installed process, so development state cannot accidentally become global
/// product state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DevelopmentExecutionContext {
    pub repository_root: PathBuf,
    pub state_root: PathBuf,
    pub port: Option<u16>,
    pub process_identity: String,
    #[serde(default)]
    pub client_overrides: BTreeMap<String, PathBuf>,
}

impl DevelopmentExecutionContext {
    pub fn validate(&self) -> Result<(), String> {
        if !self.repository_root.is_absolute() || !self.state_root.is_absolute() {
            return Err("development repository and state roots must be absolute".into());
        }
        if self.repository_root.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) || self.state_root.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            return Err("development roots may not contain traversal".into());
        }
        if self.port == Some(0) {
            return Err("development port must be non-zero".into());
        }
        if self.process_identity.trim().is_empty() {
            return Err("development process identity must be non-empty".into());
        }
        Ok(())
    }
}

/// Runtime execution origin. Installed product execution is only trusted from
/// the user-local stable `current` tree; explicit repository composition is
/// development execution with isolated state owned by its caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeOrigin {
    Installed,
    Development,
}

impl RuntimeOrigin {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Installed => ORIGIN_INSTALLED,
            Self::Development => ORIGIN_DEVELOPMENT,
        }
    }
}

/// Evidence reported by setup/status and used to gate production bindings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeOriginEvidence {
    pub origin: RuntimeOrigin,
    pub executable: PathBuf,
    /// Lexical product root; stable `current` binding is checked separately.
    pub install_root: Option<PathBuf>,
    pub generation: Option<String>,
    /// Whether executable is classified from the stable `current` path.
    pub stable_current: bool,
    /// Present only for explicit development execution.
    #[serde(default)]
    pub development: Option<DevelopmentExecutionContext>,
}

impl RuntimeOriginEvidence {
    pub fn development(executable: impl Into<PathBuf>) -> Self {
        Self {
            origin: RuntimeOrigin::Development,
            executable: executable.into(),
            install_root: None,
            generation: None,
            stable_current: false,
            development: None,
        }
    }

    pub fn installed(
        executable: impl Into<PathBuf>,
        install_root: impl Into<PathBuf>,
        generation: impl Into<String>,
    ) -> Self {
        Self {
            origin: RuntimeOrigin::Installed,
            executable: executable.into(),
            install_root: Some(install_root.into()),
            generation: Some(generation.into()),
            stable_current: true,
            development: None,
        }
    }

    pub fn development_with_context(
        executable: impl Into<PathBuf>,
        context: DevelopmentExecutionContext,
    ) -> Result<Self, ReleaseBindingError> {
        context
            .validate()
            .map_err(|reason| ReleaseBindingError::Mismatch {
                component: "development execution context",
                expected: "absolute isolated roots, non-empty process identity, and valid port"
                    .into(),
                actual: reason,
                remediation: "use an explicit development context".into(),
            })?;
        Ok(Self {
            origin: RuntimeOrigin::Development,
            executable: executable.into(),
            install_root: None,
            generation: None,
            stable_current: false,
            development: Some(context),
        })
    }

    pub fn is_production(&self) -> bool {
        self.origin == RuntimeOrigin::Installed && self.stable_current
    }
}

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
    /// SHA-256 (hex) of the shipped `plugin/rightax-portable-core.json` bytes.
    /// Independent anchor for the portable-core validator; absent on releases
    /// assembled before the anchor existed.
    #[serde(default)]
    pub portable_core_sha256: Option<String>,
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

impl InstalledRelease {
    pub fn origin_evidence(&self) -> RuntimeOriginEvidence {
        let install_root = self
            .manifest_path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .or_else(stable_product_root);
        RuntimeOriginEvidence {
            origin: RuntimeOrigin::Installed,
            executable: self.executable_path.clone(),
            install_root,
            generation: Some(self.manifest.release_version.clone()),
            stable_current: true,
            development: None,
        }
    }

    pub fn resolved_executable_path(&self) -> Result<PathBuf, ReleaseBindingError> {
        fs::canonicalize(&self.executable_path).map_err(|source| ReleaseBindingError::Io {
            path: self.executable_path.clone(),
            source,
        })
    }

    /// Resolve immutable version root reached through lexical stable `current`.
    pub fn resolved_install_root(&self) -> Result<PathBuf, ReleaseBindingError> {
        let product_root = self.origin_evidence().install_root.ok_or_else(|| {
            ReleaseBindingError::InvalidManifest {
                path: self.manifest_path.clone(),
                reason: "installed release has no stable install root".into(),
            }
        })?;
        let current_root = product_root.join("current");
        fs::canonicalize(&current_root).map_err(|source| ReleaseBindingError::Io {
            path: current_root,
            source,
        })
    }
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
        if let Some(digest) = &self.portable_core_sha256 {
            digest_field(path, "portableCoreSha256", digest)?;
        }
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

/// Return user-local stable product root used by production adapters.
/// Windows deliberately binds this to `%LOCALAPPDATA%`; no process or shell
/// state is consulted and a missing root remains a development origin.
pub fn stable_product_root() -> Option<PathBuf> {
    let data_root = stable_data_root()?;
    Some(data_root.join("Orthic Labs").join("Legion"))
}

/// Return stable lexical `current` tree below product root. It may be a
/// junction/symlink to an immutable, verified release generation.
pub fn stable_current_root() -> Option<PathBuf> {
    stable_product_root().map(|root| root.join("current"))
}

/// Recognize exactly `<product-root>/current/bin/legion[.exe]`.
/// Windows path components are compared case-insensitively, including when a
/// launcher or current directory uses different casing.
pub fn is_stable_current_executable(path: &Path) -> bool {
    stable_install_root(path).is_some()
}

/// Return stable product root for one lexical executable path. This preserves
/// the user-facing `current` path even when that directory is a Windows
/// junction to an immutable versioned generation.
pub fn stable_install_root(path: impl AsRef<Path>) -> Option<PathBuf> {
    let path = path.as_ref();
    let product_root = stable_product_root()?;
    let current_root = product_root.join("current");
    is_stable_current_executable_at(path, &current_root).then_some(product_root)
}

/// Classify one executable without loading release files. This is useful for
/// status output when an installed manifest is missing or invalid.
pub fn runtime_origin_for_executable(path: impl Into<PathBuf>) -> RuntimeOriginEvidence {
    let executable = path.into();
    match stable_install_root(&executable) {
        Some(root) => RuntimeOriginEvidence {
            origin: RuntimeOrigin::Installed,
            executable,
            install_root: Some(root),
            generation: None,
            stable_current: true,
            development: None,
        },
        None => RuntimeOriginEvidence::development(executable),
    }
}

/// Classify the running process from its executable path.
pub fn detect_runtime_origin() -> Result<RuntimeOriginEvidence, ReleaseBindingError> {
    let executable = std::env::current_exe().map_err(|source| ReleaseBindingError::Io {
        path: PathBuf::from("<current_exe>"),
        source,
    })?;
    Ok(runtime_origin_for_executable(executable))
}

/// Locate the canonical installed manifest below the running executable's
/// user-local stable `current` root. No source checkout or caller-selected
/// fallback is consulted.
pub fn load_installed_release() -> Result<InstalledRelease, ReleaseBindingError> {
    let executable = std::env::current_exe().map_err(|source| ReleaseBindingError::Io {
        path: PathBuf::from("<current_exe>"),
        source,
    })?;
    let evidence = runtime_origin_for_executable(executable.clone());
    let install_root =
        evidence
            .install_root
            .clone()
            .ok_or_else(|| ReleaseBindingError::Mismatch {
                component: "runtime origin",
                expected: format!("{STABLE_INSTALL_PRODUCT_ROOT}/current/bin/legion executable"),
                actual: executable.display().to_string(),
                remediation: REPAIR_COMMAND,
            })?;
    let current_root = install_root.join("current");
    let resolved_install_root =
        fs::canonicalize(&current_root).map_err(|source| ReleaseBindingError::Io {
            path: current_root.clone(),
            source,
        })?;
    let resolved_executable =
        fs::canonicalize(&executable).map_err(|source| ReleaseBindingError::Io {
            path: executable.clone(),
            source,
        })?;
    if !path_is_within(&resolved_install_root, &resolved_executable) {
        return Err(ReleaseBindingError::Mismatch {
            component: "resolved executable",
            expected: resolved_install_root.display().to_string(),
            actual: resolved_executable.display().to_string(),
            remediation: REPAIR_COMMAND,
        });
    }
    let manifest_path = current_root.join(CANONICAL_RELEASE_MANIFEST);
    if !manifest_path.is_file() {
        return Err(ReleaseBindingError::InvalidManifest {
            path: manifest_path,
            reason: "installed release manifest share/legion/release.json was not found".into(),
        });
    }
    verify_resolved_path(
        &resolved_install_root,
        &manifest_path,
        "resolved release manifest",
    )?;
    let manifest = load_release_manifest(&manifest_path)?;
    exact(
        "runtime platform",
        &manifest.runtime.platform,
        std::env::consts::OS,
    )?;
    exact(
        "runtime architecture",
        &manifest.runtime.architecture,
        current_runtime_architecture(),
    )?;
    check_file("runtime digest", &manifest.runtime.sha256, &executable)?;
    Ok(InstalledRelease {
        manifest,
        manifest_path,
        executable_path: executable,
    })
}

/// Ensure an installed application binds only files lexically rooted at the
/// user-local stable `current` tree. Relative paths, parent traversal, and
/// mismatched executable evidence fail closed.
pub fn verify_stable_current_binding(
    evidence: &RuntimeOriginEvidence,
    manifest_path: &Path,
    inputs: &ReleaseBindingInputs,
) -> Result<(), ReleaseBindingError> {
    if evidence.origin != RuntimeOrigin::Installed || !evidence.stable_current {
        return Err(ReleaseBindingError::Mismatch {
            component: "runtime origin",
            expected: "installed".into(),
            actual: "development".into(),
            remediation: REPAIR_COMMAND,
        });
    }
    let root = evidence
        .install_root
        .as_deref()
        .ok_or_else(|| ReleaseBindingError::Mismatch {
            component: "install root",
            expected: STABLE_INSTALL_PRODUCT_ROOT.into(),
            actual: "missing".into(),
            remediation: REPAIR_COMMAND,
        })?;
    if !stable_product_root_is(root) {
        return Err(ReleaseBindingError::Mismatch {
            component: "install root",
            expected: stable_product_root()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| STABLE_INSTALL_PRODUCT_ROOT.into()),
            actual: root.display().to_string(),
            remediation: REPAIR_COMMAND,
        });
    }
    let current_root = root.join("current");
    if !is_stable_current_executable_at(&evidence.executable, &current_root)
        || !is_stable_current_executable_at(&inputs.runtime_path, &current_root)
        || path_has_symlink_component(&current_root, &evidence.executable)
        || path_has_symlink_component(&current_root, &inputs.runtime_path)
    {
        return Err(ReleaseBindingError::Mismatch {
            component: "stable current executable",
            expected: current_root
                .join("bin")
                .join(if cfg!(windows) {
                    "legion.exe"
                } else {
                    "legion"
                })
                .display()
                .to_string(),
            actual: inputs.runtime_path.display().to_string(),
            remediation: REPAIR_COMMAND,
        });
    }
    if !same_path(&evidence.executable, &inputs.runtime_path) {
        return Err(ReleaseBindingError::Mismatch {
            component: "runtime executable",
            expected: evidence.executable.display().to_string(),
            actual: inputs.runtime_path.display().to_string(),
            remediation: REPAIR_COMMAND,
        });
    }
    let resolved_current_root =
        fs::canonicalize(&current_root).map_err(|source| ReleaseBindingError::Io {
            path: current_root.clone(),
            source,
        })?;
    let resolved_executable =
        fs::canonicalize(&evidence.executable).map_err(|source| ReleaseBindingError::Io {
            path: evidence.executable.clone(),
            source,
        })?;
    if !path_is_within(&resolved_current_root, &resolved_executable) {
        return Err(ReleaseBindingError::Mismatch {
            component: "resolved stable current executable",
            expected: resolved_current_root.display().to_string(),
            actual: resolved_executable.display().to_string(),
            remediation: REPAIR_COMMAND,
        });
    }
    let mut paths = vec![
        manifest_path,
        inputs.catalog_path.as_path(),
        inputs.mcp_tool_schema_path.as_path(),
    ];
    match &inputs.declarative_assets {
        DeclarativeAssets::File(path) | DeclarativeAssets::Directory(path) => paths.push(path),
    }
    for path in paths {
        verify_stable_current_path(evidence, path, "stable current binding")?;
    }
    Ok(())
}

/// Validate one additional installed binding path, such as a catalog root
/// consumed by the application but not represented in `ReleaseBindingInputs`.
pub fn verify_stable_current_path(
    evidence: &RuntimeOriginEvidence,
    path: &Path,
    component: &'static str,
) -> Result<(), ReleaseBindingError> {
    if evidence.origin != RuntimeOrigin::Installed || !evidence.stable_current {
        return Err(ReleaseBindingError::Mismatch {
            component: "runtime origin",
            expected: "installed".into(),
            actual: "development".into(),
            remediation: REPAIR_COMMAND,
        });
    }
    let root = evidence
        .install_root
        .as_deref()
        .ok_or_else(|| ReleaseBindingError::Mismatch {
            component: "install root",
            expected: STABLE_INSTALL_PRODUCT_ROOT.into(),
            actual: "missing".into(),
            remediation: REPAIR_COMMAND,
        })?;
    if !stable_product_root_is(root) {
        return Err(ReleaseBindingError::Mismatch {
            component: "install root",
            expected: stable_product_root()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| STABLE_INSTALL_PRODUCT_ROOT.into()),
            actual: root.display().to_string(),
            remediation: REPAIR_COMMAND,
        });
    }
    let current_root = root.join("current");
    if !path_is_within(&current_root, path) || path_has_symlink_component(&current_root, path) {
        Err(ReleaseBindingError::Mismatch {
            component,
            expected: current_root.display().to_string(),
            actual: path.display().to_string(),
            remediation: REPAIR_COMMAND,
        })
    } else if resolved_path_is_within(&current_root, path) {
        Ok(())
    } else {
        Err(ReleaseBindingError::Mismatch {
            component,
            expected: current_root.display().to_string(),
            actual: path.display().to_string(),
            remediation: REPAIR_COMMAND,
        })
    }
}

fn stable_data_root() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join("Library/Application Support"))
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
            })
    }
}

fn is_stable_current_executable_at(path: &Path, root: &Path) -> bool {
    if !path.is_absolute() || !root.is_absolute() {
        return false;
    }
    let path = normalized_components(path);
    let root = normalized_components(root);
    if path.len() != root.len() + 2 {
        return false;
    }
    if !root
        .iter()
        .zip(path.iter())
        .all(|(expected, actual)| path_component_eq(expected, actual))
    {
        return false;
    }
    let bin = &path[root.len()];
    let executable = &path[root.len() + 1];
    path_component_eq(bin, "bin")
        && path_component_eq(
            executable,
            if cfg!(windows) {
                "legion.exe"
            } else {
                "legion"
            },
        )
}

fn path_is_within(root: &Path, path: &Path) -> bool {
    if !root.is_absolute() || !path.is_absolute() {
        return false;
    }
    let root = normalized_components(root);
    let path = normalized_components(path);
    path.len() >= root.len()
        && root
            .iter()
            .zip(path.iter())
            .all(|(expected, actual)| path_component_eq(expected, actual))
}

fn stable_product_root_is(root: &Path) -> bool {
    stable_product_root()
        .map(|expected| same_path(&expected, root))
        .unwrap_or(false)
}

fn verify_resolved_path(
    root: &Path,
    path: &Path,
    component: &'static str,
) -> Result<(), ReleaseBindingError> {
    if resolved_path_is_within(root, path) {
        Ok(())
    } else {
        Err(ReleaseBindingError::Mismatch {
            component,
            expected: root.display().to_string(),
            actual: path.display().to_string(),
            remediation: REPAIR_COMMAND,
        })
    }
}

fn resolved_path_is_within(root: &Path, path: &Path) -> bool {
    if !path.exists() {
        return true;
    }
    let Ok(root) = fs::canonicalize(root) else {
        return false;
    };
    let Ok(path) = fs::canonicalize(path) else {
        return false;
    };
    path_is_within(&root, &path)
}

fn path_has_symlink_component(root: &Path, path: &Path) -> bool {
    let mut cursor = path.to_path_buf();
    loop {
        if same_path(&cursor, root) {
            return false;
        }
        if fs::symlink_metadata(&cursor)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return true;
        }
        let Some(parent) = cursor.parent() else {
            return false;
        };
        if same_path(parent, &cursor) {
            return false;
        }
        cursor = parent.to_path_buf();
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    let left = normalized_components(left);
    let right = normalized_components(right);
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(expected, actual)| path_component_eq(expected, actual))
}

fn normalized_components(path: &Path) -> Vec<String> {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let normalized = normalized.strip_prefix("//?/").unwrap_or(&normalized);
    let normalized = normalized.strip_prefix("UNC/").unwrap_or(normalized);
    normalized
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .map(|component| component.to_owned())
        .collect()
}

fn path_component_eq(expected: &str, actual: &str) -> bool {
    if cfg!(windows) {
        expected.eq_ignore_ascii_case(actual)
    } else {
        expected == actual
    }
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

fn canonical_runtime_architecture<'a>(platform: &str, architecture: &'a str) -> &'a str {
    if platform == "windows" && architecture == "aarch64" {
        "arm64"
    } else {
        architecture
    }
}

/// Return release-manifest architecture identity for this compiled runtime.
pub fn current_runtime_architecture() -> &'static str {
    canonical_runtime_architecture(std::env::consts::OS, std::env::consts::ARCH)
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
                version: "0.2.1".into(),
                source_commit: "4c1a414269d8ffdb95b4b1e685440bd34784b41b".into(),
            },
            portable_core_sha256: None,
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
                version: "0.2.1".into(),
                source_commit: "4c1a414269d8ffdb95b4b1e685440bd34784b41b".into(),
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
    fn runtime_architecture_canonicalizes_only_windows_arm() {
        assert_eq!(
            canonical_runtime_architecture("windows", "aarch64"),
            "arm64"
        );
        assert_eq!(
            canonical_runtime_architecture("windows", "x86_64"),
            "x86_64"
        );
        assert_eq!(
            canonical_runtime_architecture("macos", "aarch64"),
            "aarch64"
        );
        assert_eq!(canonical_runtime_architecture("macos", "x86_64"), "x86_64");
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
        different_inputs.rightkit_ax.version = "0.2.2".into();
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
