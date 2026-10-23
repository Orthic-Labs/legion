//! Host-owned trusted process owner for native Audit external tools.
//!
//! `HostPolicyOwner` is the `TrustedOwner` the root wires when (and only when) a
//! host policy file exists *outside* every audited tree and run directory. The
//! file (`<LEGION state root>/audit-owner-policy.json`) names which absolute
//! executables, with which sha256 digest, for which providers, invocation class
//! and environment names, may run. Nothing in the audited repository, a request
//! or the process environment can add a tool. A grant is minted only over the
//! exact admission binding digest, with a fresh nonce and a short TTL;
//! `OwnerBackedPolicy` enforces single use, owner/revision match and expiry.
//!
//! Provenance (`OwnerProvenance::Verified`) is build-integrity provenance for the
//! confinement runtime: the key id is the sha256 of the label
//! `crates-io:rightkit-sandbox@0.6.1` (the admission type requires 64 lowercase
//! hex) and the receipt digest is the crates.io checksum pinned in `Cargo.lock`.
//! It proves which sandbox crate this binary was built against, not who wrote the
//! policy file: the policy file is same-user authority (0600, owner-only parent,
//! outside audited roots) and not a signed artifact.
//!
//! Policy shape (all keys required unless noted, unknown keys rejected):
//! `{"schemaVersion":1,"policyRevision":"r1","toolchainRoots":[...] (optional),
//!   "tools":[{"providers":["id"],"executable":"/abs/tool","sha256":"sha256:<hex>",
//!             "class":"read-only-static|project-executing|network-metadata",
//!             "environmentNames":["HOME"] (optional),
//!             "version":"1.2.3" (optional; recorded as the executed toolchain
//!             version, defaults to the pinned sha256)}],
//!   "gradle":{"java":"/abs/jdk/bin/java" (must also be a project-executing tool
//!             for code.android.lint),"wrapperJarSha256":["sha256:.."],
//!             "distributionSha256":["<hex>"],
//!             "dependencyCacheRoot":"/abs/dir" (optional)} (optional)}`
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use legion_effects::{
    owner_process::{InvocationClass, OwnerProcess},
    sandbox_runtime::{EnforcedExecPolicy, ExecHardening, RightKitSandboxRuntime},
    EffectError,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub use crate::native_providers::code::gradle_model::GradlePins;
use crate::owner_admission::{
    OwnerGrant, OwnerIdentity, OwnerPolicyConfig, OwnerProvenance, OwnerQuery, OwnerVerdict,
    PlanBinding, TrustedOwner,
};
use crate::profiles::RuntimeConstraint;
use legion_effects::SandboxReceipt;

pub const POLICY_FILE: &str = "audit-owner-policy.json";
pub const OWNER_ID: &str = "legion-host-policy-owner";
/// Label whose sha256 is the `key_id` (admission requires 64 lowercase hex).
pub const SANDBOX_PROVENANCE_LABEL: &str = "crates-io:rightkit-sandbox@0.6.1";
/// crates.io checksum (sha256 of the `.crate`) of rightkit-sandbox 0.6.1 as locked
/// in `engine/Cargo.lock`; checked against the lock file by a unit test.
pub const SANDBOX_LOCK_CHECKSUM: &str =
    "cc88dcb8ce6b88b80a715edc73a889b082b732abccdf419d2e2b76d7bc677976";
pub const GRANT_TTL_MS: u64 = 60_000;
pub const MAX_TIMEOUT_MS: u64 = 30 * 60 * 1000;
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PolicyFile {
    schema_version: u32,
    policy_revision: String,
    #[serde(default)]
    toolchain_roots: Vec<PathBuf>,
    tools: Vec<ToolEntry>,
    #[serde(default)]
    gradle: Option<GradleEntry>,
}

/// Optional `gradle` policy section: pins for owner-contained Gradle model
/// extraction (`code.android.lint`, typed Kotlin). `java` must also be a
/// `project-executing` tool entry for `code.android.lint`; the digest lists are
/// the only wrapper jars / distributions the extractor will run.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GradleEntry {
    java: PathBuf,
    wrapper_jar_sha256: Vec<String>,
    distribution_sha256: Vec<String>,
    #[serde(default)]
    dependency_cache_root: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ToolEntry {
    providers: Vec<String>,
    executable: PathBuf,
    sha256: String,
    class: String,
    #[serde(default)]
    environment_names: Vec<String>,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Clone, Debug)]
struct HostTool {
    providers: BTreeSet<String>,
    executable: PathBuf,
    digest: String,
    class: InvocationClass,
    environment_names: BTreeSet<String>,
    version: Option<String>,
}

/// One host-policy tool entry as request builders may read it. The pin is the
/// policy's digest, never a digest computed from the file about to run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolPin {
    pub executable: PathBuf,
    /// `sha256:<64 lowercase hex>` from the host policy file.
    pub digest: String,
    pub class: InvocationClass,
    pub environment_names: BTreeSet<String>,
    /// Executable file name.
    pub name: String,
    /// Policy-declared version, else the pinned digest.
    pub version: String,
}

/// What a request builder needs to produce admissible requests for the active
/// owner: the shared plan binding, the containment receipt (id == containment id)
/// and the policy's tool pins. It carries no authority; admission and the owner
/// still decide every request.
#[derive(Clone, Debug)]
pub struct OwnerRequestContext {
    plan: PlanBinding,
    receipt: SandboxReceipt,
    exec_policy: EnforcedExecPolicy,
    tools: Vec<(BTreeSet<String>, ToolPin)>,
}

impl OwnerRequestContext {
    pub fn plan(&self) -> &PlanBinding {
        &self.plan
    }
    pub fn sandbox_receipt(&self) -> SandboxReceipt {
        self.receipt.clone()
    }
    /// The exec/socket policy the sandbox enforces for this containment
    /// (recorded beside the receipt; includes any explicit gaps).
    pub fn enforced_exec_policy(&self) -> &EnforcedExecPolicy {
        &self.exec_policy
    }
    /// The policy entry for a canonical executable path and provider id.
    pub fn pin_for(&self, provider_id: &str, executable: &Path) -> Option<&ToolPin> {
        self.tools
            .iter()
            .find(|(providers, pin)| {
                pin.executable == executable && providers.contains(provider_id)
            })
            .map(|(_, pin)| pin)
    }
}

pub struct HostPolicyOwner {
    revision: String,
    tools: Vec<HostTool>,
    toolchain_roots: Vec<PathBuf>,
    gradle: Option<GradlePins>,
    clock: fn() -> u64,
}

/// `<LEGION state root>/audit-owner-policy.json`, using the same state-root
/// resolution as the host receipts (`LEGION_STATE_ROOT`, else the per-user
/// platform default). `None` when no home can be resolved.
pub fn default_policy_path() -> Option<PathBuf> {
    if let Some(root) = std::env::var_os("LEGION_STATE_ROOT") {
        return Some(PathBuf::from(root).join(POLICY_FILE));
    }
    let home = PathBuf::from(std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?);
    let root = if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Orthic Labs/Legion/state")
    } else if cfg!(windows) {
        home.join("AppData/Local/Orthic Labs/Legion/state")
    } else {
        home.join(".local/state/legion")
    };
    Some(root.join(POLICY_FILE))
}

impl HostPolicyOwner {
    /// `Ok(None)`: no policy file (owner unavailable, caller keeps deny-all).
    /// `Err`: a file exists but is untrustworthy or malformed (also deny-all).
    /// `audited_roots` are every tree the audit reads or writes (frozen source,
    /// scratch/output); the policy file, tools and toolchain roots must be
    /// disjoint from them.
    pub fn load(path: &Path, audited_roots: &[PathBuf]) -> Result<Option<Self>, String> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("{}: {error}", path.display())),
            Ok(_) => {}
        }
        let roots = audited_roots
            .iter()
            .map(|root| std::fs::canonicalize(root).map_err(|e| format!("{}: {e}", root.display())))
            .collect::<Result<Vec<_>, _>>()?;
        let bytes = read_trusted_policy(path, &roots)?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("policy json: {e}"))?;
        let digest = crate::digest(&value).map_err(|e| e.to_string())?;
        let file: PolicyFile =
            serde_json::from_value(value).map_err(|e| format!("policy schema: {e}"))?;
        if file.schema_version != 1 {
            return Err("unsupported policy schema version".into());
        }
        if file.policy_revision.trim().is_empty() || file.tools.is_empty() {
            return Err("policy revision and at least one tool are required".into());
        }
        let outside = |candidate: &Path| {
            !roots
                .iter()
                .any(|root| candidate.starts_with(root) || root.starts_with(candidate))
        };
        let mut toolchain_roots = Vec::new();
        for root in &file.toolchain_roots {
            let canonical = std::fs::canonicalize(root)
                .map_err(|e| format!("toolchain root {}: {e}", root.display()))?;
            if !root.is_absolute() || canonical != *root || !outside(&canonical) {
                return Err(format!(
                    "toolchain root {} must be canonical and outside audited roots",
                    root.display()
                ));
            }
            toolchain_roots.push(canonical);
        }
        let mut tools = Vec::new();
        let mut provider_classes: BTreeMap<String, InvocationClass> = BTreeMap::new();
        for entry in file.tools {
            let canonical = std::fs::canonicalize(&entry.executable)
                .map_err(|e| format!("tool {}: {e}", entry.executable.display()))?;
            if !entry.executable.is_absolute()
                || canonical != entry.executable
                || !canonical.is_file()
                || !outside(&canonical)
            {
                return Err(format!(
                    "tool {} must be a canonical file outside audited roots",
                    entry.executable.display()
                ));
            }
            let digest = normalize_digest(&entry.sha256)?;
            let class = match entry.class.as_str() {
                "read-only-static" => InvocationClass::ReadOnlyStatic,
                "project-executing" => InvocationClass::ProjectExecuting,
                "network-metadata" => InvocationClass::NetworkMetadata,
                other => return Err(format!("unknown invocation class {other:?}")),
            };
            if entry.providers.is_empty() || entry.providers.iter().any(|p| p.trim().is_empty()) {
                return Err("every tool needs at least one provider id".into());
            }
            for provider in &entry.providers {
                if provider_classes
                    .insert(provider.clone(), class)
                    .is_some_and(|c| c != class)
                {
                    return Err(format!("provider {provider} has conflicting classes"));
                }
            }
            tools.push(HostTool {
                providers: entry.providers.into_iter().collect(),
                executable: canonical,
                digest,
                class,
                environment_names: entry.environment_names.into_iter().collect(),
                version: entry.version.filter(|v| !v.trim().is_empty()),
            });
        }
        let gradle = match file.gradle {
            None => None,
            Some(entry) => Some(validate_gradle(entry, &tools, &outside)?),
        };
        Ok(Some(Self {
            revision: format!("{}:{digest}", file.policy_revision),
            tools,
            toolchain_roots,
            gradle,
            clock: system_now_ms,
        }))
    }

    /// Host-policy Gradle pins, when the policy file declares a `gradle`
    /// section. Never derived from the audited repository.
    pub fn gradle_pins(&self) -> Option<GradlePins> {
        self.gradle.clone()
    }

    #[doc(hidden)]
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    /// Policy revision bound into every grant (file revision + file digest).
    pub fn policy_revision(&self) -> &str {
        &self.revision
    }

    /// Frozen admission configuration derived only from the host policy plus the
    /// audit's own frozen roots.
    pub fn owner_config(
        &self,
        plan_id: &str,
        frozen_root: &Path,
        output_root: &Path,
    ) -> Result<OwnerPolicyConfig, String> {
        if plan_id.trim().is_empty() {
            return Err("plan id is required".into());
        }
        self.owner_config_bound(PlanBinding::bound(plan_id), frozen_root, output_root)
    }

    /// As `owner_config`, with the frozen plan digest bound later through `plan`.
    /// Until bound, admission denies every request (`plan-not-bound`).
    pub fn owner_config_bound(
        &self,
        plan: PlanBinding,
        frozen_root: &Path,
        output_root: &Path,
    ) -> Result<OwnerPolicyConfig, String> {
        let classes = self
            .tools
            .iter()
            .flat_map(|tool| tool.providers.iter().map(|p| (p.clone(), tool.class)))
            .collect::<BTreeMap<_, _>>();
        let environment = self
            .tools
            .iter()
            .flat_map(|tool| tool.environment_names.iter().cloned())
            .collect::<BTreeSet<_>>();
        OwnerPolicyConfig::with_plan_binding(
            self.revision.clone(),
            plan,
            format!("rightkit-sandbox-0.6.1:{}", self.revision),
            &[frozen_root.to_path_buf()],
            output_root,
            classes,
            environment,
            MAX_TIMEOUT_MS,
            MAX_OUTPUT_BYTES,
        )
    }

    /// Request-builder view of this policy for `config` (same plan binding and
    /// containment id the admission layer enforces).
    pub fn request_context(&self, config: &OwnerPolicyConfig) -> OwnerRequestContext {
        let receipt = config
            .containment_profile(
                OWNER_ID,
                InvocationClass::ReadOnlyStatic,
                self.tools.iter().map(|t| t.executable.clone()).collect(),
            )
            .sandbox_receipt();
        OwnerRequestContext {
            plan: config.plan_binding(),
            receipt,
            exec_policy: exec_hardening(config).enforced(),
            tools: self
                .tools
                .iter()
                .map(|tool| {
                    (
                        tool.providers.clone(),
                        ToolPin {
                            executable: tool.executable.clone(),
                            digest: tool.digest.clone(),
                            class: tool.class,
                            environment_names: tool.environment_names.clone(),
                            name: tool
                                .executable
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                            version: tool.version.clone().unwrap_or_else(|| tool.digest.clone()),
                        },
                    )
                })
                .collect(),
        }
    }

    /// Contained process for the executor. Fails closed (`Err`) when this host
    /// cannot apply OS confinement; never returns an unconfined process.
    pub fn process(
        &self,
        config: &OwnerPolicyConfig,
    ) -> Result<OwnerProcess<RightKitSandboxRuntime>, EffectError> {
        // Widest class wins for the profile; per-executable classes only narrow.
        let class = if self
            .tools
            .iter()
            .any(|t| t.class == InvocationClass::NetworkMetadata)
        {
            InvocationClass::NetworkMetadata
        } else if self
            .tools
            .iter()
            .any(|t| t.class == InvocationClass::ProjectExecuting)
        {
            InvocationClass::ProjectExecuting
        } else {
            InvocationClass::ReadOnlyStatic
        };
        let profile = config.containment_profile(
            OWNER_ID,
            class,
            self.tools.iter().map(|t| t.executable.clone()).collect(),
        );
        // The Gradle dependency cache is a read-only grant, present only when
        // the policy declared it (validated canonical and outside audited roots
        // at load). Without it Gradle runs `--offline` with no cache read.
        let mut toolchain_roots = self.toolchain_roots.clone();
        if let Some(cache) = self
            .gradle
            .as_ref()
            .and_then(|g| g.dependency_cache_root.clone())
        {
            if !toolchain_roots.contains(&cache) {
                toolchain_roots.push(cache);
            }
        }
        let runtime = RightKitSandboxRuntime::new(OWNER_ID)?
            .with_toolchain_roots(toolchain_roots)?
            .with_exec_hardening(exec_hardening(config))?
            .with_executable_classes(
                self.tools
                    .iter()
                    .map(|t| (t.executable.clone(), t.class))
                    .collect(),
            )?;
        OwnerProcess::new(runtime, profile)
    }

    pub fn into_trusted(self) -> Arc<dyn TrustedOwner> {
        Arc::new(self)
    }
}

impl TrustedOwner for HostPolicyOwner {
    fn identity(&self) -> OwnerIdentity {
        OwnerIdentity {
            owner_id: OWNER_ID.into(),
            version: "rightkit-sandbox@0.6.1".into(),
            provenance: OwnerProvenance::Verified {
                key_id: sha256_hex(SANDBOX_PROVENANCE_LABEL.as_bytes()),
                receipt_digest: SANDBOX_LOCK_CHECKSUM.into(),
            },
        }
    }

    fn admit(&self, query: &OwnerQuery<'_>) -> OwnerVerdict {
        let binding = query.binding;
        let deny = |reason: &str| OwnerVerdict::Denied(reason.into());
        if binding.owner_id != OWNER_ID || binding.policy_revision != self.revision {
            return deny("owner-or-revision-mismatch");
        }
        if query.binding_digest != binding.digest() {
            return deny("binding-digest-mismatch");
        }
        let Some(tool) = self
            .tools
            .iter()
            .find(|tool| tool.executable == binding.executable)
        else {
            return deny("tool-not-in-host-policy");
        };
        if !tool.providers.contains(&binding.provider_id) {
            return deny("provider-not-allowed-for-tool");
        }
        if tool.class != binding.class {
            return deny("invocation-class-mismatch");
        }
        if tool.digest != binding.executable_digest {
            return deny("executable-digest-mismatch");
        }
        if binding
            .environment
            .keys()
            .any(|name| !tool.environment_names.contains(name))
        {
            return deny("environment-name-not-allowed-for-tool");
        }
        match std::fs::read(&tool.executable) {
            Ok(bytes) if format!("sha256:{}", sha256_hex(&bytes)) == tool.digest => {}
            _ => return deny("executable-bytes-do-not-match-policy-digest"),
        }
        let mut nonce = [0u8; 16];
        if getrandom::fill(&mut nonce).is_err() {
            return OwnerVerdict::Unavailable("no entropy for grant nonce".into());
        }
        OwnerVerdict::Granted(OwnerGrant {
            owner_id: OWNER_ID.into(),
            binding_digest: query.binding_digest.into(),
            policy_revision: self.revision.clone(),
            nonce: hex::encode(nonce),
            expires_at_ms: (self.clock)() + GRANT_TTL_MS,
        })
    }
}

#[cfg(unix)]
fn read_trusted_policy(path: &Path, audited: &[PathBuf]) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let uid = legion_effects::sandbox_runtime::effective_uid();
    let canonical = std::fs::canonicalize(path).map_err(|e| e.to_string())?;
    if canonical != path {
        return Err("policy path must be canonical (no symlinks)".into());
    }
    if audited.iter().any(|root| canonical.starts_with(root)) {
        return Err("policy file lies inside an audited root".into());
    }
    let parent = canonical.parent().ok_or("policy file has no parent")?;
    let parent_meta = std::fs::metadata(parent).map_err(|e| e.to_string())?;
    if parent_meta.mode() & 0o022 != 0 || (parent_meta.uid() != uid && parent_meta.uid() != 0) {
        return Err("policy directory must not be group/world writable or foreign-owned".into());
    }
    // O_NOFOLLOW + fstat on the opened handle closes the check/use gap.
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(legion_effects::sandbox_runtime::o_nofollow())
        .open(&canonical)
        .map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err("policy file must be a regular file owned by this user with mode 0600".into());
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(&mut file, 1 << 20), &mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_trusted_policy(_path: &Path, _audited: &[PathBuf]) -> Result<Vec<u8>, String> {
    Err("host policy file permissions cannot be verified on this platform".into())
}

fn validate_gradle(
    entry: GradleEntry,
    tools: &[HostTool],
    outside: &dyn Fn(&Path) -> bool,
) -> Result<GradlePins, String> {
    let java = std::fs::canonicalize(&entry.java)
        .map_err(|e| format!("gradle java {}: {e}", entry.java.display()))?;
    if !entry.java.is_absolute() || java != entry.java || !java.is_file() || !outside(&java) {
        return Err("gradle java must be a canonical file outside audited roots".into());
    }
    let listed = tools.iter().any(|tool| {
        tool.executable == java
            && tool.class == InvocationClass::ProjectExecuting
            && tool
                .providers
                .contains(crate::native_providers::code::android::PROVIDER_ID)
    });
    if !listed {
        return Err(
            "gradle java must be a project-executing tool entry for code.android.lint".into(),
        );
    }
    let digests = |values: Vec<String>, what: &str| -> Result<BTreeSet<String>, String> {
        if values.is_empty() {
            return Err(format!("gradle {what} must list at least one digest"));
        }
        values
            .iter()
            .map(|value| normalize_digest(value))
            .collect::<Result<BTreeSet<_>, _>>()
    };
    let dependency_cache_root = match entry.dependency_cache_root {
        None => None,
        Some(root) => {
            let canonical = std::fs::canonicalize(&root)
                .map_err(|e| format!("gradle cache root {}: {e}", root.display()))?;
            if !root.is_absolute()
                || canonical != root
                || !canonical.is_dir()
                || !outside(&canonical)
            {
                return Err(
                    "gradle dependency cache root must be a canonical directory outside audited roots"
                        .into(),
                );
            }
            Some(canonical)
        }
    };
    Ok(GradlePins {
        java,
        wrapper_jar_sha256: digests(entry.wrapper_jar_sha256, "wrapperJarSha256")?,
        distribution_sha256: digests(entry.distribution_sha256, "distributionSha256")?,
        dependency_cache_root,
    })
}

/// `no-node-python` (the fail-closed default) hardens exec and sockets.
fn exec_hardening(config: &OwnerPolicyConfig) -> ExecHardening {
    ExecHardening {
        deny_interpreters: config.runtime_constraint() == RuntimeConstraint::NoNodePython,
    }
}

fn normalize_digest(value: &str) -> Result<String, String> {
    let hex = value.strip_prefix("sha256:").unwrap_or(value);
    if hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(format!("sha256:{hex}"))
    } else {
        Err("tool sha256 must be 64 lowercase hex digits".into())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_checksum_matches_cargo_lock() {
        let lock =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
                .unwrap();
        let block = lock
            .split("[[package]]")
            .find(|b| {
                b.contains("name = \"rightkit-sandbox\"") && b.contains("version = \"0.6.1\"")
            })
            .expect("rightkit-sandbox 0.6.1 is locked");
        assert!(block.contains(&format!("checksum = \"{SANDBOX_LOCK_CHECKSUM}\"")));
    }

    #[test]
    fn provenance_is_admissible_verified_form() {
        let owner = HostPolicyOwner {
            revision: "r".into(),
            tools: vec![],
            toolchain_roots: vec![],
            gradle: None,
            clock: system_now_ms,
        };
        match owner.identity().provenance {
            OwnerProvenance::Verified { key_id, .. } => assert_eq!(key_id.len(), 64),
            OwnerProvenance::Unverified(_) => panic!("must be verified"),
        }
    }
}
