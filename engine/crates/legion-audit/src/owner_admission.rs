//! Owner-backed external admission for native Audit.
//!
//! `OwnerBackedPolicy` is a `PolicyAuthorizer`: it validates a typed request
//! against host-frozen configuration, derives a canonical binding of everything
//! that determines what will run, and asks a `TrustedOwner` for a single-use
//! grant over exactly that binding. Nothing here can mint a grant: grants come
//! only from the owner object the root wires, and repository files, request
//! fields and environment values never reach the grant path.
//!
//! Admission is *policy*. It is deliberately separate from OS containment
//! (`legion_effects::owner_process`), executable integrity (the executor's
//! digest check) and attestation (signed run receipts). A pinned digest only
//! identifies an executable; it never grants admission.
//!
//! When no verified owner exists, `NativeAuthorizer::resolve` yields the
//! `OwnerAdmissionRequired` fallback: every external effect is denied before
//! resolution, version probe or spawn.
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_effects::{
    owner_process::{ContainmentProfile, InvocationClass},
    DigestState, ExecutableIdentity, ExternalToolRequest, PolicyAuthorizer, PolicyDecision,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::execution_policy::{
    self, OwnerAdmissionRequired, OWNER_POLICY_ID, OWNER_POLICY_VERSION,
};

/// Longest grant lifetime accepted, regardless of what an owner mints.
pub const MAX_GRANT_TTL_MS: u64 = 5 * 60 * 1000;

/// Environment names that can redirect code loading; never admissible.
fn forbidden_environment_name(name: &str) -> bool {
    name.starts_with("LD_")
        || name.starts_with("DYLD_")
        || matches!(
            name,
            "NODE_OPTIONS"
                | "BASH_ENV"
                | "ENV"
                | "PYTHONSTARTUP"
                | "PYTHONPATH"
                | "RUSTC_WRAPPER"
                | "RUSTC_WORKSPACE_WRAPPER"
                | "CARGO_BUILD_RUSTC_WRAPPER"
                | "GIT_SSH_COMMAND"
        )
}

/// How the owner proves it is the installed, signed owner. Only an owner
/// adapter that actually verified signed provenance may report `Verified`;
/// enrollment JSON alone can only produce `Unverified`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerProvenance {
    Verified {
        key_id: String,
        receipt_digest: String,
    },
    Unverified(String),
}

impl OwnerProvenance {
    fn is_verified(&self) -> bool {
        match self {
            Self::Verified {
                key_id,
                receipt_digest,
            } => lower_hex(key_id, 64) && !receipt_digest.trim().is_empty(),
            Self::Unverified(_) => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerIdentity {
    pub owner_id: String,
    pub version: String,
    pub provenance: OwnerProvenance,
}

/// Everything that determines what will run. Its digest is what the owner
/// grants over; any change to any field invalidates the grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionBinding {
    pub class: InvocationClass,
    pub request_id: String,
    pub provider_id: String,
    pub plan_id: String,
    pub task_id: Option<String>,
    pub policy_revision: String,
    pub owner_id: String,
    pub executable: PathBuf,
    pub executable_digest: String,
    pub args: Vec<String>,
    pub version_args: Vec<String>,
    pub skip_version_probe: bool,
    pub version_requirement: Option<String>,
    pub cwd: PathBuf,
    /// Effective environment: name -> sha256 of value (values never leave).
    pub environment: BTreeMap<String, String>,
    pub output_root: PathBuf,
    pub containment_id: String,
    pub timeout_ms: u64,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
}

impl AdmissionBinding {
    pub fn to_value(&self) -> Value {
        json!({
            "kind": "native-owner-admission-binding",
            "class": self.class.as_str(),
            "requestId": self.request_id, "providerId": self.provider_id,
            "planId": self.plan_id, "taskId": self.task_id,
            "policyRevision": self.policy_revision, "ownerId": self.owner_id,
            "executable": self.executable, "executableDigest": self.executable_digest,
            "args": self.args, "versionArgs": self.version_args,
            "skipVersionProbe": self.skip_version_probe,
            "versionRequirement": self.version_requirement,
            "cwd": self.cwd, "environment": self.environment,
            "outputRoot": self.output_root, "containmentId": self.containment_id,
            "timeoutMs": self.timeout_ms,
            "stdoutLimit": self.stdout_limit, "stderrLimit": self.stderr_limit,
        })
    }
    pub fn digest(&self) -> String {
        crate::digest(&self.to_value()).expect("admission binding is serializable")
    }
}

pub struct OwnerQuery<'a> {
    pub binding: &'a AdmissionBinding,
    pub binding_digest: &'a str,
}

/// Single-use authorization over one binding digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerGrant {
    pub owner_id: String,
    pub binding_digest: String,
    pub policy_revision: String,
    pub nonce: String,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerVerdict {
    Granted(OwnerGrant),
    Denied(String),
    Unavailable(String),
}

/// Implemented by the adapter for the real owner (Guard/RustRight/rightkit).
/// Must be authoritative: it, not repository content, decides.
pub trait TrustedOwner: Send + Sync {
    fn identity(&self) -> OwnerIdentity;
    fn admit(&self, query: &OwnerQuery<'_>) -> OwnerVerdict;
}

/// Host-frozen admission configuration. Never derived from the audited tree.
#[derive(Clone, Debug)]
pub struct OwnerPolicyConfig {
    policy_revision: String,
    plan_id: String,
    containment_id: String,
    frozen_roots: Vec<PathBuf>,
    output_root: PathBuf,
    classes: BTreeMap<String, InvocationClass>,
    environment_names: BTreeSet<String>,
    max_timeout_ms: u64,
    max_output_bytes: usize,
}

impl OwnerPolicyConfig {
    /// `classes` maps provider id -> class; unlisted providers are denied.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_revision: impl Into<String>,
        plan_id: impl Into<String>,
        containment_id: impl Into<String>,
        frozen_roots: &[PathBuf],
        output_root: &Path,
        classes: BTreeMap<String, InvocationClass>,
        environment_names: BTreeSet<String>,
        max_timeout_ms: u64,
        max_output_bytes: usize,
    ) -> Result<Self, String> {
        let (policy_revision, plan_id, containment_id) = (
            policy_revision.into(),
            plan_id.into(),
            containment_id.into(),
        );
        if [&policy_revision, &plan_id, &containment_id]
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err("policy revision, plan id and containment id are required".into());
        }
        if frozen_roots.is_empty() || max_timeout_ms == 0 || max_output_bytes == 0 {
            return Err("frozen roots and positive limits are required".into());
        }
        if let Some(name) = environment_names.iter().find(|name| {
            name.is_empty() || name.contains(['=', '\0']) || forbidden_environment_name(name)
        }) {
            return Err(format!("environment name {name:?} is not admissible"));
        }
        let canon = |path: &Path| {
            std::fs::canonicalize(path).map_err(|error| format!("{}: {error}", path.display()))
        };
        let frozen_roots = frozen_roots
            .iter()
            .map(|root| canon(root))
            .collect::<Result<Vec<_>, _>>()?;
        let output_root = canon(output_root)?;
        if frozen_roots
            .iter()
            .any(|root| output_root.starts_with(root) || root.starts_with(&output_root))
        {
            return Err("output root must be disjoint from frozen input roots".into());
        }
        Ok(Self {
            policy_revision,
            plan_id,
            containment_id,
            frozen_roots,
            output_root,
            classes,
            environment_names,
            max_timeout_ms,
            max_output_bytes,
        })
    }

    pub fn output_root(&self) -> &Path {
        &self.output_root
    }
    pub fn containment_id(&self) -> &str {
        &self.containment_id
    }

    /// Containment contract the owner's `ContainedRuntime` must be built with
    /// for one class and executable set (root wires this into `OwnerProcess`).
    pub fn containment_profile(
        &self,
        owner_id: &str,
        class: InvocationClass,
        allowed_executables: BTreeSet<PathBuf>,
    ) -> ContainmentProfile {
        ContainmentProfile {
            owner_id: owner_id.into(),
            containment_id: self.containment_id.clone(),
            class,
            read_only_roots: self.frozen_roots.clone(),
            scratch_root: self.output_root.clone(),
            allowed_executables,
            environment_names: self.environment_names.clone(),
            max_timeout_ms: self.max_timeout_ms,
            max_stdout: self.max_output_bytes,
            max_stderr: self.max_output_bytes,
        }
    }
}

/// Owner-backed authorizer. Construct with `OwnerBackedPolicy::new`; prefer
/// `NativeAuthorizer::resolve`, which falls back to denial.
pub struct OwnerBackedPolicy {
    owner: Arc<dyn TrustedOwner>,
    frozen_identity: OwnerIdentity,
    config: OwnerPolicyConfig,
    policy_digest: String,
    seen_nonces: Mutex<HashSet<String>>,
    clock: fn() -> u64,
}

fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

impl OwnerBackedPolicy {
    /// Refuses (Err = reason) unless the owner reports verified signed provenance.
    pub fn new(owner: Arc<dyn TrustedOwner>, config: OwnerPolicyConfig) -> Result<Self, String> {
        let frozen_identity = owner.identity();
        if frozen_identity.owner_id.trim().is_empty() {
            return Err("owner identity is empty".into());
        }
        if let OwnerProvenance::Unverified(reason) = &frozen_identity.provenance {
            return Err(format!("owner provenance unverified: {reason}"));
        }
        if !frozen_identity.provenance.is_verified() {
            return Err("owner provenance malformed".into());
        }
        let policy_digest = crate::digest(&descriptor(&frozen_identity, &config))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            owner,
            frozen_identity,
            config,
            policy_digest,
            seen_nonces: Mutex::new(HashSet::new()),
            clock: system_now_ms,
        })
    }

    #[doc(hidden)]
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    pub fn owner_id(&self) -> &str {
        &self.frozen_identity.owner_id
    }
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
    pub fn config(&self) -> &OwnerPolicyConfig {
        &self.config
    }
    /// Frozen-policy meaning for plan/report binding.
    pub fn binding(&self) -> Value {
        execution_policy::owner_binding(&descriptor(&self.frozen_identity, &self.config))
    }

    fn decision(&self, allowed: bool, reason: String) -> PolicyDecision {
        PolicyDecision {
            allowed,
            policy_id: OWNER_POLICY_ID.into(),
            policy_version: OWNER_POLICY_VERSION,
            policy_digest: self.policy_digest.clone(),
            reason: Some(reason),
        }
    }

    fn evaluate(&self, request: &ExternalToolRequest) -> Result<String, String> {
        let cfg = &self.config;
        // 1. Frozen identity of policy, plan and owner.
        if request.policy_id != OWNER_POLICY_ID {
            return Err("policy-id-mismatch".into());
        }
        if request.plan_id != cfg.plan_id {
            return Err("plan-mismatch".into());
        }
        if self.owner.identity() != self.frozen_identity {
            return Err("owner-identity-changed".into());
        }
        let class = *cfg
            .classes
            .get(&request.provider_id)
            .ok_or("invocation-unclassified")?;
        if request.shell {
            return Err("shell-forbidden".into());
        }
        if !safe_request_id(&request.request_id) {
            return Err("request-id-unsafe".into());
        }
        // 2. Containment is mandatory for every class (version probe included).
        let sandbox_ok = request.requires_network_sandbox
            && request
                .sandbox
                .as_ref()
                .is_some_and(|receipt| receipt.id == cfg.containment_id && receipt.network);
        if !sandbox_ok {
            return Err("containment-receipt-mismatch".into());
        }
        // 3. Limits.
        if request.timeout_ms == 0
            || request.timeout_ms > cfg.max_timeout_ms
            || request.stdout_limit == 0
            || request.stdout_limit > cfg.max_output_bytes
            || request.stderr_limit == 0
            || request.stderr_limit > cfg.max_output_bytes
        {
            return Err("limits-exceed-policy".into());
        }
        // 4. Executable identity: pinned, canonical, not repo/scratch-controlled.
        let pin = request
            .expected_digest
            .as_deref()
            .filter(|digest| {
                digest
                    .strip_prefix("sha256:")
                    .is_some_and(|hex| lower_hex(hex, 64))
            })
            .ok_or("executable-digest-pin-required")?;
        let requested = Path::new(&request.executable);
        if !requested.is_absolute() {
            return Err("executable-not-absolute".into());
        }
        let identity = ExecutableIdentity::resolve(&request.executable, Some(pin))
            .map_err(|_| "executable-identity-unverified".to_string())?;
        let executable = identity
            .canonical_path
            .clone()
            .filter(|path| path == requested)
            .ok_or("executable-not-canonical")?;
        if identity.digest_state != DigestState::Sealed {
            return Err("executable-identity-unverified".into());
        }
        if executable.starts_with(&cfg.output_root)
            || (class != InvocationClass::ProjectExecuting
                && cfg
                    .frozen_roots
                    .iter()
                    .any(|root| executable.starts_with(root)))
        {
            return Err("executable-inside-controlled-root".into());
        }
        // 5. cwd canonical and inside a frozen root or the output root.
        let cwd = std::fs::canonicalize(&request.cwd).map_err(|_| "cwd-unresolved")?;
        if cwd != Path::new(&request.cwd) {
            return Err("cwd-not-canonical".into());
        }
        let allowed_roots = || {
            cfg.frozen_roots
                .iter()
                .chain(std::iter::once(&cfg.output_root))
        };
        if !allowed_roots().any(|root| cwd.starts_with(root)) {
            return Err("cwd-outside-admitted-roots".into());
        }
        // 6. Arguments may not name paths outside admitted roots.
        for arg in request.args.iter().chain(request.version_args.iter()) {
            if arg.contains('\0') {
                return Err("argument-nul".into());
            }
            let candidate = match arg.strip_prefix('-').and(arg.split_once('=')) {
                Some((_, value)) => value,
                None => arg.as_str(),
            };
            let path = Path::new(candidate);
            let escapes = path
                .components()
                .any(|part| matches!(part, Component::ParentDir));
            // `has_root` also catches Windows drive-relative roots such as
            // `/etc/passwd`, which `is_absolute` reports as relative there.
            if path.is_absolute() || path.has_root() || escapes {
                let joined = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    cwd.join(path)
                };
                let resolved =
                    resolve_allowing_missing(&joined).ok_or("argument-path-unresolved")?;
                if !allowed_roots().any(|root| resolved.starts_with(root)) {
                    return Err("argument-path-outside-admitted-roots".into());
                }
            }
        }
        // 7. Environment: names admitted by host policy only.
        if request
            .environment_allowlist
            .iter()
            .any(|name| !cfg.environment_names.contains(name))
            || request
                .environment
                .keys()
                .any(|name| !cfg.environment_names.contains(name))
        {
            return Err("environment-name-not-admitted".into());
        }
        let environment = request
            .environment
            .iter()
            .filter(|(name, _)| request.environment_allowlist.contains(*name))
            .map(|(name, value)| (name.clone(), sha256_hex(value.as_bytes())))
            .collect::<BTreeMap<_, _>>();
        // 8. Bind, ask the owner, verify the grant.
        let binding = AdmissionBinding {
            class,
            request_id: request.request_id.clone(),
            provider_id: request.provider_id.clone(),
            plan_id: request.plan_id.clone(),
            task_id: request.task_id.clone(),
            policy_revision: cfg.policy_revision.clone(),
            owner_id: self.frozen_identity.owner_id.clone(),
            executable,
            executable_digest: pin.into(),
            args: request.args.clone(),
            version_args: request.version_args.clone(),
            skip_version_probe: request.skip_version_probe,
            version_requirement: request.version_requirement.clone(),
            cwd,
            environment,
            output_root: cfg.output_root.clone(),
            containment_id: cfg.containment_id.clone(),
            timeout_ms: request.timeout_ms,
            stdout_limit: request.stdout_limit,
            stderr_limit: request.stderr_limit,
        };
        let binding_digest = binding.digest();
        let verdict = self.owner.admit(&OwnerQuery {
            binding: &binding,
            binding_digest: &binding_digest,
        });
        let grant = match verdict {
            OwnerVerdict::Granted(grant) => grant,
            OwnerVerdict::Denied(_) => return Err("owner-denied".into()),
            OwnerVerdict::Unavailable(_) => return Err("owner-unavailable".into()),
        };
        if grant.owner_id != self.frozen_identity.owner_id {
            return Err("grant-owner-mismatch".into());
        }
        if grant.binding_digest != binding_digest {
            return Err("grant-binding-mismatch".into());
        }
        if grant.policy_revision != cfg.policy_revision {
            return Err("grant-policy-stale".into());
        }
        let now = (self.clock)();
        if grant.expires_at_ms <= now || grant.expires_at_ms - now > MAX_GRANT_TTL_MS {
            return Err("grant-expired-or-unbounded".into());
        }
        if grant.nonce.trim().is_empty() {
            return Err("grant-nonce-missing".into());
        }
        let mut seen = self
            .seen_nonces
            .lock()
            .map_err(|_| "grant-ledger-poisoned")?;
        if !seen.insert(grant.nonce) {
            return Err("grant-replayed".into());
        }
        Ok(binding_digest)
    }
}

impl PolicyAuthorizer for OwnerBackedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        match self.evaluate(request) {
            Ok(binding_digest) => self.decision(
                true,
                format!(
                    "owner-admitted:{}:{binding_digest}",
                    self.frozen_identity.owner_id
                ),
            ),
            Err(code) => self.decision(false, format!("owner-admission-denied:{code}")),
        }
    }
}

/// Root-facing selector: owner-backed when a verified owner exists, else the
/// unconditional-denial fallback. A missing owner is never treated as admitted.
pub enum NativeAuthorizer {
    Owner(Box<OwnerBackedPolicy>),
    Required {
        fallback: OwnerAdmissionRequired,
        reason: String,
    },
}

impl NativeAuthorizer {
    pub fn resolve(
        owner: Option<Arc<dyn TrustedOwner>>,
        config: Option<OwnerPolicyConfig>,
    ) -> Self {
        let required = |reason: String| Self::Required {
            fallback: OwnerAdmissionRequired,
            reason,
        };
        match (owner, config) {
            (Some(owner), Some(config)) => match OwnerBackedPolicy::new(owner, config) {
                Ok(policy) => Self::Owner(Box::new(policy)),
                Err(reason) => required(reason),
            },
            (None, _) => required("no trusted owner available".into()),
            (_, None) => required("no owner policy configuration".into()),
        }
    }
    pub fn is_owner_backed(&self) -> bool {
        matches!(self, Self::Owner(_))
    }
    pub fn unavailable_reason(&self) -> Option<&str> {
        match self {
            Self::Required { reason, .. } => Some(reason),
            Self::Owner(_) => None,
        }
    }
    /// Frozen policy binding to record in the plan/report for this authorizer.
    pub fn binding(&self) -> Value {
        match self {
            Self::Owner(policy) => policy.binding(),
            Self::Required { .. } => execution_policy::binding(),
        }
    }
}

impl PolicyAuthorizer for NativeAuthorizer {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        match self {
            Self::Owner(policy) => policy.authorize(request),
            Self::Required { fallback, .. } => fallback.authorize(request),
        }
    }
}

fn descriptor(identity: &OwnerIdentity, config: &OwnerPolicyConfig) -> Value {
    let provenance = match &identity.provenance {
        OwnerProvenance::Verified {
            key_id,
            receipt_digest,
        } => {
            json!({"verified": true, "keyId": key_id, "receiptDigest": receipt_digest})
        }
        OwnerProvenance::Unverified(reason) => json!({"verified": false, "reason": reason}),
    };
    json!({
        "ownerId": identity.owner_id, "ownerVersion": identity.version,
        "provenance": provenance,
        "policyRevision": config.policy_revision, "planId": config.plan_id,
        "containmentId": config.containment_id,
        "frozenRoots": config.frozen_roots, "outputRoot": config.output_root,
        "classes": config.classes.iter().map(|(k, v)| (k.clone(), v.as_str())).collect::<BTreeMap<_, _>>(),
        "environmentNames": config.environment_names,
        "maxTimeoutMs": config.max_timeout_ms, "maxOutputBytes": config.max_output_bytes,
    })
}

fn safe_request_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with(['/', '\\'])
        && !id.contains(['\0', '\\'])
        && !id
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

/// Canonicalize the deepest existing ancestor and append the remaining
/// components; rejects `..` in the missing tail and dangling symlinks.
fn resolve_allowing_missing(path: &Path) -> Option<PathBuf> {
    let mut existing = path.to_path_buf();
    let mut tail = Vec::new();
    while std::fs::symlink_metadata(&existing).is_err() {
        let name = existing.file_name()?.to_os_string();
        if name == ".." || name == "." {
            return None;
        }
        tail.push(name);
        existing = existing.parent()?.to_path_buf();
    }
    let mut resolved = std::fs::canonicalize(&existing).ok()?;
    for name in tail.into_iter().rev() {
        resolved.push(name);
    }
    Some(resolved)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
