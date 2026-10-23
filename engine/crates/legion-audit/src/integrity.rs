use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{error::AuditError, plan::AuditPlan};

type HmacSha256 = Hmac<Sha256>;

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, AuditError> {
    legion_contracts::canonical_json_bytes(value)
        .map_err(|error| AuditError::Invalid(error.to_string()))
}

pub fn digest<T: Serialize>(value: &T) -> Result<String, AuditError> {
    Ok(format!(
        "sha256:{}",
        hex_bytes(&Sha256::digest(canonical_bytes(value)?))
    ))
}

pub fn plan_digest(plan: &AuditPlan) -> Result<String, AuditError> {
    digest(plan)
}

pub fn sign(plan: &AuditPlan, key: &[u8]) -> Result<String, AuditError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| AuditError::Invalid("empty HMAC key".into()))?;
    mac.update(&canonical_bytes(plan)?);
    Ok(format!(
        "hmac-sha256:{}",
        hex_bytes(&mac.finalize().into_bytes())
    ))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn verify(
    plan: &AuditPlan,
    expected_digest: &str,
    signature: Option<&str>,
    key: Option<&[u8]>,
) -> Result<(), AuditError> {
    plan.validate_execution_policy()?;
    if plan_digest(plan)? != expected_digest {
        return Err(AuditError::SourceDrift("audit plan digest mismatch".into()));
    }
    match (signature, key) {
        (Some(value), Some(secret)) if sign(plan, secret)? == value => Ok(()),
        (None, None) => Ok(()),
        _ => Err(AuditError::Invalid(
            "audit plan HMAC verification failed".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Plan-signing key custody
//
// The per-run plan HMAC key never lives in the run (report) tree. It is kept
// in the per-user host state directory, keyed by run id + plan digest, mode
// 0600. The run records only the run id and a key id (a domain-separated
// digest of the key). A tampered run directory therefore cannot re-sign its
// plan: the key is simply not there to read.
// ---------------------------------------------------------------------------

/// Directory name, beneath the per-user state directory, holding plan keys.
pub const PLAN_KEY_DIR: &str = "audit-plan-keys";
/// Environment override for explicit host-injected plan keys.
pub const PLAN_KEY_ENV: &str = "AUDIT_PLAN_SIGNING_KEY";
const PLAN_KEY_DOMAIN: &[u8] = b"legion-audit-plan-key-v1\0";
const LEGACY_EPOCH_KEY_FILE: &str = "epoch.key";

/// Where a run's plan key was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanKeySource {
    /// Explicit `AUDIT_PLAN_SIGNING_KEY`.
    Environment,
    /// Per-user host state directory (the only custody new runs use).
    HostState,
    /// Legacy `<run>/epoch.key`: readable, but weak custody (key sits beside
    /// the data it signs).
    LegacyRunDirEpoch,
}

/// Result of resolving the plan-signing key for a persisted run.
#[derive(Debug, Clone)]
pub enum PlanKeyResolution {
    Found {
        key: Vec<u8>,
        source: PlanKeySource,
    },
    /// No key is available: the plan signature cannot be verified.
    Unverifiable {
        reason: String,
    },
}

/// Identifier recorded in the run for a plan key; reveals nothing usable.
pub fn plan_key_id(key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_KEY_DOMAIN);
    hasher.update(key);
    format!("sha256:{}", hex_bytes(&hasher.finalize()))
}

/// A fresh opaque run id (random, no host or time information).
pub fn new_run_id() -> Result<String, AuditError> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|error| AuditError::Invalid(format!("could not generate run id: {error}")))?;
    Ok(format!("run-{}", hex_bytes(&nonce)))
}

/// A fresh 32-byte plan-signing key.
pub fn new_plan_key() -> Result<Vec<u8>, AuditError> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key)
        .map_err(|error| AuditError::Invalid(format!("could not generate plan key: {error}")))?;
    Ok(key.to_vec())
}

/// Per-user host directory that holds plan keys.
pub fn host_plan_key_dir() -> Result<std::path::PathBuf, AuditError> {
    use std::path::PathBuf;
    let state = match std::env::var_os(legion_contracts::state_root::STATE_ROOT_ENV)
        .filter(|value| !value.is_empty())
    {
        Some(root) => PathBuf::from(root),
        None => {
            let receipts = legion_contracts::state_root::user_state_receipts_root(
                cfg!(target_os = "macos"),
                cfg!(windows),
                std::env::var_os("HOME").map(PathBuf::from),
                std::env::var_os("USERPROFILE").map(PathBuf::from),
                std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
                std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
            )
            .ok_or_else(|| AuditError::Invalid("Legion user state root unavailable".into()))?;
            receipts
                .parent()
                .ok_or_else(|| AuditError::Invalid("Legion user state root unavailable".into()))?
                .to_path_buf()
        }
    };
    if !state.is_absolute()
        || state
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(AuditError::Invalid(
            "Legion state root must be absolute without parent traversal".into(),
        ));
    }
    Ok(state.join(PLAN_KEY_DIR))
}

fn plan_key_path(
    directory: &std::path::Path,
    run_id: &str,
    plan_digest: &str,
) -> Result<std::path::PathBuf, AuditError> {
    let plain = |value: &str| {
        !value.is_empty()
            && value.len() <= 96
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    };
    let digest = plan_digest
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| AuditError::Invalid("plan digest is not canonical sha256".into()))?;
    if !plain(run_id) {
        return Err(AuditError::Invalid("run id is not a plain token".into()));
    }
    Ok(directory.join(format!("{run_id}.{digest}.key")))
}

/// Persists the run's plan key in host state (0600, create-new) and returns
/// its key id. Refuses a host directory that resolves inside `run_dir`.
pub fn store_host_plan_key(
    run_dir: &std::path::Path,
    run_id: &str,
    plan_digest: &str,
    key: &[u8],
) -> Result<String, AuditError> {
    use std::io::Write;
    let directory = host_plan_key_dir()?;
    let path = plan_key_path(&directory, run_id, plan_digest)?;
    std::fs::create_dir_all(&directory)
        .map_err(|error| AuditError::Invalid(format!("could not create plan key dir: {error}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700));
    }
    if let (Ok(resolved), Ok(run)) = (directory.canonicalize(), run_dir.canonicalize()) {
        if resolved.starts_with(&run) {
            return Err(AuditError::Invalid(
                "plan key custody must be outside the run directory".into(),
            ));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| AuditError::Invalid(format!("could not store plan key: {error}")))?;
    file.write_all(hex_bytes(key).as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| AuditError::Invalid(format!("could not write plan key: {error}")))?;
    Ok(plan_key_id(key))
}

fn read_private_key(path: &std::path::Path) -> Result<Vec<u8>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|error| error.to_string())?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err("plan key is readable by group or others; refusing to use it".into());
        }
    }
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let key = hex::decode(text.trim()).map_err(|_| "plan key is not hex".to_owned())?;
    if key.len() < 16 {
        return Err("plan key is malformed or too short".into());
    }
    Ok(key)
}

/// Resolves the plan-signing key for the persisted run `run_dir` whose
/// `plan.json` content is `plan`. Order: explicit environment key, host-state
/// key bound to the run (checked against the recorded key id), legacy
/// `<run>/epoch.key` only for runs that predate host custody. A run that
/// declares host custody never falls back to a run-dir key.
pub fn resolve_plan_key(run_dir: &std::path::Path, plan: &serde_json::Value) -> PlanKeyResolution {
    if let Some(value) = std::env::var_os(PLAN_KEY_ENV).filter(|value| !value.is_empty()) {
        return PlanKeyResolution::Found {
            key: value.to_string_lossy().as_bytes().to_vec(),
            source: PlanKeySource::Environment,
        };
    }
    let unverifiable = |reason: String| PlanKeyResolution::Unverifiable { reason };
    if let Some(binding) = plan.get("planKey").filter(|value| !value.is_null()) {
        let run_id = binding.get("runId").and_then(|v| v.as_str());
        let key_id = binding.get("keyId").and_then(|v| v.as_str());
        let digest = plan.pointer("/seal/digest").and_then(|v| v.as_str());
        let (Some(run_id), Some(key_id), Some(digest)) = (run_id, key_id, digest) else {
            return unverifiable("plan.planKey is malformed".into());
        };
        let directory = match host_plan_key_dir() {
            Ok(directory) => directory,
            Err(error) => return unverifiable(error.to_string()),
        };
        let path = match plan_key_path(&directory, run_id, digest) {
            Ok(path) => path,
            Err(error) => return unverifiable(error.to_string()),
        };
        return match read_private_key(&path) {
            Ok(key) if plan_key_id(&key) == key_id => PlanKeyResolution::Found {
                key,
                source: PlanKeySource::HostState,
            },
            Ok(_) => unverifiable("host plan key does not match the recorded key id".into()),
            Err(error) => unverifiable(format!(
                "host plan key for {run_id} is unavailable ({error}) and {PLAN_KEY_ENV} is not set"
            )),
        };
    }
    // Plans signed with the lens epoch key (no planKey): the epoch key lives
    // in host custody, found through the plan's epoch digest or epoch.ref and
    // verified against that digest. It is consulted BEFORE, and is never
    // overridden by, a run-dir `epoch.key`.
    match crate::native_providers::reasoning::ingest::host_epoch_key_for_plan(run_dir, plan) {
        Some(Ok(key)) => {
            return PlanKeyResolution::Found {
                key,
                source: PlanKeySource::HostState,
            }
        }
        Some(Err(error)) => return unverifiable(format!("host epoch key is unusable: {error}")),
        None => {}
    }
    let legacy = run_dir.join(LEGACY_EPOCH_KEY_FILE);
    if legacy.is_file() {
        return match read_private_key(&legacy) {
            Ok(key) => PlanKeyResolution::Found {
                key,
                source: PlanKeySource::LegacyRunDirEpoch,
            },
            Err(error) => unverifiable(format!("legacy epoch key is unusable: {error}")),
        };
    }
    unverifiable(format!(
        "no plan signing key: the run records no host key binding, has no {LEGACY_EPOCH_KEY_FILE}, and {PLAN_KEY_ENV} is not set"
    ))
}

/// Drop-in replacement for `load_epoch(run_dir)?.0` where the key verifies a
/// plan seal: reads `<run>/plan.json` and resolves under host custody.
pub fn plan_signing_key_for_run(run_dir: &std::path::Path) -> Result<Vec<u8>, AuditError> {
    let bytes = std::fs::read(run_dir.join("plan.json"))
        .map_err(|error| AuditError::Invalid(format!("cannot read plan.json: {error}")))?;
    let plan: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| AuditError::Invalid(format!("plan.json is invalid: {error}")))?;
    match resolve_plan_key(run_dir, &plan) {
        PlanKeyResolution::Found { key, .. } => Ok(key),
        PlanKeyResolution::Unverifiable { reason } => Err(AuditError::Invalid(format!(
            "unverifiable-signature: {reason}"
        ))),
    }
}
