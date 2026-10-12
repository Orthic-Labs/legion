//! Pinned enrollment for RustRight attested test runs.
//!
//! This module deliberately contains no signature implementation. The pinned
//! RustRight client performs request canonicalization and offline receipt
//! verification; Legion supplies every expected value independently.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::Digest;

const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestedRunsEnrollment {
    pub(crate) schema_version: u32,
    pub(crate) host: String,
    pub(crate) key_id: String,
    pub(crate) public_key: String,
    pub(crate) broker_digest: String,
    pub(crate) client_executable: PathBuf,
    pub(crate) client_digest: String,
    pub(crate) adapters: BTreeMap<String, AdapterEnrollment>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterEnrollment {
    pub(crate) broker_adapter_id: String,
    #[serde(default)]
    pub(crate) qualified_version: Option<String>,
}

#[derive(Debug)]
pub enum EnrollmentError {
    Io(std::io::Error),
    Invalid(String),
}

impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "cannot read attested-runs enrollment: {error}"),
            Self::Invalid(message) => {
                write!(formatter, "invalid attested-runs enrollment: {message}")
            }
        }
    }
}

impl std::error::Error for EnrollmentError {}

impl AttestedRunsEnrollment {
    /// Read an explicit host enrollment. Callers must separately enforce that
    /// the path is absolute and outside both audited and scratch roots.
    pub fn load(path: &Path) -> Result<Self, EnrollmentError> {
        let metadata = fs::symlink_metadata(path).map_err(EnrollmentError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(EnrollmentError::Invalid(
                "enrollment must be a regular file".into(),
            ));
        }
        if metadata.len() > 1024 * 1024 {
            return Err(EnrollmentError::Invalid("enrollment exceeds 1 MiB".into()));
        }
        let bytes = fs::read(path).map_err(EnrollmentError::Io)?;
        if bytes.len() > 1024 * 1024 {
            return Err(EnrollmentError::Invalid("enrollment exceeds 1 MiB".into()));
        }
        let enrollment: Self = serde_json::from_slice(&bytes)
            .map_err(|error| EnrollmentError::Invalid(error.to_string()))?;
        enrollment.validate()?;
        Ok(enrollment)
    }

    pub fn validate(&self) -> Result<(), EnrollmentError> {
        let invalid = |reason: &str| EnrollmentError::Invalid(reason.into());
        if self.schema_version != SCHEMA_VERSION {
            return Err(invalid("unsupported schemaVersion"));
        }
        if self.host.trim().is_empty() || self.host.contains('\0') {
            return Err(invalid("host is empty or malformed"));
        }
        if !lower_hex(&self.key_id, 64)
            || !lower_hex(&self.broker_digest, 64)
            || !lower_hex(&self.client_digest, 64)
        {
            return Err(invalid(
                "keyId and digests must be 64 lowercase hex characters",
            ));
        }
        if !self.public_key.starts_with("04") || !lower_hex(&self.public_key, 130) {
            return Err(invalid("publicKey must be an uncompressed SEC1 P-256 key"));
        }
        let public_key =
            hex::decode(&self.public_key).map_err(|_| invalid("publicKey is malformed hex"))?;
        let actual_key_id = hex::encode(sha2::Sha256::digest(public_key));
        if self.key_id != actual_key_id {
            return Err(invalid("keyId does not match publicKey"));
        }
        if !self.client_executable.is_absolute() {
            return Err(invalid("clientExecutable must be absolute"));
        }
        if self.adapters.keys().any(|name| !runner_name(name))
            || self.adapters.values().any(|adapter| {
                adapter.broker_adapter_id.trim().is_empty()
                    || adapter.broker_adapter_id.contains('\0')
                    || adapter
                        .qualified_version
                        .as_deref()
                        .is_some_and(|version| version.trim().is_empty() || version.contains('\0'))
            })
        {
            return Err(invalid("adapter registry contains an invalid entry"));
        }
        Ok(())
    }

    pub fn adapter(&self, runner: &str) -> Option<&AdapterEnrollment> {
        self.adapters.get(runner)
    }
}

pub(crate) fn fresh_nonce() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| format!("os-random-unavailable: {error}"))?;
    Ok(hex::encode(bytes))
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn runner_name(value: &str) -> bool {
    matches!(
        value,
        "npm"
            | "pnpm"
            | "yarn"
            | "bun"
            | "pytest"
            | "swift"
            | "mvn"
            | "gradle"
            | "dotnet"
            | "go"
            | "bundle"
            | "flutter"
            | "dart"
            | "mix"
    )
}
