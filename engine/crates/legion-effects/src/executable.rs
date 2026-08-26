use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::EffectError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestState {
    Unchecked,
    Sealed,
    Mismatch,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureState {
    Unknown,
    Valid,
    Invalid,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionProbeEvidence {
    pub args: Vec<String>,
    pub output: Option<String>,
    pub exit_code: Option<i32>,
    pub qualified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableIdentity {
    pub requested_path: String,
    pub canonical_path: Option<PathBuf>,
    pub digest: Option<String>,
    pub digest_state: DigestState,
    pub signature: SignatureState,
    pub version: VersionProbeEvidence,
}

impl ExecutableIdentity {
    pub fn resolve(path: &str, expected_digest: Option<&str>) -> Result<Self, EffectError> {
        if !Path::new(path).is_absolute() {
            return Err(EffectError::UnsealedExecutable(path.into()));
        }
        let canonical = fs::canonicalize(path)
            .map_err(|error| EffectError::MissingExecutable(error.to_string()))?;
        let bytes = fs::read(&canonical)
            .map_err(|error| EffectError::MissingExecutable(error.to_string()))?;
        let digest = format!("sha256:{}", hex_digest(&bytes));
        let state = match expected_digest {
            Some(expected) if expected != digest => DigestState::Mismatch,
            Some(_) => DigestState::Sealed,
            None => DigestState::Unchecked,
        };
        if state == DigestState::Mismatch {
            return Err(EffectError::UnsealedExecutable(
                "executable digest mismatch".into(),
            ));
        }
        Ok(Self {
            requested_path: path.into(),
            canonical_path: Some(canonical),
            digest: Some(digest),
            digest_state: state,
            signature: SignatureState::Unknown,
            version: VersionProbeEvidence {
                args: Vec::new(),
                output: None,
                exit_code: None,
                qualified: false,
            },
        })
    }

    pub fn with_version_probe(mut self, probe: VersionProbeEvidence) -> Self {
        self.version = probe;
        self
    }
    pub fn sealed(&self) -> bool {
        self.digest.is_some() && matches!(self.digest_state, DigestState::Sealed)
    }

    pub fn version_qualified(&self, requirement: Option<&str>) -> bool {
        self.version.qualified
            && requirement.is_none_or(|required| {
                self.version
                    .output
                    .as_deref()
                    .is_some_and(|output| output.contains(required))
            })
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0xf) as usize] as char);
    }
    output
}
