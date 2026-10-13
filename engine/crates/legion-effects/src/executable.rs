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
    /// True only when the caller opted out of the probe because the
    /// executable is pinned by digest. `qualified` stays false: no version
    /// was observed.
    pub skipped_by_policy: bool,
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
                skipped_by_policy: false,
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
                self.version.output.as_deref().is_some_and(|output| {
                    if let Some(exact) = required.strip_prefix("exact:") {
                        let versions = output
                            .split(|character: char| {
                                !(character.is_ascii_alphanumeric()
                                    || matches!(character, '.' | '-' | '+' | '_'))
                            })
                            .filter(|token| {
                                let version = token.strip_prefix('v').unwrap_or(token);
                                version.contains('.')
                                    && version.as_bytes().first().is_some_and(u8::is_ascii_digit)
                            })
                            .collect::<Vec<_>>();
                        !exact.is_empty()
                            && versions.len() == 1
                            && (versions[0] == exact
                                || versions[0].strip_prefix('v') == Some(exact))
                    } else {
                        output.contains(required)
                    }
                })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(output: &str) -> ExecutableIdentity {
        ExecutableIdentity {
            requested_path: "/test/runner".into(),
            canonical_path: Some(PathBuf::from("/test/runner")),
            digest: Some("sha256:test".into()),
            digest_state: DigestState::Sealed,
            signature: SignatureState::Unknown,
            version: VersionProbeEvidence {
                args: vec!["--version".into()],
                output: Some(output.into()),
                exit_code: Some(0),
                qualified: true,
                skipped_by_policy: false,
            },
        }
    }

    #[test]
    fn exact_version_mode_is_opt_in_and_rejects_substrings() {
        assert!(identity("pnpm v9.1.0").version_qualified(Some("exact:9.1.0")));
        assert!(!identity("pnpm 19.1.0").version_qualified(Some("exact:9.1.0")));
        assert!(!identity("pnpm 9.1.0-rc.1").version_qualified(Some("exact:9.1.0")));
        assert!(!identity("pnpm 19.1.0, expected 9.1.0").version_qualified(Some("exact:9.1.0")));
        assert!(!identity("pnpm 19.1.0").version_qualified(Some("exact:")));
        assert!(identity("pnpm 19.1.0").version_qualified(Some("9.1.0")));
    }
}
