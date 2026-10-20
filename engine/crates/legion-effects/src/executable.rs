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
                    } else if let Some(tool_version) = required.strip_prefix("exact-tool:") {
                        tool_version
                            .strip_prefix("osv-scanner:")
                            .is_some_and(|exact| osv_scanner_version_matches(output, exact))
                    } else {
                        output.contains(required)
                    }
                })
            })
    }
}

// OSV's primary version is distinct from its embedded SCALIBR version. Keep
// this opt-in grammar closed: every line must match the known ordered banner.
fn osv_scanner_version_matches(output: &str, exact: &str) -> bool {
    if !stable_version(exact) {
        return false;
    }
    let mut lines = output.lines();
    let primary = lines
        .next()
        .and_then(|line| line.strip_prefix("osv-scanner version: "));
    let scalibr = lines
        .next()
        .and_then(|line| line.strip_prefix("osv-scalibr version: "));
    let commit = lines.next().and_then(|line| line.strip_prefix("commit: "));
    let built = lines
        .next()
        .and_then(|line| line.strip_prefix("built at: "));
    primary == Some(exact)
        && scalibr.is_some_and(stable_version)
        && commit.is_some_and(|commit| {
            commit.len() == 40
                && commit
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        && built.is_some_and(utc_build_timestamp)
        && lines.next().is_none()
}

fn stable_version(version: &str) -> bool {
    let parts = version.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
        })
}

fn utc_build_timestamp(timestamp: &str) -> bool {
    let bytes = timestamp.as_bytes();
    if bytes.len() != 20
        || bytes.iter().enumerate().any(|(index, byte)| match index {
            4 | 7 => *byte != b'-',
            10 => *byte != b'T',
            13 | 16 => *byte != b':',
            19 => *byte != b'Z',
            _ => !byte.is_ascii_digit(),
        })
    {
        return false;
    }
    // ASCII was checked before indexing, so every slice is a character boundary.
    let number = |start, end| timestamp[start..end].parse::<u32>().unwrap();
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let days = match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return false,
    };
    year > 0
        && (1..=days).contains(&day)
        && number(11, 13) < 24
        && number(14, 16) < 60
        && number(17, 19) < 60
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

    // Exact CI 39367156023 native v2.2.2 receipt banner (SHA-256
    // c119923cf4845a7bf772facdc8de9fe6176d8542a3067ef8b1428877c96c0ce9).
    const OSV_BANNER: &str = "osv-scanner version: 2.2.2\nosv-scalibr version: 0.3.1\ncommit: 16ed4529c0d0cc1ddf1bed2fb08deba187339673\nbuilt at: 2025-08-27T02:52:51Z\n";
    const OSV_REQUIREMENT: &str = "exact-tool:osv-scanner:2.2.2";

    #[test]
    fn exact_osv_tool_mode_accepts_primary_version_with_ordered_metadata() {
        assert!(identity(OSV_BANNER).version_qualified(Some(OSV_REQUIREMENT)));
        assert!(
            identity(OSV_BANNER.trim_end_matches('\n')).version_qualified(Some(OSV_REQUIREMENT))
        );
        assert!(
            identity(&OSV_BANNER.replace('\n', "\r\n")).version_qualified(Some(OSV_REQUIREMENT))
        );
        // Generic exact retains its one-version rule, even for OSV banners.
        assert!(!identity(OSV_BANNER).version_qualified(Some("exact:2.2.2")));
        let mut unqualified = identity(OSV_BANNER);
        unqualified.version.qualified = false;
        assert!(!unqualified.version_qualified(Some(OSV_REQUIREMENT)));
    }

    #[test]
    fn exact_osv_tool_mode_rejects_forged_or_ambiguous_banners() {
        for banner in [
            OSV_BANNER.replace("osv-scanner version: 2.2.2", "osv-scanner version: 12.2.2"),
            OSV_BANNER.replace(
                "osv-scanner version: 2.2.2",
                "osv-scanner version: 2.2.2-rc.1",
            ),
            OSV_BANNER.replace("osv-scanner version: 2.2.2", "other-scanner version: 2.2.2"),
            OSV_BANNER.replace("osv-scalibr version: 0.3.1", "osv-scanner version: 2.2.2"),
            OSV_BANNER.replace(
                "osv-scalibr version: 0.3.1",
                "osv-scalibr version: 0.3.1 extra 2.2.2",
            ),
            OSV_BANNER.replace("osv-scalibr version: 0.3.1\n", ""),
            OSV_BANNER.replace(
                "osv-scalibr version: 0.3.1\ncommit: 16ed4529c0d0cc1ddf1bed2fb08deba187339673",
                "commit: 16ed4529c0d0cc1ddf1bed2fb08deba187339673\nosv-scalibr version: 0.3.1",
            ),
            OSV_BANNER.replace(
                "commit: 16ed4529c0d0cc1ddf1bed2fb08deba187339673",
                "commit: 16ed4529c0d0cc1ddf1bed2fb08deba187339673 extra",
            ),
            OSV_BANNER.replace("2025-08-27T02:52:51Z", "2025-02-29T02:52:51Z"),
            OSV_BANNER.replace("2025-08-27T02:52:51Z", "2025-08-27T24:52:51Z"),
            format!("{OSV_BANNER}osv-scanner version: 2.2.2\n"),
            format!("{OSV_BANNER}unknown: 2.2.2\n"),
            format!("{OSV_BANNER}\n"),
            format!("\n{OSV_BANNER}"),
        ] {
            assert!(
                !identity(&banner).version_qualified(Some(OSV_REQUIREMENT)),
                "{banner:?}"
            );
        }
        for requirement in [
            "exact-tool:osv-scanner:2.2.3",
            "exact-tool:osv-scanner:02.2.2",
            "exact-tool:osv-scanner:",
            "exact-tool:unknown:2.2.2",
        ] {
            assert!(!identity(OSV_BANNER).version_qualified(Some(requirement)));
        }
    }
}
