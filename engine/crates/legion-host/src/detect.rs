use crate::{descriptor::HostDescriptor, error::HostError};
use std::collections::{BTreeMap, BTreeSet};

/// Running harness identity, distinct from installed-client detection. Native
/// marker/session evidence establishes this binding; config directories do not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurrentHarness {
    ClaudeCode,
    Codex,
}

impl CurrentHarness {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
        }
    }
}

/// Resolve runtime identity without a default or installation-based fallback.
/// These session variables are also consumed by Legion's run/contract binding.
/// A declared unsupported harness or conflicting session families fails closed.
pub fn current_harness_from_environment(
    environment: &BTreeMap<String, String>,
) -> Result<CurrentHarness, HostError> {
    let present = |name: &str| {
        environment
            .get(name)
            .is_some_and(|value| !value.trim().is_empty())
    };
    let codex = ["CODEX_THREAD_ID", "CODEX_SESSION_ID"]
        .iter()
        .any(|name| present(name));
    let claude_marker = present("CLAUDECODE");
    let claude_session = present("CLAUDE_CODE_SESSION_ID");
    let claude_indicator = claude_marker || claude_session || present("CLAUDE_SESSION_ID");
    let fail = |reason: &str| HostError::HarnessConflict {
        path: "process environment".into(),
        reason: reason.into(),
    };
    if codex && claude_indicator {
        return Err(fail("conflicting running-harness session evidence"));
    }
    let resolved = if codex {
        CurrentHarness::Codex
    } else if claude_marker && claude_session {
        // Actual Claude desktop Bash exposes this marker + canonical session
        // pair. Legacy CLAUDE_SESSION_ID may coexist but cannot replace it.
        CurrentHarness::ClaudeCode
    } else {
        return Err(fail("running-harness marker/session binding missing"));
    };
    if let Some(declared) = environment
        .get("LEGION_HARNESS")
        .filter(|value| !value.trim().is_empty())
    {
        let declared = match declared.as_str() {
            "claude" | "claude-code" => CurrentHarness::ClaudeCode,
            "codex" => CurrentHarness::Codex,
            _ => return Err(fail("declared running harness unsupported")),
        };
        if declared != resolved {
            return Err(fail(
                "declared harness conflicts with running session evidence",
            ));
        }
    }
    Ok(resolved)
}

pub fn current_harness() -> Result<CurrentHarness, HostError> {
    // Collect only identity evidence, never auth values or unrelated process env.
    let environment = [
        "CODEX_THREAD_ID",
        "CODEX_SESSION_ID",
        "CLAUDE_CODE_SESSION_ID",
        "CLAUDE_SESSION_ID",
        "CLAUDECODE",
        "LEGION_HARNESS",
    ]
    .into_iter()
    .filter_map(|name| std::env::var(name).ok().map(|value| (name.into(), value)))
    .collect();
    current_harness_from_environment(&environment)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostEvidence {
    pub files: BTreeSet<String>,
    pub environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandResolutionEvidence {
    pub client_id: String,
    pub resolution_mode: String,
    pub resolved_executable: String,
    pub runtime_digest: String,
    pub provenance: String,
    pub launch_environment_digest: String,
    pub source_checkout: bool,
    pub path_sanitized: bool,
}

impl CommandResolutionEvidence {
    pub fn validate(&self) -> Result<(), HostError> {
        if !matches!(
            self.resolution_mode.as_str(),
            "agent-plugins-bare-command" | "supported-native-exact-path-registration"
        ) {
            return Err(HostError::CommandResolution {
                client: self.client_id.clone(),
                reason: "unsupported resolution mode".into(),
            });
        }
        if self.source_checkout {
            return Err(HostError::SourceCheckoutReference {
                path: self.resolved_executable.clone(),
            });
        }
        if [
            &self.client_id,
            &self.resolved_executable,
            &self.runtime_digest,
            &self.provenance,
            &self.launch_environment_digest,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err(HostError::CommandResolution {
                client: self.client_id.clone(),
                reason: "incomplete resolution evidence".into(),
            });
        }
        Ok(())
    }
}

impl HostEvidence {
    pub fn with_files(files: impl IntoIterator<Item = String>) -> Self {
        Self {
            files: files.into_iter().collect(),
            ..Self::default()
        }
    }
    pub fn with_environment(environment: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            environment: environment.into_iter().collect(),
            ..Self::default()
        }
    }
}

pub fn detect(descriptor: &HostDescriptor, evidence: &HostEvidence) -> Result<bool, HostError> {
    descriptor.validate()?;
    Ok(descriptor
        .detect
        .any_of
        .iter()
        .any(|path| evidence.files.contains(path))
        || descriptor.detect.env.iter().any(|name| {
            evidence
                .environment
                .get(name)
                .is_some_and(|value| !value.is_empty())
        }))
}

pub fn detect_all<'a>(
    descriptors: &'a [HostDescriptor],
    evidence: &HostEvidence,
) -> Result<Vec<&'a HostDescriptor>, HostError> {
    let mut detected = Vec::new();
    for descriptor in descriptors {
        if detect(descriptor, evidence)? {
            detected.push(descriptor);
        }
    }
    detected.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(detected)
}

#[cfg(test)]
mod current_harness_tests {
    use super::*;

    fn environment(rows: &[(&str, &str)]) -> BTreeMap<String, String> {
        rows.iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect()
    }

    #[test]
    fn session_evidence_resolves_both_harnesses() {
        for name in ["CODEX_THREAD_ID", "CODEX_SESSION_ID"] {
            assert_eq!(
                current_harness_from_environment(&environment(&[(name, "session")])).unwrap(),
                CurrentHarness::Codex
            );
        }
        for legacy in [false, true] {
            let mut rows = vec![("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", "session")];
            if legacy {
                rows.push(("CLAUDE_SESSION_ID", "legacy"));
            }
            assert_eq!(
                current_harness_from_environment(&environment(&rows)).unwrap(),
                CurrentHarness::ClaudeCode
            );
        }
        assert_eq!(CurrentHarness::ClaudeCode.as_str(), "claude-code");
        assert_eq!(CurrentHarness::Codex.as_str(), "codex");
    }

    #[test]
    fn identity_missing_conflicting_or_unsupported_fails_closed() {
        for rows in [
            vec![],
            vec![("CODEX_HOME", "installed")],
            vec![("CODEX_THREAD_ID", " ")],
            vec![("LEGION_HARNESS", "codex")],
            vec![("CLAUDECODE", "1")],
            vec![("CLAUDE_CODE_SESSION_ID", "session")],
            vec![("CLAUDE_SESSION_ID", "legacy")],
            vec![("CLAUDECODE", "1"), ("CLAUDE_SESSION_ID", "legacy")],
            vec![("CLAUDECODE", " "), ("CLAUDE_CODE_SESSION_ID", "session")],
            vec![("CLAUDECODE", "1"), ("CLAUDE_CODE_SESSION_ID", " ")],
            vec![("CODEX_THREAD_ID", "one"), ("CLAUDECODE", "1")],
            vec![
                ("CODEX_SESSION_ID", "one"),
                ("CLAUDE_CODE_SESSION_ID", "two"),
            ],
            vec![
                ("CODEX_THREAD_ID", "one"),
                ("CLAUDECODE", "1"),
                ("CLAUDE_CODE_SESSION_ID", "two"),
            ],
            vec![("CODEX_THREAD_ID", "one"), ("CLAUDE_SESSION_ID", "two")],
            vec![
                ("CODEX_THREAD_ID", "one"),
                ("LEGION_HARNESS", "claude-code"),
            ],
            vec![("CODEX_THREAD_ID", "one"), ("LEGION_HARNESS", "cursor")],
        ] {
            assert!(current_harness_from_environment(&environment(&rows)).is_err());
        }
    }
}
