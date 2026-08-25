use crate::{descriptor::HostDescriptor, error::HostError};
use std::collections::{BTreeMap, BTreeSet};

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
