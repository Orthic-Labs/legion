use crate::{descriptor::HostDescriptor, error::HostError};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostEvidence {
    pub files: BTreeSet<String>,
    pub environment: BTreeMap<String, String>,
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
