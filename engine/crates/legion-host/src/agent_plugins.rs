//! External qualification evidence for the portable Agent Plugins package.
//! Portable-core assembly and containment are owned by pinned RightAX tooling;
//! this crate only classifies supplied evidence and never manufactures it.

use serde::{Deserialize, Serialize};

pub const RIGHTKIT_AX_VERSION: &str = "0.2.1";
pub const RIGHTKIT_AX_SOURCE_COMMIT: &str = "4c1a414269d8ffdb95b4b1e685440bd34784b41b";

/// Supplied external evidence only.  This crate never provisions RightKit,
/// signs artifacts, launches a real client, or converts an absent prerequisite
/// into a passing qualification result.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalQualificationInputs {
    #[serde(default)]
    pub signed_artifact_evidence: Option<String>,
    #[serde(default)]
    pub rightkit_ax: Option<PinnedAxEvidence>,
    #[serde(default)]
    pub real_client_evidence: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedAxEvidence {
    pub version: String,
    pub source_commit: String,
    pub report_reference: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExternalQualificationStatus {
    Pass,
    ExternalQualificationBlocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalQualification {
    pub status: ExternalQualificationStatus,
    pub missing_prerequisites: Vec<String>,
}

/// Classify supplied evidence without ever fabricating a passing external
/// qualification.  `PASS` is possible only when all three evidence classes
/// are explicitly present and AX matches the frozen exact pin.
pub fn classify_external_qualification(
    inputs: &ExternalQualificationInputs,
) -> ExternalQualification {
    let mut missing_prerequisites = Vec::new();
    if !non_empty_evidence(inputs.signed_artifact_evidence.as_deref()) {
        missing_prerequisites.push("signed-artifact-evidence".into());
    }
    match &inputs.rightkit_ax {
        Some(evidence)
            if evidence.version == RIGHTKIT_AX_VERSION
                && evidence.source_commit == RIGHTKIT_AX_SOURCE_COMMIT
                && !evidence.report_reference.trim().is_empty() => {}
        _ => missing_prerequisites.push(format!(
            "pinned-rightkit-ax-{}@{}",
            RIGHTKIT_AX_VERSION, RIGHTKIT_AX_SOURCE_COMMIT
        )),
    }
    if !non_empty_evidence(inputs.real_client_evidence.as_deref()) {
        missing_prerequisites.push("real-client-evidence".into());
    }
    missing_prerequisites.sort();
    let status = if missing_prerequisites.is_empty() {
        ExternalQualificationStatus::Pass
    } else {
        ExternalQualificationStatus::ExternalQualificationBlocked
    };
    ExternalQualification {
        status,
        missing_prerequisites,
    }
}

fn non_empty_evidence(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}
