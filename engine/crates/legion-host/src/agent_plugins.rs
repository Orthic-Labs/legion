//! Mechanical assembly and validation for the portable Agent Plugins package.
//! It deliberately accepts already-verified identity material and never
//! manufactures Legion runtime, policy, routing, or receipt semantics.

use crate::{digest_bytes, validate_relative_path, HostError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};

const PACKAGE_FILES: [&str; 6] = [
    "plugin.json",
    "mcp.json",
    "skills/legion/SKILL.md",
    "share/legion/release-binding.json",
    "share/legion/identity/release-identity.json",
    "share/legion/schemas/mcp-tools.schema.json",
];

pub const RIGHTKIT_AX_VERSION: &str = "0.2.0";
pub const RIGHTKIT_AX_SOURCE_COMMIT: &str = "01f52555202da3dffc6b649ca44e803b55238081";

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

#[derive(Clone, Debug)]
pub struct PortableTemplates {
    pub plugin_json: Vec<u8>,
    pub mcp_json: Vec<u8>,
    pub skill_markdown: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct VerifiedPortableInputs {
    pub release_binding: Vec<u8>,
    pub release_identity: Vec<u8>,
    pub mcp_tool_schema: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssembledPackage {
    pub root: PathBuf,
    pub entries: Vec<String>,
    pub digest: String,
}

pub fn validate_templates(templates: &PortableTemplates) -> Result<(), HostError> {
    let plugin: Value = serde_json::from_slice(&templates.plugin_json)?;
    if !plugin.is_object() {
        return Err(HostError::InvalidDescriptor {
            path: "plugin.json".into(),
            reason: "must be a JSON object".into(),
        });
    }
    let mcp: Value = serde_json::from_slice(&templates.mcp_json)?;
    let mcp_object = mcp
        .as_object()
        .ok_or_else(|| HostError::InvalidDescriptor {
            path: "mcp.json".into(),
            reason: "must be a JSON object".into(),
        })?;
    if mcp_object
        .keys()
        .any(|key| key != "$schema" && key != "mcpServers")
    {
        return Err(HostError::InvalidDescriptor {
            path: "mcp.json".into(),
            reason: "contains an unapproved top-level field".into(),
        });
    }
    let server = mcp
        .get("mcpServers")
        .and_then(|value| value.get("legion"))
        .ok_or_else(|| HostError::InvalidDescriptor {
            path: "mcp.json.mcpServers.legion".into(),
            reason: "missing legion server".into(),
        })?;
    let args = server
        .get("args")
        .and_then(Value::as_array)
        .ok_or_else(|| HostError::InvalidDescriptor {
            path: "mcp.json.mcpServers.legion.args".into(),
            reason: "must be an array".into(),
        })?;
    let expected = ["serve", "--stdio", "--plugin-root", "${PLUGIN_ROOT}"];
    if server.get("type").and_then(Value::as_str) != Some("stdio")
        || server.get("command").and_then(Value::as_str) != Some("legion")
        || args.iter().filter_map(Value::as_str).collect::<Vec<_>>() != expected.to_vec()
    {
        return Err(HostError::InvalidDescriptor {
            path: "mcp.json".into(),
            reason: "must use the exact bare legion stdio contract".into(),
        });
    }
    if templates.skill_markdown.is_empty() {
        return Err(HostError::InvalidDescriptor {
            path: "skills/legion/SKILL.md".into(),
            reason: "must be non-empty".into(),
        });
    }
    Ok(())
}

pub fn assemble_clean_room(
    root: impl AsRef<Path>,
    templates: &PortableTemplates,
    inputs: &VerifiedPortableInputs,
) -> Result<AssembledPackage, HostError> {
    validate_templates(templates)?;
    for path in PACKAGE_FILES {
        validate_relative_path(path)?;
    }
    for (name, bytes) in [
        ("release-binding.json", &inputs.release_binding),
        ("release-identity.json", &inputs.release_identity),
        ("mcp-tools.schema.json", &inputs.mcp_tool_schema),
    ] {
        if serde_json::from_slice::<Value>(bytes).is_err() {
            return Err(HostError::ReleaseBindingMismatch {
                reason: format!("verified {name} is not JSON"),
            });
        }
    }
    let root = root.as_ref();
    reject_symlink_ancestors(root)?;
    if root.exists() {
        return Err(HostError::HarnessConflict {
            path: root.display().to_string(),
            reason: "clean-room root must not already exist".into(),
        });
    }
    fs::create_dir_all(root).map_err(|error| HostError::Io {
        path: root.into(),
        reason: error.to_string(),
    })?;
    let entries: [(&str, &[u8]); 6] = [
        (PACKAGE_FILES[0], &templates.plugin_json),
        (PACKAGE_FILES[1], &templates.mcp_json),
        (PACKAGE_FILES[2], &templates.skill_markdown),
        (PACKAGE_FILES[3], &inputs.release_binding),
        (PACKAGE_FILES[4], &inputs.release_identity),
        (PACKAGE_FILES[5], &inputs.mcp_tool_schema),
    ];
    for (relative, bytes) in entries {
        let path = root.join(relative);
        let parent = path.parent().ok_or_else(|| HostError::PathEscape {
            path: relative.into(),
            reason: "has no parent".into(),
        })?;
        reject_symlink_ancestors(parent)?;
        fs::create_dir_all(parent).map_err(|error| HostError::Io {
            path: parent.into(),
            reason: error.to_string(),
        })?;
        fs::write(&path, bytes).map_err(|error| HostError::Io {
            path: path.clone(),
            reason: error.to_string(),
        })?;
        if fs::symlink_metadata(&path)
            .map_err(|error| HostError::Io {
                path: path.clone(),
                reason: error.to_string(),
            })?
            .file_type()
            .is_symlink()
        {
            return Err(HostError::PathEscape {
                path: path.display().to_string(),
                reason: "package entries may not be symlinks".into(),
            });
        }
    }
    let mut all = Vec::new();
    for relative in PACKAGE_FILES {
        all.extend_from_slice(
            &fs::read(root.join(relative)).map_err(|error| HostError::Io {
                path: root.join(relative),
                reason: error.to_string(),
            })?,
        );
    }
    Ok(AssembledPackage {
        root: root.into(),
        entries: PACKAGE_FILES
            .iter()
            .map(|value| value.to_string())
            .collect(),
        digest: digest_bytes(&all),
    })
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), HostError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(HostError::PathEscape {
                    path: ancestor.display().to_string(),
                    reason: "clean-room staging path crosses a symlink".into(),
                });
            }
            Ok(_) | Err(_) => {}
        }
    }
    Ok(())
}
