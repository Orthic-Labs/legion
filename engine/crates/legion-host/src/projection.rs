use crate::{
    capability::Fidelity,
    descriptor::HostDescriptor,
    error::HostError,
    ownership::{digest_bytes, owned_block, OwnershipMark},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CollisionPolicy {
    CreateOnly,
    MergeOwned,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionItem {
    pub path: String,
    pub bytes: Vec<u8>,
    pub owner: String,
    pub generation: String,
    pub collision: CollisionPolicy,
    #[serde(default)]
    pub before_digest: Option<String>,
}

pub fn project_instructions(
    descriptor: &HostDescriptor,
    path: &str,
    content: &[u8],
    generation: &str,
) -> Result<ProjectionItem, HostError> {
    let payload = owned_block(&descriptor.id, generation, content)?;
    Ok(ProjectionItem {
        path: path.into(),
        bytes: payload,
        owner: descriptor.id.clone(),
        generation: generation.into(),
        collision: CollisionPolicy::MergeOwned,
        before_digest: None,
    })
}

pub fn project_skills(
    descriptor: &HostDescriptor,
    target_dir: &str,
    skills: &BTreeMap<String, Vec<u8>>,
    generation: &str,
) -> Result<Vec<ProjectionItem>, HostError> {
    let surface = descriptor
        .surfaces
        .get("skills")
        .ok_or_else(|| HostError::SourceDrift {
            path: "surfaces.skills".into(),
            reason: "skills surface is not declared".into(),
        })?;
    if matches!(Fidelity::parse(&surface.fidelity)?, Fidelity::Unsupported) {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for (id, bytes) in skills {
        if id.trim().is_empty() || id.contains('/') || id.contains('\\') || id.contains("..") {
            return Err(HostError::InvalidDescriptor {
                path: "skills.id".into(),
                reason: "skill id must be a single safe path component".into(),
            });
        }
        result.push(ProjectionItem {
            path: format!("{target_dir}/{id}"),
            bytes: bytes.clone(),
            owner: descriptor.id.clone(),
            generation: generation.into(),
            collision: CollisionPolicy::CreateOnly,
            before_digest: None,
        });
    }
    Ok(result)
}

pub fn project_mcp(
    descriptor: &HostDescriptor,
    path: &str,
    existing: Option<&[u8]>,
    command: &str,
    args: &[String],
    generation: &str,
) -> Result<ProjectionItem, HostError> {
    let surface = descriptor
        .surfaces
        .get("mcp")
        .ok_or_else(|| HostError::SourceDrift {
            path: "surfaces.mcp".into(),
            reason: "MCP surface is not declared".into(),
        })?;
    if matches!(Fidelity::parse(&surface.fidelity)?, Fidelity::Unsupported) {
        return Ok(ProjectionItem {
            path: path.into(),
            bytes: existing.unwrap_or_default().to_vec(),
            owner: descriptor.id.clone(),
            generation: generation.into(),
            collision: CollisionPolicy::MergeOwned,
            before_digest: None,
        });
    }
    let mechanism = &surface.mechanism;
    let before_digest = existing.map(|bytes| digest_bytes(bytes));
    let next = match mechanism.kind.as_str() {
        "json" => {
            let mut value: serde_json::Value = match existing {
                Some(bytes) if !bytes.is_empty() => {
                    serde_json::from_slice(bytes).map_err(|_| HostError::HarnessConflict {
                        path: path.into(),
                        reason: "existing JSON does not parse".into(),
                    })?
                }
                _ => serde_json::json!({}),
            };
            let key = mechanism.key.as_deref().unwrap_or("mcpServers");
            let object = value
                .as_object_mut()
                .ok_or_else(|| HostError::HarnessConflict {
                    path: path.into(),
                    reason: "existing JSON root is not an object".into(),
                })?;
            let servers = object
                .entry(key.to_owned())
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .ok_or_else(|| HostError::HarnessConflict {
                    path: path.into(),
                    reason: "MCP registry is not an object".into(),
                })?;
            let mut server = serde_json::json!({"command": command, "args": args});
            if let Some(current) = servers.get("legion") {
                let current_object =
                    current
                        .as_object()
                        .ok_or_else(|| HostError::HarnessConflict {
                            path: path.into(),
                            reason: "existing Legion MCP entry is not an object".into(),
                        })?;
                let metadata = current_object.get("_legionOwnership").ok_or_else(|| {
                    HostError::HarnessConflict {
                        path: path.into(),
                        reason: "existing Legion MCP entry has no ownership marker".into(),
                    }
                })?;
                let mark: OwnershipMark =
                    serde_json::from_value(metadata.clone()).map_err(|_| {
                        HostError::HarnessConflict {
                            path: path.into(),
                            reason: "existing Legion MCP ownership marker is malformed".into(),
                        }
                    })?;
                let mut payload = current.clone();
                payload.as_object_mut().unwrap().remove("_legionOwnership");
                let payload_bytes = serde_json::to_vec(&payload)?;
                if mark.owner != descriptor.id || !mark.owns(&payload_bytes) {
                    return Err(HostError::HarnessConflict {
                        path: path.into(),
                        reason: "existing Legion MCP entry ownership digest does not match".into(),
                    });
                }
            }
            let mark = OwnershipMark::new(
                descriptor.id.as_str(),
                generation,
                &serde_json::to_vec(&server)?,
            )?;
            server
                .as_object_mut()
                .unwrap()
                .insert("_legionOwnership".into(), serde_json::to_value(mark)?);
            servers.insert("legion".into(), server);
            serde_json::to_vec_pretty(&value)
                .map(|mut bytes| {
                    bytes.push(b'\n');
                    bytes
                })
                .map_err(HostError::from)?
        }
        "toml" => {
            let text = std::str::from_utf8(existing.unwrap_or_default()).map_err(|_| {
                HostError::HarnessConflict {
                    path: path.into(),
                    reason: "existing TOML is not UTF-8".into(),
                }
            })?;
            if !text.trim().is_empty() {
                text.parse::<toml::Value>()
                    .map_err(|_| HostError::HarnessConflict {
                        path: path.into(),
                        reason: "existing TOML does not parse".into(),
                    })?;
            }
            let table = mechanism.table.as_deref().unwrap_or("mcp_servers");
            let header = format!("[{table}.legion]");
            if let Some(start) = text.lines().position(|line| line.trim() == header) {
                let lines = text.lines().collect::<Vec<_>>();
                let marker_line = start
                    .checked_sub(1)
                    .and_then(|index| lines.get(index))
                    .copied()
                    .unwrap_or_default();
                let marker_text = marker_line.trim_start_matches('#').trim();
                let mark = parse_comment_marker(marker_text).ok_or_else(|| {
                    HostError::HarnessConflict {
                        path: path.into(),
                        reason: "existing Legion TOML entry has no ownership marker".into(),
                    }
                })?;
                let end = (start + 1..lines.len())
                    .find(|index| lines[*index].trim_start().starts_with('['))
                    .unwrap_or(lines.len());
                let payload = lines[start..end].join("\n");
                if mark.owner != descriptor.id || !mark.owns(payload.as_bytes()) {
                    return Err(HostError::HarnessConflict {
                        path: path.into(),
                        reason: "existing Legion TOML ownership digest does not match".into(),
                    });
                }
            }
            let payload = format!(
                "[{table}.legion]\ncommand = {}\nargs = [{}]",
                toml::Value::String(command.into()),
                args.iter()
                    .map(|arg| toml::Value::String(arg.clone()).to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let mark = OwnershipMark::new(descriptor.id.as_str(), generation, payload.as_bytes())?;
            format!(
                "{}\n# {}\n{}\n# /legion-owned\n",
                text.trim_end(),
                mark.marker()
                    .trim_start_matches("<!-- ")
                    .trim_end_matches(" -->"),
                payload
            )
            .into_bytes()
        }
        _ => {
            return Err(HostError::SemanticBlocker {
                reason: format!("MCP mechanism {} has no native projection", mechanism.kind),
            })
        }
    };
    Ok(ProjectionItem {
        path: path.into(),
        bytes: next,
        owner: descriptor.id.clone(),
        generation: generation.into(),
        collision: CollisionPolicy::MergeOwned,
        before_digest,
    })
}

fn parse_comment_marker(text: &str) -> Option<OwnershipMark> {
    let fields = text
        .strip_prefix("legion-owned ")?
        .split_whitespace()
        .filter_map(|field| field.split_once('='))
        .collect::<BTreeMap<_, _>>();
    Some(OwnershipMark {
        owner: fields.get("owner")?.to_string(),
        generation: fields.get("generation")?.to_string(),
        digest: fields.get("digest")?.to_string(),
    })
}
