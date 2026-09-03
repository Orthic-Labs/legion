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
    let before_digest = existing.map(digest_bytes);
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
                // Same reasoning as the TOML path: our own stale entry is what
                // repair updates; only a foreign owner is a conflict.
                if mark.owner != descriptor.id {
                    return Err(HostError::HarnessConflict {
                        path: path.into(),
                        reason: "existing MCP entry is owned by another writer".into(),
                    });
                }
                let _ = &payload_bytes;
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
                // A document, not a bare value: `parse::<toml::Value>()` in
                // toml 1.x reads a single value and rejects every real
                // config.toml with "unexpected content, expected nothing".
                toml::from_str::<toml::Value>(text)
                    .map_err(|_| HostError::HarnessConflict {
                        path: path.into(),
                        reason: "existing TOML does not parse".into(),
                    })?;
            }
            let table = mechanism.table.as_deref().unwrap_or("mcp_servers");
            let header = format!("[{table}.legion]");
            // Remove any prior Legion-owned block before appending the fresh
            // one below. Without this, re-running the projection over its own
            // previous output (repair, twice) would append a second
            // `[table.legion]` table on every call instead of replacing it.
            let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
            if let Some(start) = lines.iter().position(|line| line.trim() == header) {
                let marker_index = start.checked_sub(1);
                let marker_line = marker_index
                    .and_then(|index| lines.get(index))
                    .cloned()
                    .unwrap_or_default();
                let marker_text = marker_line.trim_start_matches('#').trim();
                // An unmarked entry is usually Legion's own output from a build
                // that wrote no marker. Refusing it forever makes `setup repair`
                // permanently red with no way out, so adopt an entry that is
                // byte-identical to what this version would write, and keep
                // refusing anything a user actually authored.
                let mark = match parse_comment_marker(marker_text) {
                    Some(mark) => Some(mark),
                    None => {
                        let expected = format!(
                            "[{table}.legion]
command = {}
args = [{}]",
                            toml_string(command),
                            args.iter()
                                .map(|arg| toml_string(arg))
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                        let existing_end = (start + 1..lines.len())
                            .find(|index| lines[*index].trim_start().starts_with('['))
                            .unwrap_or(lines.len());
                        let existing = lines[start..existing_end].join("
");
                        // Compare parsed values, not bytes. An older build
                        // wrote basic strings where this one writes literal
                        // strings, so a byte compare rejects an entry that is
                        // ours and semantically identical.
                        // `parse::<Value>()` reads a bare value in toml 1.x and
                        // rejects a document; commit f987682d fixed exactly this
                        // for config.toml. Parse as a document.
                        let same = match (
                            toml::from_str::<toml::Value>(existing.trim_end()),
                            toml::from_str::<toml::Value>(&expected),
                        ) {
                            (Ok(left), Ok(right)) => left == right,
                            _ => existing.trim_end() == expected,
                        };
                        if !same {
                            return Err(HostError::HarnessConflict {
                                path: path.into(),
                                reason: "existing Legion TOML entry has no ownership marker".into(),
                            });
                        }
                        None
                    }
                };
                // The payload digested at write time is exactly the table
                // (through the last `args = [...]` line), not the trailing
                // `# /legion-owned` footer comment. Read-back verification
                // must stop at the same place, or the digest never matches
                // its own prior output.
                let footer = (start + 1..lines.len()).find(|index| lines[*index].trim() == "# /legion-owned");
                let payload_end = footer.unwrap_or_else(|| {
                    (start + 1..lines.len())
                        .find(|index| lines[*index].trim_start().starts_with('['))
                        .unwrap_or(lines.len())
                });
                let payload = lines[start..payload_end].join("\n");
                if let Some(mark) = &mark {
                    // A digest mismatch under our OWN marker means the entry we
                    // wrote is stale — the executable path or args moved with an
                    // upgrade — which is precisely what repair exists to correct.
                    // Refusing it left setup permanently red with no way out. A
                    // marker naming a different owner is still a real conflict.
                    if mark.owner != descriptor.id {
                        return Err(HostError::HarnessConflict {
                            path: path.into(),
                            reason: "existing TOML entry is owned by another writer".into(),
                        });
                    }
                }
                let removal_end = footer.map_or(payload_end, |index| index + 1);
                // Only step back over the line above when it really is our
                // marker. On an adopted, unmarked entry that line belongs to
                // whatever precedes the table, and removing it would delete
                // the user's content.
                let block_start = if mark.is_some() {
                    marker_index.unwrap_or(start)
                } else {
                    start
                };
                lines.drain(block_start..removal_end);
            }
            let retained = lines.join("\n");
            let payload = format!(
                "[{table}.legion]\ncommand = {}\nargs = [{}]",
                toml_string(command),
                args.iter()
                    .map(|arg| toml_string(arg))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let mark = OwnershipMark::new(descriptor.id.as_str(), generation, payload.as_bytes())?;
            format!(
                "{}\n# {}\n{}\n# /legion-owned\n",
                retained.trim_end(),
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

/// Render one TOML string value. A Windows executable path is full of
/// backslashes, and a basic string would have to escape every one of them; a
/// literal string carries the path verbatim and is what other products already
/// write into `config.toml`. Values that cannot be a literal string (they
/// contain a single quote, a newline, or a control character) fall back to an
/// escaped basic string. Legion 0.3.13 shipped the unescaped basic form, which
/// made the whole file unparseable and left Codex unregistered (run
/// 33664640926).
fn toml_string(value: &str) -> String {
    let literal_safe = !value.contains('\'')
        && !value.contains('\n')
        && !value.contains('\r')
        && !value.chars().any(char::is_control);
    if literal_safe {
        return format!("'{value}'");
    }
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                escaped.push_str(&format!("\\u{:04X}", other as u32));
            }
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    escaped
}

pub(crate) fn parse_comment_marker(text: &str) -> Option<OwnershipMark> {
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
